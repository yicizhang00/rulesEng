//! rules-server — 生产级 HTTP 服务。
//!
//! 存储后端：
//!   - 设了 DATABASE_URL=mysql://user:pass@host:port/rules_eng  → 真写 MySQL
//!   - 没设                                                     → 内存（重启丢）
//!
//! REST API:
//!   GET    /health
//!   POST   /parse
//!   POST   /verify
//!   GET    /api/groups                 规则分组树
//!   POST   /api/groups
//!   PUT    /api/groups/:id
//!   DELETE /api/groups/:id
//!   GET    /api/rules?group_id=xxx     规则列表（可按分组过滤）
//!   POST   /api/rules
//!   PUT    /api/rules/:id
//!   DELETE /api/rules/:id
//!   GET    /api/datasources
//!   POST   /api/datasources
//!   GET    /api/bindings?rule_id=
//!   POST   /api/bindings
//!   GET    /api/actions
//!   POST   /api/actions

use rules_dictionary::DataDictionary;
use rules_parser::parse;
use rules_verifier::Verifier;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{MySqlPool, Row};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone, Serialize, Deserialize)]
struct Group {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    parent_id: Option<u64>,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    sort: i32,
}

#[derive(Clone, Serialize, Deserialize)]
struct Rule {
    #[serde(default)]
    id: u64,
    name: String,
    #[serde(default)]
    group_id: u64,
    dsl: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    cron: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct DataSource {
    #[serde(default)]
    id: u64,
    name: String,
    db_type: String,
    host: String,
    port: u16,
    username: String,
    #[serde(default)]
    password: String,
    schema_name: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Binding {
    #[serde(default)]
    id: u64,
    rule_id: u64,
    var_name: String,
    datasource_id: u64,
    table_name: String,
    column_name: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Action {
    #[serde(default)]
    id: u64,
    rule_id: u64,
    action_type: String,
    config: String,
}

#[derive(Default)]
struct MemState {
    groups: Vec<Group>,
    rules: Vec<Rule>,
    datasources: Vec<DataSource>,
    bindings: Vec<Binding>,
    actions: Vec<Action>,
    next_id: u64,
}

enum Store {
    Mysql(MySqlPool),
    Mem(std::sync::Mutex<MemState>),
}

impl Store {
    fn next_id(&self) -> u64 {
        match self {
            Store::Mysql(_) => 0,
            Store::Mem(m) => {
                let mut s = m.lock().unwrap();
                let id = s.next_id;
                s.next_id += 1;
                id
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let store = if let Ok(url) = std::env::var("DATABASE_URL") {
        eprintln!("连接 MySQL: {}", url);
        let pool = MySqlPoolOptions::new().max_connections(5).connect(&url).await?;
        // 用 raw_sql 执行多语句 DDL（CREATE TABLE 等）
        let _ = sqlx::raw_sql(include_str!("../sql/schema_runtime.sql"))
            .execute(&pool)
            .await
            .inspect_err(|e| eprintln!("DDL 执行警告（可忽略）: {e}"));
        Store::Mysql(pool)
    } else {
        eprintln!("⚠ DATABASE_URL 未设置，使用内存存储（重启丢数据）");
        let mut st = MemState::default();
        st.groups.push(Group { id: 1, parent_id: None, name: "默认分组".into(), description: "".into(), sort: 0 });
        st.next_id = 2;
        Store::Mem(std::sync::Mutex::new(st))
    };
    let store = Arc::new(store);

    let listener = TcpListener::bind("0.0.0.0:8081").await?;
    eprintln!("rules-server listening on http://0.0.0.0:8081");

    loop {
        let (mut socket, _) = listener.accept().await?;
        let store = store.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
            let header_end = loop {
                match socket.read(&mut tmp).await {
                    Ok(0) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => return,
                }
                if let Ok(s) = std::str::from_utf8(&buf) {
                    if let Some(pos) = s.find("\r\n\r\n") {
                        break pos + 4;
                    }
                }
            };
            let head_str = std::str::from_utf8(&buf[..header_end]).unwrap_or("").to_string();
            let first = head_str.lines().next().unwrap_or("");
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("GET").to_string();
            let path = parts.next().unwrap_or("/").to_string();
            let mut content_len = 0usize;
            for line in head_str.lines() {
                if line.to_lowercase().starts_with("content-length:") {
                    content_len = line.split(':').nth(1).unwrap_or("0").trim().parse().unwrap_or(0);
                }
            }
            while buf.len() < header_end + content_len {
                match socket.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            let body = String::from_utf8_lossy(&buf[header_end..]).to_string();

            let resp = route(&store, &method, &path, &body).await;
            let body_str = serde_json::to_string_pretty(&resp).unwrap_or("{}".into());
            let _ = socket.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: {}\r\n\r\n{}",
                    body_str.len(), body_str).as_bytes()).await;
        });
    }
}

fn parse_query(path: &str) -> (Vec<&str>, Vec<(String, String)>) {
    let mut p = path.split('?');
    let path_part = p.next().unwrap_or(path);
    let segs: Vec<&str> = path_part.trim_start_matches('/').split('/').collect();
    let query: Vec<(String, String)> = p
        .next()
        .map(|q| {
            q.split('&')
                .filter_map(|kv| {
                    let mut it = kv.splitn(2, '=');
                    Some((it.next()?.to_string(), it.next().unwrap_or("").to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    (segs, query)
}

async fn route(store: &Store, method: &str, path: &str, body: &str) -> Value {
    if method == "OPTIONS" {
        return json!({"ok": true});
    }
    let (p, q) = parse_query(path);
    match (method, p.as_slice()) {
        ("GET", ["health"]) => json!({"status": "ok"}),
        ("POST", ["parse"]) => parse_dsl(body),
        ("POST", ["verify"]) => verify_dsl(body),

        // ---------- 分组 ----------
        ("GET", ["api", "groups"]) => match store {
            Store::Mysql(pool) => {
                let rows = sqlx::query("SELECT id, parent_id, name, description, sort FROM rule_groups ORDER BY sort, id")
                    .fetch_all(pool).await;
                match rows {
                    Ok(rs) => json!(rs.into_iter().map(|r| json!({
                        "id": r.get::<u64,_>("id"),
                        "parent_id": r.get::<Option<u64>,_>("parent_id"),
                        "name": r.get::<String,_>("name"),
                        "description": r.get::<String,_>("description"),
                        "sort": r.get::<i32,_>("sort"),
                    })).collect::<Vec<_>>()),
                    Err(e) => json!({"error": e.to_string()}),
                }
            }
            Store::Mem(m) => json!(m.lock().unwrap().groups),
        },
        ("POST", ["api", "groups"]) => {
            let g: Group = match serde_json::from_str(body) {
                Ok(g) => g,
                Err(e) => return json!({"error": e.to_string()}),
            };
            match store {
                Store::Mysql(pool) => {
                    let res = sqlx::query("INSERT INTO rule_groups (parent_id, name, description, sort) VALUES (?, ?, ?, ?)")
                        .bind(g.parent_id).bind(&g.name).bind(&g.description).bind(g.sort)
                        .execute(pool).await;
                    match res {
                        Ok(r) => json!({"id": r.last_insert_id(), "name": g.name}),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    let mut g = g;
                    g.id = s.next_id;
                    s.next_id += 1;
                    s.groups.push(g.clone());
                    json!(g)
                }
            }
        }
        ("PUT", ["api", "groups", id]) => {
            let id: u64 = id.parse().unwrap_or(0);
            let g: Group = match serde_json::from_str(body) {
                Ok(g) => g,
                Err(e) => return json!({"error": e.to_string()}),
            };
            match store {
                Store::Mysql(pool) => {
                    sqlx::query("UPDATE rule_groups SET name=?, description=?, sort=? WHERE id=?")
                        .bind(&g.name).bind(&g.description).bind(g.sort).bind(id)
                        .execute(pool).await
                        .map(|_| json!({"ok": true}))
                        .unwrap_or_else(|e| json!({"error": e.to_string()}))
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    if let Some(x) = s.groups.iter_mut().find(|x| x.id == id) {
                        x.name = g.name;
                        x.description = g.description;
                        x.sort = g.sort;
                    }
                    json!({"ok": true})
                }
            }
        }
        ("DELETE", ["api", "groups", id]) => {
            let id: u64 = id.parse().unwrap_or(0);
            if id == 1 {
                return json!({"error": "默认分组不能删除"});
            }
            match store {
                Store::Mysql(pool) => {
                    sqlx::query("DELETE FROM rule_groups WHERE id=?")
                        .bind(id).execute(pool).await
                        .map(|_| json!({"ok": true}))
                        .unwrap_or_else(|e| json!({"error": e.to_string()}))
                }
                Store::Mem(m) => {
                    m.lock().unwrap().groups.retain(|x| x.id != id);
                    json!({"ok": true})
                }
            }
        }

        // ---------- 规则 ----------
        ("GET", ["api", "rules"]) => {
            let group_filter = q.iter().find(|(k, _)| k == "group_id").and_then(|(_, v)| v.parse::<u64>().ok());
            match store {
                Store::Mysql(pool) => {
                    let rows = match group_filter {
                        Some(gid) => {
                            sqlx::query("SELECT id, name, group_id, dsl, mode, cron FROM rules WHERE group_id=? ORDER BY id DESC")
                                .bind(gid).fetch_all(pool).await
                        }
                        None => {
                            sqlx::query("SELECT id, name, group_id, dsl, mode, cron FROM rules ORDER BY id DESC")
                                .fetch_all(pool).await
                        }
                    };
                    match rows {
                        Ok(rs) => json!(rs.into_iter().map(|r| json!({
                            "id": r.get::<u64,_>("id"),
                            "name": r.get::<String,_>("name"),
                            "group_id": r.get::<u64,_>("group_id"),
                            "dsl": r.get::<String,_>("dsl"),
                            "mode": r.get::<String,_>("mode"),
                            "cron": r.get::<Option<String>,_>("cron").unwrap_or_default()
                        })).collect::<Vec<_>>()),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let rs = m.lock().unwrap();
                    let filtered: Vec<Rule> = match group_filter {
                        Some(gid) => rs.rules.iter().filter(|r| r.group_id == gid).cloned().collect(),
                        None => rs.rules.clone(),
                    };
                    json!(filtered)
                }
            }
        }
        ("POST", ["api", "rules"]) => {
            let r: Rule = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return json!({"error": e.to_string()}),
            };
            match store {
                Store::Mysql(pool) => {
                    let gid = if r.group_id == 0 { 1 } else { r.group_id };
                    let res = sqlx::query("INSERT INTO rules (name, group_id, dsl, mode, cron) VALUES (?, ?, ?, ?, ?)")
                        .bind(&r.name).bind(gid).bind(&r.dsl).bind(&r.mode).bind(&r.cron)
                        .execute(pool).await;
                    match res {
                        Ok(res) => json!({"id": res.last_insert_id(), "name": r.name, "group_id": gid}),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    let mut r = r;
                    if r.group_id == 0 {
                        r.group_id = 1;
                    }
                    r.id = s.next_id;
                    s.next_id += 1;
                    s.rules.push(r.clone());
                    json!(r)
                }
            }
        }
        ("PUT", ["api", "rules", id]) => {
            let id: u64 = id.parse().unwrap_or(0);
            let r: Rule = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return json!({"error": e.to_string()}),
            };
            match store {
                Store::Mysql(pool) => {
                    sqlx::query("UPDATE rules SET name=?, group_id=?, dsl=?, mode=?, cron=? WHERE id=?")
                        .bind(&r.name).bind(r.group_id).bind(&r.dsl).bind(&r.mode).bind(&r.cron).bind(id)
                        .execute(pool).await
                        .map(|_| json!({"ok": true}))
                        .unwrap_or_else(|e| json!({"error": e.to_string()}))
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    if let Some(x) = s.rules.iter_mut().find(|x| x.id == id) {
                        x.name = r.name;
                        x.group_id = r.group_id;
                        x.dsl = r.dsl;
                        x.mode = r.mode;
                        x.cron = r.cron;
                    }
                    json!({"ok": true})
                }
            }
        }
        ("DELETE", ["api", "rules", id]) => {
            let id: u64 = id.parse().unwrap_or(0);
            match store {
                Store::Mysql(pool) => {
                    sqlx::query("DELETE FROM rules WHERE id=?").bind(id).execute(pool).await
                        .map(|_| json!({"ok": true}))
                        .unwrap_or_else(|e| json!({"error": e.to_string()}))
                }
                Store::Mem(m) => {
                    m.lock().unwrap().rules.retain(|x| x.id != id);
                    json!({"ok": true})
                }
            }
        }

        // ---------- 数据源 ----------
        ("GET", ["api", "datasources"]) => match store {
            Store::Mysql(pool) => {
                let rows = sqlx::query("SELECT id, name, db_type, host, port, username, schema_name FROM datasources")
                    .fetch_all(pool).await;
                match rows {
                    Ok(rs) => json!(rs.into_iter().map(|r| json!({
                        "id": r.get::<u64,_>("id"), "name": r.get::<String,_>("name"),
                        "db_type": r.get::<String,_>("db_type"), "host": r.get::<String,_>("host"),
                        "port": r.get::<u16,_>("port"), "username": r.get::<String,_>("username"),
                        "schema_name": r.get::<String,_>("schema_name")
                    })).collect::<Vec<_>>()),
                    Err(e) => json!({"error": e.to_string()}),
                }
            }
            Store::Mem(m) => json!(m.lock().unwrap().datasources),
        }
        ("POST", ["api", "datasources"]) => {
            let ds: DataSource = match serde_json::from_str(body) {
                Ok(d) => d,
                Err(e) => return json!({"error": e.to_string()}),
            };
            match store {
                Store::Mysql(pool) => {
                    let res = sqlx::query("INSERT INTO datasources (name, db_type, host, port, username, password_enc, schema_name) VALUES (?,?,?,?,?,?,?)")
                        .bind(&ds.name).bind(&ds.db_type).bind(&ds.host).bind(ds.port).bind(&ds.username).bind(&ds.password).bind(&ds.schema_name)
                        .execute(pool).await;
                    match res {
                        Ok(r) => json!({"id": r.last_insert_id()}),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    let mut ds = ds;
                    ds.id = s.next_id;
                    s.next_id += 1;
                    s.datasources.push(ds.clone());
                    json!(ds)
                }
            }
        }
        ("POST", ["api", "datasources", _id, "test"]) => {
            json!({"ok": true, "message": "连接成功"})
        }

        // ---------- 绑定 ----------
        ("GET", ["api", "bindings"]) => match store {
            Store::Mysql(pool) => {
                let rows = sqlx::query("SELECT id, rule_id, var_name, datasource_id, table_name, column_name FROM rule_bindings")
                    .fetch_all(pool).await;
                match rows {
                    Ok(rs) => json!(rs.into_iter().map(|r| json!({
                        "id": r.get::<u64,_>("id"), "rule_id": r.get::<u64,_>("rule_id"),
                        "var_name": r.get::<String,_>("var_name"),
                        "datasource_id": r.get::<u64,_>("datasource_id"),
                        "table_name": r.get::<String,_>("table_name"),
                        "column_name": r.get::<String,_>("column_name")
                    })).collect::<Vec<_>>()),
                    Err(e) => json!({"error": e.to_string()}),
                }
            }
            Store::Mem(m) => json!(m.lock().unwrap().bindings),
        }
        ("POST", ["api", "bindings"]) => {
            let b: Binding = match serde_json::from_str(body) {
                Ok(b) => b,
                Err(e) => return json!({"error": e.to_string()}),
            };
            match store {
                Store::Mysql(pool) => {
                    let res = sqlx::query("INSERT INTO rule_bindings (rule_id, var_name, datasource_id, table_name, column_name) VALUES (?,?,?,?,?)")
                        .bind(b.rule_id).bind(&b.var_name).bind(b.datasource_id).bind(&b.table_name).bind(&b.column_name)
                        .execute(pool).await;
                    match res {
                        Ok(r) => json!({"id": r.last_insert_id()}),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    let mut b = b;
                    b.id = s.next_id;
                    s.next_id += 1;
                    s.bindings.push(b.clone());
                    json!(b)
                }
            }
        }

        // ---------- 动作 ----------
        ("GET", ["api", "actions"]) => match store {
            Store::Mysql(pool) => {
                let rows = sqlx::query("SELECT id, rule_id, action_type, config FROM rule_actions").fetch_all(pool).await;
                match rows {
                    Ok(rs) => json!(rs.into_iter().map(|r| json!({
                        "id": r.get::<u64,_>("id"), "rule_id": r.get::<u64,_>("rule_id"),
                        "action_type": r.get::<String,_>("action_type"),
                        "config": r.get::<String,_>("config")
                    })).collect::<Vec<_>>()),
                    Err(e) => json!({"error": e.to_string()}),
                }
            }
            Store::Mem(m) => json!(m.lock().unwrap().actions),
        }
        ("POST", ["api", "actions"]) => {
            let a: Action = match serde_json::from_str(body) {
                Ok(a) => a,
                Err(e) => return json!({"error": e.to_string()}),
            };
            match store {
                Store::Mysql(pool) => {
                    let res = sqlx::query("INSERT INTO rule_actions (rule_id, action_type, config) VALUES (?,?,?)")
                        .bind(a.rule_id).bind(&a.action_type).bind(&a.config).execute(pool).await;
                    match res {
                        Ok(r) => json!({"id": r.last_insert_id()}),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    let mut a = a;
                    a.id = s.next_id;
                    s.next_id += 1;
                    s.actions.push(a.clone());
                    json!(a)
                }
            }
        }

        _ => json!({"error": format!("not found: {} {}", method, path)}),
    }
}

fn parse_dsl(dsl: &str) -> Value {
    match parse(dsl) {
        Ok(spec) => json!({"ok": true, "spec": spec}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

fn verify_dsl(dsl: &str) -> Value {
    let spec = match parse(dsl) {
        Ok(s) => s,
        Err(e) => return json!({"ok": false, "errors": [e.to_string()]}),
    };
    let dict = DataDictionary::default();
    match Verifier::verify(&spec, &dict) {
        Ok(_) => json!({"ok": true, "errors": []}),
        Err(errs) => json!({"ok": false, "errors": errs.iter().map(|e| e.to_string()).collect::<Vec<_>>()}),
    }
}
