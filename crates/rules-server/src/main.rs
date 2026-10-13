//! rules-server — 生产级 HTTP 服务（v1.0）。
//!
//! 存储后端（FR11）：
//!   - 设了 DATABASE_URL=mysql://user:pass@host:port/rules_eng  → 真写 MySQL
//!   - 没设                                                     → 内存（重启丢）
//!
//! 启动时幂等执行 `sql/schema_runtime.sql`（PRD §9 物理模型），随后做一次
//! 结构升级（`migrate_legacy_schema`），把 v0.x 的旧列名补齐到 v1.0 语义。
//!
//! REST API：
//!   GET    /health
//!   GET    /api/modes                        四模目录（PURE/STATEFUL/STREAM/DMN）与其约束
//!   POST   /parse                            DSL 文本 → AST JSON / 精确错误
//!   POST   /verify[?rule_id=N]               DSL 文本 → 分级校验报告（含反例参数）
//!   POST   /api/counterexample               DSL 文本 → 反例诊断（AC1）
//!   GET    /api/groups                       规则分组树
//!   POST   /api/groups
//!   PUT    /api/groups/:id
//!   DELETE /api/groups/:id                   删除分组 → 组内规则迁移到默认分组（FR9）
//!   GET    /api/rules?group_id=xxx           规则列表（可按分组过滤）
//!   GET    /api/rules/:id                    单条规则详情
//!   POST   /api/rules                        新建规则（parse+verify 门禁 → rules + rule_versions）
//!   PUT    /api/rules/:id                    更新规则（同样走门禁 + 版本快照）
//!   DELETE /api/rules/:id
//!   GET    /api/rules/:id/versions           规则版本历史
//!   POST   /api/rules/:id/export-dmn         导出 DMN 1.3 XML（FR3）
//!   POST   /api/rules/:id/counterexample     针对已落库规则求反例（AC1）
//!   POST   /api/dmn/import                   导入 DMN 1.3 XML → DSL + AST（FR3）
//!   POST   /api/decision-tables/trial        决策表试算（FR3 / AC4）
//!   GET    /api/datasources
//!   POST   /api/datasources
//!   PUT    /api/datasources/:id
//!   DELETE /api/datasources/:id
//!   POST   /api/datasources/:id/test         真实连接探测
//!   GET    /api/datasources/:id/schema       schema → table → column 三级树（FR8）
//!   GET    /api/bindings?rule_id=            变量 ↔ 列物理绑定（FR8，别名 /api/variable-bindings）
//!   POST   /api/bindings                     upsert（rule_id + var_name 唯一）
//!   DELETE /api/bindings/:id
//!   GET    /api/actions
//!   POST   /api/actions
//!   DELETE /api/actions/:id

use rules_ast::SpecFile;
use rules_dictionary::{DataDictionary, ScalarValue};
use rules_parser::parse;
use rules_runtime::{RegulatoryRuntime, Value as RtValue};
use rules_verifier::{Verifier, VerifyIssue, VerifyReport};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::mysql::MySqlRow;
use sqlx::{MySqlPool, Row};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// v1.0 四模的落库取值（与 `rules.mode` ENUM 逐字对齐）。
const MODES: [&str; 4] = ["PURE", "STATEFUL", "STREAM", "DMN"];
/// 规则生命周期状态机（与 `rules.status` ENUM 逐字对齐）。
const STATUSES: [&str; 4] = ["DRAFT", "VERIFIED", "PUBLISHED", "ARCHIVED"];
/// 默认版本号，与 DDL 的 `version VARCHAR(32) DEFAULT '1.0.0'` 一致。
const DEFAULT_VERSION: &str = "1.0.0";
/// 默认分组主键（FR9：删除分组时规则安全迁移到此）。
const DEFAULT_GROUP_ID: u64 = 1;

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

/// 规则（v1.0）。字段名与 `rules` 表列一一对应。
#[derive(Clone, Serialize, Deserialize)]
struct Rule {
    #[serde(default)]
    id: u64,
    name: String,
    #[serde(default)]
    group_id: u64,
    /// `PURE` / `STATEFUL` / `STREAM` / `DMN`；留空时由 AST 推断。
    #[serde(default)]
    mode: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    entity_type: String,
    /// DSL 正文。兼容旧字段名 `dsl`。
    #[serde(default, alias = "dsl", rename = "dsl_content")]
    dsl_content: String,
    /// 四模同构 AST 的标准 JSON。客户端一般不用填，服务端解析后回填。
    #[serde(default)]
    ast_json: String,
    /// 仅 `mode=DMN` 有值：原始 DMN 1.3 文档（第三方互通无损凭据）。
    #[serde(default)]
    dmn_xml: String,
    /// `DRAFT` / `VERIFIED` / `PUBLISHED` / `ARCHIVED`。
    #[serde(default)]
    status: String,
    /// 提交人。不落 `rules` 表，写进 `rule_versions.submitted_by`。
    #[serde(default)]
    owner: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct DataSource {
    #[serde(default)]
    id: u64,
    name: String,
    /// `MYSQL` / `POSTGRESQL` / `KAFKA`。兼容旧字段名 `db_type`（大小写不敏感）。
    #[serde(default, alias = "db_type")]
    ds_type: String,
    host: String,
    port: u16,
    username: String,
    #[serde(default)]
    password: String,
    /// 库名。兼容旧字段名 `schema_name`。
    #[serde(default, alias = "schema_name")]
    database_name: String,
}

/// 变量 ↔ 数据源列物理绑定（FR8，表名 `variable_bindings`）。
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

/// 规则版本快照（PRD §9 之外的运行时保留表）。
#[derive(Clone, Serialize, Deserialize)]
struct RuleVersion {
    #[serde(default)]
    id: u64,
    rule_id: u64,
    version: i64,
    dsl_text: String,
    #[serde(default)]
    ast_json: String,
    #[serde(default)]
    verify_report: String,
    #[serde(default)]
    submitted_by: String,
}

/// 触发器登记（运行时保留表）。
#[derive(Clone, Serialize, Deserialize)]
struct Trigger {
    #[serde(default)]
    id: u64,
    rule_id: u64,
    mode: String,
}

#[derive(Default)]
struct MemState {
    groups: Vec<Group>,
    rules: Vec<Rule>,
    datasources: Vec<DataSource>,
    bindings: Vec<Binding>,
    actions: Vec<Action>,
    versions: Vec<RuleVersion>,
    triggers: Vec<Trigger>,
    next_id: u64,
}

enum Store {
    Mysql(MySqlPool),
    Mem(std::sync::Mutex<MemState>),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let store = if let Ok(url) = std::env::var("DATABASE_URL") {
        eprintln!("连接已配置的 MySQL 数据库");
        let pool = MySqlPoolOptions::new().max_connections(5).connect(&url).await?;
        // 用 raw_sql 执行多语句 DDL（PRD §9，全部 CREATE TABLE IF NOT EXISTS 幂等）
        let _ = sqlx::raw_sql(include_str!("../sql/schema_runtime.sql"))
            .execute(&pool)
            .await
            .inspect_err(|e| eprintln!("DDL 执行警告（可忽略）: {e}"));
        if let Err(e) = migrate_legacy_schema(&pool).await {
            eprintln!("⚠ 结构升级警告（服务继续启动）: {e}");
        }
        Store::Mysql(pool)
    } else {
        eprintln!("⚠ DATABASE_URL 未设置，使用内存存储（重启丢数据）");
        Store::Mem(std::sync::Mutex::new(MemState::seeded()))
    };
    let store = Arc::new(store);

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".into());
    let listener = TcpListener::bind(&bind_addr).await?;
    eprintln!("rules-server listening on http://{bind_addr}");

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
            // 允许 path 里带绝对 URL（部分客户端会发 `POST http://h/p HTTP/1.1`）
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("GET").to_string();
            let raw_path = parts.next().unwrap_or("/").to_string();
            let path = match raw_path.find("://") {
                Some(_) => raw_path.splitn(2, "://").nth(1).and_then(|rest| rest.find('/').map(|i| rest[i..].to_string())).unwrap_or_else(|| "/".to_string()),
                None => raw_path,
            };
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
            let body_str = serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into());
            let _ = socket.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: {}\r\n\r\n{}",
                    body_str.as_bytes().len(), body_str).as_bytes()).await;
        });
    }
}

impl MemState {
    fn seeded() -> Self {
        let mut st = MemState::default();
        st.groups.push(Group {
            id: DEFAULT_GROUP_ID,
            parent_id: None,
            name: "默认分组".into(),
            description: "未归类规则".into(),
            sort: 0,
        });
        st.next_id = DEFAULT_GROUP_ID + 1;
        st
    }
}

fn row_u64(row: &MySqlRow, column: &str) -> u64 {
    row.try_get::<u64, _>(column)
        .or_else(|_| row.try_get::<u32, _>(column).map(u64::from))
        .or_else(|_| row.try_get::<i32, _>(column).map(|value| value as u64))
        .unwrap_or_default()
}

fn row_u16(row: &MySqlRow, column: &str) -> u16 {
    row.try_get::<u16, _>(column)
        .or_else(|_| row.try_get::<u32, _>(column).map(|value| value as u16))
        .or_else(|_| row.try_get::<i32, _>(column).map(|value| value as u16))
        .unwrap_or_default()
}

fn row_i64(row: &MySqlRow, column: &str) -> i64 {
    row.try_get::<i64, _>(column)
        .or_else(|_| row.try_get::<i32, _>(column).map(i64::from))
        .unwrap_or_default()
}

/// 读取可能是 TEXT 也可能是 JSON 类型的列（MySQL JSON 列不能用 String 解码）。
/// 统一用 `try_get` 链式回退，避免解码失败 panic 掉连接。
fn row_opt_text(row: &MySqlRow, column: &str) -> String {
    if let Ok(value) = row.try_get::<Option<String>, _>(column) {
        return value.unwrap_or_default();
    }
    if let Ok(value) = row.try_get::<Option<sqlx::types::Json<Value>>, _>(column) {
        return value.map(|json| json.0.to_string()).unwrap_or_default();
    }
    String::new()
}

fn normalize_mode(raw: &str) -> Option<String> {
    let up = raw.trim().to_ascii_uppercase();
    if up.is_empty() {
        return None;
    }
    // 接受 DSL 里的书写形式（`decision_table`）与落库枚举（`DMN`）
    let mapped = match up.as_str() {
        "DECISION_TABLE" | "DMN" | "DECISIONTABLE" => "DMN",
        other => other,
    };
    if MODES.contains(&mapped) {
        Some(mapped.to_string())
    } else {
        None
    }
}

fn normalize_status(raw: &str) -> Option<String> {
    let up = raw.trim().to_ascii_uppercase();
    if up.is_empty() {
        return None;
    }
    if STATUSES.contains(&up.as_str()) {
        Some(up)
    } else {
        None
    }
}

/// 解析 DSL 并返回 (AST, 该文件声明的主模式)。
fn entity_type_of(spec: &SpecFile) -> String {
    spec.specs
        .first()
        .map(|s| s.entity_name.clone())
        .or_else(|| spec.entities.first().map(|e| e.name.clone()))
        .unwrap_or_default()
}

fn rt_value_to_json(v: &RtValue) -> Value {
    match v {
        RtValue::Num(n) => json!(n),
        RtValue::Bool(b) => json!(b),
        RtValue::Text(s) => json!(s),
    }
}

fn json_to_rt_value(v: &Value) -> RtValue {
    match v {
        Value::Number(n) => RtValue::Num(n.as_f64().unwrap_or(0.0)),
        Value::Bool(b) => RtValue::Bool(*b),
        Value::String(s) => RtValue::Text(s.clone()),
        Value::Null => RtValue::Num(0.0),
        other => RtValue::Text(other.to_string()),
    }
}

async fn ensure_column(pool: &MySqlPool, table: &str, column: &str, definition: &str) -> anyhow::Result<()> {
    let exists = sqlx::query("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?")
        .bind(table)
        .bind(column)
        .fetch_optional(pool)
        .await?;
    if exists.is_none() {
        sqlx::query(&format!("ALTER TABLE `{table}` ADD COLUMN `{column}` {definition}"))
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// 表是否存在（升级旧库时用来决定要不要建表）。
async fn table_exists(pool: &MySqlPool, table: &str) -> bool {
    sqlx::query("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?")
        .bind(table)
        .fetch_optional(pool)
        .await
        .map(|r| r.is_some())
        .unwrap_or(false)
}

/// 列是否存在。
async fn column_exists(pool: &MySqlPool, table: &str, column: &str) -> bool {
    sqlx::query("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?")
        .bind(table)
        .bind(column)
        .fetch_optional(pool)
        .await
        .map(|r| r.is_some())
        .unwrap_or(false)
}

/// 读列的 `COLUMN_TYPE`（例如 `enum('LIFECYCLE','ONCE')`），用于识别旧 ENUM。
async fn column_type(pool: &MySqlPool, table: &str, column: &str) -> String {
    sqlx::query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?")
        .bind(table)
        .bind(column)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|r| r.get::<Option<String>, _>("COLUMN_TYPE").unwrap_or_default())
        .unwrap_or_default()
}

/// 旧库的 `mode` / `status` 可能是 `ENUM('LIFECYCLE','ONCE')` 这类窄枚举。
/// 先把它们放宽成 `VARCHAR`，否则下一句 UPDATE 会因数据截断而失败，
/// 升级就被卡死在半路。新库由 `schema_runtime.sql` 直接建成规范 ENUM，不受影响。
async fn widen_legacy_enum(pool: &MySqlPool, table: &str, column: &str, definition: &str) -> anyhow::Result<()> {
    let ty = column_type(pool, table, column).await.to_ascii_lowercase();
    if ty.starts_with("enum") && !ty.contains("stateful") && !ty.contains("dmn") {
        sqlx::query(&format!("ALTER TABLE `{table}` MODIFY COLUMN `{column}` {definition}"))
            .execute(pool)
            .await
            .inspect_err(|e| eprintln!("放宽旧列 {table}.{column} 失败: {e}"))?;
    }
    Ok(())
}

/// 把 v0.x 的旧表/旧列就地升级到 v1.0 语义。
///
/// 关键点：**数据不丢**——旧列（`rules.dsl`、`rule_bindings`）若存在，
/// 先补齐新列再 `UPDATE ... SELECT` 平移，最后才删旧列。
async fn migrate_legacy_schema(pool: &MySqlPool) -> anyhow::Result<()> {
    // ---- 分组：补齐 v1.0 列 ----
    ensure_column(pool, "rule_groups", "parent_id", "BIGINT UNSIGNED NULL DEFAULT NULL").await?;
    ensure_column(pool, "rule_groups", "description", "VARCHAR(255) NULL").await?;
    ensure_column(pool, "rule_groups", "sort", "INT NOT NULL DEFAULT 0").await?;

    // ---- 规则：补齐 v1.0 列 ----
    ensure_column(pool, "rules", "version", &format!("VARCHAR(32) NOT NULL DEFAULT '{DEFAULT_VERSION}'")).await?;
    ensure_column(pool, "rules", "dsl_content", "MEDIUMTEXT NULL").await?;
    ensure_column(pool, "rules", "ast_json", "JSON NULL").await?;
    ensure_column(pool, "rules", "dmn_xml", "MEDIUMTEXT NULL").await?;
    ensure_column(pool, "rules", "mode", "VARCHAR(16) NOT NULL DEFAULT 'PURE'").await?;
    ensure_column(pool, "rules", "status", "VARCHAR(16) NOT NULL DEFAULT 'DRAFT'").await?;
    ensure_column(pool, "rules", "entity_type", "VARCHAR(64) NOT NULL DEFAULT ''").await?;
    ensure_column(pool, "rules", "updated_at", "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP").await?;

    if column_exists(pool, "rules", "dsl").await {
        // 旧列存在 → 平移数据，再删旧列
        let _ = sqlx::query("UPDATE rules SET dsl_content = dsl WHERE (dsl_content IS NULL OR dsl_content = '') AND dsl IS NOT NULL")
            .execute(pool)
            .await
            .inspect_err(|e| eprintln!("旧 rules.dsl 平移到 dsl_content 失败（继续）: {e}"));
        let _ = sqlx::query("ALTER TABLE rules DROP COLUMN dsl")
            .execute(pool)
            .await
            .inspect_err(|e| eprintln!("删除旧列 rules.dsl 失败（继续）: {e}"));
    }
    // 旧 `cron` / `owner`：owner 语义迁到版本表，cron 在 v1.0 已无对应概念
    let _ = sqlx::query("UPDATE rules SET dsl_content='' WHERE dsl_content IS NULL").execute(pool).await;
    let _ = sqlx::query("UPDATE rules SET ast_json=JSON_OBJECT() WHERE ast_json IS NULL").execute(pool).await;
    let _ = sqlx::query("UPDATE rules SET entity_type='' WHERE entity_type IS NULL").execute(pool).await;

    // 旧 `LIFECYCLE` / `ONCE` 模式值映射到 v1.0 的 STREAM
    widen_legacy_enum(pool, "rules", "mode", "VARCHAR(16) NOT NULL DEFAULT 'PURE'").await?;
    widen_legacy_enum(pool, "rules", "status", "VARCHAR(16) NOT NULL DEFAULT 'DRAFT'").await?;
    let _ = sqlx::query("UPDATE rules SET mode='STREAM' WHERE UPPER(mode) IN ('LIFECYCLE','ONCE')")
        .execute(pool)
        .await;
    let _ = sqlx::query("UPDATE rules SET mode='PURE' WHERE mode IS NULL OR mode=''")
        .execute(pool)
        .await;
    let _ = sqlx::query("UPDATE rules SET status='DRAFT' WHERE status IS NULL OR status=''")
        .execute(pool)
        .await;

    // ---- 绑定表：rule_bindings → variable_bindings ----
    if table_exists(pool, "rule_bindings").await {
        // 旧表存在：把数据平移进新表（新表由 schema_runtime.sql 建好）
        let _ = sqlx::query(
            "INSERT IGNORE INTO variable_bindings (rule_id, var_name, datasource_id, table_name, column_name)
             SELECT rule_id, var_name,
                    COALESCE(datasource_id, 0), COALESCE(table_name, ''), COALESCE(column_name, '')
             FROM rule_bindings",
        )
        .execute(pool)
        .await
        .inspect_err(|e| eprintln!("rule_bindings → variable_bindings 平移失败（继续）: {e}"));
    }
    ensure_column(pool, "variable_bindings", "datasource_id", "BIGINT UNSIGNED NOT NULL DEFAULT 0").await?;
    ensure_column(pool, "variable_bindings", "table_name", "VARCHAR(128) NOT NULL DEFAULT ''").await?;
    ensure_column(pool, "variable_bindings", "column_name", "VARCHAR(128) NOT NULL DEFAULT ''").await?;

    // ---- 数据源：db_type/schema_name → ds_type/database_name ----
    ensure_column(pool, "datasources", "ds_type", "VARCHAR(16) NULL").await?;
    ensure_column(pool, "datasources", "database_name", "VARCHAR(128) NOT NULL DEFAULT ''").await?;
    if column_exists(pool, "datasources", "db_type").await {
        let _ = sqlx::query("UPDATE datasources SET ds_type=UPPER(db_type) WHERE ds_type IS NULL OR ds_type=''")
            .execute(pool)
            .await
            .inspect_err(|e| eprintln!("db_type → ds_type 平移失败（继续）: {e}"));
        let _ = sqlx::query("ALTER TABLE datasources DROP COLUMN db_type").execute(pool).await;
    }
    if column_exists(pool, "datasources", "schema_name").await {
        let _ = sqlx::query("UPDATE datasources SET database_name=schema_name WHERE database_name='' AND schema_name IS NOT NULL")
            .execute(pool)
            .await
            .inspect_err(|e| eprintln!("schema_name → database_name 平移失败（继续）: {e}"));
        let _ = sqlx::query("ALTER TABLE datasources DROP COLUMN schema_name").execute(pool).await;
    }
    let _ = sqlx::query("UPDATE datasources SET ds_type='MYSQL' WHERE ds_type IS NULL OR ds_type=''")
        .execute(pool)
        .await;

    // ---- 默认分组（FR9 兜底） ----
    let _ = sqlx::query(
        "INSERT INTO rule_groups (id, parent_id, name, description, sort)
         SELECT 1, NULL, '默认分组', '未归类规则', 0
         WHERE NOT EXISTS (SELECT 1 FROM rule_groups WHERE id = 1)",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query("UPDATE rules SET group_id=1 WHERE group_id IS NULL").execute(pool).await;
    Ok(())
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

// =====================================================================
// 校验辅助
// =====================================================================

/// 用给定 var 名集合构造校验用字典（FR5：var 取保守值）。
fn dict_for_vars(names: impl IntoIterator<Item = String>) -> DataDictionary {
    let mut dict = DataDictionary::default();
    for name in names {
        dict.set_var(name, ScalarValue::Bool(true));
    }
    dict
}

/// 收集 DSL 中声明的零元 metric 名（供展示/绑定面板复用）。
#[allow(dead_code)]
fn declared_vars(spec: &SpecFile) -> Vec<String> {
    spec.metrics.iter().filter(|m| m.params.is_empty()).map(|m| m.name.clone()).collect()
}

fn issues_json(items: &[VerifyIssue]) -> Value {
    json!(items
        .iter()
        .map(|i| json!({
            "kind": i.kind,
            "severity": i.severity,
            "message": i.message,
            "specs": i.specs,
            // AC1：反例参数必须能被前端直接渲染
            "counterexample": i
                .counterexample
                .iter()
                .map(|(name, value)| json!({"var": name, "value": value}))
                .collect::<Vec<_>>(),
            "counterexample_text": i.counterexample_text,
        }))
        .collect::<Vec<_>>())
}

fn report_json(report: &VerifyReport) -> Value {
    json!({
        "status": if report.is_ok() { "PASS" } else { "FAIL" },
        "errors": issues_json(&report.errors),
        "warnings": issues_json(&report.warnings),
    })
}

/// 解析 + 校验。返回 (AST JSON 字符串, 报告)，解析失败返回 Err(错误消息)。
fn verify_text(dsl: &str, bound_vars: &[String]) -> Result<(String, VerifyReport, SpecFile), String> {
    let spec = parse(dsl).map_err(|e| e.to_string())?;
    let ast_json = serde_json::to_string(&spec).unwrap_or_else(|_| "{}".into());
    // 只有"已绑定到数据源列"的 var 才登记进字典；其余（含 DSL 内新声明的 var）
    // 走 verifier 的 UNDEFINED_VAR 提示路径——保守策略，不阻断入库（FR5 / §7.3）。
    let report = Verifier::verify_report(&spec, &dict_for_vars(bound_vars.to_vec()));
    Ok((ast_json, report, spec))
}

fn parse_dsl(dsl: &str) -> Value {
    match parse(dsl) {
        Ok(spec) => json!({
            "ok": true,
            "spec": spec,
            "mode": spec.inferred_mode().db_value(),
        }),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

async fn bound_vars_of(store: &Store, rule_id: u64) -> Vec<String> {
    match store {
        Store::Mysql(pool) => bound_vars_mysql(pool, rule_id).await,
        Store::Mem(m) => {
            let state = m.lock().unwrap();
            state.bindings.iter().filter(|b| b.rule_id == rule_id).map(|b| b.var_name.clone()).collect()
        }
    }
}

async fn verify_route(store: &Store, rule_id: Option<u64>, dsl: &str) -> Value {
    let bound = match rule_id {
        Some(id) => bound_vars_of(store, id).await,
        None => Vec::new(),
    };
    let mut out = counterexample_json(dsl, &bound);
    out["ok"] = json!(out["status"] == "PASS");
    out
}

/// 反例诊断（AC1）：解析 + 校验，输出全部反例参数。
fn counterexample_json(dsl: &str, bound_vars: &[String]) -> Value {
    match verify_text(dsl, bound_vars) {
        Ok((_ast, report, spec)) => {
            let mut out = report_json(&report);
            out["entity_type"] = json!(entity_type_of(&spec));
            out["mode"] = json!(spec.inferred_mode().db_value());
            out
        }
        Err(e) => json!({
            "status": "FAIL",
            "entity_type": "",
            "mode": "",
            "errors": [{
                "kind": "PARSE_ERROR",
                "severity": "error",
                "message": e,
                "specs": [],
                "counterexample": [],
                "counterexample_text": "",
            }],
            "warnings": [],
        }),
    }
}

async fn bound_vars_mysql(pool: &MySqlPool, rule_id: u64) -> Vec<String> {
    let sql = if table_exists(pool, "variable_bindings").await {
        "SELECT var_name FROM variable_bindings WHERE rule_id=?"
    } else {
        "SELECT var_name FROM rule_bindings WHERE rule_id=?"
    };
    sqlx::query(sql)
        .bind(rule_id)
        .fetch_all(pool)
        .await
        .map(|rows| rows.into_iter().map(|r| r.get::<String, _>("var_name")).collect())
        .unwrap_or_default()
}

/// 规则保存门禁：解析 + 校验，errors 非空则拒绝。
fn gate_rule(dsl: &str, bound_vars: &[String]) -> Result<(String, VerifyReport, SpecFile), Value> {
    let (ast_json, report, spec) = match verify_text(dsl, bound_vars) {
        Ok(v) => v,
        Err(e) => {
            return Err(json!({
                "error": format!("规则解析失败：{e}"),
                "status": "FAIL",
                "errors": [{
                    "kind": "PARSE_ERROR", "severity": "error", "message": e,
                    "specs": [], "counterexample": [], "counterexample_text": "",
                }],
                "warnings": [],
            }))
        }
    };
    if !report.is_ok() {
        return Err(json!({
            "error": "规则未通过形式化校验，禁止入库",
            "status": "FAIL",
            "errors": issues_json(&report.errors),
            "warnings": issues_json(&report.warnings),
        }));
    }
    Ok((ast_json, report, spec))
}

/// 规则字段校验（FR1 / FR9 / FR11）。
fn validate_rule_input(rule: &Rule) -> Option<String> {
    if rule.name.trim().is_empty() {
        return Some("规则名称不能为空".into());
    }
    if rule.name.chars().count() > 128 {
        return Some("规则名称不能超过 128 字符".into());
    }
    if !rule.mode.trim().is_empty() && normalize_mode(&rule.mode).is_none() {
        return Some(format!("mode 只能是 {}，收到 '{}'", MODES.join(" / "), rule.mode));
    }
    if !rule.status.trim().is_empty() && normalize_status(&rule.status).is_none() {
        return Some(format!("status 只能是 {}，收到 '{}'", STATUSES.join(" / "), rule.status));
    }
    if !rule.version.trim().is_empty() && rule.version.chars().count() > 32 {
        return Some("version 不能超过 32 字符".into());
    }
    if rule.dsl_content.trim().is_empty() && rule.dmn_xml.trim().is_empty() {
        return Some("dsl_content 与 dmn_xml 不能同时为空".into());
    }
    None
}

/// 由 DMN XML 反推 DSL 文本 + AST（FR3）。
fn dsl_from_dmn_xml(xml: &str) -> Result<(String, SpecFile), String> {
    let tables = rules_dmn::import_tables(xml).map_err(|e| format!("DMN 解析失败：{e}"))?;
    if tables.is_empty() {
        return Err("DMN 文档中没有 <decisionTable> 元素".into());
    }
    let dsl = tables
        .iter()
        .map(rules_dmn::render_decision_table_dsl)
        .collect::<Vec<_>>()
        .join("\n");
    let spec = parse(&dsl).map_err(|e| format!("DMN 转出的 DSL 无法回读：{e}"))?;
    Ok((dsl, spec))
}

/// 规则 DMN 导出（若库里有 `dmn_xml` 直接回吐，否则由 AST 现算）。
fn export_rule_dmn(dsl: &str, cached_xml: &str) -> Result<String, String> {
    if !cached_xml.trim().is_empty() {
        return Ok(cached_xml.to_string());
    }
    let spec = parse(dsl).map_err(|e| format!("规则 DSL 解析失败：{e}"))?;
    if spec.decision_tables.is_empty() {
        return Err("该规则不包含决策表（mode 应为 DMN）".into());
    }
    Ok(rules_dmn::export_tables(&spec.decision_tables))
}

/// 决策表试算（FR3 / AC4）：纯查表，不触碰任何运行时状态。
fn trial_table(dsl: &str, table: &str, args: &[RtValue]) -> Value {
    let spec = match parse(dsl) {
        Ok(s) => s,
        Err(e) => return json!({"ok": false, "error": format!("DSL 解析失败：{e}")}),
    };
    let Some(decl) = spec.decision_tables.iter().find(|t| t.name == table) else {
        return json!({
            "ok": false,
            "error": format!("规则中不存在决策表 '{table}'"),
            "available": spec.decision_tables.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
        });
    };
    let decl = decl.clone();
    let rt = RegulatoryRuntime::new(spec, DataDictionary::default());
    let Some(outcome) = rt.evaluate_table(table, args) else {
        return json!({"ok": false, "error": "决策表求值失败"});
    };
    let out_cols: Vec<Value> = decl
        .outputs
        .iter()
        .enumerate()
        .map(|(i, p)| {
            json!({
                "name": p.name,
                "type": p.ty.as_str(),
                "value": outcome.outputs.get(i).map(rt_value_to_json).unwrap_or(Value::Null),
            })
        })
        .collect();
    json!({
        "ok": true,
        "table": decl.name,
        "hit_policy": decl.hit_policy.as_str(),
        "inputs": decl.params.iter().map(|p| json!({"name": p.name, "type": p.ty.as_str()})).collect::<Vec<_>>(),
        "args": args.iter().map(rt_value_to_json).collect::<Vec<_>>(),
        "row": outcome.row,
        "hits": outcome.hits,
        "hit_count": outcome.hit_count(),
        "default": outcome.default,
        "result": out_cols,
        "table_dsl": rules_dmn::render_decision_table_dsl(&decl),
    })
}

async fn route(store: &Store, method: &str, path: &str, body: &str) -> Value {
    if method == "OPTIONS" {
        return json!({"ok": true});
    }
    let (mut p, q) = parse_query(path);
    // 兼容别名：/api/variable-bindings ≡ /api/bindings
    for seg in p.iter_mut() {
        if *seg == "variable-bindings" || *seg == "variable_bindings" {
            *seg = "bindings";
        }
    }
    let p: Vec<&str> = p;
    let query_u64 = |key: &str| q.iter().find(|(k, _)| k == key).and_then(|(_, v)| v.parse::<u64>().ok());
    match (method, p.as_slice()) {
        ("GET", ["health"]) => json!({"status": "ok", "version": env!("CARGO_PKG_VERSION")}),
        ("GET", ["api", "modes"]) => json!({
            "modes": [
                {"value": "PURE",     "dsl": "pure",           "title": "Verified 纯函数", "desc": "单调状态格；Verdict::Allow/Deny；Z3 死区/冲突/除零证明"},
                {"value": "STATEFUL", "dsl": "stateful",       "title": "Drools 兼容",     "desc": "会话级 Working Memory；insert/retract；DAG 无环 + 32 步熔断"},
                {"value": "STREAM",   "dsl": "stream",         "title": "Flink CEP 增强",  "desc": "滑动窗口 O(1) 淘汰；crosses_above/below；LeaseUpdate 惩罚租约"},
                {"value": "DMN",      "dsl": "decision_table", "title": "DMN 决策表",      "desc": "UNIQUE/FIRST/PRIORITY/COLLECT；平铺为一阶谓词交 SMT 证明"},
            ],
            "statuses": STATUSES,
        }),
        ("POST", ["parse"]) => parse_dsl(body),
        ("POST", ["verify"]) => verify_route(store, query_u64("rule_id"), body).await,
        ("POST", ["api", "counterexample"]) => {
            let dsl = body_dsl(body);
            counterexample_json(&dsl, &[])
        }

        // ---------- 分组 ----------
        ("GET", ["api", "groups"]) => match store {
            Store::Mysql(pool) => {
                let rows = sqlx::query("SELECT id, parent_id, name, description, sort FROM rule_groups ORDER BY sort, id")
                    .fetch_all(pool).await;
                match rows {
                    Ok(rs) => json!(rs.into_iter().map(|r| json!({
                        "id": row_u64(&r, "id"),
                        "parent_id": r.get::<Option<u64>,_>("parent_id"),
                        "name": r.get::<String,_>("name"),
                        "description": r.get::<Option<String>,_>("description").unwrap_or_default(),
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
            if g.name.trim().is_empty() {
                return json!({"error": "分组名称不能为空"});
            }
            match store {
                Store::Mysql(pool) => {
                    if let Some(parent_id) = g.parent_id {
                        let parent_exists = sqlx::query("SELECT id FROM rule_groups WHERE id=?")
                            .bind(parent_id).fetch_optional(pool).await;
                        if !matches!(parent_exists, Ok(Some(_))) {
                            return json!({"error": "上级分组不存在"});
                        }
                    }
                    let res = sqlx::query("INSERT INTO rule_groups (parent_id, name, description, sort) VALUES (?, ?, ?, ?)")
                        .bind(g.parent_id).bind(&g.name).bind(&g.description).bind(g.sort)
                        .execute(pool).await;
                    match res {
                        Ok(r) => json!({"id": r.last_insert_id(), "parent_id": g.parent_id, "name": g.name}),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    if g.parent_id.is_some_and(|parent| !s.groups.iter().any(|group| group.id == parent)) {
                        return json!({"error": "上级分组不存在"});
                    }
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
            if id == DEFAULT_GROUP_ID && g.parent_id.is_some() {
                return json!({"error": "默认分组必须保持为顶级分组"});
            }
            match store {
                Store::Mysql(pool) => {
                    let rows = sqlx::query("SELECT id, parent_id FROM rule_groups")
                        .fetch_all(pool).await;
                    let rows = match rows {
                        Ok(rows) => rows,
                        Err(e) => return json!({"error": e.to_string()}),
                    };
                    let parents: std::collections::HashMap<u64, Option<u64>> = rows.into_iter()
                        .map(|row| (row_u64(&row, "id"), row.get::<Option<u64>, _>("parent_id")))
                        .collect();
                    if !parents.contains_key(&id) { return json!({"error": "分组不存在"}); }
                    if g.name.trim().is_empty() { return json!({"error": "分组名称不能为空"}); }
                    let mut ancestor = g.parent_id;
                    let mut seen = std::collections::HashSet::new();
                    while let Some(parent_id) = ancestor {
                        if parent_id == id || !seen.insert(parent_id) {
                            return json!({"error": "分组不能移动到自身或其子分组下"});
                        }
                        let Some(parent_parent) = parents.get(&parent_id) else {
                            return json!({"error": "上级分组不存在"});
                        };
                        ancestor = *parent_parent;
                    }
                    sqlx::query("UPDATE rule_groups SET parent_id=?, name=?, description=?, sort=? WHERE id=?")
                        .bind(g.parent_id).bind(&g.name).bind(&g.description).bind(g.sort).bind(id)
                        .execute(pool).await
                        .map(|_| json!({"ok": true}))
                        .unwrap_or_else(|e| json!({"error": e.to_string()}))
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    if !s.groups.iter().any(|group| group.id == id) { return json!({"error": "分组不存在"}); }
                    if g.name.trim().is_empty() { return json!({"error": "分组名称不能为空"}); }
                    let mut ancestor = g.parent_id;
                    let mut seen = std::collections::HashSet::new();
                    while let Some(parent_id) = ancestor {
                        if parent_id == id || !seen.insert(parent_id) {
                            return json!({"error": "分组不能移动到自身或其子分组下"});
                        }
                        let Some(parent) = s.groups.iter().find(|group| group.id == parent_id) else {
                            return json!({"error": "上级分组不存在"});
                        };
                        ancestor = parent.parent_id;
                    }
                    if let Some(x) = s.groups.iter_mut().find(|x| x.id == id) {
                        x.parent_id = g.parent_id;
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
            if id == DEFAULT_GROUP_ID {
                return json!({"error": "默认分组不能删除"});
            }
            match store {
                Store::Mysql(pool) => {
                    let mut tx = match pool.begin().await {
                        Ok(tx) => tx,
                        Err(e) => return json!({"error": e.to_string()}),
                    };
                    let parent = match sqlx::query("SELECT parent_id FROM rule_groups WHERE id=?")
                        .bind(id).fetch_optional(&mut *tx).await {
                        Ok(Some(row)) => row.get::<Option<u64>, _>("parent_id").or(Some(DEFAULT_GROUP_ID)),
                        Ok(None) => return json!({"error": "分组不存在"}),
                        Err(e) => return json!({"error": e.to_string()}),
                    };
                    let result = async {
                        sqlx::query("UPDATE rules SET group_id=1 WHERE group_id=?").bind(id).execute(&mut *tx).await?;
                        sqlx::query("UPDATE rule_groups SET parent_id=? WHERE parent_id=?").bind(parent).bind(id).execute(&mut *tx).await?;
                        sqlx::query("DELETE FROM rule_groups WHERE id=?").bind(id).execute(&mut *tx).await?;
                        tx.commit().await
                    }.await;
                    result.map(|_| json!({"ok": true})).unwrap_or_else(|e| json!({"error": e.to_string()}))
                }
                Store::Mem(m) => {
                    let mut state = m.lock().unwrap();
                    let Some(parent) = state.groups.iter().find(|group| group.id == id).and_then(|group| group.parent_id).or(Some(DEFAULT_GROUP_ID)) else {
                        return json!({"error": "默认分组不存在"});
                    };
                    for rule in &mut state.rules {
                        if rule.group_id == id { rule.group_id = DEFAULT_GROUP_ID; }
                    }
                    for group in &mut state.groups {
                        if group.parent_id == Some(id) { group.parent_id = Some(parent); }
                    }
                    state.groups.retain(|group| group.id != id);
                    json!({"ok": true})
                }
            }
        }

        // ---------- 规则 ----------
        ("GET", ["api", "rules"]) => {
            let group_filter = query_u64("group_id");
            match store {
                Store::Mysql(pool) => {
                    const COLS: &str = "r.id, r.name, r.group_id, r.mode, r.version, r.entity_type, r.dsl_content, r.status, \
                        (SELECT v.submitted_by FROM rule_versions v WHERE v.rule_id = r.id ORDER BY v.version DESC LIMIT 1) AS owner";
                    let rows = match group_filter {
                        Some(gid) => sqlx::query(&format!("SELECT {COLS} FROM rules r WHERE r.group_id=? ORDER BY r.id DESC"))
                            .bind(gid).fetch_all(pool).await,
                        None => sqlx::query(&format!("SELECT {COLS} FROM rules r ORDER BY r.id DESC"))
                            .fetch_all(pool).await,
                    };
                    match rows {
                        Ok(rs) => json!(rs.into_iter().map(|r| json!({
                            "id": row_u64(&r, "id"),
                            "name": r.get::<String,_>("name"),
                            "group_id": row_u64(&r, "group_id"),
                            "mode": normalize_mode(&r.get::<Option<String>,_>("mode").unwrap_or_default())
                                .unwrap_or_else(|| "PURE".into()),
                            "version": r.get::<Option<String>,_>("version").unwrap_or_else(|| DEFAULT_VERSION.into()),
                            "entity_type": r.get::<Option<String>,_>("entity_type").unwrap_or_default(),
                            "dsl_content": r.get::<Option<String>,_>("dsl_content").unwrap_or_default(),
                            "status": normalize_status(&r.get::<Option<String>,_>("status").unwrap_or_default())
                                .unwrap_or_else(|| "DRAFT".into()),
                            "owner": r.get::<Option<String>,_>("owner").unwrap_or_default(),
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
        ("GET", ["api", "rules", id]) => {
            let id: u64 = id.parse().unwrap_or(0);
            match store {
                Store::Mysql(pool) => {
                    let row = sqlx::query("SELECT r.id, r.name, r.group_id, r.mode, r.version, r.entity_type, r.dsl_content, r.ast_json, r.dmn_xml, r.status, \
                        (SELECT v.submitted_by FROM rule_versions v WHERE v.rule_id = r.id ORDER BY v.version DESC LIMIT 1) AS owner \
                        FROM rules r WHERE r.id=?")
                        .bind(id).fetch_optional(pool).await;
                    match row {
                        Ok(Some(r)) => json!({
                            "id": row_u64(&r, "id"),
                            "name": r.get::<String,_>("name"),
                            "group_id": row_u64(&r, "group_id"),
                            "mode": normalize_mode(&r.get::<Option<String>,_>("mode").unwrap_or_default())
                                .unwrap_or_else(|| "PURE".into()),
                            "version": r.get::<Option<String>,_>("version").unwrap_or_else(|| DEFAULT_VERSION.into()),
                            "entity_type": r.get::<Option<String>,_>("entity_type").unwrap_or_default(),
                            "dsl_content": r.get::<Option<String>,_>("dsl_content").unwrap_or_default(),
                            "ast_json": row_opt_text(&r, "ast_json"),
                            "dmn_xml": r.get::<Option<String>,_>("dmn_xml").unwrap_or_default(),
                            "status": normalize_status(&r.get::<Option<String>,_>("status").unwrap_or_default())
                                .unwrap_or_else(|| "DRAFT".into()),
                            "owner": r.get::<Option<String>,_>("owner").unwrap_or_default(),
                        }),
                        Ok(None) => json!({"error": "规则不存在"}),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let s = m.lock().unwrap();
                    match s.rules.iter().find(|r| r.id == id) {
                        Some(r) => json!(r),
                        None => json!({"error": "规则不存在"}),
                    }
                }
            }
        }
        ("GET", ["api", "rules", id, "versions"]) => {
            let id: u64 = id.parse().unwrap_or(0);
            match store {
                Store::Mysql(pool) => {
                    let rows = sqlx::query("SELECT id, rule_id, version, dsl_text, ast_json, verify_report, submitted_by FROM rule_versions WHERE rule_id=? ORDER BY version DESC")
                        .bind(id).fetch_all(pool).await;
                    match rows {
                        Ok(rs) => json!(rs.into_iter().map(|r| json!({
                            "id": row_u64(&r, "id"),
                            "rule_id": row_u64(&r, "rule_id"),
                            "version": row_i64(&r, "version"),
                            "dsl_text": row_opt_text(&r, "dsl_text"),
                            "ast_json": row_opt_text(&r, "ast_json"),
                            "verify_report": row_opt_text(&r, "verify_report"),
                            "submitted_by": row_opt_text(&r, "submitted_by"),
                        })).collect::<Vec<_>>()),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let s = m.lock().unwrap();
                    let mut list: Vec<RuleVersion> = s.versions.iter().filter(|v| v.rule_id == id).cloned().collect();
                    list.sort_by(|a, b| b.version.cmp(&a.version));
                    json!(list)
                }
            }
        }

        // ---------- DMN 导出（FR3） ----------
        ("POST", ["api", "rules", id, "export-dmn"]) | ("GET", ["api", "rules", id, "export-dmn"]) => {
            let id: u64 = id.parse().unwrap_or(0);
            let Some((dsl, cached)) = load_rule_dsl(store, id).await else {
                return json!({"ok": false, "error": "规则不存在"});
            };
            match export_rule_dmn(&dsl, &cached) {
                Ok(xml) => {
                    // 顺手把生成的 XML 缓存进 dmn_xml 列（幂等；下次直接回吐）
                    if cached.trim().is_empty() {
                        cache_dmn_xml(store, id, &xml).await;
                    }
                    let tables: Vec<String> = parse(&dsl)
                        .map(|s| s.decision_tables.iter().map(|t| t.name.clone()).collect())
                        .unwrap_or_default();
                    json!({"ok": true, "rule_id": id, "xml": xml, "tables": tables})
                }
                Err(e) => json!({"ok": false, "error": e}),
            }
        }

        // ---------- DMN 导入（FR3） ----------
        ("POST", ["api", "dmn", "import"]) => {
            let xml = body_xml(body);
            if xml.trim().is_empty() {
                return json!({"ok": false, "error": "请求体必须是 DMN XML 文本或 {\"xml\": \"...\"}"});
            }
            match rules_dmn::import_tables(&xml) {
                Ok(tables) => {
                    let dsl = tables.iter().map(rules_dmn::render_decision_table_dsl).collect::<Vec<_>>().join("\n");
                    // 自检：转出的 DSL 必须能被 parser 无损回读
                    match parse(&dsl) {
                        Ok(spec) => {
                            let ast_json = serde_json::to_string(&spec).unwrap_or_else(|_| "{}".into());
                            json!({
                                "ok": true,
                                "dsl_content": dsl,
                                "ast_json": ast_json,
                                "mode": "DMN",
                                "tables": tables.iter().map(|t| json!({
                                    "name": t.name,
                                    "hit_policy": t.hit_policy.as_str(),
                                    "rows": t.rows.len(),
                                    "inputs": t.params.iter().map(|p| json!({"name": p.name, "type": p.ty.as_str()})).collect::<Vec<_>>(),
                                    "outputs": t.outputs.iter().map(|p| json!({"name": p.name, "type": p.ty.as_str()})).collect::<Vec<_>>(),
                                })).collect::<Vec<_>>(),
                            })
                        }
                        Err(e) => json!({"ok": false, "error": format!("DMN 转出的 DSL 无法回读：{e}"), "dsl_content": dsl}),
                    }
                }
                Err(e) => json!({"ok": false, "error": format!("DMN 解析失败：{e}")}),
            }
        }

        // ---------- 决策表试算（FR3 / AC4） ----------
        ("POST", ["api", "decision-tables", "trial"]) => {
            let payload: Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(e) => return json!({"ok": false, "error": format!("请求体必须是 JSON：{e}")}),
            };
            let dsl = payload
                .get("dsl_content")
                .or_else(|| payload.get("dsl"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // 允许直接给 rule_id，服务端自己去取正文
            let dsl = if dsl.trim().is_empty() {
                match payload.get("rule_id").and_then(|v| v.as_u64()) {
                    Some(rid) => load_rule_dsl(store, rid).await.map(|(d, _)| d).unwrap_or_default(),
                    None => String::new(),
                }
            } else {
                dsl
            };
            if dsl.trim().is_empty() {
                return json!({"ok": false, "error": "缺少 dsl_content（或 rule_id）"});
            }
            let table = payload.get("table").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let args: Vec<RtValue> = payload
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().map(json_to_rt_value).collect())
                .unwrap_or_default();
            let table = if table.trim().is_empty() {
                // 未指定表名 → 取第一条
                parse(&dsl)
                    .ok()
                    .and_then(|s| s.decision_tables.first().map(|t| t.name.clone()))
                    .unwrap_or_default()
            } else {
                table
            };
            trial_table(&dsl, &table, &args)
        }

        // ---------- 规则反例诊断（AC1） ----------
        ("POST", ["api", "rules", id, "counterexample"]) => {
            let id: u64 = id.parse().unwrap_or(0);
            let inline = body_dsl(body);
            let (dsl, bound) = if inline.trim().is_empty() {
                match load_rule_dsl(store, id).await {
                    Some((dsl, _)) => {
                        let bound = bound_vars_of(store, id).await;
                        (dsl, bound)
                    }
                    None => return json!({"ok": false, "error": "规则不存在"}),
                }
            } else {
                (inline, bound_vars_of(store, id).await)
            };
            let mut out = counterexample_json(&dsl, &bound);
            out["rule_id"] = json!(id);
            json!(out)
        }

        ("POST", ["api", "rules"]) => {
            let r: Rule = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return json!({"error": e.to_string()}),
            };
            if let Some(err) = validate_rule_input(&r) {
                return json!({"error": err});
            }
            // DMN XML 优先：只有 XML 时先反推出 DSL（FR3）
            let (dsl, dmn_xml) = if r.dsl_content.trim().is_empty() && !r.dmn_xml.trim().is_empty() {
                match dsl_from_dmn_xml(&r.dmn_xml) {
                    Ok((dsl, _)) => (dsl, r.dmn_xml.clone()),
                    Err(e) => return json!({"error": e}),
                }
            } else {
                (r.dsl_content.clone(), r.dmn_xml.clone())
            };
            let (ast_json, report, spec) = match gate_rule(&dsl, &[]) {
                Ok(v) => v,
                Err(err) => return err,
            };
            let mode = normalize_mode(&r.mode).unwrap_or_else(|| spec.inferred_mode().db_value().to_string());
            let status = normalize_status(&r.status).unwrap_or_else(|| "DRAFT".into());
            let version = if r.version.trim().is_empty() { DEFAULT_VERSION.to_string() } else { r.version.clone() };
            let entity_type = entity_type_of(&spec);
            let warnings = issues_json(&report.warnings);
            let gid = if r.group_id == 0 { DEFAULT_GROUP_ID } else { r.group_id };

            match store {
                Store::Mysql(pool) => {
                    if let Err(e) = ensure_group_exists(pool, gid).await {
                        return json!({"error": e});
                    }
                    if let Err(e) = ensure_name_version_free(pool, &r.name, &version, None).await {
                        return json!({"error": e});
                    }
                    let res = sqlx::query(
                        "INSERT INTO rules (name, group_id, mode, version, entity_type, dsl_content, ast_json, dmn_xml, status) \
                         VALUES (?, ?, ?, ?, ?, ?, CAST(? AS JSON), ?, ?)")
                        .bind(&r.name).bind(gid).bind(&mode).bind(&version).bind(&entity_type)
                        .bind(&dsl).bind(&ast_json)
                        .bind(if dmn_xml.trim().is_empty() { None } else { Some(dmn_xml.clone()) })
                        .bind(&status)
                        .execute(pool).await;
                    match res {
                        Ok(res) => {
                            let rule_id = res.last_insert_id();
                            if let Err(e) = save_version(pool, rule_id, &dsl, &ast_json, &report, &r.owner).await {
                                return json!({"error": format!("版本落库失败: {e}")});
                            }
                            if let Err(e) = save_trigger(pool, rule_id, &mode).await {
                                return json!({"error": format!("触发器落库失败: {e}")});
                            }
                            json!({
                                "id": rule_id, "name": r.name, "group_id": gid,
                                "mode": mode, "version": version, "status": status,
                                "entity_type": entity_type, "warnings": warnings,
                            })
                        }
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    if !s.groups.iter().any(|g| g.id == gid) {
                        return json!({"error": "分组不存在"});
                    }
                    if s.rules.iter().any(|x| x.name == r.name && x.version == version) {
                        return json!({"error": format!("同名同版本规则已存在：{} @ {}", r.name, version)});
                    }
                    let mut saved = r.clone();
                    saved.id = s.next_id;
                    s.next_id += 1;
                    saved.group_id = gid;
                    saved.dsl_content = dsl.clone();
                    saved.mode = mode.clone();
                    saved.version = version.clone();
                    saved.status = status.clone();
                    saved.entity_type = entity_type.clone();
                    saved.ast_json = ast_json.clone();
                    saved.dmn_xml = dmn_xml.clone();
                    let rule_id = saved.id;
                    push_mem_version(&mut s, rule_id, &dsl, &ast_json, &report, &r.owner);
                    push_mem_trigger(&mut s, rule_id, &mode);
                    s.rules.push(saved);
                    json!({
                        "id": rule_id, "name": r.name, "group_id": gid,
                        "mode": mode, "version": version, "status": status,
                        "entity_type": entity_type, "warnings": warnings,
                    })
                }
            }
        }
        ("PUT", ["api", "rules", id]) => {
            let id: u64 = id.parse().unwrap_or(0);
            let r: Rule = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return json!({"error": e.to_string()}),
            };
            if let Some(err) = validate_rule_input(&r) {
                return json!({"error": err});
            }
            let bound = bound_vars_of(store, id).await;
            let (dsl, dmn_xml) = if r.dsl_content.trim().is_empty() && !r.dmn_xml.trim().is_empty() {
                match dsl_from_dmn_xml(&r.dmn_xml) {
                    Ok((dsl, _)) => (dsl, r.dmn_xml.clone()),
                    Err(e) => return json!({"error": e}),
                }
            } else {
                (r.dsl_content.clone(), r.dmn_xml.clone())
            };
            let (ast_json, report, spec) = match gate_rule(&dsl, &bound) {
                Ok(v) => v,
                Err(err) => return err,
            };
            let mode = normalize_mode(&r.mode).unwrap_or_else(|| spec.inferred_mode().db_value().to_string());
            let status = normalize_status(&r.status).unwrap_or_else(|| "DRAFT".into());
            let version = if r.version.trim().is_empty() { DEFAULT_VERSION.to_string() } else { r.version.clone() };
            let entity_type = entity_type_of(&spec);
            let warnings = issues_json(&report.warnings);

            match store {
                Store::Mysql(pool) => {
                    if let Err(e) = ensure_group_exists(pool, r.group_id).await {
                        return json!({"error": e});
                    }
                    if let Err(e) = ensure_name_version_free(pool, &r.name, &version, Some(id)).await {
                        return json!({"error": e});
                    }
                    let res = sqlx::query(
                        "UPDATE rules SET name=?, group_id=?, mode=?, version=?, entity_type=?, dsl_content=?, ast_json=CAST(? AS JSON), dmn_xml=?, status=? WHERE id=?")
                        .bind(&r.name).bind(r.group_id).bind(&mode).bind(&version).bind(&entity_type)
                        .bind(&dsl).bind(&ast_json)
                        .bind(if dmn_xml.trim().is_empty() { None } else { Some(dmn_xml.clone()) })
                        .bind(&status).bind(id)
                        .execute(pool).await;
                    match res {
                        Ok(done) if done.rows_affected() == 0 => json!({"error": "规则不存在"}),
                        Ok(_) => {
                            if let Err(e) = save_version(pool, id, &dsl, &ast_json, &report, &r.owner).await {
                                return json!({"error": format!("版本落库失败: {e}")});
                            }
                            if let Err(e) = save_trigger(pool, id, &mode).await {
                                return json!({"error": format!("触发器落库失败: {e}")});
                            }
                            json!({"ok": true, "mode": mode, "version": version, "status": status, "warnings": warnings})
                        }
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    if !s.rules.iter().any(|x| x.id == id) {
                        return json!({"error": "规则不存在"});
                    }
                    if s.rules.iter().any(|x| x.id != id && x.name == r.name && x.version == version) {
                        return json!({"error": format!("同名同版本规则已存在：{} @ {}", r.name, version)});
                    }
                    if let Some(x) = s.rules.iter_mut().find(|x| x.id == id) {
                        x.name = r.name.clone();
                        x.group_id = r.group_id;
                        x.dsl_content = dsl.clone();
                        x.ast_json = ast_json.clone();
                        x.dmn_xml = dmn_xml.clone();
                        x.mode = mode.clone();
                        x.version = version.clone();
                        x.status = status.clone();
                        x.entity_type = entity_type.clone();
                        x.owner = r.owner.clone();
                    }
                    push_mem_version(&mut s, id, &dsl, &ast_json, &report, &r.owner);
                    push_mem_trigger(&mut s, id, &mode);
                    json!({"ok": true, "mode": mode, "version": version, "status": status, "warnings": warnings})
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
                    let mut s = m.lock().unwrap();
                    s.rules.retain(|x| x.id != id);
                    s.versions.retain(|v| v.rule_id != id);
                    s.triggers.retain(|t| t.rule_id != id);
                    s.bindings.retain(|b| b.rule_id != id);
                    s.actions.retain(|a| a.rule_id != id);
                    json!({"ok": true})
                }
            }
        }

        // ---------- 数据源 ----------
        ("GET", ["api", "datasources"]) => match store {
            Store::Mysql(pool) => {
                let rows = sqlx::query("SELECT id, name, ds_type, host, port, username, database_name FROM datasources")
                    .fetch_all(pool).await;
                match rows {
                    Ok(rs) => json!(rs.into_iter().map(|r| json!({
                        "id": row_u64(&r, "id"), "name": r.get::<String,_>("name"),
                        "ds_type": r.get::<Option<String>,_>("ds_type").unwrap_or_else(|| "MYSQL".into()),
                        "host": r.get::<String,_>("host"),
                        "port": row_u16(&r, "port"), "username": r.get::<String,_>("username"),
                        "database_name": r.get::<Option<String>,_>("database_name").unwrap_or_default()
                    })).collect::<Vec<_>>()),
                    Err(e) => json!({"error": e.to_string()}),
                }
            }
            Store::Mem(m) => json!(m.lock().unwrap().datasources.iter().map(|d| json!({
                "id": d.id, "name": d.name, "ds_type": d.ds_type, "host": d.host,
                "port": d.port, "username": d.username, "database_name": d.database_name
            })).collect::<Vec<_>>()),
        },
        ("POST", ["api", "datasources"]) => {
            let ds: DataSource = match serde_json::from_str(body) {
                Ok(d) => d,
                Err(e) => return json!({"error": e.to_string()}),
            };
            if ds.name.trim().is_empty() {
                return json!({"error": "数据源名称不能为空"});
            }
            if ds.password.is_empty() {
                return json!({"error": "必须填写数据库密码"});
            }
            let ds_type = match normalize_ds_type(&ds.ds_type) {
                Some(t) => t,
                None => return json!({"error": format!("ds_type 只能是 MYSQL / POSTGRESQL / KAFKA，收到 '{}'", ds.ds_type)}),
            };
            match store {
                Store::Mysql(pool) => {
                    let res = sqlx::query("INSERT INTO datasources (name, ds_type, host, port, username, password_enc, database_name) VALUES (?,?,?,?,?,?,?)")
                        .bind(&ds.name).bind(&ds_type).bind(&ds.host).bind(ds.port).bind(&ds.username).bind(&ds.password).bind(&ds.database_name)
                        .execute(pool).await;
                    match res {
                        Ok(r) => json!({"id": r.last_insert_id(), "ds_type": ds_type}),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    if s.datasources.iter().any(|d| d.name == ds.name) {
                        return json!({"error": "数据源名称已存在"});
                    }
                    let mut ds = ds;
                    ds.id = s.next_id;
                    s.next_id += 1;
                    ds.ds_type = ds_type;
                    s.datasources.push(ds.clone());
                    json!(ds)
                }
            }
        }
        ("PUT", ["api", "datasources", id]) => {
            let id: u64 = id.parse().unwrap_or(0);
            let ds: DataSource = match serde_json::from_str(body) {
                Ok(d) => d,
                Err(e) => return json!({"error": e.to_string()}),
            };
            if ds.name.trim().is_empty() {
                return json!({"error": "数据源名称不能为空"});
            }
            let ds_type = match normalize_ds_type(&ds.ds_type) {
                Some(t) => t,
                None => return json!({"error": format!("ds_type 只能是 MYSQL / POSTGRESQL / KAFKA，收到 '{}'", ds.ds_type)}),
            };
            match store {
                Store::Mysql(pool) => {
                    let existing = sqlx::query("SELECT password_enc FROM datasources WHERE id=?")
                        .bind(id).fetch_optional(pool).await;
                    let password = match existing {
                        Ok(Some(row)) => {
                            let old = row.get::<Option<String>, _>("password_enc").unwrap_or_default();
                            if ds.password.is_empty() { old } else { ds.password.clone() }
                        }
                        Ok(None) => return json!({"error": "数据源不存在"}),
                        Err(e) => return json!({"error": e.to_string()}),
                    };
                    sqlx::query("UPDATE datasources SET name=?, ds_type=?, host=?, port=?, username=?, password_enc=?, database_name=? WHERE id=?")
                        .bind(&ds.name).bind(&ds_type).bind(&ds.host).bind(ds.port).bind(&ds.username)
                        .bind(&password).bind(&ds.database_name).bind(id)
                        .execute(pool).await
                        .map(|_| json!({"ok": true}))
                        .unwrap_or_else(|e| json!({"error": e.to_string()}))
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    match s.datasources.iter_mut().find(|d| d.id == id) {
                        Some(d) => {
                            d.name = ds.name; d.ds_type = ds_type; d.host = ds.host;
                            d.port = ds.port; d.username = ds.username; d.database_name = ds.database_name;
                            if !ds.password.is_empty() { d.password = ds.password; }
                            json!({"ok": true})
                        }
                        None => json!({"error": "数据源不存在"}),
                    }
                }
            }
        }
        ("DELETE", ["api", "datasources", id]) => {
            let id: u64 = id.parse().unwrap_or(0);
            match store {
                Store::Mysql(pool) => {
                    sqlx::query("DELETE FROM datasources WHERE id=?").bind(id).execute(pool).await
                        .map(|_| json!({"ok": true}))
                        .unwrap_or_else(|e| json!({"error": e.to_string()}))
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    s.datasources.retain(|d| d.id != id);
                    s.bindings.retain(|b| b.datasource_id != id);
                    json!({"ok": true})
                }
            }
        }
        ("POST", ["api", "datasources", id, "test"]) => {
            let id: u64 = id.parse().unwrap_or(0);
            match load_datasource(store, id).await {
                Some(ds) => match probe_datasource(&ds).await {
                    Ok(tables) => json!({"ok": true, "message": format!("连接成功，发现 {} 张表", tables.len()), "tables": tables}),
                    Err(e) => json!({"ok": false, "error": e}),
                },
                None => json!({"ok": false, "error": "数据源不存在"}),
            }
        }
        ("GET", ["api", "datasources", id, "schema"]) => {
            let id: u64 = id.parse().unwrap_or(0);
            match load_datasource(store, id).await {
                Some(ds) => match load_schema(&ds).await {
                    Ok(tree) => json!({"ok": true, "database": ds.database_name, "tables": tree}),
                    Err(e) => json!({"ok": false, "error": e}),
                },
                None => json!({"ok": false, "error": "数据源不存在"}),
            }
        }

        // ---------- 绑定 ----------
        ("GET", ["api", "bindings"]) => {
            let rule_filter = query_u64("rule_id");
            match store {
                Store::Mysql(pool) => {
                    let rows = match rule_filter {
                        Some(rid) => sqlx::query("SELECT id, rule_id, var_name, datasource_id, table_name, column_name FROM variable_bindings WHERE rule_id=?")
                            .bind(rid).fetch_all(pool).await,
                        None => sqlx::query("SELECT id, rule_id, var_name, datasource_id, table_name, column_name FROM variable_bindings")
                            .fetch_all(pool).await,
                    };
                    match rows {
                        Ok(rs) => json!(rs.into_iter().map(|r| json!({
                            "id": row_u64(&r, "id"), "rule_id": row_u64(&r, "rule_id"),
                            "var_name": r.get::<String,_>("var_name"),
                            "datasource_id": row_u64(&r, "datasource_id"),
                            "table_name": r.get::<Option<String>,_>("table_name").unwrap_or_default(),
                            "column_name": r.get::<Option<String>,_>("column_name").unwrap_or_default()
                        })).collect::<Vec<_>>()),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let s = m.lock().unwrap();
                    let filtered: Vec<Binding> = match rule_filter {
                        Some(rid) => s.bindings.iter().filter(|b| b.rule_id == rid).cloned().collect(),
                        None => s.bindings.clone(),
                    };
                    json!(filtered)
                }
            }
        }
        ("POST", ["api", "bindings"]) => {
            let b: Binding = match serde_json::from_str(body) {
                Ok(b) => b,
                Err(e) => return json!({"error": e.to_string()}),
            };
            if b.var_name.trim().is_empty() {
                return json!({"error": "变量名不能为空"});
            }
            if b.table_name.trim().is_empty() || b.column_name.trim().is_empty() {
                return json!({"error": "必须选择目标表与目标列（FR8：变量必须映射到具体物理列）"});
            }
            match store {
                Store::Mysql(pool) => {
                    if b.datasource_id == 0 {
                        return json!({"error": "必须选择数据源"});
                    }
                    if let Err(e) = ensure_rule_exists(pool, b.rule_id).await {
                        return json!({"error": e});
                    }
                    let ds_ok = sqlx::query("SELECT id FROM datasources WHERE id=?")
                        .bind(b.datasource_id).fetch_optional(pool).await;
                    if !matches!(ds_ok, Ok(Some(_))) {
                        return json!({"error": "数据源不存在"});
                    }
                    let res = sqlx::query("INSERT INTO variable_bindings (rule_id, var_name, datasource_id, table_name, column_name) VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE datasource_id=VALUES(datasource_id), table_name=VALUES(table_name), column_name=VALUES(column_name)")
                        .bind(b.rule_id).bind(&b.var_name).bind(b.datasource_id).bind(&b.table_name).bind(&b.column_name)
                        .execute(pool).await;
                    match res {
                        Ok(r) => json!({"id": r.last_insert_id(), "upserted": true}),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let mut s = m.lock().unwrap();
                    if let Some(x) = s.bindings.iter_mut().find(|x| x.rule_id == b.rule_id && x.var_name == b.var_name) {
                        x.datasource_id = b.datasource_id;
                        x.table_name = b.table_name;
                        x.column_name = b.column_name;
                        return json!({"id": x.id, "upserted": true});
                    }
                    let mut b = b;
                    b.id = s.next_id;
                    s.next_id += 1;
                    s.bindings.push(b.clone());
                    json!(b)
                }
            }
        }
        ("DELETE", ["api", "bindings", id]) => {
            let id: u64 = id.parse().unwrap_or(0);
            match store {
                Store::Mysql(pool) => {
                    sqlx::query("DELETE FROM variable_bindings WHERE id=?").bind(id).execute(pool).await
                        .map(|_| json!({"ok": true}))
                        .unwrap_or_else(|e| json!({"error": e.to_string()}))
                }
                Store::Mem(m) => {
                    m.lock().unwrap().bindings.retain(|b| b.id != id);
                    json!({"ok": true})
                }
            }
        }

        // ---------- 动作 ----------
        ("GET", ["api", "actions"]) => {
            let rule_filter = query_u64("rule_id");
            match store {
                Store::Mysql(pool) => {
                    let rows = match rule_filter {
                        Some(rid) => sqlx::query("SELECT id, rule_id, action_type, config FROM rule_actions WHERE rule_id=?")
                            .bind(rid).fetch_all(pool).await,
                        None => sqlx::query("SELECT id, rule_id, action_type, config FROM rule_actions").fetch_all(pool).await,
                    };
                    match rows {
                        Ok(rs) => json!(rs.into_iter().map(|r| json!({
                            "id": row_u64(&r, "id"), "rule_id": row_u64(&r, "rule_id"),
                            "action_type": r.get::<String,_>("action_type"),
                            "config": r.get::<String,_>("config")
                        })).collect::<Vec<_>>()),
                        Err(e) => json!({"error": e.to_string()}),
                    }
                }
                Store::Mem(m) => {
                    let s = m.lock().unwrap();
                    let filtered: Vec<Action> = match rule_filter {
                        Some(rid) => s.actions.iter().filter(|a| a.rule_id == rid).cloned().collect(),
                        None => s.actions.clone(),
                    };
                    json!(filtered)
                }
            }
        }
        ("POST", ["api", "actions"]) => {
            let a: Action = match serde_json::from_str(body) {
                Ok(a) => a,
                Err(e) => return json!({"error": e.to_string()}),
            };
            let allowed = ["sms", "http", "email", "state_transition"];
            if !allowed.contains(&a.action_type.as_str()) {
                return json!({"error": format!("不支持的动作类型 '{}'，可选：{}", a.action_type, allowed.join(" / "))});
            }
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
        ("DELETE", ["api", "actions", id]) => {
            let id: u64 = id.parse().unwrap_or(0);
            match store {
                Store::Mysql(pool) => {
                    sqlx::query("DELETE FROM rule_actions WHERE id=?").bind(id).execute(pool).await
                        .map(|_| json!({"ok": true}))
                        .unwrap_or_else(|e| json!({"error": e.to_string()}))
                }
                Store::Mem(m) => {
                    m.lock().unwrap().actions.retain(|a| a.id != id);
                    json!({"ok": true})
                }
            }
        }

        _ => json!({"error": format!("not found: {} {}", method, path)}),
    }
}

// =====================================================================
// 请求体解析辅助
// =====================================================================

/// 请求体既可是裸 DSL 文本，也可是 `{"dsl_content": "..."}` / `{"dsl": "..."}`。
fn body_dsl(body: &str) -> String {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            return v
                .get("dsl_content")
                .or_else(|| v.get("dsl"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
        }
    }
    body.to_string()
}

/// 请求体既可是裸 DMN XML，也可是 `{"xml": "..."}`。
fn body_xml(body: &str) -> String {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            return v.get("xml").or_else(|| v.get("dmn_xml")).and_then(|x| x.as_str()).unwrap_or("").to_string();
        }
    }
    body.to_string()
}

fn normalize_ds_type(raw: &str) -> Option<String> {
    let up = raw.trim().to_ascii_uppercase();
    if up.is_empty() {
        return Some("MYSQL".into());
    }
    match up.as_str() {
        "MYSQL" | "MARIADB" => Some("MYSQL".into()),
        "POSTGRESQL" | "POSTGRES" | "PG" => Some("POSTGRESQL".into()),
        "KAFKA" => Some("KAFKA".into()),
        _ => None,
    }
}

// =====================================================================
// 落库辅助
// =====================================================================

async fn ensure_group_exists(pool: &MySqlPool, group_id: u64) -> Result<(), String> {
    let exists = sqlx::query("SELECT id FROM rule_groups WHERE id=?").bind(group_id).fetch_optional(pool).await;
    match exists {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(format!("分组 {group_id} 不存在")),
        Err(e) => Err(e.to_string()),
    }
}

async fn ensure_rule_exists(pool: &MySqlPool, rule_id: u64) -> Result<(), String> {
    let exists = sqlx::query("SELECT id FROM rules WHERE id=?").bind(rule_id).fetch_optional(pool).await;
    match exists {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(format!("规则 {rule_id} 不存在")),
        Err(e) => Err(e.to_string()),
    }
}

/// `uk_name_version` 前置检查：给出比 MySQL 1062 更可读的错误。
async fn ensure_name_version_free(
    pool: &MySqlPool,
    name: &str,
    version: &str,
    exclude: Option<u64>,
) -> Result<(), String> {
    let rows = sqlx::query("SELECT id FROM rules WHERE name=? AND version=?")
        .bind(name)
        .bind(version)
        .fetch_all(pool)
        .await;
    match rows {
        Ok(rs) => {
            let clash = rs.iter().any(|r| Some(row_u64(r, "id")) != exclude);
            if clash {
                Err(format!("同名同版本规则已存在：{name} @ {version}"))
            } else {
                Ok(())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

async fn load_rule_dsl(store: &Store, id: u64) -> Option<(String, String)> {
    match store {
        Store::Mysql(pool) => {
            let row = sqlx::query("SELECT dsl_content, dmn_xml FROM rules WHERE id=?")
                .bind(id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()?;
            Some((
                row.get::<Option<String>, _>("dsl_content").unwrap_or_default(),
                row.get::<Option<String>, _>("dmn_xml").unwrap_or_default(),
            ))
        }
        Store::Mem(m) => {
            let s = m.lock().unwrap();
            s.rules.iter().find(|r| r.id == id).map(|r| (r.dsl_content.clone(), r.dmn_xml.clone()))
        }
    }
}

async fn cache_dmn_xml(store: &Store, id: u64, xml: &str) {
    match store {
        Store::Mysql(pool) => {
            let _ = sqlx::query("UPDATE rules SET dmn_xml=? WHERE id=?").bind(xml).bind(id).execute(pool).await;
        }
        Store::Mem(m) => {
            let mut s = m.lock().unwrap();
            if let Some(r) = s.rules.iter_mut().find(|r| r.id == id) {
                r.dmn_xml = xml.to_string();
            }
        }
    }
}

async fn save_version(
    pool: &MySqlPool,
    rule_id: u64,
    dsl: &str,
    ast_json: &str,
    report: &VerifyReport,
    owner: &str,
) -> Result<(), sqlx::Error> {
    let row = sqlx::query("SELECT COALESCE(MAX(version),0)+1 AS v FROM rule_versions WHERE rule_id=?")
        .bind(rule_id)
        .fetch_one(pool)
        .await?;
    let version = row_i64(&row, "v");
    let report_str = report_json(report).to_string();
    let ast = if ast_json.trim().is_empty() { "{}" } else { ast_json };
    sqlx::query("INSERT INTO rule_versions (rule_id, version, dsl_text, ast_json, verify_report, submitted_by) VALUES (?,?,?,CAST(? AS JSON),CAST(? AS JSON),?)")
        .bind(rule_id)
        .bind(version)
        .bind(dsl)
        .bind(ast)
        .bind(report_str)
        .bind(owner)
        .execute(pool)
        .await?;
    Ok(())
}

async fn save_trigger(pool: &MySqlPool, rule_id: u64, mode: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO rule_triggers (rule_id, mode, cdc_table, cron_expr) VALUES (?,?,NULL,NULL) ON DUPLICATE KEY UPDATE mode=VALUES(mode)")
        .bind(rule_id)
        .bind(mode)
        .execute(pool)
        .await?;
    Ok(())
}

fn push_mem_version(
    s: &mut MemState,
    rule_id: u64,
    dsl: &str,
    ast_json: &str,
    report: &VerifyReport,
    owner: &str,
) {
    let version = s
        .versions
        .iter()
        .filter(|v| v.rule_id == rule_id)
        .map(|v| v.version)
        .max()
        .unwrap_or(0)
        + 1;
    let row_id = s.next_id;
    s.next_id += 1;
    s.versions.push(RuleVersion {
        id: row_id,
        rule_id,
        version,
        dsl_text: dsl.to_string(),
        ast_json: ast_json.to_string(),
        verify_report: report_json(report).to_string(),
        submitted_by: owner.to_string(),
    });
}

fn push_mem_trigger(s: &mut MemState, rule_id: u64, mode: &str) {
    if s.triggers.iter().any(|t| t.rule_id == rule_id && t.mode == mode) {
        return;
    }
    let row_id = s.next_id;
    s.next_id += 1;
    s.triggers.push(Trigger { id: row_id, rule_id, mode: mode.to_string() });
}

// =====================================================================
// 数据源探测
// =====================================================================

async fn load_datasource(store: &Store, id: u64) -> Option<DataSource> {
    match store {
        Store::Mysql(pool) => {
            let row = sqlx::query("SELECT id, name, ds_type, host, port, username, password_enc, database_name FROM datasources WHERE id=?")
                .bind(id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()?;
            Some(DataSource {
                id: row_u64(&row, "id"),
                name: row.get::<String, _>("name"),
                ds_type: row.get::<Option<String>, _>("ds_type").unwrap_or_else(|| "MYSQL".into()),
                host: row.get::<String, _>("host"),
                port: row_u16(&row, "port"),
                username: row.get::<String, _>("username"),
                password: row.get::<Option<String>, _>("password_enc").unwrap_or_default(),
                database_name: row.get::<Option<String>, _>("database_name").unwrap_or_default(),
            })
        }
        Store::Mem(m) => m.lock().unwrap().datasources.iter().find(|d| d.id == id).cloned(),
    }
}

fn connector_url(ds: &DataSource) -> String {
    format!(
        "mysql://{}:{}@{}:{}/{}?charset=utf8mb4",
        ds.username, ds.password, ds.host, ds.port, ds.database_name
    )
}

/// 真实连接探测：连上后列出该库下的表名。
async fn probe_datasource(ds: &DataSource) -> Result<Vec<String>, String> {
    if ds.ds_type != "MYSQL" {
        return Err(format!("暂不支持在线探测 '{}' 类型数据源（当前仅支持 MYSQL）", ds.ds_type));
    }
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&connector_url(ds))
        .await
        .map_err(|e| format!("连接失败: {e}"))?;
    let rows = sqlx::query("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME")
        .bind(&ds.database_name)
        .fetch_all(&pool)
        .await
        .map_err(|e| format!("查询表结构失败: {e}"))?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("TABLE_NAME")).collect())
}

/// schema/库 → table → column 三级树（FR8.2）。
async fn load_schema(ds: &DataSource) -> Result<Value, String> {
    if ds.ds_type != "MYSQL" {
        return Err(format!("暂不支持 '{}' 类型的结构拉取（当前仅支持 MYSQL）", ds.ds_type));
    }
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&connector_url(ds))
        .await
        .map_err(|e| format!("连接失败: {e}"))?;
    let rows = sqlx::query("SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME, ORDINAL_POSITION")
        .bind(&ds.database_name)
        .fetch_all(&pool)
        .await
        .map_err(|e| format!("查询列结构失败: {e}"))?;

    let mut tables: Vec<(String, Vec<Value>)> = Vec::new();
    for row in rows {
        let table: String = row.get("TABLE_NAME");
        let column: String = row.get("COLUMN_NAME");
        let data_type: String = row.get("DATA_TYPE");
        match tables.last_mut() {
            Some((name, cols)) if *name == table => {
                cols.push(json!({"name": column, "type": data_type}));
            }
            _ => tables.push((table, vec![json!({"name": column, "type": data_type})])),
        }
    }
    Ok(json!(tables
        .into_iter()
        .map(|(name, columns)| json!({"table": name, "columns": columns}))
        .collect::<Vec<_>>()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_store() -> Store {
        Store::Mem(std::sync::Mutex::new(MemState::seeded()))
    }

    #[tokio::test]
    async fn deleting_group_moves_rules_and_children_to_default() {
        let store = memory_store();
        let parent = route(&store, "POST", "/api/groups", r#"{"name":"披露","parent_id":1}"#).await;
        let parent_id = parent["id"].as_u64().unwrap();
        let child = route(&store, "POST", "/api/groups", &format!(r#"{{"name":"年报","parent_id":{parent_id}}}"#)).await;
        let child_id = child["id"].as_u64().unwrap();
        route(&store, "POST", "/api/rules", &format!(r#"{{"name":"R","group_id":{parent_id},"dsl_content":"{}"}}"#, dsl_json(GOOD_DSL))).await;

        let deleted = route(&store, "DELETE", &format!("/api/groups/{parent_id}"), "").await;
        assert_eq!(deleted["ok"], true);
        let groups = route(&store, "GET", "/api/groups", "").await;
        assert_eq!(groups.as_array().unwrap().iter().find(|g| g["id"] == child_id).unwrap()["parent_id"], 1);
        let rules = route(&store, "GET", "/api/rules?group_id=1", "").await;
        assert_eq!(rules.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn group_cannot_be_moved_under_its_descendant() {
        let store = memory_store();
        let parent = route(&store, "POST", "/api/groups", r#"{"name":"A","parent_id":1}"#).await;
        let parent_id = parent["id"].as_u64().unwrap();
        let child = route(&store, "POST", "/api/groups", &format!(r#"{{"name":"B","parent_id":{parent_id}}}"#)).await;
        let child_id = child["id"].as_u64().unwrap();
        let result = route(&store, "PUT", &format!("/api/groups/{parent_id}"), &format!(r#"{{"name":"A","parent_id":{child_id}}}"#)).await;
        assert!(result["error"].as_str().unwrap().contains("自身或其子分组"));
    }

    const GOOD_DSL: &str = r#"entity Company { key: code states: [NORMAL, SUSPENDED, TERMINATED] initial: NORMAL }
stream R = Stream[E].filter(event.t == "R")
contract C on Company {
    let deadline = 100000.0
    invariant: (now() > deadline) implies historically(exists(R), within: 60d)
    violation { severity: CRITICAL guard: DaysOverdue(deadline) > 5.0 transition: NORMAL -> SUSPENDED emit: "x" }
}"#;

    fn dsl_json(dsl: &str) -> String {
        dsl.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
    }

    #[tokio::test]
    async fn rule_save_is_gated_by_verification() {
        let store = memory_store();
        // 未声明实体的规则必须被拒绝且不落库
        let bad = r#"entity Company { key: code states: [NORMAL, DONE] initial: NORMAL }
stream S = Stream[E].filter(event.t == "S")
contract C on Account {
    invariant: always(true)
    violation { severity: INFO emit: "x" }
}"#;
        let payload = format!(r#"{{"name":"Bad","group_id":1,"dsl_content":"{}"}}"#, dsl_json(bad));
        let result = route(&store, "POST", "/api/rules", &payload).await;
        assert_eq!(result["status"], "FAIL");
        assert!(result["error"].as_str().unwrap().contains("禁止入库"));
        let rules = route(&store, "GET", "/api/rules", "").await;
        assert_eq!(rules.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn rule_save_infers_mode_and_writes_version() {
        let store = memory_store();
        let payload = format!(r#"{{"name":"Good","group_id":1,"dsl_content":"{}"}}"#, dsl_json(GOOD_DSL));
        let created = route(&store, "POST", "/api/rules", &payload).await;
        let rule_id = created["id"].as_u64().unwrap();
        assert_eq!(created["mode"], "STREAM");
        assert_eq!(created["version"], "1.0.0");
        assert_eq!(created["status"], "DRAFT");

        let versions = route(&store, "GET", &format!("/api/rules/{rule_id}/versions"), "").await;
        assert_eq!(versions.as_array().unwrap().len(), 1);
        assert_eq!(versions[0]["version"], 1);

        // 再次保存 → 版本递增
        let update = format!(r#"{{"name":"Good","group_id":1,"dsl_content":"{}"}}"#, dsl_json(GOOD_DSL));
        route(&store, "PUT", &format!("/api/rules/{rule_id}"), &update).await;
        let versions = route(&store, "GET", &format!("/api/rules/{rule_id}/versions"), "").await;
        assert_eq!(versions.as_array().unwrap().len(), 2);
        assert_eq!(versions[0]["version"], 2);
    }

    #[tokio::test]
    async fn legacy_dsl_field_name_is_accepted() {
        let store = memory_store();
        let payload = format!(r#"{{"name":"Legacy","group_id":1,"dsl":"{}"}}"#, dsl_json(GOOD_DSL));
        let created = route(&store, "POST", "/api/rules", &payload).await;
        assert!(created["id"].as_u64().is_some(), "{created}");
    }

    #[tokio::test]
    async fn invalid_mode_is_rejected() {
        let store = memory_store();
        let payload = format!(r#"{{"name":"Bad","group_id":1,"mode":"LIFECYCLE","dsl_content":"{}"}}"#, dsl_json(GOOD_DSL));
        let result = route(&store, "POST", "/api/rules", &payload).await;
        assert!(result["error"].as_str().unwrap().contains("mode 只能是"));
    }

    #[tokio::test]
    async fn duplicate_name_version_is_rejected() {
        let store = memory_store();
        let payload = format!(r#"{{"name":"Dup","group_id":1,"dsl_content":"{}"}}"#, dsl_json(GOOD_DSL));
        route(&store, "POST", "/api/rules", &payload).await;
        let again = route(&store, "POST", "/api/rules", &payload).await;
        assert!(again["error"].as_str().unwrap().contains("同名同版本"));
    }

    #[tokio::test]
    async fn binding_upsert_is_idempotent() {
        let store = memory_store();
        let first = route(&store, "POST", "/api/bindings", r#"{"rule_id":1,"var_name":"cancel_ratio","datasource_id":1,"table_name":"t","column_name":"c"}"#).await;
        assert!(first["id"].as_u64().is_some());
        route(&store, "POST", "/api/bindings", r#"{"rule_id":1,"var_name":"cancel_ratio","datasource_id":1,"table_name":"t","column_name":"c2"}"#).await;
        // 别名路径同样命中同一张表
        let list = route(&store, "GET", "/api/variable-bindings?rule_id=1", "").await;
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["column_name"], "c2");
    }

    #[tokio::test]
    async fn binding_requires_table_and_column() {
        let store = memory_store();
        let bad = route(&store, "POST", "/api/bindings", r#"{"rule_id":1,"var_name":"v","datasource_id":1,"table_name":"","column_name":""}"#).await;
        assert!(bad["error"].as_str().unwrap().contains("目标表"));
    }

    #[tokio::test]
    async fn verify_route_reports_warnings_without_blocking() {
        let store = memory_store();
        let dsl = r#"entity Company { key: code states: [NORMAL, DONE] initial: NORMAL }
stream Unused = Stream[E].filter(event.t == "X")
contract C on Company {
    invariant: always(true)
    violation { severity: INFO emit: "x" }
}"#;
        let result = route(&store, "POST", "/verify", dsl).await;
        assert_eq!(result["ok"], true);
        assert_eq!(result["status"], "PASS");
        assert!(result["warnings"].as_array().unwrap().len() >= 1);
    }

    #[tokio::test]
    async fn counterexample_endpoint_surfaces_witness() {
        // 前提为 1 > 2 的死规则：必须报错并给出反例字段（AC1）
        let dsl = r#"entity Account { key: id states: [OPEN, CLOSED] initial: OPEN }
stream S = Stream[E].filter(event.t == "X")
contract Dead on Account {
    invariant: (1 > 2) implies always(false)
    violation { severity: CRITICAL emit: "dead" }
}"#;
        let out = counterexample_json(dsl, &[]);
        assert_eq!(out["status"], "FAIL");
        let errs = out["errors"].as_array().unwrap();
        assert!(!errs.is_empty());
        assert!(errs[0].get("counterexample").is_some());
    }

    #[tokio::test]
    async fn modes_catalog_lists_four_modes() {
        let store = memory_store();
        let out = route(&store, "GET", "/api/modes", "").await;
        assert_eq!(out["modes"].as_array().unwrap().len(), 4);
        assert_eq!(out["statuses"].as_array().unwrap().len(), 4);
    }

    const DMN_DSL: &str = r#"decision_table DetermineCouponAmount(req_day: int) -> (amount: int) {
    hit_policy: UNIQUE
    rules: [
        in [1 .. 3] => (10),
        in [4 .. 5] => (20),
        default => (0)
    ]
}"#;

    #[tokio::test]
    async fn decision_table_trial_returns_hit_row() {
        let store = memory_store();
        let payload = json!({"dsl_content": DMN_DSL, "table": "DetermineCouponAmount", "args": [4]}).to_string();
        let out = route(&store, "POST", "/api/decision-tables/trial", &payload).await;
        assert_eq!(out["ok"], true, "{out}");
        assert_eq!(out["row"], 1);
        assert_eq!(out["result"][0]["value"], json!(20.0));
        assert_eq!(out["hit_policy"], "UNIQUE");
    }

    #[tokio::test]
    async fn decision_table_trial_defaults_to_first_table() {
        let store = memory_store();
        let payload = json!({"dsl_content": DMN_DSL, "args": [9]}).to_string();
        let out = route(&store, "POST", "/api/decision-tables/trial", &payload).await;
        assert_eq!(out["ok"], true, "{out}");
        assert_eq!(out["default"], true);
        assert_eq!(out["result"][0]["value"], json!(0.0));
    }

    #[tokio::test]
    async fn dmn_export_and_import_round_trip() {
        let store = memory_store();
        // 建一条 DMN 规则
        let payload = json!({"name": "Coupon", "group_id": 1, "mode": "DMN", "dsl_content": DMN_DSL}).to_string();
        let created = route(&store, "POST", "/api/rules", &payload).await;
        let rule_id = created["id"].as_u64().unwrap();
        assert_eq!(created["mode"], "DMN");

        // 导出
        let exported = route(&store, "POST", &format!("/api/rules/{rule_id}/export-dmn"), "").await;
        assert_eq!(exported["ok"], true, "{exported}");
        let xml = exported["xml"].as_str().unwrap();
        assert!(xml.contains("<decisionTable"));
        assert!(xml.contains("hitPolicy=\"U\""));

        // 再导入 → DSL 必须能回读
        let imported = route(&store, "POST", "/api/dmn/import", &json!({"xml": xml}).to_string()).await;
        assert_eq!(imported["ok"], true, "{imported}");
        assert_eq!(imported["mode"], "DMN");
        assert!(imported["dsl_content"].as_str().unwrap().contains("decision_table DetermineCouponAmount"));
        assert!(parse(imported["dsl_content"].as_str().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn rule_can_be_created_from_dmn_xml_only() {
        let store = memory_store();
        let xml = rules_dmn::export_tables(
            &parse(DMN_DSL).unwrap().decision_tables,
        );
        let payload = json!({"name": "FromXml", "group_id": 1, "dmn_xml": xml}).to_string();
        let created = route(&store, "POST", "/api/rules", &payload).await;
        assert!(created["id"].as_u64().is_some(), "{created}");
        assert_eq!(created["mode"], "DMN");

        let detail = route(&store, "GET", &format!("/api/rules/{}", created["id"].as_u64().unwrap()), "").await;
        assert!(detail["dsl_content"].as_str().unwrap().contains("decision_table"));
        assert!(!detail["ast_json"].as_str().unwrap().is_empty());
        assert!(!detail["dmn_xml"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dmn_export_rejects_non_dmn_rule() {
        let store = memory_store();
        let payload = format!(r#"{{"name":"NotDmn","group_id":1,"dsl_content":"{}"}}"#, dsl_json(GOOD_DSL));
        let created = route(&store, "POST", "/api/rules", &payload).await;
        let rule_id = created["id"].as_u64().unwrap();
        let out = route(&store, "POST", &format!("/api/rules/{rule_id}/export-dmn"), "").await;
        assert_eq!(out["ok"], false);
        assert!(out["error"].as_str().unwrap().contains("不包含决策表"));
    }

    #[tokio::test]
    async fn datasource_accepts_legacy_field_names() {
        let store = memory_store();
        let out = route(&store, "POST", "/api/datasources", r#"{"name":"ds1","db_type":"mysql","host":"h","port":3306,"username":"u","password":"p","schema_name":"db"}"#).await;
        assert_eq!(out["ds_type"], "MYSQL", "{out}");
        assert_eq!(out["database_name"], "db");
    }
}
