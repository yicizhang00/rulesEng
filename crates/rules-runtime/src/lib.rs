//! rules-runtime — 事件驱动的规则执行引擎。
//!
//! 职责：
//! - 接收事件，按 stream filter 分桶到滑动窗口；
//! - 维护多实体实例状态机（Company / Account / Security ...）；
//! - 每个 tick 评估所有 contract invariant；
//! - 违规且 guard 通过时，触发状态转移并通过 AlertDispatcher 派发告警。

use rules_ast::*;
use rules_dictionary::DataDictionary;
use rules_dispatcher::{Alert, AlertDispatcher, StdoutDispatcher};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Event {
    pub event_type: String,
    pub fields: HashMap<String, String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct EntityInstance {
    pub id: String,
    pub state: String,
}

pub struct RegulatoryRuntime {
    pub spec: SpecFile,
    /// entity_name -> (entity_id -> instance)
    pub entities: HashMap<String, HashMap<String, EntityInstance>>,
    /// stream_name -> 滑动窗口
    pub stream_windows: HashMap<String, VecDeque<Event>>,
    pub dict: DataDictionary,
    dispatcher: Arc<dyn AlertDispatcher>,
    pub now: u64,
}

impl RegulatoryRuntime {
    pub fn new(spec: SpecFile, dict: DataDictionary) -> Self {
        let mut entities = HashMap::new();
        for e in &spec.entities {
            entities.insert(e.name.clone(), HashMap::new());
        }
        Self {
            spec,
            entities,
            stream_windows: HashMap::new(),
            dict,
            dispatcher: Arc::new(StdoutDispatcher),
            now: 0,
        }
    }

    pub fn with_dispatcher(mut self, d: Arc<dyn AlertDispatcher>) -> Self {
        self.dispatcher = d;
        self
    }

    pub fn set_clock(&mut self, now: u64) {
        self.now = now;
    }

    /// 显式注册一个实体实例。用于纯时钟驱动场景（无前置事件）或测试。
    pub fn ensure_entity(&mut self, entity_name: &str, entity_id: &str) {
        let init_state = self
            .spec
            .entities
            .iter()
            .find(|e| e.name == entity_name)
            .map(|e| e.initial.clone())
            .unwrap_or_default();
        self.entities
            .entry(entity_name.to_string())
            .or_default()
            .entry(entity_id.to_string())
            .or_insert_with(|| EntityInstance {
                id: entity_id.to_string(),
                state: init_state,
            });
    }

    /// 摄入一个事件。
    ///
    /// 1. 按 stream filter 投递到对应窗口；
    /// 2. 按事件里的 "<entity_lowercase>_id" 字段路由/创建实体实例。
    pub fn ingest(&mut self, event: Event) {
        // 1) stream 分桶
        let mut matched_streams: Vec<String> = Vec::new();
        for s in &self.spec.streams {
            if s.event_type == event.event_type && eval_event_filter(&s.filter, &event) {
                let deque = self.stream_windows.entry(s.name.clone()).or_default();
                deque.push_back(event.clone());
                matched_streams.push(s.name.clone());
            }
        }
        for name in &matched_streams {
            self.evict_expired(name);
        }

        // 2) 实体路由
        for e in &self.spec.entities {
            let key_field = format!("{}_id", e.name.to_lowercase());
            if let Some(id) = event.fields.get(&key_field) {
                let bucket = self.entities.entry(e.name.clone()).or_default();
                bucket.entry(id.clone()).or_insert_with(|| EntityInstance {
                    id: id.clone(),
                    state: e.initial.clone(),
                });
            }
        }
    }

    fn evict_expired(&mut self, stream_name: &str) {
        // 收集需要的窗口大小（由 historically within 提示）。
        let hint = self
            .spec
            .contracts
            .iter()
            .filter_map(|c| collect_window_hint(&c.invariant, stream_name))
            .max()
            .unwrap_or(86_400 * 30); // 默认保留 30 天
        if let Some(deque) = self.stream_windows.get_mut(stream_name) {
            while let Some(front) = deque.front() {
                if self.now.saturating_sub(front.timestamp) > hint {
                    deque.pop_front();
                } else {
                    break;
                }
            }
        }
    }

    /// 推进一个 tick，评估所有 contract。
    pub fn tick(&mut self) {
        // 对每个实体类型、每个实体实例评估
        let entity_names: Vec<String> = self.spec.entities.iter().map(|e| e.name.clone()).collect();
        for en in entity_names {
            let instance_ids: Vec<String> = self
                .entities
                .get(&en)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            for eid in instance_ids {
                self.eval_contracts_for_instance(&en, &eid);
            }
        }
    }

    fn eval_contracts_for_instance(&mut self, entity_name: &str, entity_id: &str) {
        let contracts: Vec<ContractDecl> = self
            .spec
            .contracts
            .iter()
            .filter(|c| c.entity_name == entity_name)
            .cloned()
            .collect();

        for c in contracts {
            let violated = match &c.invariant {
                TemporalExpr::Implies(ant, cons) => {
                    let a = self.eval_temporal(ant, entity_name, entity_id, None);
                    let b = self.eval_temporal(cons, entity_name, entity_id, None);
                    a && !b
                }
                other => !self.eval_temporal(other, entity_name, entity_id, None),
            };

            if !violated {
                continue;
            }

            // guard
            let guard_ok = match &c.violation.guard {
                Some(g) => self.eval_scalar(g, entity_name, entity_id, None) > 0.0,
                None => true,
            };
            if !guard_ok {
                continue;
            }

            // 状态转移
            let mut trace = Vec::new();
            if let Some((from, to)) = &c.violation.transition {
                if let Some(inst) = self
                    .entities
                    .get_mut(entity_name)
                    .and_then(|m| m.get_mut(entity_id))
                {
                    if inst.state == *from {
                        trace.push(("state".into(), format!("{} -> {}", inst.state, to)));
                        inst.state = to.clone();
                    }
                }
            }

            self.dispatcher.dispatch(Alert {
                contract: c.name.clone(),
                entity_id: entity_id.to_string(),
                severity: c.violation.severity.clone(),
                message: c.violation.message.clone(),
                timestamp: self.now,
                trace,
            });
        }
    }

    // ---------- 时序求值 ----------
    fn eval_temporal(
        &self,
        t: &TemporalExpr,
        entity_name: &str,
        entity_id: &str,
        event_ctx: Option<&Event>,
    ) -> bool {
        match t {
            TemporalExpr::Predicate(p) => self.eval_scalar(p, entity_name, entity_id, event_ctx) > 0.0,
            TemporalExpr::Historically { expr, within } => {
                // 过去 within 内，expr 至少成立一次。
                let window = within.unwrap_or(Duration::from_secs(86_400)).as_secs();
                // 仅支持 exists(stream) 形式（与原型一致）。
                if let TemporalExpr::Predicate(Expr::Call { func, args }) = &**expr {
                    if func == "exists" {
                        if let Some(Expr::Ident(stream)) = args.first() {
                            if let Some(deque) = self.stream_windows.get(stream) {
                                for ev in deque.iter().rev() {
                                    if self.now >= ev.timestamp
                                        && self.now - ev.timestamp <= window
                                    {
                                        if event_belongs_to_entity(ev, entity_name, entity_id) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                false
            }
            TemporalExpr::Always(inner) => self.eval_temporal(inner, entity_name, entity_id, event_ctx),
            TemporalExpr::Eventually(inner) => {
                // v1 近似：当前已成立即视为满足；真正的"未来承诺"需要 scheduler（v1.5）。
                self.eval_temporal(inner, entity_name, entity_id, event_ctx)
            }
            TemporalExpr::WithinOp { window, inner } => {
                // v1 近似：过去 window 内 inner 成立过一次（与 historically 对称）。
                let secs = window.as_secs();
                if let TemporalExpr::Predicate(Expr::Call { func, args }) = &**inner {
                    if func == "exists" {
                        if let Some(Expr::Ident(stream)) = args.first() {
                            if let Some(deque) = self.stream_windows.get(stream) {
                                for ev in deque.iter().rev() {
                                    if self.now >= ev.timestamp && self.now - ev.timestamp <= secs {
                                        if event_belongs_to_entity(ev, entity_name, entity_id) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                false
            }
            TemporalExpr::Until { p, q } => {
                // v1 近似：若 q 已在历史窗口出现过，则 until 已满足；否则要求 p 当前为真。
                let q_satisfied = self.eval_temporal(q, entity_name, entity_id, event_ctx);
                if q_satisfied {
                    true
                } else {
                    self.eval_temporal(p, entity_name, entity_id, event_ctx)
                }
            }
            TemporalExpr::Implies(a, b) => {
                !self.eval_temporal(a, entity_name, entity_id, event_ctx)
                    || self.eval_temporal(b, entity_name, entity_id, event_ctx)
            }
            TemporalExpr::And(a, b) => {
                self.eval_temporal(a, entity_name, entity_id, event_ctx)
                    && self.eval_temporal(b, entity_name, entity_id, event_ctx)
            }
            TemporalExpr::Or(a, b) => {
                self.eval_temporal(a, entity_name, entity_id, event_ctx)
                    || self.eval_temporal(b, entity_name, entity_id, event_ctx)
            }
            TemporalExpr::Not(inner) => {
                !self.eval_temporal(inner, entity_name, entity_id, event_ctx)
            }
        }
    }

    // ---------- 标量求值 ----------
    fn eval_scalar(
        &self,
        e: &Expr,
        entity_name: &str,
        entity_id: &str,
        event_ctx: Option<&Event>,
    ) -> f64 {
        match e {
            Expr::Number(n) => *n,
            Expr::Str(_) => 0.0,
            Expr::DurationLit(d) => d.as_secs() as f64,
            Expr::Ident(name) => {
                // 先查 var
                if let Some(v) = self.dict.vars.get(name) {
                    return v.as_num().unwrap_or(0.0);
                }
                0.0
            }
            Expr::Path(parts) => {
                // 1) event 字段
                if let Some(ev) = event_ctx {
                    if let Some(v) = ev.fields.get(&parts.join(".")) {
                        return v.parse().unwrap_or(0.0);
                    }
                    // event.type == "X" 这种 path，parts[0]=event, parts[1]=field
                    if parts.first().map(|s| s.as_str()) == Some("event") && parts.len() == 2 {
                        if let Some(v) = ev.fields.get(&parts[1]) {
                            return v.parse().unwrap_or(0.0);
                        }
                    }
                }
                // 2) 外部字典绑定
                if let Some(v) = self.dict.lookup_external(parts) {
                    return v.as_num().unwrap_or(0.0);
                }
                0.0
            }
            Expr::Call { func, args } => match func.as_str() {
                "now" => self.now as f64,
                "DaysOverdue" => {
                    let deadline = self.eval_scalar(&args[0], entity_name, entity_id, event_ctx);
                    if self.now as f64 > deadline {
                        (self.now as f64 - deadline) / 86400.0
                    } else {
                        0.0
                    }
                }
                "max" => {
                    let a = self.eval_scalar(&args[0], entity_name, entity_id, event_ctx);
                    let b = self.eval_scalar(&args[1], entity_name, entity_id, event_ctx);
                    a.max(b)
                }
                "count" => {
                    if let Some(Expr::Ident(s)) = args.first() {
                        self.stream_windows.get(s).map(|d| d.len() as f64).unwrap_or(0.0)
                    } else {
                        0.0
                    }
                }
                // exists 在时序层处理，这里返回 0
                _ => 0.0,
            },
            Expr::Binary { op, left, right } => {
                let l = self.eval_scalar(left, entity_name, entity_id, event_ctx);
                let r = self.eval_scalar(right, entity_name, entity_id, event_ctx);
                let b = match op {
                    BinaryOp::Add => l + r,
                    BinaryOp::Sub => l - r,
                    BinaryOp::Mul => l * r,
                    BinaryOp::Div => {
                        if r.abs() < f64::EPSILON {
                            0.0
                        } else {
                            l / r
                        }
                    }
                    BinaryOp::Gt => return if l > r { 1.0 } else { 0.0 },
                    BinaryOp::Gte => return if l >= r { 1.0 } else { 0.0 },
                    BinaryOp::Lt => return if l < r { 1.0 } else { 0.0 },
                    BinaryOp::Lte => return if l <= r { 1.0 } else { 0.0 },
                    BinaryOp::Eq => return if (l - r).abs() < f64::EPSILON { 1.0 } else { 0.0 },
                    BinaryOp::Neq => return if (l - r).abs() >= f64::EPSILON { 1.0 } else { 0.0 },
                    BinaryOp::And => return if l > 0.0 && r > 0.0 { 1.0 } else { 0.0 },
                    BinaryOp::Or => return if l > 0.0 || r > 0.0 { 1.0 } else { 0.0 },
                };
                b
            }
            Expr::UnaryNot(inner) => {
                if self.eval_scalar(inner, entity_name, entity_id, event_ctx) > 0.0 {
                    0.0
                } else {
                    1.0
                }
            }
        }
    }

    /// 查询某实体实例当前状态（测试用）。
    pub fn entity_state(&self, entity_name: &str, entity_id: &str) -> Option<&str> {
        self.entities
            .get(entity_name)
            .and_then(|m| m.get(entity_id))
            .map(|i| i.state.as_str())
    }
}

// ---------- 辅助 ----------

fn eval_event_filter(expr: &Expr, event: &Event) -> bool {
    match expr {
        Expr::Binary { op, left, right } => {
            if let (Expr::Path(path), Expr::Str(expected)) = (&**left, &**right) {
                // event.type == "X"
                let field = if path.first().map(|s| s.as_str()) == Some("event") && path.len() == 2 {
                    path[1].clone()
                } else {
                    path.last().cloned().unwrap_or_default()
                };
                if let Some(val) = event.fields.get(&field) {
                    return match op {
                        BinaryOp::Eq => val == expected,
                        BinaryOp::Neq => val != expected,
                        _ => false,
                    };
                }
            }
            true
        }
        _ => true,
    }
}

fn event_belongs_to_entity(ev: &Event, entity_name: &str, entity_id: &str) -> bool {
    let key_field = format!("{}_id", entity_name.to_lowercase());
    ev.fields.get(&key_field).map(|s| s.as_str()) == Some(entity_id)
}

fn collect_window_hint(t: &TemporalExpr, stream_name: &str) -> Option<u64> {
    match t {
        TemporalExpr::Historically { expr, within } => {
            if let TemporalExpr::Predicate(Expr::Call { func, args }) = &**expr {
                if func == "exists" {
                    if let Some(Expr::Ident(s)) = args.first() {
                        if s == stream_name {
                            return within.map(|d| d.as_secs());
                        }
                    }
                }
            }
            None
        }
        TemporalExpr::Always(i) | TemporalExpr::Eventually(i) | TemporalExpr::Not(i) => {
            collect_window_hint(i, stream_name)
        }
        TemporalExpr::Until { p, q } => collect_window_hint(p, stream_name)
            .or_else(|| collect_window_hint(q, stream_name)),
        TemporalExpr::WithinOp { inner, .. } => collect_window_hint(inner, stream_name),
        TemporalExpr::Implies(a, b) | TemporalExpr::And(a, b) | TemporalExpr::Or(a, b) => {
            collect_window_hint(a, stream_name).or_else(|| collect_window_hint(b, stream_name))
        }
        _ => None,
    }
}

