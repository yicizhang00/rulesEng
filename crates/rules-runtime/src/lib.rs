//! rules-runtime — 事件驱动的时序状态机执行引擎。
//!
//! ## 与 Drools / RETE 的路线差异
//!
//! 产生式引擎的执行模型是"事实插入 → 重跑 RETE 网络 → 激活规则"，
//! 事实是离散对象，"时间"只是一个字段。本引擎反过来：
//!
//! ```text
//!   event ──► 环形缓冲区(RingBuffer)            每条流一个定长环，O(1) push
//!         └─► 扁平时序状态机(TemporalAutomaton)  单向扫描 Vec<AutoNode>，u8/i64 状态
//!                    │
//!                    └─► 不变量被打破 ──► 确定性状态迁移 + 告警
//! ```
//!
//! 三个关键点：
//! 1. **状态与计算不割裂**：metric 是 DSL 内部的派生信号（可带 `where` 守卫，
//!    也可直接 `from <stream>.fold(...)`），微服务不需要为每条新监管条目补上游聚合；
//! 2. **时间是一等算子**：`historically/eventually/within/until` 被编译成状态机的
//!    记忆单元（latch / pending / timers），而不是在每次事件到来时递归遍历 AST；
//! 3. **事件驱动而非轮询**：`ingest()` 在事件落地的同一拍推进受影响实体的状态机，
//!    `tick()` 只用于纯时钟驱动的推进（截止期到期）。

use rules_ast::*;
use rules_dictionary::DataDictionary;
use rules_dispatcher::{Alert, AlertDispatcher, StdoutDispatcher};
use rules_flatvm::{Env, FlatProgram, FlatVm, Interner, Operand, RingBuffer, RingEntry, SlotBinder};
use rules_temporal::{Atom, AtomHost, AtomKind, AutoState, TemporalAutomaton};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

pub mod decision;
pub mod memory;
pub mod modes;
pub mod wheel;

pub use decision::{DecisionEnv, DecisionOutcome};
pub use memory::{
    check_dag, run_session, CycleReport, Fact, SessionResult, WorkingMemory, MAX_ACTIVATION_STEPS,
};
pub use modes::{Adjudication, LeaseLedger, ModeRouter};
pub use wheel::{
    ExpiryOutcome, ExpiryWake, HashedWheelTimer, LongHorizonScheduler, TimerId, WheelStats,
    DAY_SECS, YEAR_DAYS,
};

// =====================================================================
// 基础类型
// =====================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub event_type: String,
    pub fields: HashMap<String, String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EntityInstance {
    pub id: String,
    pub state: String,
    /// FR5：单调状态格的位向量表示。`Effect::Transition{to}` 以 `mask |= bit_of(to)`
    /// 单调推进——已置位的位永不清零，这正是"状态只增不减"的格序保证。
    pub mask: u64,
    /// FR3 / §5 用例 1：实体级状态变量（`state var frozen_until: Timestamp = 0`）。
    /// 惩罚租约（`LeaseUpdate`）写在这里，且按 `max` 单调推进。
    pub vars: HashMap<String, Value>,
}

impl EntityInstance {
    pub fn new(id: impl Into<String>, state: impl Into<String>) -> Self {
        EntityInstance {
            id: id.into(),
            state: state.into(),
            mask: 0,
            vars: HashMap::new(),
        }
    }
}

/// 一次运行期违规的完整记录（PEP 裁决 + 可观测性负载）。
///
/// 与 [`Alert`] 的关系：Alert 面向人（日志/告警通道），`ViolationRecord` 面向机器
/// ——它是 `IngressInterceptor` 判定"物理阻断"的依据，也是 AC1/AC4 反例回放的输入。
#[derive(Debug, Clone, PartialEq)]
pub struct ViolationRecord {
    pub spec_name: String,
    pub entity_name: String,
    pub entity_id: String,
    pub event_type: String,
    pub verdict: Verdict,
    pub severity: Severity,
    pub message: String,
    pub explain: String,
    pub effects: Vec<Effect>,
    pub timestamp: u64,
}

/// 运行期值。文本与数值不再相互伪装——这是"状态与计算不割裂"的前提：
/// `event.report_type == "APPROVED"` 与 `days_overdue > 5` 走同一套求值。
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Num(f64),
    Text(String),
    Bool(bool),
}

impl Value {
    pub fn truthy(&self) -> bool {
        match self {
            Value::Num(n) => *n > 0.0,
            Value::Bool(b) => *b,
            Value::Text(s) => !s.is_empty() && s != "0" && s != "false",
        }
    }
    pub fn as_num(&self) -> f64 {
        match self {
            Value::Num(n) => *n,
            Value::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            Value::Text(s) => s.parse().unwrap_or(0.0),
        }
    }
    pub fn as_text(&self) -> String {
        match self {
            Value::Num(n) => format!("{n}"),
            Value::Bool(b) => b.to_string(),
            Value::Text(s) => s.clone(),
        }
    }
}

/// 事件 / 环形记录的统一取字段入口。
#[derive(Clone)]
enum Item<'r> {
    Ev(&'r Event),
    Ring(Rc<RingEntry>, Rc<Vec<String>>),
}

impl Item<'_> {
    fn field(&self, name: &str, interner: &Interner) -> Option<Value> {
        match self {
            Item::Ev(ev) => {
                let raw = ev.fields.get(name)?;
                Some(parse_value(raw))
            }
            Item::Ring(entry, names) => {
                let off = names.iter().position(|n| n == name)?;
                let text_id = entry.text(off);
                if text_id != 0 {
                    return Some(parse_value(interner.resolve(text_id)));
                }
                Some(Value::Num(entry.num(off)))
            }
        }
    }
}

fn parse_value(raw: &str) -> Value {
    if let Ok(n) = raw.parse::<f64>() {
        return Value::Num(n);
    }
    match raw {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => Value::Text(raw.to_string()),
    }
}

// =====================================================================
// 扁平槽位绑定
// =====================================================================

/// 一个 spec 的配对槽空间：索引 i 同时承载数值投影与驻留文本 id。
#[derive(Debug, Clone, Default)]
pub struct SpecBindings {
    /// 槽位名（下标即槽位偏移）。
    pub names: Vec<String>,
    index: HashMap<String, u32>,
}

impl SlotBinder for SpecBindings {
    fn bind(&mut self, name: &str) -> Option<rules_flatvm::Binding> {
        let off = *self.index.entry(name.to_string()).or_insert_with(|| {
            self.names.push(name.to_string());
            (self.names.len() - 1) as u32
        });
        Some(rules_flatvm::Binding::Field(off))
    }
}

// =====================================================================
// 流运行期描述
// =====================================================================

/// 一条流的运行期视图：事件类型、过滤算子、字段投影、环形缓冲区。
struct StreamRuntime {
    /// 仅保留 `filter` 算子（决定"哪些事件进入窗口"）。
    filters: Vec<Lambda>,
    /// 投影字段名（只保留 lambda 真正引用到的字段）。
    field_names: Vec<String>,
    field_index: HashMap<String, u32>,
    window_secs: Option<u64>,
}

impl StreamRuntime {
    /// 该记录是否属于某实体实例。
    fn belongs(&self, entry: &RingEntry, key: u32) -> bool {
        entry.key == key
    }
}

// =====================================================================
// 引擎
// =====================================================================

pub struct RegulatoryRuntime {
    pub spec: SpecFile,
    pub dict: DataDictionary,
    /// entity_name -> (entity_id -> instance)
    pub entities: HashMap<String, HashMap<String, EntityInstance>>,
    /// stream_name -> 环形缓冲区
    rings: HashMap<String, RingBuffer>,
    streams: HashMap<String, StreamRuntime>,
    /// event_type -> 命中的流名
    streams_by_event: HashMap<String, Vec<String>>,
    /// spec_name -> 编译后的时序状态机
    automata: HashMap<String, TemporalAutomaton>,
    /// spec_name -> 下标（避免长期持有 &SpecDecl 造成的借用冲突）
    spec_index: HashMap<String, usize>,
    /// (spec_name, entity_id) -> 状态机运行状态
    auto_states: HashMap<(String, String), AutoState>,
    /// spec_name -> 槽位绑定
    bindings: HashMap<String, SpecBindings>,
    /// metric 名 -> 声明
    metrics: HashMap<String, MetricDecl>,
    /// 字符串驻留表（实体键 + 文本字段共用）
    interner: Interner,
    dispatcher: Arc<dyn AlertDispatcher>,
    pub now: u64,
    /// PRD §4.3.1：惩罚租约账本（`frozen_until`，单调、无后台定时器）。
    pub leases: LeaseLedger,
    /// PRD §4：名字 → 执行模式的路由表。
    pub router: ModeRouter,
    /// 全部运行期违规记录（按发生序，跨 `ingest` / `tick` 累积）。
    pub violations: Vec<ViolationRecord>,
    /// 当前拍的事件类型（用于违规记录与 `on Event[...]` 归属）。
    current_event_type: String,
    /// 本拍实际写入过环的流名（PEP 物理阻断的撤回清单）。
    last_pushed: Vec<String>,
}

impl RegulatoryRuntime {
    pub fn new(spec: SpecFile, dict: DataDictionary) -> Self {
        let mut interner = Interner::new();

        // ---- 流：字段投影 + 环形缓冲区 ----
        let mut streams = HashMap::new();
        let mut rings = HashMap::new();
        let mut streams_by_event: HashMap<String, Vec<String>> = HashMap::new();

        // 第一遍：从流自身的算子（filter/map/fold/join...）收集投影字段。
        // 投影是"声明式 schema"——决定环形缓冲区里每条记录的扁平槽位布局。
        let mut declared_fields: HashMap<String, Vec<String>> = HashMap::new();
        for s in &spec.streams {
            let mut field_names: Vec<String> = Vec::new();
            for op in &s.ops {
                let lam: Option<(&[String], &Expr)> = match op {
                    StreamOp::Filter(l) | StreamOp::Map(l) => Some((&l.params, &l.body)),
                    StreamOp::Distinct(Some(l)) | StreamOp::Aggregate { lambda: Some(l), .. } => {
                        Some((&l.params, &l.body))
                    }
                    StreamOp::Fold { acc, item, body, .. } => {
                        let params = vec![acc.clone(), item.clone()];
                        // 借用局部参数列表，稍后即用即弃
                        for path in collect_param_fields(body, &params) {
                            if !field_names.contains(&path) {
                                field_names.push(path);
                            }
                        }
                        None
                    }
                    _ => None,
                };
                if let Some((params, body)) = lam {
                    for path in collect_param_fields(body, params) {
                        if !field_names.contains(&path) {
                            field_names.push(path);
                        }
                    }
                }
            }
            declared_fields.insert(s.name.clone(), field_names);
        }

        // 第二遍：spec 里的流量化 lambda（`S.exists(r => r.code == c.code)`）同样
        // 需要把字段投影进环——否则跨时间维度的关联谓词在运行时读不到该字段。
        for sd in &spec.specs {
            let mut refs: Vec<(String, String)> = Vec::new();
            collect_stream_refs(&sd.invariant, &mut refs);
            for (stream_name, field) in refs {
                if let Some(fields) = declared_fields.get_mut(&stream_name) {
                    if !fields.contains(&field) {
                        fields.push(field);
                    }
                }
            }
        }

        // 第三遍：metric 的滑动折叠（`from S.fold(init, (acc, t) => acc + t.amount)`）
        // 引用的字段也必须投影进源流的环，否则运行期读不到该列。
        for m in &spec.metrics {
            if let MetricBody::StreamFold { stream, acc, item, body, .. } = &m.body {
                let params = vec![acc.clone(), item.clone()];
                let fields = collect_param_fields(body, &params);
                if let Some(dst) = declared_fields.get_mut(stream) {
                    for f in fields {
                        if !dst.contains(&f) {
                            dst.push(f);
                        }
                    }
                }
            }
        }

        // 装载期预驻留"枚举常量"符号（状态名、字面标识符、路径末段）。
        // 这样运行期 `<状态名> == SUSPENDED` 这类比较退化为 u32 相等，
        // 且不会因为 id_of() 未命中而误落到数值比较路径。
        {
            let mut syms: Vec<String> = Vec::new();
            for e in &spec.entities {
                for st in &e.states {
                    push_unique(&mut syms, st.as_str());
                }
                push_unique(&mut syms, &e.initial);
                for t in &e.terminal {
                    push_unique(&mut syms, t);
                }
            }
            for st in &spec.streams {
                for op in &st.ops {
                    match op {
                        StreamOp::Filter(l) | StreamOp::Map(l) => collect_literals(&l.body, &mut syms),
                        StreamOp::Distinct(Some(l)) | StreamOp::Aggregate { lambda: Some(l), .. } => {
                            collect_literals(&l.body, &mut syms)
                        }
                        StreamOp::Fold { init, body, .. } => {
                            collect_literals(init, &mut syms);
                            collect_literals(body, &mut syms);
                        }
                        StreamOp::Join { on, .. } | StreamOp::CoGroup { on, .. } => {
                            collect_literals(on, &mut syms)
                        }
                        StreamOp::Window(w) => collect_literals(&w.size, &mut syms),
                        _ => {}
                    }
                }
            }
            for m in &spec.metrics {
                match &m.body {
                    MetricBody::Scalar { expr, guard } => {
                        collect_literals(expr, &mut syms);
                        if let Some(g) = guard {
                            collect_literals(g, &mut syms);
                        }
                    }
                    MetricBody::StreamFold { init, body, .. } => {
                        collect_literals(init, &mut syms);
                        collect_literals(body, &mut syms);
                    }
                    MetricBody::StreamAgg { .. } => {}
                }
            }
            for sd in &spec.specs {
                for (_, e) in &sd.given {
                    collect_literals(e, &mut syms);
                }
                collect_temporal_literals(&sd.invariant, &mut syms);
                if let Some(g) = &sd.violation.guard {
                    collect_literals(g, &mut syms);
                }
            }
            for s in syms {
                if !s.is_empty() {
                    interner.intern(&s);
                }
            }
        }

        for s in &spec.streams {
            // FR6 / 用例 1：`Stream[OrderIntent, CancelIntent]` 必须把该流
            // 注册到**每一个**来源事件类型上，否则撤单事件不会进同一窗口。
            let event_types = s.event_types(&spec.streams);
            let mut filters = Vec::new();
            for op in &s.ops {
                if let StreamOp::Filter(l) = op {
                    filters.push(l.clone());
                }
            }
            let mut field_names = declared_fields.remove(&s.name).unwrap_or_default();
            field_names.sort();
            let field_index = field_names
                .iter()
                .enumerate()
                .map(|(i, n)| (n.clone(), i as u32))
                .collect();

            let window_secs = s.window_secs();
            let cap = match window_secs {
                Some(w) => RingBuffer::for_window(w, 64),
                None => RingBuffer::with_capacity(4096),
            };
            rings.insert(s.name.clone(), cap);
            for et in event_types {
                if et.is_empty() {
                    continue;
                }
                let bucket = streams_by_event.entry(et.to_string()).or_default();
                if !bucket.contains(&s.name) {
                    bucket.push(s.name.clone());
                }
            }
            streams.insert(
                s.name.clone(),
                StreamRuntime { filters, field_names, field_index, window_secs },
            );
        }

        // ---- 实体 ----
        let mut entities = HashMap::new();
        for e in &spec.entities {
            entities.insert(e.name.clone(), HashMap::new());
        }

        // ---- metric 表 ----
        let metrics: HashMap<String, MetricDecl> =
            spec.metrics.iter().map(|m| (m.name.clone(), m.clone())).collect();

        // ---- 编译时序状态机 ----
        let mut automata = HashMap::new();
        let mut spec_index = HashMap::new();
        let mut bindings = HashMap::new();
        for (i, s) in spec.specs.iter().enumerate() {
            let mut b = SpecBindings::default();
            let aut = rules_temporal::compile_spec(s, &mut b, &mut interner);
            automata.insert(s.name.clone(), aut);
            spec_index.insert(s.name.clone(), i);
            bindings.insert(s.name.clone(), b);
        }

        // ---- 模式路由（PRD §4）----
        let router = ModeRouter::build(&spec);

        Self {
            spec,
            dict,
            entities,
            rings,
            streams,
            streams_by_event,
            automata,
            spec_index,
            auto_states: HashMap::new(),
            bindings,
            metrics,
            interner,
            dispatcher: Arc::new(StdoutDispatcher),
            now: 0,
            leases: LeaseLedger::new(),
            router,
            violations: Vec::new(),
            current_event_type: String::new(),
            last_pushed: Vec::new(),
        }
    }

    pub fn with_dispatcher(mut self, d: Arc<dyn AlertDispatcher>) -> Self {
        self.dispatcher = d;
        self
    }

    /// 运行期热注册一个派生信号（等价于 `metric name(...) := expr`）。
    pub fn register_metric(&mut self, decl: MetricDecl) {
        self.metrics.insert(decl.name.clone(), decl);
    }

    pub fn set_clock(&mut self, now: u64) {
        self.now = now;
    }

    pub fn ensure_entity(&mut self, entity_name: &str, entity_id: &str) {
        let (init_state, init_mask, init_vars) = match self.spec.entity(entity_name) {
            Some(e) => {
                // FR5：初始掩码 = initial 状态对应的位（位向量实体）
                let mask = e.mask_of(&e.initial).unwrap_or(0);
                // §5 用例 1：`state var frozen_until: Timestamp = 0`
                let vars: Vec<(String, Expr)> =
                    e.state_vars.iter().map(|v| (v.name.clone(), v.init.clone())).collect();
                (e.initial.clone(), mask, vars)
            }
            None => (String::new(), 0, Vec::new()),
        };
        if self.entities.contains_key(entity_name)
            && self
                .entities
                .get(entity_name)
                .map(|m| m.contains_key(entity_id))
                .unwrap_or(false)
        {
            return;
        }
        let mut inst = EntityInstance::new(entity_id, init_state);
        inst.mask = init_mask;
        for (name, init) in init_vars {
            let mut ev = Eval::new(self, None, entity_name, entity_id, None);
            let v = ev.eval(&init);
            inst.vars.insert(name, v);
        }
        self.entities
            .entry(entity_name.to_string())
            .or_default()
            .insert(entity_id.to_string(), inst);
    }

    pub fn entity_state(&self, entity_name: &str, entity_id: &str) -> Option<&str> {
        self.entities
            .get(entity_name)
            .and_then(|m| m.get(entity_id))
            .map(|i| i.state.as_str())
    }

    /// 某条流窗口内的记录数（测试 / 可观测性）。
    pub fn stream_len(&self, stream_name: &str) -> usize {
        self.rings.get(stream_name).map(|r| r.len()).unwrap_or(0)
    }

    /// 编译后的时序状态机（可观测性）。
    pub fn automaton(&self, spec_name: &str) -> Option<&TemporalAutomaton> {
        self.automata.get(spec_name)
    }

    /// 某个实体实例上的状态机快照。
    pub fn auto_state(&self, spec_name: &str, entity_id: &str) -> Option<&AutoState> {
        self.auto_states.get(&(spec_name.to_string(), entity_id.to_string()))
    }

    /// 实体实例键的候选字段：`key:` 声明优先，回落 `<lower>_id`。
    fn key_fields(&self, entity_name: &str) -> Vec<String> {
        let mut keys = Vec::new();
        if let Some(e) = self.spec.entity(entity_name) {
            if !e.key.is_empty() {
                keys.push(e.key.clone());
            }
        }
        let fallback = format!("{}_id", entity_name.to_lowercase());
        if !keys.contains(&fallback) {
            keys.push(fallback);
        }
        keys
    }

    // -----------------------------------------------------------------
    // 事件摄入
    // -----------------------------------------------------------------

    /// 摄入一个事件：投影入环 → 实体路由 → **同拍推进受影响实体的状态机**。
    pub fn ingest(&mut self, event: Event) {
        let ts = event.timestamp.max(self.now);
        self.now = ts;
        self.current_event_type = event.event_type.clone();

        // 1) 投影入环
        let matched: Vec<String> =
            self.streams_by_event.get(&event.event_type).cloned().unwrap_or_default();

        // 事件的实体归属。filter lambda 里的裸键名（`e.seat_id == seat_id`）需要
        // 实体上下文才能求值——否则右侧 `seat_id` 会退化成字符串字面量。
        let owner = self.entity_owner_of(&event);

        self.last_pushed.clear();
        for stream_name in &matched {
            // 取所需数据后立即释放对 streams 的借用
            let (filters, field_names, window_secs) = match self.streams.get(stream_name) {
                Some(s) => (s.filters.clone(), s.field_names.clone(), s.window_secs),
                None => continue,
            };
            if !filters.iter().all(|f| self.eval_filter(f, &event, owner.as_ref())) {
                continue;
            }
            let mut nums = vec![0.0; field_names.len()];
            let mut texts = vec![0u32; field_names.len()];
            for (i, name) in field_names.iter().enumerate() {
                if let Some(raw) = event.fields.get(name) {
                    nums[i] = raw.parse::<f64>().unwrap_or(0.0);
                    texts[i] = self.interner.intern(raw);
                }
            }
            let key = self.entity_key_of(&event);
            let key_id = self.interner.intern(&key);
            let evt_id = self.interner.intern(&event.event_type);
            if let Some(ring) = self.rings.get_mut(stream_name) {
                ring.push(RingEntry::tagged(ts, key_id, evt_id, nums, texts));
                if let Some(w) = window_secs {
                    ring.evict_before(ts.saturating_sub(w));
                }
            }
            self.last_pushed.push(stream_name.clone());
        }

        // 2) 实体路由
        let mut touched: Vec<(String, String)> = Vec::new();
        let entity_names: Vec<String> = self.spec.entities.iter().map(|e| e.name.clone()).collect();
        for en in entity_names {
            let keys = self.key_fields(&en);
            if let Some(id) = keys.iter().find_map(|k| event.fields.get(k)) {
                let id = id.clone();
                self.ensure_entity(&en, &id);
                touched.push((en, id));
            }
        }

        // 3) 同拍推进时序状态机（事件驱动，而非轮询）
        for (en, eid) in touched {
            self.step_entity(&en, &eid, Some(&event));
        }
    }

    /// 事件的实体归属：返回第一个"键字段在事件里出现"的实体。
    fn entity_owner_of(&self, event: &Event) -> Option<(String, String)> {
        for e in &self.spec.entities {
            let keys = self.key_fields(&e.name);
            if let Some(v) = keys.iter().find_map(|k| event.fields.get(k)) {
                return Some((e.name.clone(), v.clone()));
            }
        }
        None
    }

    /// 事件的实体键：优先取投影字段里像 "键" 的字段，最后回落实体声明的 `key`。
    fn entity_key_of(&self, event: &Event) -> String {
        for e in &self.spec.entities {
            if !e.key.is_empty() {
                if let Some(v) = event.fields.get(&e.key) {
                    return v.clone();
                }
            }
            let fallback = format!("{}_id", e.name.to_lowercase());
            if let Some(v) = event.fields.get(&fallback) {
                return v.clone();
            }
        }
        for probe in ["id", "code", "account_id", "company_id"] {
            if let Some(v) = event.fields.get(probe) {
                return v.clone();
            }
        }
        String::new()
    }

    fn eval_filter(
        &self,
        l: &Lambda,
        event: &Event,
        owner: Option<&(String, String)>,
    ) -> bool {
        let (en, eid) = match owner {
            Some((a, b)) => (a.as_str(), b.as_str()),
            None => ("", ""),
        };
        let mut ev = Eval::new(self, None, en, eid, Some(event));
        ev.push_item(&l.params, Item::Ev(event));
        let out = ev.truthy(&l.body);
        ev.pop_items(l.params.len());
        out
    }

    // -----------------------------------------------------------------
    // 时钟推进
    // -----------------------------------------------------------------

    /// 推进一个 tick：对所有实体实例评估所有 spec（用于截止期这类无事件驱动的推进）。
    ///
    /// PRD §4.3.2：租约到期回收发生在**时钟推进**上，而不是独立定时器线程
    /// ——这样"60s 后放行"与业务时钟严格同序，不会出现 1 秒的漏单窗口。
    pub fn tick(&mut self) {
        self.release_expired_leases();
        let names: Vec<String> = self.spec.entities.iter().map(|e| e.name.clone()).collect();
        for en in names {
            let ids: Vec<String> = self
                .entities
                .get(&en)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            for eid in ids {
                self.step_entity(&en, &eid, None);
            }
        }
    }

    /// 回收已到期的惩罚租约，返回本次放行的实体数。
    pub fn release_expired_leases(&mut self) -> usize {
        self.leases.release_expired(self.now)
    }

    // -----------------------------------------------------------------
    // v1.0：PEP / PDP 边界（PRD §3、§4）
    // -----------------------------------------------------------------

    /// 名字所属的执行模式（PRD §4 的四模同构路由）。
    pub fn mode_of(&self, name: &str) -> Option<Mode> {
        self.router.mode_of(name)
    }

    /// 按名取决策表（模式 D）。
    pub fn decision_table(&self, name: &str) -> Option<&DecisionTableDecl> {
        self.spec.decision_table(name)
    }

    /// **决策表试算**（控制台 / 服务端「试算」入口，FR3）。
    ///
    /// 按名求值一张决策表：`args` 是输入参数的绑定值（顺序与
    /// [`DecisionTableDecl::params`] 一致），返回命中行下标、命中集合与输出列。
    ///
    /// 与运行期查表的区别：这里**不推进任何状态**，纯粹是"给定输入，看表怎么判"，
    /// 因此可以在规则上线前让业务人员反复试算阈值区间。
    pub fn evaluate_table(&self, table: &str, args: &[Value]) -> Option<DecisionOutcome> {
        let decl = self.spec.decision_tables.iter().find(|d| d.name == table)?.clone();
        let mut env = RuntimeDecisionEnv { rt: self, entity_name: "", entity_id: "", now: self.now };
        Some(decision::evaluate(&decl, args, &mut env))
    }

    /// 某实体实例当前的位向量掩码（单调状态格）。
    pub fn state_mask(&self, entity_name: &str, entity_id: &str) -> u64 {
        self.entities
            .get(entity_name)
            .and_then(|m| m.get(entity_id))
            .map(|i| i.mask)
            .unwrap_or(0)
    }

    /// 某实体实例是否处于惩罚租约冻结期。
    pub fn is_frozen(&self, entity_name: &str, entity_id: &str) -> bool {
        self.leases.is_frozen(entity_name, entity_id, self.now)
    }

    /// **FR5：状态名 → 位**（显式 `= 0x08` 优先，否则按声明顺序 `1 << i`）。
    ///
    /// 离散时间轮的唤醒载荷需要携带这一位，从而在到期时**只读位图**即可判定，
    /// 与本引擎的状态格严格同源（不会出现"轮子里算出来的位"和"实体里存的位"不一致）。
    pub fn state_bit(&self, entity_name: &str, state: &str) -> Option<u64> {
        self.spec
            .entity(entity_name)
            .and_then(|e| e.mask_of(state).or_else(|| e.bit_of(state).map(|i| 1u64 << i)))
    }

    /// **FR5：双轨调度器** —— 为某实体实例注册一次长周期状态复核唤醒。
    ///
    /// 返回 `None` 表示 DSL 里没有声明该状态（或没有该实体），调用方应视为
    /// 编程错误而非静默忽略；返回 `Some(id)` 后可用 `cancel` 提前撤销。
    pub fn watch_state_expiry(
        &self,
        sched: &mut LongHorizonScheduler,
        entity_name: &str,
        entity_id: &str,
        state: &str,
        label: impl Into<String>,
        deadline: u64,
    ) -> Option<TimerId> {
        let bit = self.state_bit(entity_name, state)?;
        Some(sched.watch_state(entity_name, entity_id, state, bit, label, deadline))
    }

    /// **FR5 + AC3 闭环**：推进时间轮并用**当前位图**判定每笔到期唤醒。
    ///
    /// 这是"双轨"的汇合点：因果轨维护 `state |= next_state`，唤醒轨在到期时
    /// 只做一次 `state & required_bit`。返回值即监管结论——
    /// [`ExpiryOutcome::Lapsed`] 表示该状态位从未被点亮（如批文 365 天未启动发行）。
    pub fn advance_schedule(
        &mut self,
        sched: &mut LongHorizonScheduler,
        target: u64,
    ) -> Vec<(ExpiryWake, ExpiryOutcome)> {
        self.set_clock(target);
        let entities = &self.entities;
        sched.advance_and_check(target, |w| {
            entities
                .get(&w.entity)
                .and_then(|m| m.get(&w.entity_id))
                .map(|i| i.mask)
                .unwrap_or(0)
        })
    }

    /// **FR5：单调推进位向量状态**（`state |= mask`），返回推进后的掩码。
    ///
    /// 状态格的推进来自外部事实（批文下达、业务动作完成），而不是 DSL 里的
    /// 过程式赋值——这正是"状态与计算不割裂"的边界：DSL 只声明合法状态空间，
    /// 谁来点亮某一位由 PEP 放行后的业务侧决定。
    pub fn set_state_bits(&mut self, entity_name: &str, entity_id: &str, states: &[&str]) -> u64 {
        let mask = self.spec.entity(entity_name).map(|e| {
            states.iter().fold(0u64, |acc, s| {
                acc | e.mask_of(s).or_else(|| e.bit_of(s).map(|i| 1u64 << i)).unwrap_or(0)
            })
        });
        let mask = mask.unwrap_or(0);
        self.ensure_entity(entity_name, entity_id);
        if let Some(inst) = self.entities.get_mut(entity_name).and_then(|m| m.get_mut(entity_id)) {
            inst.mask |= mask;
            inst.state = modes::render_bits(self.spec.entity(entity_name), inst.mask);
            return inst.mask;
        }
        0
    }

    /// 直接写入位向量掩码（外部状态同步用；仍保持单调——只并入不覆盖）。
    pub fn set_state_mask(&mut self, entity_name: &str, entity_id: &str, mask: u64) -> u64 {
        self.ensure_entity(entity_name, entity_id);
        if let Some(inst) = self.entities.get_mut(entity_name).and_then(|m| m.get_mut(entity_id)) {
            inst.mask |= mask;
            inst.state = modes::render_bits(self.spec.entity(entity_name), inst.mask);
            return inst.mask;
        }
        0
    }

    /// 写入实体级状态变量（数据源绑定 / 测试注入）。
    pub fn set_entity_var(
        &mut self,
        entity_name: &str,
        entity_id: &str,
        name: &str,
        value: Value,
    ) {
        self.ensure_entity(entity_name, entity_id);
        if let Some(inst) = self.entities.get_mut(entity_name).and_then(|m| m.get_mut(entity_id)) {
            inst.vars.insert(name.to_string(), value);
        }
    }

    /// 实体实例的状态变量读取（`frozen_until` 走租约账本兜底）。
    pub fn entity_var(&self, entity_name: &str, entity_id: &str, name: &str) -> Option<Value> {
        self.entities
            .get(entity_name)
            .and_then(|m| m.get(entity_id))
            .and_then(|i| i.vars.get(name))
            .cloned()
            .or_else(|| {
                (name == "frozen_until")
                    .then(|| Value::Num(self.leases.frozen_until(entity_name, entity_id) as f64))
            })
    }

    /// **PEP 准入裁决**（PRD §3 的 PEP 侧唯一入口）。
    ///
    /// 三阶段：
    /// 1. `guard` 快筛：只读当前状态，不推进任何窗口 / 状态机；
    /// 2. 事件落地：投影入环 → 实体路由 → 同拍推进状态机；
    /// 3. **物理阻断**：若任一不变量被打破，则把刚落地的记录从窗口撤回，
    ///    使被拒事件不占用滑动窗口配额（AC2 的"第 21 笔同线程物理阻断"）。
    pub fn admit(&mut self, event: Event) -> Adjudication {
        if let Some(adj) = self.prefilter(&event) {
            self.current_event_type = event.event_type.clone();
            return adj;
        }
        let cursor = self.violations.len();
        self.ingest(event.clone());
        let denied = self.violations[cursor..].iter().find(|v| v.verdict.is_deny()).cloned();
        match denied {
            None => Adjudication::allow(event.event_type, self.now),
            Some(v) => {
                self.rollback_last(&event);
                Adjudication::from_record(&v, false)
            }
        }
    }

    /// **PDP 全量裁决**：不撤回窗口，返回本拍产生的全部违规（含 `ALLOW` 时为空）。
    ///
    /// 与 [`RegulatoryRuntime::admit`] 的区别：这里是"审计视角"——事件照常落地，
    /// 我们只报告它打破了哪些不变量。PEP 侧用 `admit`，回放/对账侧用 `adjudicate`。
    pub fn adjudicate(&mut self, event: Event) -> Vec<Adjudication> {
        let cursor = self.violations.len();
        self.ingest(event);
        self.violations[cursor..].iter().map(|v| Adjudication::from_record(v, false)).collect()
    }

    /// PEP 前置快筛：只读的 `guard` 求值（`Guard` 属于准入路径，不产生状态迁移）。
    fn prefilter(&self, event: &Event) -> Option<Adjudication> {
        for spec in self.spec.specs.iter().filter(|s| s.is_guard()) {
            if !spec.events.is_empty() && !spec.events.iter().any(|e| e == &event.event_type) {
                continue;
            }
            let aut = match self.automata.get(&spec.name) {
                Some(a) => a,
                None => continue,
            };
            for eid in self.instances_of(event, &spec.entity_name) {
                let mut st = aut.new_state();
                let mut ev = Eval::new(self, Some(spec), &spec.entity_name, &eid, Some(event));
                ev.fill_slots(&spec.name);
                let ok = aut.step(&mut st, &mut ev, self.now.max(event.timestamp));
                if ok {
                    continue;
                }
                let guard_ok = match &spec.violation.guard {
                    None => true,
                    Some(g) => {
                        let g = g.clone();
                        ev.truthy(&g)
                    }
                };
                if guard_ok {
                    let mut adj = Adjudication::deny(
                        spec,
                        &spec.entity_name,
                        &eid,
                        aut.explain(&st),
                        self.now.max(event.timestamp),
                        true,
                    );
                    adj.event_type = event.event_type.clone();
                    return Some(adj);
                }
            }
        }
        None
    }

    /// 事件涉及的某实体实例键（键声明优先，回落 `<lower>_id`）。
    fn instances_of(&self, event: &Event, entity_name: &str) -> Vec<String> {
        self.key_fields(entity_name)
            .iter()
            .find_map(|k| event.fields.get(k))
            .map(|v| vec![v.clone()])
            .unwrap_or_default()
    }

    /// 撤回本拍刚入环的记录（PEP 物理阻断）。
    fn rollback_last(&mut self, event: &Event) -> usize {
        let _ = event;
        let pushed: Vec<String> = std::mem::take(&mut self.last_pushed);
        let mut n = 0;
        for s in pushed {
            if let Some(r) = self.rings.get_mut(&s) {
                if r.pop_last().is_some() {
                    n += 1;
                }
            }
        }
        n
    }

    /// PRD §4.2：模式 B 的编译期 DAG 无环检验（32 步熔断由运行期负责）。
    pub fn check_rule_dag(&self) -> Result<(), CycleReport> {
        memory::check_dag(&self.spec.stateful_rules)
    }

    /// PRD §4.2 / FR7：以受限工作内存执行全部 `stateful` 规则（前向链 + 步长熔断）。
    pub fn run_stateful(&self, facts: Vec<Fact>) -> SessionResult {
        let mut wm = WorkingMemory::new();
        for f in facts {
            wm.insert(f);
        }
        memory::run_session(&self.spec.stateful_rules, wm, |e, params| {
            let mut ev = Eval::new(self, None, "", "", None);
            ev.eval_in_env(e, params)
        })
    }

    /// 自上次游标以来的违规（增量读取，供 interceptor / 对账使用）。
    pub fn violations_since(&self, cursor: usize) -> &[ViolationRecord] {
        &self.violations[cursor.min(self.violations.len())..]
    }

    /// 清空违规记录并返回游标可用值。
    pub fn clear_violations(&mut self) {
        self.violations.clear();
    }

    /// 推进某实体实例上的全部状态机；不变量被打破且 guard 通过时施加迁移。
    ///
    /// `event` 是**触发本次推进的事件**：事件驱动拍带上它，纯时钟推进（`tick`）为 `None`。
    /// 事件作用域的策略（`invariant X on Event[T] { when: event.f ... }`）依赖它；
    /// 无事件拍上这类策略自然为真空成立，不会误报。
    fn step_entity(&mut self, entity_name: &str, entity_id: &str, event: Option<&Event>) {
        let targets: Vec<(String, usize)> = self
            .spec
            .specs
            .iter()
            .enumerate()
            .filter(|(_, s)| s.entity_name == entity_name)
            .map(|(i, s)| (s.name.clone(), i))
            .collect();

        let mut pending: Vec<PendingViolation> = Vec::new();

        for (spec_name, spec_i) in targets {
            let spec_events = self.spec.specs[spec_i].events.clone();
            // 事件作用域策略：只在声明的事件类型到达时评估
            if !spec_events.is_empty() {
                match event {
                    Some(ev) if spec_events.iter().any(|t| t == &ev.event_type) => {}
                    _ => continue,
                }
            }

            let key = (spec_name.clone(), entity_id.to_string());
            let mut st = match self.auto_states.remove(&key) {
                Some(st) => st,
                None => match self.automata.get(&spec_name) {
                    Some(a) => a.new_state(),
                    None => continue,
                },
            };

            let mut violation: Option<(String, Option<f64>)> = None;
            {
                let aut = match self.automata.get(&spec_name) {
                    Some(a) => a,
                    None => continue,
                };
                let spec = &self.spec.specs[spec_i];
                let mut ev = Eval::new(self, Some(spec), entity_name, entity_id, event);
                ev.fill_slots(&spec_name);
                let ok = aut.step(&mut st, &mut ev, self.now);
                if !ok {
                    let guard_value = match &spec.violation.guard {
                        None => Some(1.0),
                        Some(g) => Some(ev.eval(g).as_num()),
                    };
                    if guard_value.map(|v| v > 0.0).unwrap_or(true) {
                        violation = Some((aut.explain(&st), guard_value));
                    }
                }
            }
            self.auto_states.insert(key, st);

            if let Some((explain, guard_value)) = violation {
                pending.push(PendingViolation {
                    spec_name: spec_name.clone(),
                    entity_name: entity_name.to_string(),
                    entity_id: entity_id.to_string(),
                    event_type: self.current_event_type.clone(),
                    explain,
                    guard_value,
                });
            }
        }

        for p in pending {
            self.apply_violation(p);
        }
    }

    fn apply_violation(&mut self, p: PendingViolation) {
        let spec_i = match self.spec_index.get(&p.spec_name) {
            Some(i) => *i,
            None => return,
        };
        let spec = self.spec.specs[spec_i].clone();
        let violation = spec.violation.clone();

        let mut trace = vec![
            ("now".to_string(), self.now.to_string()),
            ("invariant".to_string(), format!("VIOLATED ({})", p.explain)),
        ];
        if let Some(v) = p.guard_value {
            trace.push(("guard_value".to_string(), format!("{v:.4}")));
        }
        // FR5：位向量实体的 trace 带上可读的位名（AC1/AC4 的反例参数）
        if let Some(inst) = self.entities.get(&p.entity_name).and_then(|m| m.get(&p.entity_id)) {
            if self.spec.entity(&p.entity_name).map(|e| e.is_bitvec()).unwrap_or(false) {
                trace.push((
                    "state_mask".to_string(),
                    modes::render_bits(self.spec.entity(&p.entity_name), inst.mask),
                ));
            }
        }

        // 确定性状态迁移：经典 `from --(spec)--> to` 路径
        if let Some((from, to)) = &violation.transition {
            if let Some(inst) =
                self.entities.get_mut(&p.entity_name).and_then(|m| m.get_mut(&p.entity_id))
            {
                if inst.state == *from {
                    trace.push(("state".to_string(), format!("{} -> {}", inst.state, to)));
                    inst.state = to.clone();
                } else {
                    trace.push((
                        "state".to_string(),
                        format!("{} (skip {} -> {})", inst.state, from, to),
                    ));
                }
            }
        }

        // v1.0：`Effect` 白名单的确定性副作用（租约 / 单调状态格 / 告警）
        for eff in &spec.effects {
            match eff {
                Effect::LeaseUpdate { target, expr } => {
                    let until = modes::apply_lease_expr(expr, self.now);
                    let stored = self.leases.apply(&p.entity_name, &p.entity_id, until);
                    if let Some(inst) =
                        self.entities.get_mut(&p.entity_name).and_then(|m| m.get_mut(&p.entity_id))
                    {
                        inst.vars.insert(target.clone(), Value::Num(stored as f64));
                    }
                    trace.push(("lease".to_string(), format!("{target} = {stored}")));
                }
                Effect::Transition { from, to } => {
                    // FR5：位向量实体走单调 `state |= bit_of(to)`；普通实体走守卫迁移
                    let is_bv =
                        self.spec.entity(&p.entity_name).map(|e| e.is_bitvec()).unwrap_or(false);
                    let to_bit = self
                        .spec
                        .entity(&p.entity_name)
                        .and_then(|e| e.mask_of(to).or_else(|| e.bit_of(to).map(|i| 1u64 << i)));
                    if let Some(inst) =
                        self.entities.get_mut(&p.entity_name).and_then(|m| m.get_mut(&p.entity_id))
                    {
                        if is_bv {
                            let bit = to_bit.unwrap_or(0);
                            inst.mask |= bit;
                            trace.push((
                                "state_mask".to_string(),
                                format!("|= {} {}", to, modes::render_bits(None, inst.mask)),
                            ));
                            inst.state = to.clone();
                        } else if from.is_empty() || inst.state == *from {
                            trace.push(("state".to_string(), format!("{} -> {}", inst.state, to)));
                            inst.state = to.clone();
                        }
                    }
                }
                Effect::Emit { message } => {
                    trace.push(("emit".to_string(), message.clone()));
                }
            }
        }

        self.violations.push(ViolationRecord {
            spec_name: p.spec_name.clone(),
            entity_name: p.entity_name.clone(),
            entity_id: p.entity_id.clone(),
            event_type: p.event_type.clone(),
            verdict: spec.verdict.clone(),
            severity: violation.severity,
            message: violation.message.clone(),
            explain: p.explain.clone(),
            effects: spec.effects.clone(),
            timestamp: self.now,
        });

        self.dispatcher.dispatch(Alert {
            contract: p.spec_name,
            entity_id: p.entity_id,
            severity: violation.severity,
            message: violation.message,
            timestamp: self.now,
            trace,
        });
    }
}

struct PendingViolation {
    spec_name: String,
    entity_name: String,
    entity_id: String,
    event_type: String,
    explain: String,
    guard_value: Option<f64>,
}

/// 收集 lambda 体中形如 `<param>.<field>` 的字段名。
fn collect_param_fields(e: &Expr, params: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    walk_fields(e, params, &mut out);
    out
}

fn push_unique(out: &mut Vec<String>, s: &str) {
    if !s.is_empty() && !out.iter().any(|x| x == s) {
        out.push(s.to_string());
    }
}

/// 收集表达式中的"字面符号"：裸标识符与路径末段（`ReportType.SEMI_ANNUAL` → `SEMI_ANNUAL`）。
/// 这些符号在运行期作为枚举常量参与比较，必须在装载期驻留成稳定 id。
fn collect_literals(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Ident(n) => push_unique(out, n),
        Expr::Path(parts) => {
            if let Some(last) = parts.last() {
                push_unique(out, last);
            }
        }
        Expr::Binary { left, right, .. } => {
            collect_literals(left, out);
            collect_literals(right, out);
        }
        Expr::UnaryNot(i) => collect_literals(i, out),
        Expr::Call { args, .. } => {
            for a in args {
                collect_literals(a, out);
            }
        }
        _ => {}
    }
}

/// 收集时序公式中的字面符号。
fn collect_temporal_literals(t: &TemporalExpr, out: &mut Vec<String>) {
    match t {
        TemporalExpr::Predicate(e) => collect_literals(e, out),
        TemporalExpr::Historically { expr, within } | TemporalExpr::Eventually { expr, within } => {
            collect_temporal_literals(expr, out);
            if let Some(w) = within {
                collect_literals(w, out);
            }
        }
        TemporalExpr::Within { window, inner } => {
            collect_literals(window, out);
            collect_temporal_literals(inner, out);
        }
        TemporalExpr::Always(i) | TemporalExpr::Not(i) => collect_temporal_literals(i, out),
        TemporalExpr::Until { p, q } | TemporalExpr::Since { p, q } => {
            collect_temporal_literals(p, out);
            collect_temporal_literals(q, out);
        }
        TemporalExpr::Implies(a, b) | TemporalExpr::And(a, b) | TemporalExpr::Or(a, b) => {
            collect_temporal_literals(a, out);
            collect_temporal_literals(b, out);
        }
        TemporalExpr::StreamQuant { lambda, .. } => {
            if let Some(l) = lambda {
                collect_literals(&l.body, out);
            }
        }
        TemporalExpr::CrossesAbove { threshold, .. } | TemporalExpr::CrossesBelow { threshold, .. } => {
            collect_literals(threshold, out)
        }
    }
}

/// 递归收集时序不变量中所有流量化 lambda 引用的 `(stream, field)` 对。
fn collect_stream_refs(t: &TemporalExpr, out: &mut Vec<(String, String)>) {
    match t {
        TemporalExpr::StreamQuant { stream, lambda, .. } => {
            if let Some(l) = lambda {
                for f in collect_param_fields(&l.body, &l.params) {
                    if !out.iter().any(|(s, n)| s == stream && n == &f) {
                        out.push((stream.clone(), f));
                    }
                }
            }
        }
        TemporalExpr::Historically { expr, .. }
        | TemporalExpr::Always(expr)
        | TemporalExpr::Eventually { expr, .. }
        | TemporalExpr::Within { inner: expr, .. }
        | TemporalExpr::Not(expr) => collect_stream_refs(expr, out),
        TemporalExpr::Until { p, q } | TemporalExpr::Since { p, q } => {
            collect_stream_refs(p, out);
            collect_stream_refs(q, out);
        }
        TemporalExpr::Implies(a, b) | TemporalExpr::And(a, b) | TemporalExpr::Or(a, b) => {
            collect_stream_refs(a, out);
            collect_stream_refs(b, out);
        }
        TemporalExpr::Predicate(_) => {}
        TemporalExpr::CrossesAbove { .. } | TemporalExpr::CrossesBelow { .. } => {}
    }
}

fn walk_fields(e: &Expr, params: &[String], out: &mut Vec<String>) {
    match e {
        Expr::Path(parts) => {
            if parts.len() >= 2 && params.iter().any(|p| p == &parts[0]) {
                let f = parts[1..].join(".");
                if !out.contains(&f) {
                    out.push(f);
                }
            }
        }
        Expr::Binary { left, right, .. } => {
            walk_fields(left, params, out);
            walk_fields(right, params, out);
        }
        Expr::UnaryNot(i) => walk_fields(i, params, out),
        Expr::Call { args, .. } => {
            for a in args {
                walk_fields(a, params, out);
            }
        }
        _ => {}
    }
}

// =====================================================================
// 值求值器（同时充当 AtomHost）
// =====================================================================

struct Eval<'r> {
    rt: &'r RegulatoryRuntime,
    spec: Option<&'r SpecDecl>,
    entity_name: &'r str,
    entity_id: &'r str,
    /// 当前事件上下文（事件驱动求值时绑定）。
    event: Option<&'r Event>,
    /// lambda 形参绑定栈。
    items: Vec<(String, Item<'r>)>,
    /// 局部绑定栈（metric 形参 / given / fold 累加器）。
    locals: Vec<(String, Value)>,
    /// 当前 spec 的配对槽（扁平原子使用）。
    slots_num: Vec<f64>,
    slots_text: Vec<u32>,
    vm: FlatVm,
}

impl<'r> Eval<'r> {
    fn new(
        rt: &'r RegulatoryRuntime,
        spec: Option<&'r SpecDecl>,
        entity_name: &'r str,
        entity_id: &'r str,
        event: Option<&'r Event>,
    ) -> Self {
        Self {
            rt,
            spec,
            entity_name,
            entity_id,
            event,
            items: Vec::new(),
            locals: Vec::new(),
            slots_num: Vec::new(),
            slots_text: Vec::new(),
            vm: FlatVm::new(1, 1),
        }
    }

    fn push_item(&mut self, params: &[String], item: Item<'r>) {
        for p in params {
            self.items.push((p.clone(), item.clone()));
        }
    }

    fn pop_items(&mut self, n: usize) {
        for _ in 0..n {
            self.items.pop();
        }
    }

    /// 按 spec 的槽位绑定填充配对数组。
    fn fill_slots(&mut self, spec_name: &str) {
        let names = match self.rt.bindings.get(spec_name) {
            Some(b) => b.names.clone(),
            None => return,
        };
        // given 绑定先入 locals
        if let Some(spec) = self.spec {
            let given = spec.given.clone();
            for (name, expr) in given {
                let v = self.eval(&expr);
                self.locals.push((name, v));
            }
        }
        self.slots_num = vec![0.0; names.len()];
        self.slots_text = vec![0u32; names.len()];
        for (i, name) in names.iter().enumerate() {
            let v = self.resolve_ident(name);
            self.slots_num[i] = v.as_num();
            self.slots_text[i] = match &v {
                Value::Text(_) => self.rt.interner.id_of(&v.as_text()),
                _ => 0,
            };
        }
    }

    // ---------------- 表达式求值 ----------------

    fn eval(&mut self, e: &Expr) -> Value {
        match e {
            Expr::Number(n) => Value::Num(*n),
            Expr::Hex(h) => Value::Num(*h as f64),
            Expr::Bool(b) => Value::Bool(*b),
            Expr::Str(s) => Value::Text(s.clone()),
            Expr::DurationLit(d) => Value::Num(d.as_secs() as f64),
            Expr::Ident(name) => self.resolve_ident(name),
            Expr::Path(parts) => self.resolve_path(parts),
            Expr::UnaryNot(inner) => Value::Bool(!self.eval(inner).truthy()),
            Expr::Binary { op, left, right } => self.eval_binary(*op, left, right),
            Expr::Call { func, args } => self.eval_call(func, args),
            Expr::TableLookup { table, args, index } => self.eval_table_lookup(table, args, *index),
        }
    }

    fn truthy(&mut self, e: &Expr) -> bool {
        self.eval(e).truthy()
    }

    fn eval_binary(&mut self, op: BinaryOp, left: &Expr, right: &Expr) -> Value {
        if matches!(op, BinaryOp::And) {
            let l = self.eval(left).truthy();
            return Value::Bool(l && self.eval(right).truthy());
        }
        if matches!(op, BinaryOp::Or) {
            let l = self.eval(left).truthy();
            return Value::Bool(l || self.eval(right).truthy());
        }
        let l = self.eval(left);
        let r = self.eval(right);
        self.eval_binary_values(op, l, r)
    }

    /// 值层面的二元运算（与求值路径解耦，供 `eval_in_env` 复用）。
    fn eval_binary_values(&self, op: BinaryOp, l: Value, r: Value) -> Value {
        match op {
            BinaryOp::Add => Value::Num(l.as_num() + r.as_num()),
            BinaryOp::Sub => Value::Num(l.as_num() - r.as_num()),
            BinaryOp::Mul => Value::Num(l.as_num() * r.as_num()),
            BinaryOp::Div => {
                let d = r.as_num();
                Value::Num(if d.abs() < f64::EPSILON { 0.0 } else { l.as_num() / d })
            }
            BinaryOp::Mod => {
                let d = r.as_num();
                Value::Num(if d.abs() < f64::EPSILON { 0.0 } else { l.as_num() % d })
            }
            BinaryOp::Eq => Value::Bool(value_eq(&l, &r)),
            BinaryOp::Neq => Value::Bool(!value_eq(&l, &r)),
            BinaryOp::Gt => Value::Bool(l.as_num() > r.as_num()),
            BinaryOp::Gte => Value::Bool(l.as_num() >= r.as_num()),
            BinaryOp::Lt => Value::Bool(l.as_num() < r.as_num()),
            BinaryOp::Lte => Value::Bool(l.as_num() <= r.as_num()),
            // FR5：位运算（单调状态格 `state & MASK`）
            BinaryOp::BitAnd => Value::Num(((l.as_num() as u64) & (r.as_num() as u64)) as f64),
            BinaryOp::BitOr => Value::Num(((l.as_num() as u64) | (r.as_num() as u64)) as f64),
            BinaryOp::BitXor => Value::Num(((l.as_num() as u64) ^ (r.as_num() as u64)) as f64),
            BinaryOp::Shl => {
                Value::Num(((l.as_num() as u64) << (r.as_num().clamp(0.0, 63.0) as u32)) as f64)
            }
            BinaryOp::Shr => {
                Value::Num(((l.as_num() as u64) >> (r.as_num().clamp(0.0, 63.0) as u32)) as f64)
            }
            BinaryOp::And => Value::Bool(l.truthy() && r.truthy()),
            BinaryOp::Or => Value::Bool(l.truthy() || r.truthy()),
        }
    }

    fn resolve_ident(&mut self, name: &str) -> Value {
        if let Some((_, v)) = self.locals.iter().rev().find(|(k, _)| k == name) {
            return v.clone();
        }
        match name {
            "true" => return Value::Bool(true),
            "false" => return Value::Bool(false),
            // FR5：单调状态格。位向量实体读 `state` 得到掩码；普通实体得到状态名。
            "state" | "status" => {
                return match self.state_mask() {
                    Some(m) => Value::Num(m as f64),
                    None => Value::Text(self.current_state()),
                }
            }
            "now" | "today" => return Value::Num(self.rt.now as f64),
            _ => {}
        }
        // §5 用例 1/2/3：实体级状态变量（`frozen_until`）优先于同名字面量
        if let Some(v) = self.state_var(name) {
            return v;
        }
        if let Some(v) = self.rt.dict.vars.get(name) {
            return dict_to_value(v);
        }
        // FR5：具名状态常量按位掩码求值（`CSRC_APPROVED` → `0x04`）
        let mask = self
            .rt
            .spec
            .entities
            .iter()
            .flat_map(|e| e.states.iter())
            .find(|s| s.name == name)
            .and_then(|s| s.mask);
        if let Some(m) = mask {
            return Value::Num(m as f64);
        }
        // FR2：`var <name>: <ty> [range: lo..hi] = <init>` 的编译期常量
        let var_init = self
            .rt
            .spec
            .var_decls
            .iter()
            .find(|v| v.name == name)
            .map(|v| (v.init.clone(), v.range.clone()));
        if let Some((init, range)) = var_init {
            let v = match init {
                Some(e) => self.eval(&e),
                None => Value::Num(0.0),
            };
            return self.apply_range(v, range.as_ref());
        }
        // 零元 metric 可直接当标识符使用（`audit_opinion_clean`）
        if let Some(m) = self.rt.metrics.get(name).cloned() {
            if m.params.is_empty() {
                return self.eval_metric(&m, &[]);
            }
        }
        // 实体实例键的裸写形式
        if let Some(e) = self.rt.spec.entity(self.entity_name) {
            if !e.key.is_empty() && name == e.key {
                return Value::Text(self.entity_id.to_string());
            }
        }
        // 未解释符号 → 视为枚举常量（`SUSPENDED` / `ReportType.SEMI_ANNUAL` 的末段）
        Value::Text(name.to_string())
    }

    /// 当前实体实例的位向量掩码（仅位向量实体返回 `Some`）。
    fn state_mask(&self) -> Option<u64> {
        let e = self.rt.spec.entity(self.entity_name)?;
        if !e.is_bitvec() {
            return None;
        }
        self.rt
            .entities
            .get(self.entity_name)
            .and_then(|m| m.get(self.entity_id))
            .map(|i| i.mask)
    }

    /// FR2：把值夹到 `range: lo .. hi` 的闭区间内（区间本身由 SMT 侧作为 DomainAxiom 证明）。
    fn apply_range(&mut self, v: Value, range: Option<&(Expr, Expr)>) -> Value {
        let (lo, hi) = match range {
            Some((lo, hi)) => (lo.clone(), hi.clone()),
            None => return v,
        };
        let lo = self.eval(&lo).as_num();
        let hi = self.eval(&hi).as_num();
        Value::Num(v.as_num().clamp(lo.min(hi), hi.max(lo)))
    }

    fn resolve_path(&mut self, parts: &[String]) -> Value {
        if parts.is_empty() {
            return Value::Num(0.0);
        }
        let head = parts[0].as_str();
        // 1) lambda 形参（事件 / 环形记录）
        if let Some((_, item)) = self.items.iter().rev().find(|(k, _)| k == head) {
            let item = item.clone();
            for seg in &parts[1..] {
                if let Some(v) = item.field(seg, &self.rt.interner) {
                    return v;
                }
            }
            return Value::Num(0.0);
        }
        // 2) 实体绑定变量（`c.id` / `c.code` / `c.status`）
        if let Some(spec) = self.spec {
            if head == spec.entity_var {
                let field = parts.last().map(|s| s.as_str()).unwrap_or("");
                // `c.<key>` 解析为实体实例键（而不是字段名字面量）
                let key = self
                    .rt
                    .spec
                    .entity(spec.entity_name.as_str())
                    .map(|e| e.key.clone())
                    .unwrap_or_default();
                return match field {
                    "id" | "state" | "status" if field != key => {
                        if field == "id" {
                            Value::Text(self.entity_id.to_string())
                        } else {
                            Value::Text(self.current_state())
                        }
                    }
                    other if other == key || other == "id" => {
                        Value::Text(self.entity_id.to_string())
                    }
                    other => Value::Text(other.to_string()),
                };
            }
        }
        // 3) 当前事件（`event.type` / `event.timestamp`）
        if head == "event" {
            if let Some(ev) = self.event {
                let key = parts[1..].join(".");
                // `event.timestamp` 是事件自身的时间轴，不必在 fields 里冗余一份
                if key == "timestamp" || key == "ts" || key == "time" {
                    return Value::Num(ev.timestamp as f64);
                }
                if let Some(raw) = ev.fields.get(&key) {
                    return parse_value(raw);
                }
            }
            return Value::Num(0.0);
        }
        // 4) 外部字典绑定（如 `DisclosureEvent.audit_opinion`）
        if let Some(v) = self.rt.dict.lookup_external(parts) {
            return dict_to_value(v);
        }
        // 4b) FR8：`db.<field>` —— 数据源字段读。
        //     绑定表（`bind: Datasource["x"].Table["y"]`）在本地回退模式下
        //     按名映射到实体状态变量，其次回落到全局字典。
        if head == "db" {
            if let Some(field) = parts.get(1) {
                if let Some(v) = self.state_var(field) {
                    return v;
                }
                if let Some(v) = self.rt.dict.vars.get(field) {
                    return dict_to_value(v);
                }
            }
            return Value::Num(0.0);
        }
        let joined = parts.join(".");
        if let Some(v) = self.rt.dict.vars.get(&joined) {
            return dict_to_value(v);
        }
        // 5) `ReportType.SEMI_ANNUAL` 这类枚举常量 → 取末段
        Value::Text(parts.last().cloned().unwrap_or_default())
    }

    fn current_state(&self) -> String {
        self.rt
            .entities
            .get(self.entity_name)
            .and_then(|m| m.get(self.entity_id))
            .map(|i| i.state.clone())
            .unwrap_or_default()
    }

    fn eval_call(&mut self, func: &str, args: &[Expr]) -> Value {
        if let Some(m) = self.rt.metrics.get(func).cloned() {
            return self.eval_metric(&m, args);
        }
        // 流上的聚合调用：`Trades.count()` / `Cancels.sum()` / `Reports.max()`
        // FR6 / 用例 1：`SeatActions[OrderIntent].count` 会带上来源事件类型实参，
        // 需要在同一条环上按事件类型分流。
        if let Some((stream, op)) = func.split_once('.') {
            if self.rt.streams.contains_key(stream) {
                let kind = match op {
                    "sum" => AggKind::Sum,
                    "avg" => AggKind::Avg,
                    "min" => AggKind::Min,
                    "max" => AggKind::Max,
                    _ => AggKind::Count,
                };
                let evt = match args.first() {
                    Some(Expr::Str(s)) => Some(s.clone()),
                    _ => None,
                };
                return Value::Num(self.aggregate_of(stream, kind, evt.as_deref()));
            }
        }
        match func {
            "now" | "today" => Value::Num(self.rt.now as f64),
            "days_between" => {
                let a = self.arg(args, 0);
                let b = self.arg(args, 1);
                Value::Num((a - b) / 86400.0)
            }
            "DaysOverdue" => {
                let deadline = self.arg(args, 0);
                let now = self.rt.now as f64;
                Value::Num(if now > deadline { (now - deadline) / 86400.0 } else { 0.0 })
            }
            "DaysSince" => {
                let t = self.arg(args, 0);
                let now = self.rt.now as f64;
                Value::Num(if now > t { (now - t) / 86400.0 } else { 0.0 })
            }
            "abs" => Value::Num(self.arg(args, 0).abs()),
            "max" => match self.stream_arg(args) {
                Some(s) => Value::Num(self.aggregate(&s, AggKind::Max)),
                None => Value::Num(self.arg(args, 0).max(self.arg(args, 1))),
            },
            "min" => match self.stream_arg(args) {
                Some(s) => Value::Num(self.aggregate(&s, AggKind::Min)),
                None => Value::Num(self.arg(args, 0).min(self.arg(args, 1))),
            },
            "sum" => match self.stream_arg(args) {
                Some(s) => Value::Num(self.aggregate(&s, AggKind::Sum)),
                None => Value::Num(self.arg(args, 0)),
            },
            "avg" => match self.stream_arg(args) {
                Some(s) => Value::Num(self.aggregate(&s, AggKind::Avg)),
                None => Value::Num(self.arg(args, 0)),
            },
            "count" | "len" => match self.stream_arg(args) {
                Some(s) => Value::Num(self.aggregate(&s, AggKind::Count)),
                None => Value::Num(args.len() as f64),
            },
            "ratio" => {
                let a = self.arg(args, 0);
                let b = self.arg(args, 1);
                Value::Num(if b.abs() < f64::EPSILON { 0.0 } else { a / b })
            }
            "exists" | "forall" => Value::Num(0.0),
            _ => Value::Num(0.0),
        }
    }

    /// FR3：决策表查表（`let (a, b) = DetermineAmount(event.timestamp)` 解构出的
    /// `TableLookup` 会带上输出列下标 `index`）。
    fn eval_table_lookup(&mut self, table: &str, args: &[Expr], index: usize) -> Value {
        let decl = match self.rt.spec.decision_tables.iter().find(|d| d.name == table) {
            Some(d) => d.clone(),
            None => return Value::Num(0.0),
        };
        let mut arg_vals: Vec<Value> = Vec::with_capacity(args.len());
        for a in args {
            let a = a.clone();
            arg_vals.push(self.eval(&a));
        }
        let mut env = RuntimeDecisionEnv {
            rt: self.rt,
            entity_name: self.entity_name,
            entity_id: self.entity_id,
            now: self.rt.now,
        };
        let out = decision::evaluate(&decl, &arg_vals, &mut env);
        out.outputs.get(index).cloned().unwrap_or(Value::Num(0.0))
    }

    /// FR6：边缘跃迁算子读取的"派生指标当前值"。
    fn metric_value(&mut self, metric: &str) -> Option<f64> {
        let m = self.rt.metrics.get(metric).cloned()?;
        if !m.params.is_empty() {
            return None;
        }
        Some(self.eval_metric(&m, &[]).as_num())
    }

    /// 当前实体实例的状态变量（`frozen_until` 等）。
    fn state_var(&self, name: &str) -> Option<Value> {
        if let Some(v) = self
            .rt
            .entities
            .get(self.entity_name)
            .and_then(|m| m.get(self.entity_id))
            .and_then(|i| i.vars.get(name))
        {
            return Some(v.clone());
        }
        // §4.3.3：惩罚租约账本是 `frozen_until` 的权威来源
        if name == "frozen_until" {
            return Some(Value::Num(
                self.rt.leases.frozen_until(self.entity_name, self.entity_id) as f64,
            ));
        }
        None
    }

    /// 在参数环境 `params` 下求值（模式 B 的 RHS 与模式 D 的输出子句都走它）。
    ///
    /// 两点特化：
    /// 1. `$x.f`（模式绑定路径）先按全名 `$x.f` 查，再按末段 `f` 回落；
    /// 2. 其余表达式把 `params` 压入 locals 后走常规求值。
    pub(crate) fn eval_in_env(&mut self, e: &Expr, params: &[(String, Value)]) -> Value {
        fn lookup(params: &[(String, Value)], key: &str) -> Option<Value> {
            params.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.clone())
        }
        match e {
            Expr::Path(parts) if parts.len() >= 2 => {
                let full = parts.join(".");
                if let Some(v) = lookup(params, &full) {
                    return v;
                }
                let last = parts.last().cloned().unwrap_or_default();
                if let Some(v) = lookup(params, &last) {
                    return v;
                }
                Value::Num(0.0)
            }
            Expr::Ident(n) => lookup(params, n).unwrap_or_else(|| Value::Num(0.0)),
            Expr::UnaryNot(inner) => {
                let i = inner.clone();
                Value::Bool(!self.eval_in_env(&i, params).truthy())
            }
            Expr::Binary { op, left, right } => {
                let (op, left, right) = (*op, left.clone(), right.clone());
                if matches!(op, BinaryOp::And) {
                    let l = self.eval_in_env(&left, params).truthy();
                    return Value::Bool(l && self.eval_in_env(&right, params).truthy());
                }
                if matches!(op, BinaryOp::Or) {
                    let l = self.eval_in_env(&left, params).truthy();
                    return Value::Bool(l || self.eval_in_env(&right, params).truthy());
                }
                let l = self.eval_in_env(&left, params);
                let r = self.eval_in_env(&right, params);
                self.eval_binary_values(op, l, r)
            }
            _ => {
                let marker = self.locals.len();
                self.locals.extend(params.iter().cloned());
                let v = self.eval(e);
                self.locals.truncate(marker);
                v
            }
        }
    }

    fn arg(&mut self, args: &[Expr], i: usize) -> f64 {
        match args.get(i) {
            Some(a) => {
                let a = a.clone();
                self.eval(&a).as_num()
            }
            None => 0.0,
        }
    }

    /// 若第一个实参是一个已声明的流名，则返回它。
    fn stream_arg(&self, args: &[Expr]) -> Option<String> {
        if let Some(Expr::Ident(name)) = args.first() {
            if self.rt.streams.contains_key(name) {
                return Some(name.clone());
            }
        }
        None
    }

    /// 对某实体实例在某条流窗口上做聚合（顺序扫描环形缓冲区）。
    fn aggregate(&self, stream: &str, kind: AggKind) -> f64 {
        self.aggregate_of(stream, kind, None)
    }

    /// 带事件类型切片的聚合：`SeatActions[OrderIntent].count`。
    fn aggregate_of(&self, stream: &str, kind: AggKind, evt: Option<&str>) -> f64 {
        let rt = self.rt;
        let key = rt.interner.id_of(self.entity_id);
        let evt_id = evt.map(|e| rt.interner.id_of(e));
        let ring = match rt.rings.get(stream) {
            Some(r) => r,
            None => return 0.0,
        };
        let sr = match rt.streams.get(stream) {
            Some(s) => s,
            None => return 0.0,
        };
        let mut count = 0usize;
        let mut sum = 0.0f64;
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;
        for entry in ring.iter() {
            if !sr.belongs(entry, key) {
                continue;
            }
            if let Some(id) = evt_id {
                if entry.evt != id {
                    continue;
                }
            }
            let v = match sr.field_index.get("value") {
                Some(off) => entry.num(*off as usize),
                None => 1.0,
            };
            count += 1;
            sum += v;
            min = min.min(v);
            max = max.max(v);
        }
        match kind {
            AggKind::Count => count as f64,
            AggKind::Sum => sum,
            AggKind::Avg => {
                if count == 0 {
                    0.0
                } else {
                    sum / count as f64
                }
            }
            AggKind::Min => {
                if count == 0 {
                    0.0
                } else {
                    min
                }
            }
            AggKind::Max => {
                if count == 0 {
                    0.0
                } else {
                    max
                }
            }
        }
    }

    /// 求值一个 metric 调用（形参入栈 → 求值 → 出栈）。
    fn eval_metric(&mut self, m: &MetricDecl, args: &[Expr]) -> Value {
        let marker = self.locals.len();
        for (i, p) in m.params.iter().enumerate() {
            let a = args.get(i).cloned();
            let v = match a {
                Some(a) => self.eval(&a),
                None => Value::Num(0.0),
            };
            self.locals.push((p.name.clone(), v));
        }

        let out = match &m.body {
            MetricBody::Scalar { expr, guard } => {
                let (expr, guard) = (expr.clone(), guard.clone());
                let pass = match &guard {
                    Some(g) => {
                        let g = g.clone();
                        self.truthy(&g)
                    }
                    None => true,
                };
                if pass {
                    self.eval(&expr)
                } else {
                    Value::Num(0.0)
                }
            }
            MetricBody::StreamAgg { stream, kind } => {
                Value::Num(self.aggregate(stream, *kind))
            }
            MetricBody::StreamFold { stream, init, acc, item, body } => {
                let (stream, init, acc, item, body) = (
                    stream.clone(),
                    init.clone(),
                    acc.clone(),
                    item.clone(),
                    body.clone(),
                );
                let rt = self.rt;
                let init_v = self.eval(&init);
                self.locals.push((acc.clone(), init_v.clone()));

                let key = rt.interner.id_of(self.entity_id);
                let names = Rc::new(
                    rt.streams.get(&stream).map(|s| s.field_names.clone()).unwrap_or_default(),
                );
                let entries: Vec<Rc<RingEntry>> = match rt.rings.get(&stream) {
                    Some(r) => {
                        let belongs = |e: &RingEntry| {
                            rt.streams
                                .get(&stream)
                                .map(|s| s.belongs(e, key))
                                .unwrap_or(false)
                        };
                        r.iter().filter(|e| belongs(e)).map(|e| Rc::new(e.clone())).collect()
                    }
                    None => Vec::new(),
                };

                let mut acc_v = init_v;
                for e in entries {
                    self.items.push((item.clone(), Item::Ring(e, names.clone())));
                    let next = self.eval(&body);
                    self.items.pop();
                    acc_v = next;
                    self.set_local(&acc, acc_v.clone());
                }
                acc_v
            }
        };
        self.locals.truncate(marker);
        out
    }

    fn set_local(&mut self, name: &str, v: Value) {
        if let Some((_, slot)) = self.locals.iter_mut().rev().find(|(k, _)| k == name) {
            *slot = v;
        }
    }

    /// 扫描环形缓冲区上的量化：`Stream.exists(e => P)`。
    fn eval_stream_quant(&mut self, stream: &str, quant: Quant, lambda: Option<&Lambda>) -> bool {
        let rt = self.rt;
        let key = rt.interner.id_of(self.entity_id);
        let (names, entries) = {
            let sr = match rt.streams.get(stream) {
                Some(s) => s,
                None => return quant == Quant::Forall,
            };
            let ring = match rt.rings.get(stream) {
                Some(r) => r,
                None => return quant == Quant::Forall,
            };
            let names = Rc::new(sr.field_names.clone());
            let entries: Vec<Rc<RingEntry>> = ring
                .iter()
                .filter(|e| sr.belongs(e, key))
                .map(|e| Rc::new(e.clone()))
                .collect();
            (names, entries)
        };

        if entries.is_empty() {
            // forall 在空集上真空成立；exists / count 为假
            return quant == Quant::Forall;
        }

        let lam = lambda.cloned();
        let mut hits = 0usize;
        for e in &entries {
            let matched = match &lam {
                None => true,
                Some(l) => {
                    self.items.push((
                        l.params.first().cloned().unwrap_or_else(|| "e".to_string()),
                        Item::Ring(e.clone(), names.clone()),
                    ));
                    let body = l.body.clone();
                    let ok = self.truthy(&body);
                    self.items.pop();
                    ok
                }
            };
            if matched {
                hits += 1;
            }
        }
        match quant {
            Quant::Exists | Quant::Count => hits > 0,
            Quant::Forall => hits == entries.len(),
        }
    }
}

/// 决策表求值环境：把参数绑定注入一个临时 `Eval`，从而复用整套表达式求值
/// （含 metric / 字面量 / 位运算 / 日期函数）。
struct RuntimeDecisionEnv<'a> {
    rt: &'a RegulatoryRuntime,
    entity_name: &'a str,
    entity_id: &'a str,
    now: u64,
}

impl DecisionEnv for RuntimeDecisionEnv<'_> {
    fn eval_bound(&mut self, e: &Expr, params: &[(String, Value)]) -> Value {
        let mut ev = Eval::new(self.rt, None, self.entity_name, self.entity_id, None);
        ev.locals.extend(params.iter().cloned());
        let _ = self.now;
        ev.eval(e)
    }
}

fn dict_to_value(v: &rules_dictionary::ScalarValue) -> Value {
    match v {
        rules_dictionary::ScalarValue::Num(n) => Value::Num(*n),
        rules_dictionary::ScalarValue::Time(t) => Value::Num(*t as f64),
        rules_dictionary::ScalarValue::Bool(b) => Value::Bool(*b),
        rules_dictionary::ScalarValue::Text(s) => Value::Text(s.clone()),
    }
}

fn value_eq(l: &Value, r: &Value) -> bool {
    match (l, r) {
        (Value::Num(a), Value::Num(b)) => (a - b).abs() < f64::EPSILON,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        // 文本与数值互比：先尝试把文本数值化，失败再按字符串比
        (Value::Text(a), Value::Num(b)) | (Value::Num(b), Value::Text(a)) => {
            match a.parse::<f64>() {
                Ok(n) => (n - b).abs() < f64::EPSILON,
                Err(_) => false,
            }
        }
        (a, b) => a.as_text() == b.as_text(),
    }
}

/// 扁平字节码的执行环境（扁平原子不含 `Call`，因此这里只需 `reify`）。
struct FlatEnv;

impl Env for FlatEnv {
    fn call(&mut self, _func: &str, _args: &[Operand]) -> Operand {
        Operand::ZERO_INIT
    }
    fn reify(&self, text_id: u32) -> f64 {
        text_id as f64
    }
}

impl AtomHost for Eval<'_> {
    fn eval_atom(&mut self, atom: &Atom) -> bool {
        match &atom.kind {
            AtomKind::Flat(prog) => self.eval_flat(prog),
            AtomKind::Scalar(e) => {
                let e = e.clone();
                self.truthy(&e)
            }
            AtomKind::Event(l) => {
                let l = l.clone();
                let ev = match self.event {
                    Some(ev) => ev,
                    None => return false,
                };
                self.push_item(&l.params, Item::Ev(ev));
                let ok = self.truthy(&l.body);
                self.pop_items(l.params.len());
                ok
            }
            AtomKind::Stream { stream, quant, lambda } => {
                let (s, q, l) = (stream.clone(), *quant, lambda.clone());
                self.eval_stream_quant(&s, q, l.as_ref())
            }
        }
    }

    fn window_secs(&mut self, e: &Expr) -> i64 {
        let e = e.clone();
        self.eval(&e).as_num() as i64
    }

    /// FR6：`crosses_above(metric, threshold)` 的当前侧值。
    fn metric_value(&mut self, metric: &str) -> Option<f64> {
        Eval::metric_value(self, metric)
    }

    /// FR6：阈值表达式求值（可引用 `var` 声明的常量 / `range` 上下界）。
    fn scalar(&mut self, e: &Expr) -> f64 {
        let e = e.clone();
        self.eval(&e).as_num()
    }
}

impl Eval<'_> {
    /// 执行扁平字节码：把配对槽 O(1) 换入 VM，跑完再换回（零拷贝）。
    fn eval_flat(&mut self, prog: &FlatProgram) -> bool {
        let mut nums = std::mem::take(&mut self.slots_num);
        let mut texts = std::mem::take(&mut self.slots_text);
        self.vm.swap_fields(&mut nums, &mut texts);
        let mut env = FlatEnv;
        let out = self.vm.run(prog, &mut env);
        self.vm.swap_fields(&mut nums, &mut texts);
        self.slots_num = nums;
        self.slots_text = texts;
        out.as_bool()
    }
}

/// 便于外部构造 metric（测试 / 热加载）。
pub fn scalar_metric(name: &str, params: &[(&str, DataType)], expr: Expr) -> MetricDecl {
    MetricDecl {
        name: name.to_string(),
        params: params
            .iter()
            .map(|(n, t)| Param { name: n.to_string(), ty: *t })
            .collect(),
        ret: DataType::Float,
        body: MetricBody::Scalar { expr, guard: None },
        meta: NodeMeta::default(),
        span: Span::default(),
    }
}
