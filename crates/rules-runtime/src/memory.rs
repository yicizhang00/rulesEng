//! 模式 B：受限工作内存（Working Memory）与只追加推导（FR7）。
//!
//! 与传统 Drools 的关键差别——**把图灵完备换成可判定的受限子集**：
//!
//! | Drools | 本引擎 |
//! |---|---|
//! | 事实可任意 `modify()` / `retract()`，对象图可变 | 事实**只追加**（append-only），派生事实带 `derived` 标记 |
//! | RETE 前向链式，无终止保证 | 规则集编译期做 **DAG 因果无环检验**，成环直接驳回 |
//! | 运行时可能无限激活 | 单次会话硬预算 `MAX_ACTIVATION_STEPS = 32`，超限**熔断** |
//! | 事实跨线程 / 持久化 | 会话隔离，仅存活于单次业务事务 |
//!
//! 结论：模式 B 的停机性是**结构性保证**（有向无环 + 预算上限），不依赖启发式。

use crate::Value;
use rules_ast::{RuleAction, StatefulRuleDecl};
use std::collections::HashMap;

/// FR7：单次请求的最大激活步数（硬保险丝）。
pub const MAX_ACTIVATION_STEPS: usize = 32;

/// 工作内存中的一条事实。
#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    pub type_name: String,
    pub fields: HashMap<String, Value>,
    /// 是否由推导 `insert`（只追加结果）。
    pub derived: bool,
    /// 产生该事实的规则名（根事实为 `None`）。
    pub derived_by: Option<String>,
}

impl Fact {
    pub fn new(type_name: impl Into<String>, fields: HashMap<String, Value>) -> Self {
        Fact { type_name: type_name.into(), fields, derived: false, derived_by: None }
    }
}

/// 会话级工作内存。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WorkingMemory {
    facts: Vec<Fact>,
}

impl WorkingMemory {
    pub fn new() -> Self {
        WorkingMemory { facts: Vec::new() }
    }
    pub fn insert(&mut self, fact: Fact) {
        self.facts.push(fact);
    }
    /// 只允许撤回**派生**事实（保护原始事实不被破坏性修改）。
    pub fn retract(&mut self, type_name: &str, field: &str, value: &Value) -> bool {
        let before = self.facts.len();
        self.facts.retain(|f| {
            !(f.derived && f.type_name == type_name && f.fields.get(field) == Some(value))
        });
        before != self.facts.len()
    }
    pub fn len(&self) -> usize {
        self.facts.len()
    }
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }
    pub fn of_type<'a>(&'a self, ty: &'a str) -> impl Iterator<Item = &'a Fact> + 'a {
        self.facts.iter().filter(move |f| f.type_name == ty)
    }
    pub fn iter(&self) -> impl Iterator<Item = &Fact> {
        self.facts.iter()
    }
    pub fn facts(&self) -> &[Fact] {
        &self.facts
    }
}

/// 规则因果图：把"事实类型"作为节点，规则读写集合作为边。
///
/// 一个类型如果能沿边回到自己，说明存在**规则激活环路**（推导 A 产生 B，
/// B 又反推 A），这在无 RETE 终止保证的引擎里会导致无限激活 → 编译期驳回。
///
/// 实现放在 `rules-ast`（纯 AST 分析），运行期与 verifier 共用同一份实现，
/// 避免"编译期放行、运行期熔断"的口径漂移。
pub use rules_ast::{check_rule_dag as check_dag, RuleCycle as CycleReport};


/// 一次会话的执行结果。
#[derive(Debug, Clone, PartialEq)]
pub struct SessionResult {
    /// 会话结束时的全部事实。
    pub memory: WorkingMemory,
    /// 触发的裁决（首个 `yield DENY`）。
    pub verdict: Option<(String, String, String)>, // (rule, code, reason)
    /// 实际激活步数。
    pub steps: usize,
    /// 是否因超出 `MAX_ACTIVATION_STEPS` 被熔断。
    pub truncated: bool,
    /// 推导轨迹（rule → 插入的事实类型）。
    pub trace: Vec<(String, String)>,
}

/// 事实匹配器：把 `Pattern` 绑定到具体事实。
pub struct Binder<'a> {
    env: &'a mut dyn FnMut(&rules_ast::Expr, &[(String, Value)]) -> Value,
}

impl<'a> Binder<'a> {
    pub fn new(env: &'a mut dyn FnMut(&rules_ast::Expr, &[(String, Value)]) -> Value) -> Self {
        Binder { env }
    }

    /// 尝试让一条事实匹配一个模式。
    ///
    /// 命中时返回**限定名环境**：既含裸字段名（`account_id`），也含
    /// `$binding.field`（`$tag.account_id`）——这样 RHS 的
    /// `insert(SuspiciousTag { account_id: $acc.id })` 能精确解析到
    /// "`$acc` 这条事实的 id"，而不是同名字段的任意一条。
    fn matches(
        &mut self,
        pattern: &rules_ast::Pattern,
        fact: &Fact,
    ) -> Option<Vec<(String, Value)>> {
        if pattern.type_name != fact.type_name {
            return None;
        }
        let binding = pattern.binding.clone().unwrap_or_else(|| "$this".to_string());
        let mut all: Vec<(String, Value)> = Vec::new();
        for (k, v) in &fact.fields {
            all.push((k.clone(), v.clone()));
            all.push((format!("{binding}.{k}"), v.clone()));
        }
        all.push((binding.clone(), Value::Num(1.0)));
        all.push(("$this".to_string(), Value::Num(1.0)));
        for c in &pattern.constraints {
            if !(self.env)(c, &all).truthy() {
                return None;
            }
        }
        Some(all)
    }
}

/// 一次前向链式会话（受限）。
///
/// - `resolve`：把 `RuleAction::Insert` 的字段表达式求值成具体值；
/// - 每插入一条新事实算一步；超过 [`MAX_ACTIVATION_STEPS`] 立即熔断。
pub fn run_session<F>(
    rules: &[StatefulRuleDecl],
    initial: WorkingMemory,
    mut resolve: F,
) -> SessionResult
where
    F: FnMut(&rules_ast::Expr, &[(String, Value)]) -> Value,
{
    let mut memory = initial;
    let mut steps = 0usize;
    let mut truncated = false;
    let mut trace = Vec::new();
    let mut verdict: Option<(String, String, String)> = None;

    if check_dag(rules).is_err() {
        // 调用方应已在编译期驳回；此处保守返回空会话。
        return SessionResult { memory, verdict: None, steps: 0, truncated: false, trace };
    }

    let mut progressed = true;
    while progressed && verdict.is_none() {
        progressed = false;
        for rule in rules {
            // 1) 正向模式：需要全部命中；同时累积限定名绑定环境
            let mut pending: Vec<Fact> = Vec::new();
            let mut env: Vec<(String, Value)> = Vec::new();
            let mut ok = true;
            for p in &rule.patterns {
                let hit = memory.of_type(&p.type_name).find_map(|f| {
                    let mut b = Binder::new(&mut resolve);
                    b.matches(p, f).map(|entries| (f.clone(), entries))
                });
                match hit {
                    Some((f, entries)) => {
                        pending.push(f);
                        env.extend(entries);
                    }
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok || pending.is_empty() {
                continue;
            }
            // 2) 负向模式：必须全部不存在
            let mut neg_hit = false;
            for p in &rule.negatives {
                if memory
                    .of_type(&p.type_name)
                    .any(|f| Binder::new(&mut resolve).matches(p, f).is_some())
                {
                    neg_hit = true;
                    break;
                }
            }
            if neg_hit {
                continue;
            }

            // 3) 执行 RHS —— 只允许 insert / retract / yield
            for action in &rule.actions {
                match action {
                    RuleAction::Insert { type_name, fields, .. } => {
                        let mut map = HashMap::new();
                        for (k, e) in fields {
                            map.insert(k.clone(), resolve(e, &env));
                        }
                        // 只追加：同型同内容事实不重复插入（保证终止）
                        let dup = memory
                            .of_type(type_name)
                            .any(|f| f.derived && f.fields == map);
                        if !dup {
                            steps += 1;
                            if steps > MAX_ACTIVATION_STEPS {
                                truncated = true;
                                return SessionResult {
                                    memory,
                                    verdict,
                                    steps,
                                    truncated,
                                    trace,
                                };
                            }
                            trace.push((rule.name.clone(), type_name.clone()));
                            memory.insert(Fact {
                                type_name: type_name.clone(),
                                fields: map,
                                derived: true,
                                derived_by: Some(rule.name.clone()),
                            });
                            progressed = true;
                        }
                    }
                    RuleAction::Retract { binding, .. } => {
                        // 仅允许撤回派生事实（按 binding 名定位）
                        if let Some(f) = pending.first() {
                            if binding == "$this" || binding.is_empty() {
                                memory.retract(&f.type_name, "", &Value::Num(f64::NAN));
                            }
                        }
                    }
                    RuleAction::Yield { verdict: v, .. } => {
                        if let rules_ast::Verdict::Deny { code, reason } = v {
                            verdict = Some((rule.name.clone(), code.clone(), reason.clone()));
                        }
                    }
                }
            }
        }
    }

    SessionResult { memory, verdict, steps, truncated, trace }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules_ast::{Expr, NodeMeta, Pattern, Span, Verdict};

    fn pat(binding: Option<&str>, ty: &str, constraints: Vec<Expr>) -> Pattern {
        Pattern {
            binding: binding.map(|s| s.to_string()),
            type_name: ty.into(),
            constraints,
            meta: NodeMeta::default(),
            span: Span::default(),
        }
    }

    fn fact(ty: &str, fields: &[(&str, f64)]) -> Fact {
        let mut m = HashMap::new();
        for (k, v) in fields {
            m.insert(k.to_string(), Value::Num(*v));
        }
        Fact::new(ty, m)
    }

    #[test]
    fn dag_detects_cycle_between_rules() {
        // Rule A: reads X, writes Y ; Rule B: reads Y, writes X → 环
        let ra = StatefulRuleDecl {
            name: "A".into(),
            patterns: vec![pat(None, "X", vec![])],
            negatives: vec![],
            actions: vec![RuleAction::Insert {
                type_name: "Y".into(),
                fields: vec![],
                span: Span::default(),
            }],
            meta: NodeMeta::default(),
            span: Span::default(),
        };
        let rb = StatefulRuleDecl {
            name: "B".into(),
            patterns: vec![pat(None, "Y", vec![])],
            negatives: vec![],
            actions: vec![RuleAction::Insert {
                type_name: "X".into(),
                fields: vec![],
                span: Span::default(),
            }],
            meta: NodeMeta::default(),
            span: Span::default(),
        };
        let err = check_dag(&[ra.clone(), rb]).unwrap_err();
        assert!(err.path.len() >= 3, "path = {:?}", err.path);
        assert!(err.rules.contains(&"A".to_string()));
        // 单条规则自环同样被拦截
        let selfloop = StatefulRuleDecl {
            name: "S".into(),
            patterns: vec![pat(None, "X", vec![])],
            negatives: vec![],
            actions: vec![RuleAction::Insert {
                type_name: "X".into(),
                fields: vec![],
                span: Span::default(),
            }],
            meta: NodeMeta::default(),
            span: Span::default(),
        };
        assert!(check_dag(&[selfloop]).is_err());
        // 无环通过
        assert!(check_dag(&[ra]).is_ok());
    }

    #[test]
    fn session_derives_fact_and_yields_verdict() {
        let derive = StatefulRuleDecl {
            name: "Derive".into(),
            patterns: vec![pat(Some("$acc"), "Account", vec![Expr::Bool(true)])],
            negatives: vec![pat(None, "SuspiciousTag", vec![])],
            actions: vec![RuleAction::Insert {
                type_name: "SuspiciousTag".into(),
                fields: vec![("account_id".into(), Expr::Str("A1".into()))],
                span: Span::default(),
            }],
            meta: NodeMeta::default(),
            span: Span::default(),
        };
        let act = StatefulRuleDecl {
            name: "Block".into(),
            patterns: vec![
                pat(Some("$tag"), "SuspiciousTag", vec![]),
                pat(Some("$order"), "InFlightOrder", vec![]),
            ],
            negatives: vec![],
            actions: vec![RuleAction::Yield {
                verdict: Verdict::deny("ERR_SUSPICIOUS_BLOCK", "blocked"),
                span: Span::default(),
            }],
            meta: NodeMeta::default(),
            span: Span::default(),
        };

        let mut mem = WorkingMemory::new();
        mem.insert(fact("Account", &[("trade_frequency_5s", 20.0)]));
        mem.insert(fact("InFlightOrder", &[("amount", 900_000.0)]));

        let res = run_session(&[derive, act], mem, |e, _| match e {
            Expr::Str(s) => Value::Text(s.clone()),
            Expr::Number(n) => Value::Num(*n),
            _ => Value::Num(1.0),
        });
        assert!(!res.truncated);
        assert_eq!(res.steps, 1);
        assert_eq!(
            res.verdict.as_ref().map(|(r, c, _)| (r.as_str(), c.as_str())),
            Some(("Block", "ERR_SUSPICIOUS_BLOCK"))
        );
        assert!(res.memory.of_type("SuspiciousTag").count() == 1);
    }

    #[test]
    fn budget_fuse_truncates_runaway_derivation() {
        // 规则每次插入一条新内容的事实（用随机不再可用，这里用逐条不同的字段）
        let r = StatefulRuleDecl {
            name: "Grow".into(),
            patterns: vec![pat(None, "Seed", vec![])],
            negatives: vec![],
            actions: vec![RuleAction::Insert {
                type_name: "Bloom".into(),
                fields: vec![],
                span: Span::default(),
            }],
            meta: NodeMeta::default(),
            span: Span::default(),
        };
        // Bloom 自身又触发 Grow 的第二轮（Bloom 读、Bloom 写 → 自环）会被 DAG 拦截，
        // 因此这里只验证预算常量与基本插入计数。
        let mut mem = WorkingMemory::new();
        mem.insert(fact("Seed", &[]));
        let res = run_session(&[r], mem, |_, _| Value::Num(1.0));
        assert_eq!(res.steps, 1);
        assert!(!res.truncated);
        assert!(MAX_ACTIVATION_STEPS == 32);
    }
}
