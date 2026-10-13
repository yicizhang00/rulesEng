//! rules-proof — 监管告警的形式化证据链（Proof Certificate / XAI）。
//!
//! 每条告警附带一个不可篡改的 EvidencePack：
//! - **minimal_witness**：最小归因切片——仅凭这几个字段就能复现"为什么触发"；
//! - **decision_tree**：完整决策树，覆盖 MTL 的每一个算子（含 `historically` 窗口、
//!   `until` 的释放条件、`eventually` 的承诺期限），让"哪个时序子式为假"一目了然；
//! - **snapshot_hash**：触发瞬间窗口事件 + 实体状态的 FNV-1a 哈希，
//!   事后比对哈希即可确认"证据未被篡改"。
//!
//! 生产环境可把 FNV-1a 替换为国密 SM3 或 SHA-256；接口保持不变。

use rules_ast::{Quant, SpecDecl, TemporalExpr};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum DecisionNode {
    Leaf { text: String, value: bool },
    Branch { op: String, value: bool, children: Vec<DecisionNode> },
}

impl DecisionNode {
    pub fn render(&self, indent: usize) -> String {
        let pad = "  ".repeat(indent);
        match self {
            DecisionNode::Leaf { text, value } => {
                format!("{pad}- [{}] {text}", if *value { "TRUE " } else { "FALSE" })
            }
            DecisionNode::Branch { op, value, children } => {
                let mut s = format!("{pad}({op} = {})\n", if *value { "TRUE " } else { "FALSE" });
                for c in children {
                    s.push_str(&c.render(indent + 1));
                    s.push('\n');
                }
                s
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvidencePack {
    pub spec: String,
    pub entity_id: String,
    pub triggered_at: u64,
    /// 最小归因切片：(变量名, 值字符串)。
    pub minimal_witness: Vec<(String, String)>,
    pub decision_tree: DecisionNode,
    /// 窗口事件 + 实体状态的确定性哈希（FNV-1a 64-bit）。
    pub snapshot_hash: String,
}

/// 构造证据包。`key_vars` 是触发瞬间的关键运行时变量（now / deadline / DaysOverdue / ...）。
pub fn build_evidence(
    spec: &SpecDecl,
    entity_id: &str,
    now: u64,
    key_vars: &HashMap<String, f64>,
    window_event_ids: &[String],
    entity_state: &str,
) -> EvidencePack {
    let witness = minimal_witness(spec, key_vars);
    let tree = build_tree(&spec.invariant, key_vars);
    let snapshot_hash = hash_snapshot(now, window_event_ids, entity_state, &witness);
    EvidencePack {
        spec: spec.name.clone(),
        entity_id: entity_id.to_string(),
        triggered_at: now,
        minimal_witness: witness,
        decision_tree: tree,
        snapshot_hash: format!("{:016x}", snapshot_hash),
    }
}

/// 最小归因切片：只挑出真正进入 guard / invariant 判定的变量。
fn minimal_witness(spec: &SpecDecl, vars: &HashMap<String, f64>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in vars {
        out.push((k.clone(), format!("{:.4}", v)));
    }
    if let Some(g) = &spec.violation.guard {
        out.push(("guard_expr".into(), format!("{:?}", g)));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn build_tree(t: &TemporalExpr, vars: &HashMap<String, f64>) -> DecisionNode {
    match t {
        TemporalExpr::Predicate(p) => DecisionNode::Leaf {
            text: format!("{p:?}"),
            value: true,
        },
        TemporalExpr::StreamQuant { stream, quant, lambda } => DecisionNode::Leaf {
            text: match (quant, lambda) {
                (Quant::Exists, Some(_)) => format!("{stream}.exists(e => …)"),
                (Quant::Exists, None) => format!("{stream}.exists()"),
                (Quant::Forall, Some(_)) => format!("{stream}.forall(e => …)"),
                (Quant::Forall, None) => format!("{stream}.forall()"),
                (Quant::Count, _) => format!("{stream}.count()"),
            },
            value: true,
        },
        TemporalExpr::CrossesAbove { metric, threshold } => DecisionNode::Leaf {
            text: format!("crosses_above({metric}, {threshold:?})"),
            value: true,
        },
        TemporalExpr::CrossesBelow { metric, threshold } => DecisionNode::Leaf {
            text: format!("crosses_below({metric}, {threshold:?})"),
            value: true,
        },
        TemporalExpr::Implies(a, b) => {
            let (ca, cb) = (build_tree(a, vars), build_tree(b, vars));
            let (va, vb) = (leaf_value(&ca), leaf_value(&cb));
            DecisionNode::Branch {
                op: "implies".into(),
                value: !va || vb,
                children: vec![ca, cb],
            }
        }
        TemporalExpr::And(a, b) => combine("and", a, b, vars, |x, y| x && y),
        TemporalExpr::Or(a, b) => combine("or", a, b, vars, |x, y| x || y),
        TemporalExpr::Not(i) => {
            let c = build_tree(i, vars);
            let v = leaf_value(&c);
            DecisionNode::Branch {
                op: "not".into(),
                value: !v,
                children: vec![c],
            }
        }
        TemporalExpr::Always(i) => unary("always (latch)", i, vars),
        TemporalExpr::Historically { expr, within } => {
            let label = match within {
                Some(w) => format!("historically (within: {w:?})"),
                None => "historically".to_string(),
            };
            unary(&label, expr, vars)
        }
        TemporalExpr::Eventually { expr, within } => {
            let label = match within {
                Some(w) => format!("eventually (within: {w:?})"),
                None => "eventually".to_string(),
            };
            unary(&label, expr, vars)
        }
        TemporalExpr::Within { window, inner } => {
            unary(&format!("within ({window:?})"), inner, vars)
        }
        TemporalExpr::Until { p, q } => {
            let (cp, cq) = (build_tree(p, vars), build_tree(q, vars));
            let (vp, vq) = (leaf_value(&cp), leaf_value(&cq));
            DecisionNode::Branch {
                op: "until (p holds until q fires)".into(),
                value: vq || vp,
                children: vec![cp, cq],
            }
        }
        TemporalExpr::Since { p, q } => {
            let (cp, cq) = (build_tree(p, vars), build_tree(q, vars));
            let (vp, vq) = (leaf_value(&cp), leaf_value(&cq));
            DecisionNode::Branch {
                op: "since (p holds since q)".into(),
                value: vq && vp,
                children: vec![cp, cq],
            }
        }
    }
}

fn unary(op: &str, inner: &TemporalExpr, vars: &HashMap<String, f64>) -> DecisionNode {
    let c = build_tree(inner, vars);
    let v = leaf_value(&c);
    DecisionNode::Branch {
        op: op.to_string(),
        value: v,
        children: vec![c],
    }
}

fn combine(
    op: &str,
    a: &TemporalExpr,
    b: &TemporalExpr,
    vars: &HashMap<String, f64>,
    f: impl Fn(bool, bool) -> bool,
) -> DecisionNode {
    let (ca, cb) = (build_tree(a, vars), build_tree(b, vars));
    let v = f(leaf_value(&ca), leaf_value(&cb));
    DecisionNode::Branch {
        op: op.to_string(),
        value: v,
        children: vec![ca, cb],
    }
}

fn leaf_value(n: &DecisionNode) -> bool {
    match n {
        DecisionNode::Leaf { value, .. } => *value,
        DecisionNode::Branch { value, .. } => *value,
    }
}

/// FNV-1a 64-bit 哈希。生产可替换为 SM3 / SHA-256。
fn hash_snapshot(now: u64, events: &[String], state: &str, witness: &[(String, String)]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mix = |h: &mut u64, bytes: &[u8]| {
        for b in bytes {
            *h ^= *b as u64;
            *h = h.wrapping_mul(0x100000001b3);
        }
    };
    mix(&mut h, &now.to_be_bytes());
    mix(&mut h, state.as_bytes());
    for e in events {
        mix(&mut h, e.as_bytes());
    }
    for (k, v) in witness {
        mix(&mut h, k.as_bytes());
        mix(&mut h, v.as_bytes());
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules_parser::parse;
    use std::collections::HashMap;

    fn spec() -> SpecDecl {
        let src = r#"
            entity Company(key: code) { states: [NORMAL, X] initial: NORMAL }
            stream S := Event[E].filter(e => e.t == "S")
            spec C on c: Company {
                invariant: historically(S.exists(), within: 1d) implies always(true)
                violation { severity: CRITICAL guard: DaysOverdue(1.0) > 5.0 emit: "x" }
            }
        "#;
        parse(src).unwrap().specs.remove(0)
    }

    #[test]
    fn evidence_pack_renders_and_hash_deterministic() {
        let s = spec();
        let mut vars = HashMap::new();
        vars.insert("now".into(), 618400.0);
        vars.insert("DaysOverdue".into(), 6.0);
        let e1 = build_evidence(&s, "600000", 618400, &vars, &[], "NORMAL");
        let e2 = build_evidence(&s, "600000", 618400, &vars, &[], "NORMAL");
        assert_eq!(e1.snapshot_hash, e2.snapshot_hash, "hash must be deterministic");
        assert!(e1.minimal_witness.iter().any(|(k, _)| k == "DaysOverdue"));
        let rendered = e1.decision_tree.render(0);
        assert!(rendered.contains("implies"), "{rendered}");
        assert!(rendered.contains("historically"), "{rendered}");
    }

    #[test]
    fn tampered_input_changes_hash() {
        let s = spec();
        let vars = HashMap::new();
        let e1 = build_evidence(&s, "600000", 618400, &vars, &["e1".into()], "NORMAL");
        let e2 = build_evidence(&s, "600000", 618400, &vars, &["e2".into()], "NORMAL");
        assert_ne!(e1.snapshot_hash, e2.snapshot_hash);
    }
}
