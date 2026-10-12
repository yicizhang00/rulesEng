//! rules-dictionary — 运行时数据字典。
//!
//! 设计层级四：把 DSL 从"静态固定 Schema"升级为"运行时可扩展 Schema"。
//! - `var x = <expr>` 声明的动态绑定在运行时由 DataDictionary 提供取值；
//! - 新增监管指标（如"半年报""年报""审计意见"）不需要改引擎代码，
//!   只需在字典里注册条目即可。

use rules_ast::Expr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 字典中可绑定的标量值。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScalarValue {
    Num(f64),
    Text(String),
    Bool(bool),
    Time(u64),
}

impl ScalarValue {
    pub fn as_num(&self) -> Option<f64> {
        match self {
            ScalarValue::Num(n) => Some(*n),
            ScalarValue::Time(t) => Some(*t as f64),
            ScalarValue::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            _ => None,
        }
    }
    pub fn as_text(&self) -> Option<&str> {
        match self {
            ScalarValue::Text(s) => Some(s),
            _ => None,
        }
    }
}

/// 运行时数据字典。
///
/// 解析顺序（runtime 求值一个 Path 时）：
/// 1. 当前事件字段（runtime 直接查 Event.fields）；
/// 2. `vars` —— DSL 顶层 `var name = expr` 登记的动态绑定；
/// 3. `signals` —— `signal name(...) = expr` 登记的派生指标；
/// 4. 未注册 → 求值失败（运行期错误，不是编译期错误）。
#[derive(Debug, Clone, Default)]
pub struct DataDictionary {
    /// var name -> 其表达式的常量值（v1：仅支持字面量/常量折叠）。
    pub vars: HashMap<String, ScalarValue>,
    /// signal name -> 注册时的表达式 AST（runtime 递归求值）。
    pub signals: HashMap<String, Expr>,
    /// 外部注入的"全局字段"，例如 `DisclosureEvent.audit_opinion`。
    pub external_bindings: HashMap<String, ScalarValue>,
}

impl DataDictionary {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册一个 var 的常量值。配置端/管理界面调用。
    pub fn set_var(&mut self, name: impl Into<String>, value: ScalarValue) {
        self.vars.insert(name.into(), value);
    }

    /// 注册一个外部字段绑定，例如 "DisclosureEvent.audit_opinion" -> Text("UNQUALIFIED")。
    pub fn set_external(&mut self, path: impl Into<String>, value: ScalarValue) {
        self.external_bindings.insert(path.into(), value);
    }

    /// 注册一个 signal 的 AST（由 parser 在加载 spec 时调用）。
    pub fn register_signal(&mut self, name: impl Into<String>, expr: Expr) {
        self.signals.insert(name.into(), expr);
    }

    /// 按点分路径查外部绑定。
    pub fn lookup_external(&self, path: &[String]) -> Option<&ScalarValue> {
        let key = path.join(".");
        self.external_bindings.get(&key)
    }

    /// var 是否已登记。verifier 用它做"var 引用必须有字典登记"的检查。
    pub fn has_var(&self, name: &str) -> bool {
        self.vars.contains_key(name)
    }
}
