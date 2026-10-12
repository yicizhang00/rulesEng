//! rules-dispatcher — 告警分发抽象。
//!
//! runtime 不直接 println，而是把命中的违规事件交给 AlertDispatcher。
//! v1 提供一个内存实现（Vec<Alert>）便于测试；生产可替换为 Kafka / 告警平台实现。

use rules_ast::Severity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub contract: String,
    pub entity_id: String,
    pub severity: Severity,
    pub message: String,
    pub timestamp: u64,
    /// 命中轨迹：触发时的关键上下文（days_overdue、state 等）。
    pub trace: Vec<(String, String)>,
}

pub trait AlertDispatcher: Send + Sync {
    fn dispatch(&self, alert: Alert);
}

/// 内存实现：收集所有告警，供测试与 CLI 输出。
#[derive(Debug, Default)]
pub struct VecDispatcher {
    pub alerts: std::sync::Mutex<Vec<Alert>>,
}

impl VecDispatcher {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn snapshot(&self) -> Vec<Alert> {
        self.alerts.lock().unwrap().clone()
    }
}

impl AlertDispatcher for VecDispatcher {
    fn dispatch(&self, alert: Alert) {
        self.alerts.lock().unwrap().push(alert);
    }
}

/// 打印到 stdout 的实现（CLI 默认）。
#[derive(Debug, Default)]
pub struct StdoutDispatcher;

impl AlertDispatcher for StdoutDispatcher {
    fn dispatch(&self, alert: Alert) {
        println!(
            "[ALERT ts={}] [{}] entity={} contract={}: {}",
            alert.timestamp,
            format!("{:?}", alert.severity).to_uppercase(),
            alert.entity_id,
            alert.contract,
            alert.message
        );
    }
}
