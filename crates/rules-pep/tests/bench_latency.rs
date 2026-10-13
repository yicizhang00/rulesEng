//! # PEP 延迟基准（NFR：网关内联 P99 < 1μs，平均 < 200ns）
//!
//! 运行：
//!
//! ```text
//! cargo test -p rules-pep --release --test bench_latency -- --nocapture
//! ```
//!
//! ## 测量方法
//!
//! `Instant::now()` 自身的开销约 20~40ns，与我们要测的量级同阶，因此
//! **不能**逐次计时。这里采用两级采样：
//!
//! 1. 每个"批"跑 `BATCH` 次操作，计时得到批耗时；
//! 2. 重复 `BATCHES` 批，得到分布；每批的**均摊单次延迟** = 批耗时 / BATCH。
//!
//! 同时测一条**空循环基线**（同样循环次数、无被测逻辑），把循环开销与
//! `Instant` 开销从中扣除，得到净执行时间。这比把结论建立在未扣除的数字上
//! 诚实得多。
//!
//! ## 断言策略
//!
//! `--release` 下按 NFR 断言（P99 < 1μs、平均 < 200ns）；
//! debug 构建（未优化、且带 `debug_assertions`）只断言一个宽松上界，
//! 避免把构建配置问题误报成实现问题。

use rules_pep::ffi::{
    rules_pep_admit_field, rules_pep_close, rules_pep_fast_gate, rules_pep_open, PepHandle,
};
use rules_pep::{DecisionPoint, FrozenLatch, Intent, PepCore};
use rules_runtime::Adjudication;
use std::ffi::CString;
use std::sync::Arc;
use std::time::Instant;

/// 被测契约：一条 guard（准入快筛）+ 一条 stream 不变量（洪水防护）。
const SPEC: &str = r#"
    contract SeatFloodProtection on Entity[Seat] stream {
        key: seat_id
        state var frozen_until: Timestamp = 0

        guard IsNotFrozen on Event[OrderIntent, CancelIntent] {
            when: now() < frozen_until
            verdict: DENY(code: "ERR_SEAT_FROZEN", reason: "seat frozen by lease")
        }

        stream SeatActions := Stream[OrderIntent, CancelIntent]
            .filter(e => e.seat_id == seat_id)
            .window(sliding(5s))

        metric window_order_count = sum(SeatActions[OrderIntent].count)

        invariant MaxFrequencyLimit on Event[OrderIntent, CancelIntent] {
            when: window_order_count > 20
            verdict: DENY(code: "ERR_SEAT_FLOOD", reason: "flood")
                , LeaseUpdate(frozen_until = now() + 60s)
        }
    }
"#;

const BATCH: usize = 500;
const BATCHES: usize = 400;

struct Dist {
    label: &'static str,
    p50: f64,
    p90: f64,
    p99: f64,
    max: f64,
    mean: f64,
}

impl Dist {
    fn report(&self) {
        println!(
            "{:<26} mean={:>8.1}ns  p50={:>8.1}ns  p90={:>8.1}ns  p99={:>8.1}ns  max={:>9.1}ns",
            self.label, self.mean, self.p50, self.p90, self.p99, self.max
        );
    }
    /// 净执行时间（扣除空循环基线后，按批均摊）。
    fn net(&self, baseline: &Dist) -> Dist {
        Dist {
            label: self.label,
            p50: (self.p50 - baseline.p50).max(0.0),
            p90: (self.p90 - baseline.p90).max(0.0),
            p99: (self.p99 - baseline.p99).max(0.0),
            max: (self.max - baseline.max).max(0.0),
            mean: (self.mean - baseline.mean).max(0.0),
        }
    }
}

fn run<F: FnMut()>(label: &'static str, mut op: F) -> Dist {
    // 预热：让分支预测 / 缓存行进入稳态
    for _ in 0..BATCH * 4 {
        op();
    }
    let mut per_op = Vec::with_capacity(BATCHES);
    for _ in 0..BATCHES {
        let t0 = Instant::now();
        for _ in 0..BATCH {
            op();
        }
        let elapsed = t0.elapsed().as_nanos() as f64;
        per_op.push(elapsed / BATCH as f64);
    }
    per_op.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pick = |q: f64| per_op[((per_op.len() - 1) as f64 * q).round() as usize];
    Dist {
        label,
        p50: pick(0.50),
        p90: pick(0.90),
        p99: pick(0.99),
        max: *per_op.last().unwrap(),
        mean: per_op.iter().sum::<f64>() / per_op.len() as f64,
    }
}

/// 恒放行的 PDP——用来隔离"PEP 自身开销"，不含任何规则求值。
struct NoopPdp {
    now: u64,
}

impl DecisionPoint for NoopPdp {
    fn now(&self) -> u64 {
        self.now
    }
    fn admit(&mut self, intent: &Intent) -> Adjudication {
        Adjudication::allow(intent.event_type.clone(), intent.timestamp)
    }
    fn frozen_until(&self, _e: &str, _i: &str) -> u64 {
        0
    }
}

#[test]
fn pep_latency_meets_nfr_budget() {
    let release = !cfg!(debug_assertions);
    println!();
    println!("=== rules-pep 延迟基准（BATCH={BATCH}, BATCHES={BATCHES}, release={release}）===");

    // ---- 0. 空循环基线 ----
    let mut sink = 0u64;
    let baseline = run("空循环基线", || {
        sink = sink.wrapping_add(1);
    });
    baseline.report();

    // 防止优化器把上面的循环消掉
    assert!(sink > 0);

    // ---- 1. 极速域（PepCore::fast_gate_at）----
    let latch = Arc::new(FrozenLatch::new(4096));
    let core = PepCore::with_latch(NoopPdp { now: 1000 }, latch.clone());
    // 先冻结，确保走"命中"分支（这才是热路径的真实形态）
    latch.put("Seat#PBU001", 10_000);
    let mut allowed = 0u64;
    let d_fast = run("fast_gate(命中)", || {
        if core.fast_gate_at("Seat#PBU001", 1000).is_deny() {
            allowed += 1;
        }
    });
    d_fast.report();
    assert_eq!(allowed, (BATCH * (BATCHES + 4)) as u64);
    let d_fast_net = d_fast.net(&baseline);
    println!("  └ 扣除基线后：mean={:.1}ns  p99={:.1}ns", d_fast_net.mean, d_fast_net.p99);

    // ---- 2. 极速域（Latch 裸读，无 PepCore 包装）----
    let d_latch = run("FrozenLatch::is_frozen", || {
        if latch.is_frozen("Seat#PBU001", 1000) {
            allowed += 1;
        }
    });
    d_latch.report();
    let d_latch_net = d_latch.net(&baseline);
    println!("  └ 扣除基线后：mean={:.1}ns  p99={:.1}ns", d_latch_net.mean, d_latch_net.p99);

    // ---- 3. 旁路域（PDP 全量裁决，恒放行）----
    let mut rt_core = PepCore::with_latch(NoopPdp { now: 1000 }, Arc::new(FrozenLatch::new(4096)));
    let intent = Intent::new("OrderIntent", "Seat", "PBU001", 1000);
    let d_admit = run("PepCore::admit(恒放行)", || {
        if rt_core.admit(&intent).is_allowed() {
            allowed += 1;
        }
    });
    d_admit.report();
    let d_admit_net = d_admit.net(&baseline);
    println!("  └ 扣除基线后：mean={:.1}ns  p99={:.1}ns", d_admit_net.mean, d_admit_net.p99);

    // ---- 4. 真实引擎的 C-ABI 超热路径 ----
    let spec = CString::new(SPEC).unwrap();
    let h: *mut PepHandle = unsafe { rules_pep_open(spec.as_ptr(), SPEC.len(), 4096) };
    assert!(!h.is_null(), "契约解析失败");
    let key = CString::new("Seat#PBU001").unwrap();
    unsafe {
        // 打满 21 笔让引擎广播租约，之后走的都是极速域
        let et = CString::new("OrderIntent").unwrap();
        let en = CString::new("Seat").unwrap();
        let id = CString::new("PBU001").unwrap();
        let mut last = 0;
        for _ in 0..21 {
            last = rules_pep_admit_field(
                h,
                et.as_ptr(), 11,
                en.as_ptr(), 4,
                id.as_ptr(), 6,
                std::ptr::null(), 0,
                std::ptr::null(), 0,
                1000,
            );
        }
        assert_eq!(last, 1, "第 21 笔必须被阻断");
    }

    let d_cabi = run("C-ABI fast_gate", || {
        if unsafe { rules_pep_fast_gate(h, key.as_ptr(), 11, 1005) } == 1 {
            allowed += 1;
        }
    });
    d_cabi.report();
    let d_cabi_net = d_cabi.net(&baseline);
    println!("  └ 扣除基线后：mean={:.1}ns  p99={:.1}ns", d_cabi_net.mean, d_cabi_net.p99);

    unsafe { rules_pep_close(h) };

    // ---- 5. 判定 ----
    println!();
    let candidates: [(&str, &Dist); 3] = [
        ("fast_gate(命中)", &d_fast_net),
        ("FrozenLatch::is_frozen", &d_latch_net),
        ("C-ABI fast_gate", &d_cabi_net),
    ];
    for (name, d) in candidates {
        if release {
            assert!(
                d.p99 < 1000.0,
                "NFR 违约：{name} P99 = {:.1}ns ≥ 1000ns",
                d.p99
            );
        } else {
            // debug 构建无内联、无优化，只做一个"没有数量级错误"的宽松检查
            assert!(
                d.p99 < 50_000.0,
                "debug 下 {name} P99 = {:.1}ns，疑似实现问题（非构建配置问题）",
                d.p99
            );
        }
    }

    if release {
        // NFR：平均 < 200ns（只对最纯粹的 Latch 读断言 avg，避免把基线噪声算进来）
        assert!(
            d_latch_net.mean < 200.0,
            "NFR 违约：FrozenLatch::is_frozen 平均 {:.1}ns ≥ 200ns",
            d_latch_net.mean
        );
        assert!(
            d_fast_net.mean < 200.0,
            "NFR 违约：fast_gate 平均 {:.1}ns ≥ 200ns",
            d_fast_net.mean
        );
    }
    println!("OK：延迟预算满足。");
}
