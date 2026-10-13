//! FR5 —— 长周期双轨调度器：离散时间轮（HashedWheelTimer）。
//!
//! PRD §4.1「慢状态双轨调度运行机制」把长周期业务拆成两条互不干扰的轨：
//!
//! ```text
//!   因果事件轨（准入轨）                 离散时间轮轨（唤醒轨）
//!   ─────────────────────               ──────────────────────────────
//!   仅当发生写操作时被调用               T0 批文下达瞬间注册 T0 + 365d 单次唤醒
//!   state |= next_state（单调格）        中间 365 天引擎完全休眠（0 CPU / 0 I/O）
//!   只读位图做互斥/包含判断             到期唤醒后**只**读位图判断 state & ISSUING
//! ```
//!
//! ## 为什么必须是"离散时间轮"而不是"最小堆 + 轮询"
//!
//! 朴素做法（`BinaryHeap` + 每秒 `tick()`）在 365 天跨度下要执行
//! $365 \times 86400 \approx 3.15\times10^7$ 次空转比较——CPU 不睡、缓存被反复冲刷。
//! 本实现把「时间推进」与「格扫描」彻底解耦：
//!
//! * **物理格** `buckets[slot]`：`slot = ceil(deadline / tick) & mask`，注册是 $O(1)$ 哈希定位；
//! * **最小截止期索引** `index: BTreeSet<(deadline, id)>`：支撑 $O(1)$ 地算出
//!   "下一次唤醒还有多久"（`sleep_span()`），从而把中间所有空格**一次性跳过**；
//! * `advance_to(target)` 只在真正有定时器到期时才落在格上，跳过的格数记入
//!   [`WheelStats::skipped_ticks`]，真正扫描过的格数记入
//!   [`WheelStats::evaluated_ticks`]。休眠期 `evaluated_ticks == 0` 就是
//!   "零轮询"的**可测量证据**，而不是一句注释。
//!
//! ## 与租约（FR6）的分工
//!
//! `LeaseUpdate` 走的是**自然时钟**（每次事件到达时比较 `now() < frozen_until`），
//! 因此不需要任何定时器即可解冻；本模块只负责**跨度大到"没人会来问"**的场景
//! （批文 365 天失效、超长期停牌复核），这正是"双轨"的含义——两条轨各自
//! 解决一类时间尺度问题，而不是互相替代。

use std::collections::{BTreeSet, HashMap};

/// 定时器句柄。单调递增，可跨 `advance_to` 调用持有。
pub type TimerId = u64;

/// 轮子运行统计。用于性能验收（FR5 / NFR：休眠期 0 CPU 0 I/O）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WheelStats {
    /// 累计注册的定时器数（含已取消/已触发）。
    pub registered: u64,
    /// 累计真正触发的定时器数。
    pub fired: u64,
    /// 累计被取消的定时器数。
    pub cancelled: u64,
    /// 被 $O(1)$ 跳过的空格数 —— 休眠期的"虚拟时间"。
    pub skipped_ticks: u64,
    /// 真正逐格扫描过的格数 —— 唤醒期的实际工作量。
    pub evaluated_ticks: u64,
    /// 因 `deadline` 落在更晚的一圈而重新挂入的条目数。
    pub rewound: u64,
}

/// 一次到期唤醒的载荷：告诉调用方"去读哪个实体的哪一位"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryWake {
    /// 实体类型（`Entity[Company]` 的 `Company`）。
    pub entity: String,
    /// 实体实例键（主键值）。
    pub entity_id: String,
    /// 到期时要校验的状态名（如 `ISSUING`）。
    pub state: String,
    /// 该状态对应的位（FR5 定宽位向量）。
    pub required_bit: u64,
    /// 业务标签，仅用于告警文案。
    pub label: String,
    /// 注册时的逻辑时刻（$T_0$）。
    pub registered_at: u64,
    /// 唤醒时刻（$T_0 + \Delta$）。
    pub deadline: u64,
}

/// FR5：唤醒后的判定结论。
///
/// **只读位图**，不重放事件、不查库、不做扫描。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryOutcome {
    /// 到期时目标位**未**置位 —— 不变量被打破（如批文 365 天未启动发行）。
    Lapsed,
    /// 到期时目标位**已**置位 —— 业务已推进，约束自然消解。
    Satisfied,
}

impl ExpiryOutcome {
    /// 纯粹由单调位图得出：`state & bit != 0`。
    #[inline]
    pub fn of(mask: u64, required_bit: u64) -> Self {
        if mask & required_bit != 0 {
            ExpiryOutcome::Satisfied
        } else {
            ExpiryOutcome::Lapsed
        }
    }

    pub fn is_lapsed(self) -> bool {
        matches!(self, ExpiryOutcome::Lapsed)
    }
}

struct Entry<T> {
    deadline: u64,
    payload: T,
}

/// 离散时间轮（HashedWheelTimer）。
///
/// * `tick` —— 每格代表的逻辑时间跨度（单位与 `now` 一致，工程上通常为秒或毫秒）。
/// * `wheel_size` —— 格数，**必须是 2 的幂**（用位与代替取模）。
///
/// 由于 [`advance_to`](Self::advance_to) 会**直接跳到目标截止期所在格**，
/// 超出整整一圈的长跨度定时器不会经历数十次"绕圈"，而是在一步内被唤醒；
/// 只有"落在同一格、但截止期更晚"的条目才需要重挂到下一圈
/// （记入 [`WheelStats::rewound`]），这是哈希冲突的必然代价，也是最坏 $O(\text{rounds})$。
pub struct HashedWheelTimer<T> {
    tick: u64,
    wheel_size: usize,
    mask: usize,
    buckets: Vec<Vec<(TimerId, Entry<T>)>>,
    /// `(deadline, id)` 有序索引：支撑 $O(1)$ 计算休眠跨度与"跳格唤醒"。
    index: BTreeSet<(u64, TimerId)>,
    /// `id -> deadline`，用于 $O(1)$ 取消。
    deadlines: HashMap<TimerId, u64>,
    cancelled: BTreeSet<TimerId>,
    cursor: usize,
    now: u64,
    next_id: TimerId,
    pending: usize,
    stats: WheelStats,
}

impl<T> HashedWheelTimer<T> {
    /// `wheel_size` 必须为 2 的幂；`tick` 必须非零。
    pub fn new(tick: u64, wheel_size: usize) -> Self {
        assert!(tick > 0, "tick 必须非零");
        assert!(wheel_size > 0 && wheel_size.is_power_of_two(), "wheel_size 必须为 2 的幂");
        Self {
            tick,
            wheel_size,
            mask: wheel_size - 1,
            buckets: (0..wheel_size).map(|_| Vec::new()).collect(),
            index: BTreeSet::new(),
            deadlines: HashMap::new(),
            cancelled: BTreeSet::new(),
            cursor: 0,
            now: 0,
            next_id: 1,
            pending: 0,
            stats: WheelStats::default(),
        }
    }

    /// 常用配置：`slot_seconds` 秒一格、`wheel_size` 格（如 60s × 64 格 ≈ 1 小时分辨率）。
    pub fn with_seconds(slot_seconds: u64, wheel_size: usize) -> Self {
        Self::new(slot_seconds, wheel_size)
    }

    /// 逻辑时钟（不触发任何回调）。
    pub fn now(&self) -> u64 {
        self.now
    }

    /// 直接把时钟拨到 `now`，**不**处理到期定时器。
    ///
    /// 与 `advance_to` 的区别：本方法用于时钟纠正/回放场景，明确表示
    /// "这段时间的定时器由调用方自行负责"，因此不产生 `skipped_ticks`。
    pub fn set_now(&mut self, now: u64) {
        self.now = now;
        self.cursor = self.slot_of_tick(self.tick_index(now));
    }

    pub fn stats(&self) -> WheelStats {
        self.stats
    }

    /// 在册（未触发、未取消）定时器数量。
    pub fn pending_len(&self) -> usize {
        self.pending
    }

    pub fn is_empty(&self) -> bool {
        self.pending == 0
    }

    /// 最早到期时刻。
    pub fn next_deadline(&self) -> Option<u64> {
        self.index.iter().next().map(|(d, _)| *d)
    }

    /// **双轨核心 API**：距离下一次唤醒还有多久。
    ///
    /// `None` 表示没有任何在册定时器 —— 调度器可以无限期休眠
    /// （PRD：365 天内 0 CPU / 0 I/O）。`Some(d)` 表示可以安全休眠 `d`
    /// 个逻辑时间单位而不漏掉任何唤醒点。
    pub fn sleep_span(&self) -> Option<u64> {
        self.next_deadline().map(|d| d.saturating_sub(self.now))
    }

    /// 每格的逻辑跨度。
    pub fn tick(&self) -> u64 {
        self.tick
    }

    /// 每格当前的占用数（含未到期待重挂的条目），用于测试与可视化。
    pub fn bucket_occupancy(&self) -> Vec<usize> {
        self.buckets.iter().map(|b| b.len()).collect()
    }

    /// 注册一个绝对时刻到期的定时器，返回句柄。$O(1)$ 哈希定位 + $O(\log n)$ 索引插入。
    pub fn register_at(&mut self, deadline: u64, payload: T) -> TimerId {
        let id = self.next_id;
        self.next_id += 1;
        let slot = self.slot_of_tick(self.tick_index(deadline));
        self.buckets[slot].push((id, Entry { deadline, payload }));
        self.index.insert((deadline, id));
        self.deadlines.insert(id, deadline);
        self.pending += 1;
        self.stats.registered += 1;
        id
    }

    /// 注册一个相对延迟到期的定时器。
    pub fn register_after(&mut self, delay: u64, payload: T) -> TimerId {
        self.register_at(self.now.saturating_add(delay), payload)
    }

    /// $O(1)$ 取消（惰性删除：条目仍留在格里，扫描时按 `cancelled` 集合丢弃）。
    pub fn cancel(&mut self, id: TimerId) -> bool {
        let Some(deadline) = self.deadlines.remove(&id) else {
            return false;
        };
        self.index.remove(&(deadline, id));
        self.cancelled.insert(id);
        self.pending -= 1;
        self.stats.cancelled += 1;
        true
    }

    /// 推进逻辑时钟到 `target`，按到期顺序返回所有触发载荷。
    ///
    /// * 无在册定时器，或下一次唤醒晚于 `target` → **直接跳过去**，
    ///   一格都不扫（`skipped_ticks` 累加，`evaluated_ticks` 不变）；
    /// * 否则只落在真正有到期条目的格上，逐格清空。
    ///
    /// 因此 `evaluated_ticks` 与"轮询次数"成正比，与"时间跨度"无关。
    pub fn advance_to(&mut self, target: u64) -> Vec<(TimerId, T)> {
        let mut fired: Vec<(u64, TimerId, T)> = Vec::new();
        if target <= self.now {
            return Vec::new();
        }
        loop {
            // 下一次唤醒点落在 target 之后就整体跳过
            let Some(&(deadline, _)) = self.index.iter().next() else {
                self.skip_to(target);
                break;
            };
            if deadline > target {
                self.skip_to(target);
                break;
            }
            // 直接跳到该截止期所在格（中间的格全部一次性跳过）
            let slot = self.slot_of_tick(self.tick_index(deadline));
            let kd = self.tick_index(deadline);
            let cur = self.tick_index(self.now);
            self.stats.skipped_ticks += kd.saturating_sub(cur).saturating_sub(1);
            self.now = kd * self.tick;
            self.cursor = slot;
            self.stats.evaluated_ticks += 1;

            let mut due = Vec::new();
            for entry in std::mem::take(&mut self.buckets[slot]) {
                if entry.1.deadline <= self.now {
                    due.push(entry);
                } else {
                    // 超出一圈的条目：重挂到后面的一圈
                    self.stats.rewound += 1;
                    self.buckets[slot].push(entry);
                }
            }
            for (tid, entry) in due {
                if self.cancelled.remove(&tid) {
                    continue;
                }
                self.index.remove(&(entry.deadline, tid));
                self.deadlines.remove(&tid);
                self.pending -= 1;
                self.stats.fired += 1;
                fired.push((entry.deadline, tid, entry.payload));
            }
        }
        // 按截止期排序 —— 唤醒语义是"按时间发生"，而不是"按注册顺序发生"
        fired.sort_by_key(|(deadline, id, _)| (*deadline, *id));
        fired.into_iter().map(|(_, id, payload)| (id, payload)).collect()
    }

    /// 单格推进（`advance_to(now + tick)` 的便捷封装），返回本格内的触发载荷。
    pub fn tick_once(&mut self) -> Vec<(TimerId, T)> {
        let target = self.tick_index(self.now).saturating_add(1) * self.tick;
        self.advance_to(target)
    }

    // ---- 内部：格索引 ----

    /// `ceil(t / tick)`：deadline 落在哪一格。
    #[inline]
    fn tick_index(&self, t: u64) -> u64 {
        if t == 0 {
            0
        } else {
            (t - 1) / self.tick + 1
        }
    }

    #[inline]
    fn slot_of_tick(&self, k: u64) -> usize {
        (k & self.mask as u64) as usize
    }

    /// $O(1)$ 跳过整段空格。
    fn skip_to(&mut self, target: u64) {
        if target <= self.now {
            return;
        }
        let skipped = self
            .tick_index(target)
            .saturating_sub(self.tick_index(self.now));
        self.stats.skipped_ticks += skipped;
        self.now = target;
        self.cursor = self.slot_of_tick(self.tick_index(target));
    }
}

impl<T> std::fmt::Debug for HashedWheelTimer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashedWheelTimer")
            .field("tick", &self.tick)
            .field("wheel_size", &self.wheel_size)
            .field("now", &self.now)
            .field("pending", &self.pending)
            .field("next_deadline", &self.next_deadline())
            .field("stats", &self.stats)
            .finish()
    }
}

// =====================================================================
// 长周期便捷封装：批文有效期型的单次唤醒
// =====================================================================

/// 一年（天）——FR5 例题里的 365 天批文有效期。
pub const YEAR_DAYS: u64 = 365;
/// 一天的秒数。
pub const DAY_SECS: u64 = 86_400;

/// 以「天」为格粒度的长周期时间轮（默认 64 格 ≈ 2 个月分辨率，
/// 超出两圈的跨度为常数空间重挂——365 天仅需 6 次重挂，且全在唤醒点发生）。
pub struct LongHorizonScheduler {
    wheel: HashedWheelTimer<ExpiryWake>,
}

impl Default for LongHorizonScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl LongHorizonScheduler {
    /// 1 格 = 1 天，64 格。
    pub fn new() -> Self {
        Self { wheel: HashedWheelTimer::new(DAY_SECS, 64) }
    }

    /// 自定义格粒度与格数。
    pub fn with_config(tick_secs: u64, wheel_size: usize) -> Self {
        Self { wheel: HashedWheelTimer::new(tick_secs, wheel_size) }
    }

    pub fn now(&self) -> u64 {
        self.wheel.now()
    }

    pub fn set_now(&mut self, now: u64) {
        self.wheel.set_now(now);
    }

    /// 注册一次「某实体在 `deadline` 时应处于 `state`」的复核唤醒。
    ///
    /// `required_bit` 由调用方从 [`rules_ast::EntityDecl`] 的位向量声明中得到
    /// （`mask_of` / `bit_of`），保证与状态格严格同源。
    pub fn watch_state(
        &mut self,
        entity: impl Into<String>,
        entity_id: impl Into<String>,
        state: impl Into<String>,
        required_bit: u64,
        label: impl Into<String>,
        deadline: u64,
    ) -> TimerId {
        let registered_at = self.wheel.now();
        self.wheel.register_at(
            deadline,
            ExpiryWake {
                entity: entity.into(),
                entity_id: entity_id.into(),
                state: state.into(),
                required_bit,
                label: label.into(),
                registered_at,
                deadline,
            },
        )
    }

    /// 注册「$T_0 + N$ 天后到期」的批文式有效期。
    pub fn watch_after_days(
        &mut self,
        entity: impl Into<String>,
        entity_id: impl Into<String>,
        state: impl Into<String>,
        required_bit: u64,
        label: impl Into<String>,
        days: u64,
    ) -> TimerId {
        let deadline = self.wheel.now().saturating_add(days.saturating_mul(DAY_SECS));
        self.watch_state(entity, entity_id, state, required_bit, label, deadline)
    }

    /// $O(1)$ 取消（如业务提前终止，不需要再复核）。
    pub fn cancel(&mut self, id: TimerId) -> bool {
        self.wheel.cancel(id)
    }

    /// 休眠跨度：`None` = 可以无限期休眠。
    pub fn sleep_span(&self) -> Option<u64> {
        self.wheel.sleep_span()
    }

    pub fn pending_len(&self) -> usize {
        self.wheel.pending_len()
    }

    pub fn stats(&self) -> WheelStats {
        self.wheel.stats()
    }

    /// 推进时钟并返回所有到期唤醒。
    pub fn advance_to(&mut self, target: u64) -> Vec<ExpiryWake> {
        self.wheel.advance_to(target).into_iter().map(|(_, w)| w).collect()
    }

    /// **双轨闭环**：推进时钟，并用一个"读位图"的访问器直接得出每笔到期的判定。
    ///
    /// `mask_of` 只做一次 `state & required_bit`（[`ExpiryOutcome::of`]），
    /// 不重放事件、不查库 —— 与 PRD §4.1 "到期唤醒后，仅读取单调位图" 一字不差。
    pub fn advance_and_check<F>(&mut self, target: u64, mut mask_of: F) -> Vec<(ExpiryWake, ExpiryOutcome)>
    where
        F: FnMut(&ExpiryWake) -> u64,
    {
        self.advance_to(target)
            .into_iter()
            .map(|w| {
                let mask = mask_of(&w);
                let outcome = ExpiryOutcome::of(mask, w.required_bit);
                (w, outcome)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_fire_at_exact_deadline() {
        let mut wheel: HashedWheelTimer<&'static str> = HashedWheelTimer::new(10, 8);
        wheel.register_at(100, "a");
        wheel.register_at(30, "b");

        assert_eq!(wheel.next_deadline(), Some(30));
        assert_eq!(wheel.advance_to(29), vec![]);
        assert_eq!(wheel.advance_to(30), vec![(2, "b")]);
        assert_eq!(wheel.advance_to(99), vec![]);
        assert_eq!(wheel.advance_to(100), vec![(1, "a")]);
        assert!(wheel.is_empty());
    }

    #[test]
    fn ordering_is_by_deadline_not_registration() {
        let mut wheel: HashedWheelTimer<u32> = HashedWheelTimer::new(1, 4);
        wheel.register_at(50, 500);
        wheel.register_at(10, 100);
        wheel.register_at(30, 300);
        let fired: Vec<u32> = wheel.advance_to(60).into_iter().map(|(_, v)| v).collect();
        assert_eq!(fired, vec![100, 300, 500]);
    }

    #[test]
    fn cancel_is_lazy_but_exact() {
        let mut wheel: HashedWheelTimer<&'static str> = HashedWheelTimer::new(1, 4);
        let a = wheel.register_at(10, "a");
        let b = wheel.register_at(20, "b");
        assert!(wheel.cancel(a));
        assert!(!wheel.cancel(a), "重复取消必须返回 false");
        assert_eq!(wheel.pending_len(), 1);
        assert_eq!(wheel.next_deadline(), Some(20));
        let fired: Vec<&str> = wheel.advance_to(20).into_iter().map(|(_, v)| v).collect();
        assert_eq!(fired, vec!["b"]);
        assert_eq!(wheel.stats().cancelled, 1);
        assert_eq!(wheel.stats().fired, 1);
        let _ = b;
    }

    #[test]
    fn long_horizon_sleep_costs_zero_scans() {
        // 1 格 = 1 天，8 格；注册 365 天后唤醒
        let mut wheel: HashedWheelTimer<&'static str> = HashedWheelTimer::new(DAY_SECS, 8);
        wheel.register_at(DAY_SECS * YEAR_DAYS, "expiry");

        // 沉睡 10 天：一格都没扫
        let fired = wheel.advance_to(10 * DAY_SECS);
        assert!(fired.is_empty());
        assert_eq!(wheel.stats().evaluated_ticks, 0, "休眠期不得扫描任何格");
        assert!(wheel.stats().skipped_ticks >= 10, "应记为 O(1) 跳过的空格");

        // 第 365 天唤醒：只扫极少数格（跨圈重挂）
        let fired = wheel.advance_to(DAY_SECS * YEAR_DAYS);
        assert_eq!(fired.len(), 1);
        assert!(wheel.stats().evaluated_ticks <= 2, "唤醒只需极少数格");
    }

    #[test]
    fn long_horizon_timer_is_never_lost_across_many_revolutions() {
        // 1 格 = 1 单位、4 格；deadline 1000 需要跨 250 圈
        let mut wheel: HashedWheelTimer<&'static str> = HashedWheelTimer::new(1, 4);
        wheel.register_at(1000, "far");
        let fired: Vec<&str> = wheel.advance_to(1000).into_iter().map(|(_, v)| v).collect();
        assert_eq!(fired, vec!["far"], "跨圈定时器必须被唤醒而不是丢失");
        assert!(wheel.stats().evaluated_ticks <= 2, "跨 250 圈也只扫极少数格");
    }

    #[test]
    fn co_bucketed_later_deadline_is_rewound() {
        // 4 与 8 同落在 0 号格（& 3 == 0）
        let mut wheel: HashedWheelTimer<&'static str> = HashedWheelTimer::new(1, 4);
        wheel.register_at(4, "early");
        wheel.register_at(8, "late");
        let fired: Vec<&str> = wheel.advance_to(8).into_iter().map(|(_, v)| v).collect();
        assert_eq!(fired, vec!["early", "late"]);
        assert!(wheel.stats().rewound > 0, "同格更晚的条目必须被重挂而非误触发");
    }

    #[test]
    fn sleep_span_reports_next_wakeup() {
        let mut wheel: HashedWheelTimer<u8> = HashedWheelTimer::new(60, 16);
        assert_eq!(wheel.sleep_span(), None, "无定时器 → 可无限期休眠");
        wheel.register_at(1000, 1);
        wheel.set_now(400);
        assert_eq!(wheel.sleep_span(), Some(600));
    }

    #[test]
    fn outcome_is_pure_bitmap_read() {
        assert_eq!(ExpiryOutcome::of(0b0100, 0b1000), ExpiryOutcome::Lapsed);
        assert_eq!(ExpiryOutcome::of(0b1100, 0b1000), ExpiryOutcome::Satisfied);
        assert!(ExpiryOutcome::of(0, 1).is_lapsed());
    }

    #[test]
    fn scheduler_closes_the_loop_with_bitmap() {
        let mut sched = LongHorizonScheduler::new();
        let t0 = 1_800_000_000u64;
        sched.set_now(t0);
        sched.watch_after_days("Company", "600000", "ISSUING", 0x08, "批文有效期", YEAR_DAYS);

        let mut mask = 0x04u64; // CSRC_APPROVED，未进入 ISSUING
        let woken = sched.advance_and_check(t0 + 10 * DAY_SECS, |_| mask);
        assert!(woken.is_empty());
        assert_eq!(sched.stats().evaluated_ticks, 0);

        let woken = sched.advance_and_check(t0 + YEAR_DAYS * DAY_SECS, |_| mask);
        assert_eq!(woken.len(), 1);
        assert!(woken[0].1.is_lapsed(), "未置位 ISSUING → 批文失效");
        assert_eq!(woken[0].0.label, "批文有效期");

        // 换个场景：已置位 ISSUING → 约束自然消解
        mask |= 0x08;
        let mut sched2 = LongHorizonScheduler::new();
        sched2.set_now(t0);
        sched2.watch_after_days("Company", "600000", "ISSUING", 0x08, "批文有效期", YEAR_DAYS);
        let woken = sched2.advance_and_check(t0 + YEAR_DAYS * DAY_SECS, |_| mask);
        assert_eq!(woken[0].1, ExpiryOutcome::Satisfied);
    }
}
