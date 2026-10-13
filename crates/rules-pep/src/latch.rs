//! # `latch` —— 共享内存原子位图租约广播（PRD §4.1 / NFR）
//!
//! 极速执行域要达成的目标：**引擎进程算出"某席位超限"之后，网关进程在
//! 纳秒级内看到这个事实**，且不需要任何 IPC 往返、不引入后台定时器。
//!
//! 实现方式与 PRD §4.1 的 `shm_open` / `mmap` 方案一一对应：
//!
//! ```text
//!   引擎进程 (PDP)                         网关进程 (PEP)
//!   ┌────────────────────────┐             ┌────────────────────────┐
//!   │ LeaseLedger            │             │ fast_gate              │
//!   │   ↓ 广播              │             │   ↓ 一次原子 load      │
//!   │ FrozenLatch::put() ────┼──┐       ┌─┼──► FrozenLatch::is_frozen│
//!   └────────────────────────┘  │       │ └────────────────────────┘
//!                               ▼       ▼
//!                    ┌────────────────────────────┐
//!                    │ mmap 共享内存（POSIX shm） │
//!                    │ [key_hash, frozen_until] ×N │
//!                    └────────────────────────────┘
//! ```
//!
//! ## 内存布局
//!
//! 连续 `2 × capacity` 个 `AtomicU64`，两两成槽：
//!
//! | 偏移 | 含义 |
//! |---|---|
//! | `slot[2i]`   | 实体键的 FNV-1a 64 位哈希（`0` = 空槽） |
//! | `slot[2i+1]` | `frozen_until` 绝对时间戳（秒）；`0` = 未冻结 |
//!
//! 单槽 16 字节，与 C-ABI / `AtomicU64` 对齐一致，可直接被 C/Java
//! （`VarHandle` / `Unsafe`）读写。
//!
//! ## 三条设计铁律
//!
//! 1. **单调**：写入一律 `fetch_max`。重复命中只延长冻结，绝不缩短——
//!    否则攻击者可以用一笔小额违规把大额冻结刷掉。
//! 2. **逻辑删除**：到期回收只把 `frozen_until` 置 `0`，**保留键槽**。
//!    线性探测的墓碑搬移会让读路径不再是"单次 load"，而网关内联过滤器的
//!    NFR 是 P99 < 1μs；键槽保留换来的是可证明的确定延迟。代价是容量被
//!    `capacity` 限制为**进程生命周期内的去重实体数**（报单网关的席位/PBU
//!    全集天然有界），需要时可 `clear()` 或换新 `epoch`。
//! 3. **fail-open on unknown key**：未登记过的键返回 `0`（未冻结）。
//!    这是刻意的——冻结是"附加约束"，未知实体本就不在管控集合内。
//!    真正 fail-closed 的是**协议串解析**（见 [`crate::Protocol::parse`]）。
//!
//! ## 哈希碰撞
//!
//! 槽内只存 64 位哈希，不存原串。两个不同实体键碰撞的概率约
//! `n²/2^65`（`n` = 去重实体数）；`n = 10^4` 时约 `2.7e-12`。
//! 碰撞的后果是"多冻结一个无辜实体"（保守方向），不会漏放。

use std::sync::atomic::{AtomicU64, Ordering};

/// 空槽标记。
const EMPTY: u64 = 0;

/// FNV-1a 64 位哈希，并强制最高位为 1 以避开空槽标记 `0`。
///
/// 强制 `| 1` 让"哈希恰为 0"的实体不会被误判为空槽（代价是丢失 1 位熵）。
#[inline]
pub fn key_hash(key: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h | 1
}

enum Backing {
    /// 本对象拥有的堆内存。
    Owned(Vec<AtomicU64>),
    /// 宿主 `mmap` 出来的共享内存；**不由本对象释放**。
    Mapped(*mut AtomicU64),
}

/// 共享内存冻结租约位图。
///
/// 见模块文档的内存布局与设计铁律。
pub struct FrozenLatch {
    backing: Backing,
    /// 槽数（2 的幂）。
    cap: usize,
    /// `cap - 1`，用于把哈希映到槽位。
    mask: usize,
}

// 安全性：所有可变状态都封在 `AtomicU64` 里，读写全部走原子序；
// `Mapped` 变体指向的内存由宿主保证"存活期 ≥ 本对象"且"不被第三方释放"。
unsafe impl Send for FrozenLatch {}
unsafe impl Sync for FrozenLatch {}

impl FrozenLatch {
    /// 在堆上分配 `capacity` 个槽（向上取整到 2 的幂，最小 16）。
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(16).next_power_of_two();
        let mut v = Vec::with_capacity(cap * 2);
        v.resize_with(cap * 2, || AtomicU64::new(EMPTY));
        FrozenLatch { backing: Backing::Owned(v), cap, mask: cap - 1 }
    }

    /// 在宿主提供的共享内存上**原位构造**。
    ///
    /// 典型用法（Linux）：
    ///
    /// ```text
    /// let fd = shm_open("/ruleseng.latch", O_CREAT | O_RDWR, 0o600);
    /// let bytes = FrozenLatch::byte_len_for(4096);
    /// ftruncate(fd, bytes);
    /// let ptr = mmap(null, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) as *mut AtomicU64;
    /// let latch = unsafe { FrozenLatch::attach(ptr, 4096) };
    /// ```
    ///
    /// # Safety
    ///
    /// 调用方必须保证：
    /// * `ptr` 按 8 字节对齐，且指向至少 [`FrozenLatch::byte_len_for`]`(capacity)` 字节可读写的内存；
    /// * 该内存的存活期不短于返回的 `FrozenLatch`（含 `Arc` 的所有克隆）；
    /// * 除了经本类型（或语义等价的 C/Java 侧访问器）之外，没有其他代码写这块内存；
    /// * 同一份内存不会被两个宿主用**不同的** `capacity` 调 `attach`。
    ///
    /// 内存**不会**被 `attach` 初始化——共享内存创建方需要先 [`FrozenLatch::clear`]。
    pub unsafe fn attach(ptr: *mut AtomicU64, capacity: usize) -> Self {
        let cap = capacity.max(16).next_power_of_two();
        FrozenLatch { backing: Backing::Mapped(ptr), cap, mask: cap - 1 }
    }

    /// `capacity` 个槽所需的字节数（供宿主 `ftruncate` / 分配）。
    pub fn byte_len_for(capacity: usize) -> usize {
        capacity.max(16).next_power_of_two() * 2 * std::mem::size_of::<AtomicU64>()
    }

    /// 槽数的 2 的幂（实际容量）。
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// 本实例占用的字节数。
    pub fn byte_len(&self) -> usize {
        self.cap * 2 * std::mem::size_of::<AtomicU64>()
    }

    /// 内存首地址（供跨进程/跨语言共享）。
    pub fn as_ptr(&self) -> *mut AtomicU64 {
        match &self.backing {
            Backing::Owned(v) => v.as_ptr() as *mut AtomicU64,
            Backing::Mapped(p) => *p,
        }
    }

    #[inline]
    fn slot(&self, i: usize) -> &AtomicU64 {
        debug_assert!(i < self.cap * 2);
        match &self.backing {
            Backing::Owned(v) => &v[i],
            // 安全性：由 `attach` 的契约保证地址有效且存活。
            Backing::Mapped(p) => unsafe { &*(*p).add(i) },
        }
    }

    #[inline]
    fn key_at(&self, i: usize) -> u64 {
        self.slot(i * 2).load(Ordering::Acquire)
    }

    #[inline]
    fn value_at(&self, i: usize) -> u64 {
        self.slot(i * 2 + 1).load(Ordering::Acquire)
    }

    /// 定位键所在槽位下标；未登记时返回 `None`。
    #[inline]
    fn find(&self, h: u64) -> Option<usize> {
        let mut i = (h as usize) & self.mask;
        for _ in 0..self.cap {
            let k = self.key_at(i);
            if k == h {
                return Some(i);
            }
            if k == EMPTY {
                return None;
            }
            i = (i + 1) & self.mask;
        }
        None
    }

    /// **单调写入**冻结到期时间。
    ///
    /// 返回 `None` 表示位图已满（`capacity` 不足）——此时**没有**写入。
    /// 调用方应按 2× 峰值冻结实体数规划容量；`until == 0` 请直接用
    /// [`FrozenLatch::clear`] 表达"解除冻结"。
    pub fn put(&self, key: &str, until: u64) -> Option<u64> {
        let h = key_hash(key);
        let mut i = (h as usize) & self.mask;
        for _ in 0..self.cap {
            let k = self.slot(i * 2);
            let cur = k.load(Ordering::Acquire);
            if cur == h {
                return Some(self.slot(i * 2 + 1).fetch_max(until, Ordering::AcqRel).max(until));
            }
            if cur == EMPTY {
                match k.compare_exchange(EMPTY, h, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {
                        let v = self.slot(i * 2 + 1).fetch_max(until, Ordering::AcqRel).max(until);
                        return Some(v);
                    }
                    Err(_) => {
                        // 竞争失败：别的线程占了这一槽，重读后继续线性探测。
                        if k.load(Ordering::Acquire) == h {
                            let v = self.slot(i * 2 + 1).fetch_max(until, Ordering::AcqRel).max(until);
                            return Some(v);
                        }
                    }
                }
            }
            i = (i + 1) & self.mask;
        }
        None
    }

    /// 读取冻结到期时间（`0` = 未冻结 / 未登记）。
    #[inline]
    pub fn frozen_until(&self, key: &str) -> u64 {
        match self.find(key_hash(key)) {
            Some(i) => self.value_at(i),
            None => 0,
        }
    }

    /// 是否处于冻结期。
    #[inline]
    pub fn is_frozen(&self, key: &str, now: u64) -> bool {
        self.frozen_until(key) > now
    }

    /// 到期回收：把所有 `until <= now` 的槽归零，返回回收数。O(capacity)。
    ///
    /// 由引擎的 `tick()` 或下一次为准入查询驱动——**没有后台定时器**。
    pub fn clear_expired(&self, now: u64) -> usize {
        let mut n = 0;
        for i in 0..self.cap {
            if self.key_at(i) == EMPTY {
                continue;
            }
            let v = self.slot(i * 2 + 1);
            let cur = v.load(Ordering::Acquire);
            if cur != 0 && cur <= now {
                v.store(0, Ordering::Release);
                n += 1;
            }
        }
        n
    }

    /// 把所有冻结归零（保留键槽）。等价于"换 epoch"。
    pub fn clear(&self) -> usize {
        let mut n = 0;
        for i in 0..self.cap {
            if self.key_at(i) == EMPTY {
                continue;
            }
            let v = self.slot(i * 2 + 1);
            if v.swap(0, Ordering::AcqRel) != 0 {
                n += 1;
            }
        }
        n
    }

    /// 彻底清零（含键槽），回到刚分配的初始状态。
    ///
    /// **只允许共享内存的创建方在发布给其他进程之前调用**——
    /// 并发调用会撕掉其他进程正在使用的探测链。
    pub fn reset(&self) {
        for i in 0..self.cap * 2 {
            self.slot(i).store(EMPTY, Ordering::Release);
        }
    }

    /// 已登记的键槽数（含已到期但未回收的）。
    pub fn slots_used(&self) -> usize {
        (0..self.cap).filter(|i| self.key_at(*i) != EMPTY).count()
    }

    /// 当前活跃（未到期）的冻结数。
    pub fn active(&self) -> usize {
        (0..self.cap)
            .filter(|i| self.key_at(*i) != EMPTY && self.value_at(*i) != 0)
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.slots_used() == 0
    }

    /// 活跃冻结快照：`(键哈希, 到期时间)`。
    ///
    /// 只返回哈希而非原串——位图刻意不保存字符串，见模块文档。
    /// 需要"哈希 → 实体"的反查请由引擎侧的 `LeaseLedger::snapshot()` 提供。
    pub fn entries(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for i in 0..self.cap {
            let k = self.key_at(i);
            if k == EMPTY {
                continue;
            }
            let v = self.value_at(i);
            if v != 0 {
                out.push((k, v));
            }
        }
        out
    }

    /// 装填率（`slots_used / capacity`）——用于容量规划告警。
    pub fn load_factor(&self) -> f64 {
        self.slots_used() as f64 / self.cap as f64
    }
}

impl std::fmt::Debug for FrozenLatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrozenLatch")
            .field("capacity", &self.cap)
            .field("slots_used", &self.slots_used())
            .field("active", &self.active())
            .field("byte_len", &self.byte_len())
            .field("shared", &matches!(self.backing, Backing::Mapped(_)))
            .finish()
    }
}

// =====================================================================
// 测试
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn capacity_rounds_to_power_of_two() {
        assert_eq!(FrozenLatch::new(1).capacity(), 16);
        assert_eq!(FrozenLatch::new(100).capacity(), 128);
        assert_eq!(FrozenLatch::new(4096).capacity(), 4096);
        assert_eq!(FrozenLatch::new(4097).capacity(), 8192);
    }

    #[test]
    fn byte_len_matches_layout() {
        let l = FrozenLatch::new(1024);
        assert_eq!(l.byte_len(), 1024 * 2 * 8);
        assert_eq!(FrozenLatch::byte_len_for(1024), l.byte_len());
        assert_eq!(FrozenLatch::byte_len_for(1), 16 * 2 * 8);
    }

    #[test]
    fn hash_is_nonzero_and_deterministic() {
        assert_ne!(key_hash(""), 0);
        assert_eq!(key_hash("Seat#PBU001"), key_hash("Seat#PBU001"));
        assert_ne!(key_hash("Seat#PBU001"), key_hash("Seat#PBU002"));
    }

    #[test]
    fn put_then_read_round_trips() {
        let l = FrozenLatch::new(64);
        assert_eq!(l.frozen_until("Seat#A"), 0);
        assert_eq!(l.put("Seat#A", 1000), Some(1000));
        assert_eq!(l.frozen_until("Seat#A"), 1000);
        assert_eq!(l.frozen_until("Seat#B"), 0);
    }

    #[test]
    fn put_is_monotonic() {
        let l = FrozenLatch::new(64);
        l.put("Seat#A", 1000);
        assert_eq!(l.put("Seat#A", 500), Some(1000), "不得缩短冻结期");
        assert_eq!(l.put("Seat#A", 1200), Some(1200));
        assert_eq!(l.frozen_until("Seat#A"), 1200);
    }

    #[test]
    fn is_frozen_boundary_is_exclusive() {
        let l = FrozenLatch::new(64);
        l.put("Seat#A", 100);
        assert!(l.is_frozen("Seat#A", 99));
        assert!(!l.is_frozen("Seat#A", 100), "到期时刻即放行");
        assert!(!l.is_frozen("Seat#A", 101));
        assert!(!l.is_frozen("Seat#unknown", 0), "未知键 fail-open");
    }

    #[test]
    fn clear_expired_only_clears_due_entries() {
        let l = FrozenLatch::new(64);
        l.put("Seat#A", 100);
        l.put("Seat#B", 300);
        assert_eq!(l.clear_expired(100), 1);
        assert_eq!(l.frozen_until("Seat#A"), 0);
        assert_eq!(l.frozen_until("Seat#B"), 300);
        assert_eq!(l.active(), 1);
        assert_eq!(l.slots_used(), 2, "逻辑删除保留键槽");
        assert_eq!(l.clear_expired(300), 1);
        assert_eq!(l.active(), 0, "全部到期后无活跃冻结");
        assert_eq!(l.slots_used(), 2, "键槽仍然保留");
    }

    #[test]
    fn clear_zeroes_all_values_but_keeps_slots() {
        let l = FrozenLatch::new(64);
        l.put("A", 10);
        l.put("B", 20);
        assert_eq!(l.clear(), 2);
        assert_eq!(l.active(), 0);
        assert_eq!(l.slots_used(), 2);
    }

    #[test]
    fn many_keys_survive_open_addressing() {
        let l = FrozenLatch::new(512);
        for i in 0..300 {
            l.put(&format!("Seat#{i}"), 1000 + i as u64);
        }
        for i in 0..300 {
            assert_eq!(l.frozen_until(&format!("Seat#{i}")), 1000 + i as u64, "键 {i} 丢失");
        }
        assert_eq!(l.active(), 300);
        assert!(l.load_factor() < 0.7);
    }

    #[test]
    fn full_table_reports_none_instead_of_corrupting() {
        let l = FrozenLatch::new(16);
        for i in 0..16 {
            assert!(l.put(&format!("K{i}"), 1).is_some());
        }
        assert_eq!(l.put("K-overflow", 1), None, "表满必须显式报告失败");
        assert!(l.frozen_until("K0") > 0, "表满不得破坏既有条目");
    }

    #[test]
    fn reset_clears_keys_too() {
        let l = FrozenLatch::new(16);
        l.put("A", 10);
        assert_eq!(l.slots_used(), 1);
        l.reset();
        assert_eq!(l.slots_used(), 0);
        assert!(l.is_empty());
        // 复位后仍可正常写入
        assert_eq!(l.put("A", 20), Some(20));
    }

    #[test]
    fn entries_and_snapshot_are_consistent() {
        let l = FrozenLatch::new(64);
        l.put("A", 5);
        l.put("B", 7);
        let mut e = l.entries();
        e.sort();
        assert_eq!(e.len(), 2);
        assert!(e.iter().all(|(h, _)| *h != 0));
        assert!(e.contains(&(key_hash("A"), 5)));
        assert!(e.contains(&(key_hash("B"), 7)));
    }

    #[test]
    fn attached_shared_memory_is_usable_by_both_sides() {
        // 模拟宿主 mmap：引擎侧写、网关侧读
        let mut raw: Vec<AtomicU64> = (0..FrozenLatch::byte_len_for(64) / 8)
            .map(|_| AtomicU64::new(EMPTY))
            .collect();
        let ptr = raw.as_mut_ptr();

        // 引擎进程
        let writer = unsafe { FrozenLatch::attach(ptr, 64) };
        writer.put("Seat#PBU001", 1060);

        // 网关进程（同一块内存的另一个视图）
        let reader = unsafe { FrozenLatch::attach(ptr, 64) };
        assert!(reader.is_frozen("Seat#PBU001", 1000));
        assert!(!reader.is_frozen("Seat#PBU001", 1061));
        assert_eq!(reader.frozen_until("Seat#PBU001"), 1060);

        // 网关侧也可以回写（例如本地快速路径自行续期）
        reader.put("Seat#PBU001", 2000);
        assert_eq!(writer.frozen_until("Seat#PBU001"), 2000);

        // 引擎侧回收后网关侧立刻看到
        assert_eq!(writer.clear_expired(2000), 1);
        assert_eq!(reader.frozen_until("Seat#PBU001"), 0);
    }

    #[test]
    fn concurrent_writers_do_not_lose_entries() {
        let l = Arc::new(FrozenLatch::new(1024));
        let mut handles = Vec::new();
        for t in 0..8 {
            let l = l.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..32 {
                    l.put(&format!("Seat#{t}-{i}"), (t * 32 + i + 1) as u64);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(l.active(), 256, "并发写入不得丢条目");
        assert!(l.load_factor() < 0.35);
    }

    #[test]
    fn monotonic_write_is_race_free_under_contention() {
        let l = Arc::new(FrozenLatch::new(16));
        let mut handles = Vec::new();
        for t in 0..8 {
            let l = l.clone();
            handles.push(std::thread::spawn(move || {
                let base = (t % 2) * 100;
                for k in 0..100 {
                    l.put("shared", base + k);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // 单调 max：最终值必须是所有写入的最大值
        assert_eq!(l.frozen_until("shared"), 199);
    }

    #[test]
    fn debug_output_reports_backing_kind() {
        let l = FrozenLatch::new(16);
        assert!(format!("{l:?}").contains("shared: false"));
    }
}
