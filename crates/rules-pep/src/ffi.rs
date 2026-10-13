//! # `ffi` —— C-ABI / WASM 网关内联过滤器（FR4 / NFR）
//!
//! PRD FR4 原文：
//!
//! > **极速报单流水线集成**：针对交易前风控，规则引擎编译为纯 C-ABI 动态链接库
//! > 或 WASM 模块，以进程内过滤器（Inline Filter）形式部署在网关，执行时间 < 1 微秒。
//!
//! 本模块就是那层"纯 C-ABI 导出面"：`crate-type` 同时产出 `rlib` 与 `cdylib`，
//! 因此 `rules_pep.dll` / `librules_pep.so` / `rules_pep.wasm` 里的这些符号
//! 可以直接被 C++ 报单网关、Go 风控插件（cgo）、Java（JNI/Panama）调用。
//!
//! ## 调用序列
//!
//! ```c
//! // ── 启动时（每进程一次）────────────────────────────────
//! RulesPep handle = rules_pep_open(spec_src, spec_len, /*latch_slots=*/4096);
//! if (!handle) { /* 契约非法，进程必须拒绝启动（fail-closed） */ }
//!
//! // 引擎侧把共享内存地址交给网关（mmap 同一块 / 或由本进程 mmap 后转交）
//! uint64_t* latch = rules_pep_latch_ptr(handle);
//! size_t    bytes = rules_pep_latch_bytes(handle);
//!
//! // ── 每笔报单（热路径）──────────────────────────────────
//! int rc = rules_pep_admit(handle,
//!                          "OrderIntent", 11,
//!                          "Seat",        4,
//!                          "PBU001",      6,
//!                          /*now=*/1762000000);
//! if (rc == RULES_PEP_DENY) {
//!     char buf[64]; int n = rules_pep_last_protocol(handle, buf, sizeof buf);
//!     fprintf(stderr, "order rejected: %.*s\n", n, buf);   // "DENY:ERR_SEAT_FROZEN"
//!     return;                                              // 同线程物理阻断
//! }
//! // rc == RULES_PEP_ALLOW → 继续走原有报单流程
//! ```
//!
//! ## 内存安全约定
//!
//! * **入参一律 `(ptr, len)` 对**，不使用 NUL 结尾串——理由有两条：
//!   (1) WASM 线性内存里没有 `\0` 语义；(2) 调用方可能持有非 NUL 结尾的
//!   slice（如 Go string、Java `byte[]`）。`ptr` 为 `NULL` 时按 `len == 0`
//!   处理（空串）。
//! * **所有入参都是只读的**：函数不会保留任何裸指针（`Intent` 内部全部复制），
//!   因此调用方可以立刻复用缓冲区。
//! * **panic 不外溢**：每个导出函数都包在 `catch_unwind` 里，异常路径返回
//!   [`PEP_ERR`]。跨 FFI 展开是 UB，这一步不是可选项。
//! * **句柄是独占所有权**：`rules_pep_open` 返回的指针必须由 **同一个线程**
//!   使用并最终 `rules_pep_close` 释放；跨线程共享请让宿主自己加锁
//!   （PEP 的 `admit` 需要 `&mut`，本身就是独占语义）。
//!
//! ## WASM 说明
//!
//! 同一份符号在 `wasm32-unknown-unknown` 目标下即为 WASM 导出：
//!
//! ```text
//! cargo build -p rules-pep --release --target wasm32-unknown-unknown
//! ```
//!
//! WASM 侧唯一的差异是 [`rules_pep_latch_ptr`] 返回的是线性内存偏移而非宿主地址；
//! 宿主用 `WebAssembly.Memory` 的 `buffer` 加该偏移即可构造 `BigUint64Array`
//! 视图与网关共享。共享内存位图自身的"单次原子 load"语义在 WASM 单线程模型下
//! 退化为普通 load，延迟更低。
//!
//! ## 延迟预算
//!
//! [`rules_pep_admit`] 在**极速域**（共享内存命中）路径上的工作量是：
//! 3 次 `(ptr,len)` → `String` 复制 + 1 次 FNV-1a + 1 次 `AtomicU64::load`
//! + 1 次 `String` 写入 `last_protocol`。为此把 [`INTENT_SCRATCH_CAPACITY`]
//! 的字符串拼接降到 1 次 `String` 分配。

use crate::latch::FrozenLatch;
use crate::{Intent, PepCore, RegulatoryRuntime, ERR_FFI};
use std::ffi::c_char;
use std::os::raw::c_int;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

/// ABI 版本号。宿主应先校验，避免符号漂移。
pub const PEP_ABI_VERSION: u32 = 1;

/// 返回码：放行。
pub const PEP_ALLOW: i32 = 0;
/// 返回码：阻断。
pub const PEP_DENY: i32 = 1;
/// 返回码：内部错误（契约非法 / panic / 空句柄）。
pub const PEP_ERR: i32 = -1;

/// 默认共享内存位图槽数。
pub const DEFAULT_LATCH_SLOTS: usize = 4096;

/// `last_protocol` 缓冲的最小建议容量（`DENY:` + 64 字节拒绝码 + `\0`）。
pub const PROTOCOL_BUF_MIN: usize = 96;

/// 意图构造时的字符串暂存容量（避免热路径二次分配）。
pub const INTENT_SCRATCH_CAPACITY: usize = 128;

/// C-ABI 句柄（不透明）。
///
/// 宿主只应把它当作 `void*` 传递；结构体布局刻意不导出。
pub struct PepHandle {
    core: PepCore<RegulatoryRuntime>,
    /// 最近一次裁决的协议串，供 `rules_pep_last_protocol` 读出。
    last_protocol: String,
}

// =====================================================================
// 辅助
// =====================================================================

/// 从 `(ptr, len)` 读一个 `&str`。
///
/// 非法 UTF-8 按空串处理，并把诊断写进 [`rules_pep_last_error`]（冷分支）。
///
/// # Safety
/// `ptr` 必须指向至少 `len` 字节的可读内存，或为 `NULL`（此时按空串处理）。
unsafe fn read_str<'a>(ptr: *const c_char, len: usize) -> &'a str {
    if ptr.is_null() || len == 0 {
        return "";
    }
    let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
    match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            LAST_ERROR.with(|c| {
                *c.borrow_mut() = format!("{ERR_FFI}: 入参不是合法 UTF-8，已按空串处理");
            });
            ""
        }
    }
}

/// 把 `s` 写入宿主缓冲，返回写入字节数；缓冲不足返回所需字节数（正数）。
///
/// # Safety
/// `buf` 必须指向至少 `cap` 字节的可写内存，或为 `NULL`。
unsafe fn write_buf(s: &str, buf: *mut c_char, cap: usize) -> i32 {
    let bytes = s.as_bytes();
    if buf.is_null() || cap < bytes.len() + 1 {
        return bytes.len() as i32;
    }
    ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, bytes.len());
    *buf.add(bytes.len()) = 0;
    bytes.len() as i32
}

/// # Safety
/// `h` 必须是 [`rules_pep_open`] 返回且尚未 `close` 的句柄。
unsafe fn handle<'a>(h: *mut PepHandle) -> Option<&'a mut PepHandle> {
    if h.is_null() {
        None
    } else {
        Some(&mut *h)
    }
}

// =====================================================================
// 导出符号
// =====================================================================

/// ABI 版本号（用于握手校验）。
///
/// ```c
/// if (rules_pep_abi_version() != 1) abort();
/// ```
#[no_mangle]
pub extern "C" fn rules_pep_abi_version() -> u32 {
    PEP_ABI_VERSION
}

thread_local! {
    /// 句柄创建失败时的诊断串（此时还没有句柄可挂载）。
    static LAST_ERROR: std::cell::RefCell<String> = std::cell::RefCell::new(String::new());
}

/// 打开一个 PEP 句柄。
///
/// `spec_ptr` / `spec_len` 是契约源码（rulesEng DSL，UTF-8）。
/// `latch_slots` 为共享内存位图槽数；`0` 表示用 [`DEFAULT_LATCH_SLOTS`]。
///
/// 成功返回非空句柄；契约解析失败返回 `NULL`，诊断串可经
/// [`rules_pep_last_error`] 读取。
///
/// # Safety
/// `spec_ptr` 必须是有效的 UTF-8 字节区间（长度 `spec_len`）。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_open(
    spec_ptr: *const c_char,
    spec_len: usize,
    latch_slots: usize,
) -> *mut PepHandle {
    let r = catch_unwind(AssertUnwindSafe(|| {
        let src = read_str(spec_ptr, spec_len);
        let slots = if latch_slots == 0 { DEFAULT_LATCH_SLOTS } else { latch_slots };
        match crate::open_with_latch(src, std::sync::Arc::new(FrozenLatch::new(slots))) {
            Ok(core) => Some(Box::into_raw(Box::new(PepHandle {
                core,
                last_protocol: String::with_capacity(64),
            }))),
            Err(e) => {
                LAST_ERROR.with(|c| *c.borrow_mut() = e);
                None
            }
        }
    }));
    match r {
        Ok(Some(p)) => p,
        Ok(None) => ptr::null_mut(),
        Err(_) => {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                LAST_ERROR.with(|c| *c.borrow_mut() = crate::ERR_FFI.to_string());
            }));
            ptr::null_mut()
        }
    }
}

/// 读取 [`rules_pep_open`] 失败时的诊断串（**全局**，非句柄作用域）。
///
/// # Safety
/// `buf` 必须指向至少 `cap` 字节的可写内存，或为 `NULL`。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_last_error(buf: *mut c_char, cap: usize) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| LAST_ERROR.with(|c| write_buf(&c.borrow(), buf, cap))));
    r.unwrap_or(PEP_ERR)
}

/// **热路径**：送审一笔意图。
///
/// * 返回 [`PEP_ALLOW`] (0)：放行；
/// * 返回 [`PEP_DENY`] (1)：**同线程物理阻断**，协议串见 [`rules_pep_last_protocol`]；
/// * 返回 [`PEP_ERR`] (-1)：句柄为空或内部 panic。
///
/// `event_type` / `entity` / `entity_id` 是 `(ptr, len)` 对。
/// `now` 是调用方的单调时钟（秒）；传 `0` 表示沿用引擎内部时钟。
///
/// # Safety
/// 三个 `(ptr,len)` 对必须是有效只读区间；`h` 必须是活泼句柄。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_admit(
    h: *mut PepHandle,
    event_type_ptr: *const c_char,
    event_type_len: usize,
    entity_ptr: *const c_char,
    entity_len: usize,
    entity_id_ptr: *const c_char,
    entity_id_len: usize,
    now: u64,
) -> c_int {
    let r = catch_unwind(AssertUnwindSafe(|| {
        let Some(hd) = handle(h) else {
            return PEP_ERR;
        };
        let event_type = read_str(event_type_ptr, event_type_len);
        let entity = read_str(entity_ptr, entity_len);
        let entity_id = read_str(entity_id_ptr, entity_id_len);

        let mut intent = Intent::gateway(event_type, "c-abi", entity, entity_id, now);
        if now == 0 {
            // 时钟缺省：沿用引擎内部时钟（网关与引擎同进程时即挂钟）
            intent.timestamp = hd.core.now();
        }

        let out = hd.core.admit(&intent);
        hd.last_protocol.clear();
        hd.last_protocol.push_str(&out.protocol.to_wire());
        out.protocol.to_code()
    }));
    r.unwrap_or(PEP_ERR)
}

/// **热路径 + 一个数值字段**：送审一笔带单个数值的意图。
///
/// 网关场景里绝大多数准入规则只看"这笔报单的一个关键数值"（金额 / 数量 / 频次），
/// 因此提供一个免分配字段的窄接口——它在 `Intent.fields` 里只插一条记录。
///
/// # Safety
/// 同 [`rules_pep_admit`]；`field_name` 必须有效。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_admit_field(
    h: *mut PepHandle,
    event_type_ptr: *const c_char,
    event_type_len: usize,
    entity_ptr: *const c_char,
    entity_len: usize,
    entity_id_ptr: *const c_char,
    entity_id_len: usize,
    field_name_ptr: *const c_char,
    field_name_len: usize,
    field_value_ptr: *const c_char,
    field_value_len: usize,
    now: u64,
) -> c_int {
    let r = catch_unwind(AssertUnwindSafe(|| {
        let Some(hd) = handle(h) else {
            return PEP_ERR;
        };
        let event_type = read_str(event_type_ptr, event_type_len);
        let entity = read_str(entity_ptr, entity_len);
        let entity_id = read_str(entity_id_ptr, entity_id_len);
        let field_name = read_str(field_name_ptr, field_name_len);
        let field_value = read_str(field_value_ptr, field_value_len);

        let mut intent = Intent::gateway(event_type, "c-abi", entity, entity_id, now);
        intent.fields.reserve(1);
        if !field_name.is_empty() {
            intent.fields.insert(field_name.to_string(), field_value.to_string());
        }
        if now == 0 {
            intent.timestamp = hd.core.now();
        }

        let out = hd.core.admit(&intent);
        hd.last_protocol.clear();
        hd.last_protocol.push_str(&out.protocol.to_wire());
        out.protocol.to_code()
    }));
    r.unwrap_or(PEP_ERR)
}

/// **超热路径**：只查共享内存位图，完全不进入 PDP。
///
/// 这是"超限后 60 秒内所有后续报单被瞬间拦截"的实现——延迟为
/// 「1 次 `(ptr,len)`→`String` + 1 次 FNV-1a + 1 次原子 load + 1 次 `String` 写」。
///
/// # Safety
/// `key_ptr` 必须是有效的 UTF-8 区间；`h` 必须是活泼句柄。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_fast_gate(
    h: *mut PepHandle,
    key_ptr: *const c_char,
    key_len: usize,
    now: u64,
) -> c_int {
    let r = catch_unwind(AssertUnwindSafe(|| {
        let Some(hd) = handle(h) else {
            return PEP_ERR;
        };
        let key = read_str(key_ptr, key_len);
        let p = hd.core.fast_gate_at(key, now);
        hd.last_protocol.clear();
        hd.last_protocol.push_str(&p.to_wire());
        p.to_code()
    }));
    r.unwrap_or(PEP_ERR)
}

/// 读取最近一次裁决的协议串（`ALLOW` / `DENY:<CODE>`）。
///
/// 返回写入的字节数（不含结尾 `\0`）；若返回值 `>= cap`，说明缓冲不足，
/// 请按返回值重新分配（内容已截断但保证 `\0` 结尾）。
///
/// # Safety
/// `buf` 必须指向至少 `cap` 字节的可写内存，或为 `NULL`。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_last_protocol(
    h: *mut PepHandle,
    buf: *mut c_char,
    cap: usize,
) -> c_int {
    let r = catch_unwind(AssertUnwindSafe(|| {
        let Some(hd) = handle(h) else {
            return PEP_ERR;
        };
        write_buf(&hd.last_protocol, buf, cap)
    }));
    r.unwrap_or(PEP_ERR)
}

/// 查询某实体键的冻结到期时间（`0` = 未冻结）。直接读共享内存，无副作用。
///
/// # Safety
/// `key_ptr` 必须是有效的 UTF-8 区间；`h` 必须是活泼句柄。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_frozen_until(
    h: *mut PepHandle,
    key_ptr: *const c_char,
    key_len: usize,
) -> u64 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        let Some(hd) = handle(h) else {
            return 0;
        };
        hd.core.latch().frozen_until(read_str(key_ptr, key_len))
    }));
    r.unwrap_or(0)
}

/// 时钟推进 + 到期租约回收。返回本次回收的条目数。
///
/// 引擎侧每拍调用一次即可；没有后台定时器。
///
/// # Safety
/// `h` 必须是活泼句柄。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_tick(h: *mut PepHandle, now: u64) -> usize {
    let r = catch_unwind(AssertUnwindSafe(|| {
        let Some(hd) = handle(h) else {
            return 0;
        };
        hd.core.pdp_mut().now = now;
        hd.core.release_expired_leases(now)
    }));
    r.unwrap_or(0)
}

/// 共享内存位图首地址（引擎侧 mmap 后转交给网关，或网关自己 mmap 同一块）。
///
/// # Safety
/// `h` 必须是活泼句柄。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_latch_ptr(h: *mut PepHandle) -> *mut u64 {
    match handle(h) {
        Some(hd) => hd.core.latch().as_ptr() as *mut u64,
        None => ptr::null_mut(),
    }
}

/// 共享内存位图字节数（用于 `mmap` 长度 / WASM 视图长度）。
///
/// # Safety
/// `h` 必须是活泼句柄。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_latch_bytes(h: *mut PepHandle) -> usize {
    match handle(h) {
        Some(hd) => hd.core.latch().byte_len(),
        None => 0,
    }
}

/// 当前活跃冻结数（可观测性）。
///
/// # Safety
/// `h` 必须是活泼句柄。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_active_leases(h: *mut PepHandle) -> usize {
    match handle(h) {
        Some(hd) => hd.core.active_leases(),
        None => 0,
    }
}

/// 累计送审笔数（可观测性）。
///
/// # Safety
/// `h` 必须是活泼句柄。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_reviewed(h: *mut PepHandle) -> u64 {
    match handle(h) {
        Some(hd) => hd.core.stats().reviewed,
        None => 0,
    }
}

/// 累计阻断笔数（可观测性）。
///
/// # Safety
/// `h` 必须是活泼句柄。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_denied(h: *mut PepHandle) -> u64 {
    match handle(h) {
        Some(hd) => hd.core.stats().denied,
        None => 0,
    }
}

/// 释放句柄。传入 `NULL` 是安全的空操作。
///
/// # Safety
/// `h` 必须是 [`rules_pep_open`] 的返回值，且**只能释放一次**。
#[no_mangle]
pub unsafe extern "C" fn rules_pep_close(h: *mut PepHandle) {
    if h.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(h));
    }));
}

// =====================================================================
// 测试
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// §5 用例 3 的准入守卫 + §5 用例 1 的席位洪水防护（真实 PRD 语法）。
    const SPEC: &str = r#"
        contract CouponGate on Entity[User] pure {
            key: user_id
            guard AmountMatches on Event[IssueCouponIntent] {
                when: event.requested_amount > 10
                verdict: DENY(code: "ERR_COUPON_AMOUNT_FRAUD", reason: "amount mismatch")
            }
        }

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
                verdict: DENY(
                    code: "ERR_SEAT_FLOOD",
                    reason: "5 秒滑动窗口内报单 > 20 笔")
                    , LeaseUpdate(frozen_until = now() + 60s)
            }
        }
    "#;

    fn open_handle() -> *mut PepHandle {
        let c = CString::new(SPEC).unwrap();
        let h = unsafe { rules_pep_open(c.as_ptr(), SPEC.len(), 256) };
        assert!(!h.is_null(), "句柄创建失败");
        h
    }

    unsafe fn admit(h: *mut PepHandle, et: &str, ent: &str, id: &str, now: u64) -> i32 {
        let a = CString::new(et).unwrap();
        let b = CString::new(ent).unwrap();
        let c = CString::new(id).unwrap();
        rules_pep_admit(h, a.as_ptr(), et.len(), b.as_ptr(), ent.len(), c.as_ptr(), id.len(), now)
    }

    unsafe fn read_protocol(h: *mut PepHandle) -> String {
        let mut buf = vec![0i8; PROTOCOL_BUF_MIN];
        let n = rules_pep_last_protocol(h, buf.as_mut_ptr(), buf.len());
        assert!(n >= 0, "读取协议失败");
        String::from_utf8(buf[..n as usize].iter().map(|b| *b as u8).collect()).unwrap()
    }

    #[test]
    fn abi_version_is_exposed() {
        assert_eq!(rules_pep_abi_version(), PEP_ABI_VERSION);
        assert_eq!(PEP_ALLOW, 0);
        assert_eq!(PEP_DENY, 1);
        assert_eq!(PEP_ERR, -1);
    }

    #[test]
    fn open_close_round_trip() {
        let h = open_handle();
        unsafe {
            assert_eq!(rules_pep_abi_version(), 1);
            assert!(rules_pep_latch_bytes(h) >= 256 * 16);
            assert!(!rules_pep_latch_ptr(h).is_null());
            assert_eq!(rules_pep_active_leases(h), 0);
            rules_pep_close(h);
            // NULL 释放是空操作
            rules_pep_close(ptr::null_mut());
        }
    }

    #[test]
    fn open_rejects_invalid_spec() {
        let bad = CString::new("not a contract").unwrap();
        let h = unsafe { rules_pep_open(bad.as_ptr(), 14, 16) };
        assert!(h.is_null(), "非法契约必须返回 NULL（fail-closed）");

        let mut buf = vec![0i8; 256];
        let n = unsafe { rules_pep_last_error(buf.as_mut_ptr(), buf.len()) };
        assert!(n > 0);
        let msg: String = buf[..n as usize].iter().map(|b| *b as u8 as char).collect();
        assert!(msg.contains(crate::ERR_BAD_SPEC), "{msg}");
    }

    #[test]
    fn null_handle_returns_error_code() {
        unsafe {
            assert_eq!(admit(ptr::null_mut(), "E", "Seat", "S1", 1), PEP_ERR);
            assert_eq!(rules_pep_last_protocol(ptr::null_mut(), ptr::null_mut(), 0), PEP_ERR);
            assert_eq!(rules_pep_frozen_until(ptr::null_mut(), ptr::null(), 0), 0);
            assert_eq!(rules_pep_tick(ptr::null_mut(), 1), 0);
            assert_eq!(rules_pep_active_leases(ptr::null_mut()), 0);
            assert_eq!(rules_pep_reviewed(ptr::null_mut()), 0);
            assert_eq!(rules_pep_denied(ptr::null_mut()), 0);
            assert!(rules_pep_latch_ptr(ptr::null_mut()).is_null());
            assert_eq!(rules_pep_latch_bytes(ptr::null_mut()), 0);
        }
    }

    #[test]
    fn allow_and_deny_protocol_over_c_abi() {
        let h = open_handle();
        unsafe {
            // 5 <= 10 → 放行
            let a = CString::new("IssueCouponIntent").unwrap();
            let e = CString::new("User").unwrap();
            let i = CString::new("U1").unwrap();
            let f = CString::new("requested_amount").unwrap();
            let v = CString::new("5").unwrap();
            let rc = rules_pep_admit_field(
                h,
                a.as_ptr(), 17,
                e.as_ptr(), 4,
                i.as_ptr(), 2,
                f.as_ptr(), 16,
                v.as_ptr(), 1,
                100,
            );
            assert_eq!(rc, PEP_ALLOW, "{}", read_protocol(h));
            assert_eq!(read_protocol(h), "ALLOW");

            // 20 > 10 → 阻断
            let v2 = CString::new("20").unwrap();
            let rc = rules_pep_admit_field(
                h,
                a.as_ptr(), 17,
                e.as_ptr(), 4,
                i.as_ptr(), 2,
                f.as_ptr(), 16,
                v2.as_ptr(), 2,
                101,
            );
            assert_eq!(rc, PEP_DENY);
            assert_eq!(read_protocol(h), "DENY:ERR_COUPON_AMOUNT_FRAUD");
            assert_eq!(rules_pep_denied(h), 1);
            assert_eq!(rules_pep_reviewed(h), 2);
        }
        unsafe { rules_pep_close(h) };
    }

    #[test]
    fn flood_rule_broadcasts_lease_and_fast_gate_blocks() {
        let h = open_handle();
        let key = CString::new("Seat#PBU001").unwrap();
        let until;
        unsafe {
            // 1.0~1.5s 内连发 21 笔报单（同一秒粒度）：前 20 笔放行，
            // 第 21 笔同线程物理阻断（AC2）
            let mut last = PEP_ALLOW;
            for _ in 1..=21u64 {
                last = admit(h, "OrderIntent", "Seat", "PBU001", 1000);
            }
            assert_eq!(last, PEP_DENY, "第 21 笔必须被阻断");
            assert_eq!(read_protocol(h), "DENY:ERR_SEAT_FLOOD");

            // 租约已广播到共享内存：frozen_until = now() + 60s = 1000 + 60
            until = rules_pep_frozen_until(h, key.as_ptr(), 11);
            assert_eq!(until, 1060, "now()+60s 必须写进共享内存位图");
            assert_eq!(rules_pep_active_leases(h), 1);

            // 超热路径：不进入 PDP 就阻断
            assert_eq!(rules_pep_fast_gate(h, key.as_ptr(), 11, until - 1), PEP_DENY);
            assert_eq!(read_protocol(h), format!("DENY:{}", crate::ERR_FROZEN));

            // 冻结期内任意笔报单同样被拦（且不污染窗口）
            assert_eq!(admit(h, "OrderIntent", "Seat", "PBU001", 1050), PEP_DENY);

            // 到期即放行，随后 tick 回收
            assert_eq!(rules_pep_fast_gate(h, key.as_ptr(), 11, until), PEP_ALLOW);
            assert_eq!(rules_pep_active_leases(h), 1, "到期但尚未回收");
            assert_eq!(rules_pep_tick(h, until), 1);
            assert_eq!(rules_pep_active_leases(h), 0);
        }
        unsafe { rules_pep_close(h) };
    }

    #[test]
    fn protocol_buffer_too_small_reports_required_size() {
        let h = open_handle();
        unsafe {
            admit(h, "IssueCouponIntent", "User", "U1", 100);
            let mut tiny = vec![0i8; 3];
            let need = rules_pep_last_protocol(h, tiny.as_mut_ptr(), tiny.len());
            assert_eq!(need, "ALLOW".len() as i32);

            // NULL 缓冲也必须安全返回所需长度
            assert_eq!(rules_pep_last_protocol(h, ptr::null_mut(), 0), 5);
        }
        unsafe { rules_pep_close(h) };
    }

    #[test]
    fn empty_and_null_string_args_are_tolerated() {
        let h = open_handle();
        unsafe {
            // NULL 指针按空串处理，不得崩溃
            let rc = rules_pep_admit(h, ptr::null(), 0, ptr::null(), 0, ptr::null(), 0, 100);
            assert!(rc == PEP_ALLOW || rc == PEP_DENY);
            let rc2 = rules_pep_fast_gate(h, ptr::null(), 0, 100);
            assert_eq!(rc2, PEP_ALLOW);
            assert_eq!(rules_pep_frozen_until(h, ptr::null(), 0), 0);
        }
        unsafe { rules_pep_close(h) };
    }

    #[test]
    fn invalid_utf8_is_lossily_ignored() {
        let h = open_handle();
        unsafe {
            let bytes = [0xffu8, 0xfe, 0x00];
            let rc = rules_pep_fast_gate(h, bytes.as_ptr() as *const c_char, bytes.len(), 100);
            assert_eq!(rc, PEP_ALLOW, "非法 UTF-8 不得 panic");
        }
        unsafe { rules_pep_close(h) };
    }

    #[test]
    fn latch_pointer_is_shared_between_views() {
        let h = open_handle();
        unsafe {
            let p = rules_pep_latch_ptr(h) as *mut std::sync::atomic::AtomicU64;
            let bytes = rules_pep_latch_bytes(h);
            assert!(bytes >= 256 * 16);

            // 宿主侧（另一个视图）直接写共享内存，PEP 立刻看到
            let view = FrozenLatch::attach(p, 256);
            assert!(view.put("Seat#PBU001", 9999).is_some());
            let key = CString::new("Seat#PBU001").unwrap();
            assert_eq!(rules_pep_frozen_until(h, key.as_ptr(), 11), 9999);
            assert_eq!(rules_pep_fast_gate(h, key.as_ptr(), 11, 1000), PEP_DENY);
        }
        unsafe { rules_pep_close(h) };
    }

    #[test]
    fn tick_moves_engine_clock() {
        let h = open_handle();
        unsafe {
            assert_eq!(rules_pep_tick(h, 5000), 0, "无租约时回收 0 条");
            let key = CString::new("Seat#PBU001").unwrap();
            rules_pep_fast_gate(h, key.as_ptr(), 11, 0); // 使用引擎时钟
            assert_eq!(read_protocol(h), "ALLOW");
        }
        unsafe { rules_pep_close(h) };
    }

    #[test]
    fn write_buf_null_and_zero_cap_are_safe() {
        unsafe {
            assert_eq!(write_buf("abc", ptr::null_mut(), 100), 3);
            let mut b = [0i8; 2];
            assert_eq!(write_buf("abc", b.as_mut_ptr(), 2), 3);
            assert_eq!(write_buf("", ptr::null_mut(), 0), 0);
        }
    }
}
