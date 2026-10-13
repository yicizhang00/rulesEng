# rulesEng · 项目长期约定

## 语言范式（硬约束，勿回退）
- **不是 Drools / 产生式规则**。禁止再引入 `when P then {...}` 的 LHS→RHS 语义作为一等形式。
- AST 只围绕 4 个一阶概念：`Entity`（+`TransitionDecl`）/ `Stream&Event`（含算子链）/ `Metric`（派生信号流，三形态）/ `Spec`（MTL 时序不变量 + `ViolationHandler`）。
- `spec` 声明的是**合法状态空间**（不变量何时被打破由引擎求解），不是"何时触发动作"。
- 旧语法（`contract`/`signal`/`var`/`Stream[T]`/`stream X =`/`rule…when…then`/`exists(S)`）**必须继续能解析**，走 desugar；改动 parser 后必须复跑 `legacy_syntax_desugars_to_new_ast`。
- 执行层约定：`rules-temporal` 的 `AutoNode` 保持**后序布局**（子索引 < 父索引），`step()` 必须保持单向扫描、零递归；`rules-flatvm` 的文本相等一律走 `Interner` 的 u32 id。
- 运行期新增"枚举常量"（状态名 / 字面标识符 / 路径末段）时，必须在 `RegulatoryRuntime::new()` 的装载期预驻留，否则 `id_of()` 返回 0 会静默退化为数值比较。
- 新增引用流字段的地方（流 filter/map/fold、spec 的 `StreamQuant` lambda、metric 的 `StreamFold`）都必须同步登记到该流的投影字段，否则环里读不到该列。

## 校验语义（必须保持一致）
- **分级**：`VerifyReport.errors` 阻断规则入库；`VerifyReport.warnings` 仅提示。
  - errors：`UNDEFINED_ENTITY` / `UNDEFINED_STATE` / `DEAD_RULE_VACUOUS` / `DEAD_RULE_TAUTOLOGY` / `ACTION_CONFLICT` / `TYPE_MISMATCH` / `UNDEFINED_METRIC` / `TERMINAL_STATE_HAS_EDGE` / `UNDEFINED_TRANSITION_DRIVER` / `UNDECLARED_TRANSITION` / `CAUSAL_DEADLOCK_UNTIL` / `CAUSAL_DEADLOCK_EVENTUALLY` / `UNSATISFIABLE_INVARIANT` / `IMPOSSIBLE_CONSEQUENT`
  - warnings：`COVERAGE_GAP_STREAM` / `COVERAGE_GAP_DEAD_STATE` / `UNDEFINED_EXTERNAL_METRIC` / `REDUNDANT_SPEC` / `UNREACHABLE_STATE` / `STUCK_STATE` / `TRANSITION_DRIVER_MISMATCH`
- **外部符号策略**：未登记进数据字典的符号 → warning（设计文档 §7.3），不阻断；server 校验时把该规则 `rule_bindings` 中已绑定的符号名注入 `DataDictionary`。
- `Verifier::verify()` 保留"全量问题 → Err"的旧语义供 CLI 兼容；门禁一律用 `Verifier::verify_report()`。

## 数据与接口约定
- `rules-server` 永远返回 HTTP 200 + JSON；业务失败用 `{"error": "...", "errors": [...], "warnings": [...]}` 表达，前端 `data()` 抛带 `payload` 的 Error。
- 校验问题 JSON 的归属字段是 **`specs`**（不是 `contracts`）。
- `/parse` 与 `/verify` 接收**裸 DSL 文本**作为 body（不是 JSON 包 `{dsl:...}`）。
- 规则保存（POST/PUT）必产生一条 `rule_versions` 快照：`version = COALESCE(MAX(version),0)+1`，含 `dsl_text / ast_json / verify_report / submitted_by`；同时 upsert `rule_triggers`。
- `mode`：`LIFECYCLE`（订阅式）/ `ONCE`（定时，必填 cron）；缺省 `LIFECYCLE`。
- 实体实例键：DSL `entity X(key: k)` / `entity X { key: k }` 的 `k` 优先，回落 `<entity_lowercase>_id`。
- MySQL `JSON` 类型列（`ast_json` / `verify_report` / `diff_vs_prev`）不可用 `row.get::<String>()` 解码，会 panic 掉连接；必须走 `row_opt_text()`。

## 代码组织
- 规则版本 / 证据链 / 回测是独立 crate，**尚未接入 server/web**；改动它们不影响控制面。
- 前端纯逻辑放 `web/src/logic/`（可被 Vitest 直接测），不要塞进 `.vue`。
- 前端禁止 `prompt/alert/confirm`，一律 Element Plus 弹窗 + `ElMessage`。

## 环境坑
- 遗留 `rules-server.exe` 常驻会锁 `target/debug/deps/rules_server.exe` → `cargo build` 报 LNK1104；`cargo check` 可通过。先 `taskkill /F /PID <pid>`。
- `error deleting lock file … 拒绝访问 (os error 5)` 是 Windows 增量编译锁，无害。
- 前端 vite 绑 `localhost`（IPv6 `::1`），验证用 `localhost` 而非 `127.0.0.1`；`vite.config.js` 已设 `strictPort: true`。
