import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import {
  MODES, HIT_POLICIES, STATUSES,
  sanitizeIdent, validateCanvas, nodesToDsl, dslToNodes, extractBindingTargets,
} from '../src/logic/dsl.js'

// ---------------------------------------------------------------------------
// 画布构造辅助
// ---------------------------------------------------------------------------

function canvas(mode, extra = {}) {
  const entity = {
    id: 'entity_1', type: 'entity',
    data: {
      entity: 'Account', key: 'account_id', states: 'NORMAL, RESTRICTED',
      initial: 'NORMAL', terminal: 'RESTRICTED', events: 'TradeIntent',
      ...(extra.entity || {}),
    },
  }
  const action = {
    id: 'action_1', type: 'action',
    data: {
      verdict: 'DENY', code: 'ERR_CANCEL_RATIO', reason: '撤单率异常', severity: 'CRITICAL',
      emit: '撤单率异常', transitionFrom: 'NORMAL', transitionTo: 'RESTRICTED',
      leaseTarget: '', leaseSeconds: '', ...(extra.action || {}),
    },
  }
  const conditions = (extra.conditions || [{ field: 'cancel_ratio', op: '>', value: '0.85', logic: 'AND' }])
    .map((data, index) => ({ id: `condition_${index + 1}`, type: 'condition', data }))
  const nodes = [entity]
  const edges = []
  let previous = entity
  if (mode === 'DMN') {
    const dmn = {
      id: 'dmn_1', type: 'dmn',
      data: {
        table: 'DetermineAmount', param: 'req_time', paramType: 'Timestamp',
        outputs: ['amount', 'phase'], outputTypes: ['Int', 'Int'], hitPolicy: 'UNIQUE',
        lookupArg: 'event.timestamp',
        rows: [
          { isDefault: false, from: '11-01', to: '11-03', out: '10, 1' },
          { isDefault: false, from: '11-04', to: '11-05', out: '20, 2' },
          { isDefault: true, from: '', to: '', out: '0, 0' },
        ],
        ...(extra.dmn || {}),
      },
    }
    nodes.push(dmn)
    edges.push({ id: 'e0', source: previous.id, target: dmn.id })
    previous = dmn
  }
  for (const node of conditions) {
    nodes.push(node)
    edges.push({ id: `e-${node.id}`, source: previous.id, target: node.id })
    previous = node
  }
  nodes.push(action)
  edges.push({ id: 'e-act', source: previous.id, target: action.id })
  if (extra.breakEdge) edges.pop()
  return { nodes, edges }
}

const OPTIONS = (mode, extra) => ({ name: 'CancelRatioGuard', mode, ...canvas(mode, extra) })

// ---------------------------------------------------------------------------
// 模式目录
// ---------------------------------------------------------------------------

describe('模式目录（FR1）', () => {
  it('四模齐全且落库取值与 rules.mode ENUM 一致', () => {
    expect(MODES.map(m => m.value)).toEqual(['PURE', 'STATEFUL', 'STREAM', 'DMN'])
    expect(MODES.map(m => m.dsl)).toEqual(['pure', 'stateful', 'stream', 'decision_table'])
  })

  it('命中策略与生命周期状态与 PRD 对齐', () => {
    expect(HIT_POLICIES).toEqual(['UNIQUE', 'FIRST', 'PRIORITY', 'COLLECT'])
    expect(STATUSES).toEqual(['DRAFT', 'VERIFIED', 'PUBLISHED', 'ARCHIVED'])
  })
})

describe('sanitizeIdent', () => {
  it('把非 ASCII / 非法标识符压成合法标识符', () => {
    expect(sanitizeIdent('未命名规则')).toMatch(/^Rule_[A-Za-z0-9]+$/)
    expect(sanitizeIdent('__starts_with_underscore')).toMatch(/^Rule_[A-Za-z0-9]+$/)
    expect(sanitizeIdent('Good_Name')).toBe('Good_Name')
  })
})

// ---------------------------------------------------------------------------
// 画布 → DSL
// ---------------------------------------------------------------------------

describe('nodesToDsl — 模式 A（pure）', () => {
  it('生成 contract … pure + 事件作用域 guard + DENY 裁决（reason 为语法必填项）', () => {
    const dsl = nodesToDsl(OPTIONS('PURE'))
    expect(dsl).toContain('entity Account(key: account_id) {')
    expect(dsl).toContain('contract CancelRatioGuard on Entity[Account] pure {')
    expect(dsl).toContain('guard CancelRatioGuardCheck on Event[TradeIntent] {')
    expect(dsl).toContain('when: cancel_ratio > 0.85')
    expect(dsl).toContain('code: "ERR_CANCEL_RATIO"')
    expect(dsl).toContain('reason: "撤单率异常"')
    // 状态迁移必须挂在 transition 块里，驱动指向已声明策略名
    expect(dsl).toContain('transition CancelRatioGuardTransition {')
    expect(dsl).toContain('on: CancelRatioGuardCheck')
    expect(dsl).toContain('terminal: [RESTRICTED]')
  })

  it('ALLOW 裁决不生成 code / reason', () => {
    const dsl = nodesToDsl(OPTIONS('PURE', { action: { verdict: 'ALLOW', code: '', reason: '' } }))
    expect(dsl).toContain('verdict: ALLOW()')
    expect(dsl).not.toContain('DENY(')
  })

  it('多条件按连线顺序以 and / or 连接', () => {
    const dsl = nodesToDsl(OPTIONS('PURE', {
      conditions: [
        { field: 'cancel_ratio', op: '>', value: '0.85', logic: 'AND' },
        { field: 'trade_count', op: '>=', value: '100', logic: 'OR' },
      ],
    }))
    expect(dsl).toContain('when: cancel_ratio > 0.85 or trade_count >= 100')
  })

  it('无条件节点时退化为 when: true', () => {
    const dsl = nodesToDsl({ name: 'R', mode: 'PURE', ...canvas('PURE', { conditions: [] }) })
    expect(dsl).toContain('when: true')
  })

  it('悬空连线直接拒绝生成', () => {
    expect(nodesToDsl({ name: 'R', mode: 'PURE', ...canvas('PURE', { breakEdge: true }) })).toBe('')
  })
})

describe('nodesToDsl — 模式 C（stream）', () => {
  it('生成 state var 租约账本 + LeaseUpdate 惩罚租约（无后台定时器）', () => {
    const dsl = nodesToDsl(OPTIONS('STREAM', {
      entity: { states: 'OPEN, FROZEN', initial: 'OPEN', terminal: 'FROZEN' },
      action: { transitionFrom: 'OPEN', transitionTo: 'FROZEN', leaseTarget: 'frozen_until', leaseSeconds: '60' },
    }))
    expect(dsl).toContain('contract CancelRatioGuard on Entity[Account] stream {')
    expect(dsl).toContain('state var frozen_until: Timestamp = 0')
    expect(dsl).toContain('invariant CancelRatioGuardCheck on Event[TradeIntent] {')
    expect(dsl).toContain('LeaseUpdate(frozen_until = now() + 60s)')
  })

  it('未配置租约时不生成 state var 与 LeaseUpdate', () => {
    const dsl = nodesToDsl(OPTIONS('STREAM'))
    expect(dsl).not.toContain('LeaseUpdate')
    expect(dsl).not.toContain('state var')
  })
})

describe('nodesToDsl — 模式 D（DMN）', () => {
  it('生成 decision_table 声明 + let 元组查表 + 区间/default 规则行', () => {
    const dsl = nodesToDsl(OPTIONS('DMN', { conditions: [{ field: 'amount', op: '!=', value: '10', logic: 'AND' }] }))
    expect(dsl).toContain('contract CancelRatioGuard on Entity[Account] decision_table {')
    expect(dsl).toContain('decision_table DetermineAmount(req_time: Timestamp) -> (amount: Int, phase: Int) {')
    expect(dsl).toContain('hit_policy: UNIQUE')
    expect(dsl).toContain('in [11-01 .. 11-03] => (10, 1)')
    expect(dsl).toContain('default => (0, 0)')
    expect(dsl).toContain('let (amount, phase) = DetermineAmount(event.timestamp)')
    expect(dsl).toContain('when: amount != 10')
  })

  it('单输出列使用非元组 let 绑定', () => {
    const dsl = nodesToDsl(OPTIONS('DMN', {
      dmn: { outputs: ['amount'], outputTypes: ['Int'], rows: [{ isDefault: true, from: '', to: '', out: '0' }] },
    }))
    expect(dsl).toContain('-> (amount: Int) {')
    expect(dsl).toContain('let amount = DetermineAmount(event.timestamp)')
  })

  it('非 DMN 模式下挂在画布上的决策表节点会被拒绝', () => {
    const graph = canvas('DMN')
    expect(validateCanvas({ mode: 'PURE', ...graph })).toContain('决策表节点只在模式 D')
    expect(nodesToDsl({ name: 'R', mode: 'PURE', ...graph })).toBe('')
  })

  it('DMN 模式缺少决策表节点时报错', () => {
    expect(validateCanvas({ mode: 'DMN', ...canvas('PURE') })).toContain('DMN 决策表节点')
  })
})

describe('nodesToDsl — 模式 B（stateful）', () => {
  it('生成 rule "…" stateful { when: $e: E(…) then: yield DENY(…) }', () => {
    const dsl = nodesToDsl(OPTIONS('STATEFUL'))
    expect(dsl).toContain('rule "CancelRatioGuard" stateful {')
    expect(dsl).toContain('$e: Account(cancel_ratio > 0.85)')
    expect(dsl).toContain('yield DENY(')
    expect(dsl).toContain('code: "ERR_CANCEL_RATIO"')
    // 模式 B 的规则体不是策略块，transition 不挂驱动
    expect(dsl).toContain('transition CancelRatioGuardTransition {')
    expect(dsl).not.toContain('on: CancelRatioGuardCheck')
  })
})

// ---------------------------------------------------------------------------
// 画布校验
// ---------------------------------------------------------------------------

describe('validateCanvas', () => {
  it('四模的起手画布都合法', () => {
    for (const mode of ['PURE', 'STATEFUL', 'STREAM', 'DMN']) {
      const extra = mode === 'STREAM'
        ? { action: { leaseTarget: 'frozen_until', leaseSeconds: '60' } }
        : {}
      expect(validateCanvas({ mode, ...canvas(mode, extra) })).toBeNull()
    }
  })

  it('拦住缺节点、成环、双 Action、非法标识符与非法算子', () => {
    expect(validateCanvas({ mode: 'PURE', nodes: [], edges: [] })).toContain('Entity 节点')
    const missingAction = canvas('PURE')
    missingAction.nodes = missingAction.nodes.filter(n => n.type !== 'action')
    expect(validateCanvas({ mode: 'PURE', ...missingAction })).toContain('Action 节点')

    const cyclic = canvas('PURE')
    cyclic.edges.push({ id: 'cycle', source: 'condition_1', target: 'condition_1' })
    // 环路必然破坏「每个节点恰好一条上游」的链路约束，结构必须被拒
    expect(validateCanvas({ mode: 'PURE', ...cyclic })).toBeTruthy()

    const badOp = canvas('PURE', { conditions: [{ field: 'ratio', op: 'LIKE', value: '1' }] })
    expect(validateCanvas({ mode: 'PURE', ...badOp })).toContain('比较符')

    const badField = canvas('PURE', { conditions: [{ field: '1ratio', op: '>', value: '1' }] })
    expect(validateCanvas({ mode: 'PURE', ...badField })).toContain('字段')
  })

  it('拦住初始状态不在状态列表、终态不在状态列表、非法状态迁移', () => {
    expect(validateCanvas({ mode: 'PURE', ...canvas('PURE', { entity: { initial: 'GHOST' } }) })).toContain('初始状态')
    expect(validateCanvas({ mode: 'PURE', ...canvas('PURE', { entity: { terminal: 'GHOST' } }) })).toContain('终态')
    expect(validateCanvas({ mode: 'PURE', ...canvas('PURE', { action: { transitionFrom: 'NORMAL', transitionTo: '' } }) })).toContain('同时填写')
  })

  it('DENY 必须有 code 与 reason', () => {
    expect(validateCanvas({ mode: 'PURE', ...canvas('PURE', { action: { code: '' } }) })).toContain('code')
    expect(validateCanvas({ mode: 'PURE', ...canvas('PURE', { action: { reason: '' } }) })).toContain('reason')
  })

  it('STREAM 租约必须给正数秒数', () => {
    const bad = canvas('STREAM', { action: { leaseTarget: 'frozen_until', leaseSeconds: '0' } })
    expect(validateCanvas({ mode: 'STREAM', ...bad })).toContain('秒数')
  })

  it('DMN 要求至少一行规则、必须有 default 兜底、区间必须完整', () => {
    const rows = [{ isDefault: false, from: '1', to: '2', out: '10' }]
    expect(validateCanvas({ mode: 'DMN', ...canvas('DMN', { dmn: { rows } }) })).toContain('default')

    const incomplete = [{ isDefault: false, from: '', to: '2', out: '10' }, { isDefault: true, from: '', to: '', out: '0' }]
    expect(validateCanvas({ mode: 'DMN', ...canvas('DMN', { dmn: { rows: incomplete } }) })).toContain('下界')

    const badPolicy = canvas('DMN', { dmn: { hitPolicy: 'LAST' } })
    expect(validateCanvas({ mode: 'DMN', ...badPolicy })).toContain('命中策略')
  })
})

// ---------------------------------------------------------------------------
// DSL → 画布（AC6 双向无损）
// ---------------------------------------------------------------------------

describe('dslToNodes + 往返无损（AC6）', () => {
  const cases = {
    PURE: {},
    STATEFUL: {},
    STREAM: { action: { leaseTarget: 'frozen_until', leaseSeconds: '60' }, entity: { states: 'OPEN, FROZEN', initial: 'OPEN', terminal: 'FROZEN', events: 'OrderIntent' } },
    DMN: { conditions: [{ field: 'amount', op: '!=', value: '10', logic: 'AND' }] },
  }

  for (const [mode, extra] of Object.entries(cases)) {
    it(`${mode}：nodesToDsl(dslToNodes(dsl)) === dsl`, () => {
      const dsl = nodesToDsl(OPTIONS(mode, extra))
      const back = dslToNodes(dsl)
      expect(back.error).toBeNull()
      expect(back.mode).toBe(mode)
      expect(back.name).toBe('CancelRatioGuard')
      expect(nodesToDsl({ name: back.name, mode: back.mode, nodes: back.nodes, edges: back.edges })).toBe(dsl)
    })
  }

  it('往返保留裁决、效果、迁移与租约字段', () => {
    const dsl = nodesToDsl(OPTIONS('STREAM', {
      entity: { states: 'OPEN, FROZEN', initial: 'OPEN', terminal: 'FROZEN', events: 'OrderIntent' },
      action: { transitionFrom: 'OPEN', transitionTo: 'FROZEN', leaseTarget: 'frozen_until', leaseSeconds: '60', emit: '说 "你好"' },
    }))
    const action = dslToNodes(dsl).nodes.find(n => n.type === 'action')
    expect(action.data).toMatchObject({
      verdict: 'DENY',
      code: 'ERR_CANCEL_RATIO',
      reason: '撤单率异常',
      emit: '说 "你好"',
      transitionFrom: 'OPEN',
      transitionTo: 'FROZEN',
      leaseTarget: 'frozen_until',
      leaseSeconds: '60',
    })
  })

  it('往返保留 DMN 决策表全部结构', () => {
    const dsl = nodesToDsl(OPTIONS('DMN', { conditions: [{ field: 'amount', op: '!=', value: '10', logic: 'AND' }] }))
    const dmn = dslToNodes(dsl).nodes.find(n => n.type === 'dmn')
    expect(dmn.data.table).toBe('DetermineAmount')
    expect(dmn.data.param).toBe('req_time')
    expect(dmn.data.paramType).toBe('Timestamp')
    expect(dmn.data.outputs).toEqual(['amount', 'phase'])
    expect(dmn.data.hitPolicy).toBe('UNIQUE')
    expect(dmn.data.rows).toEqual([
      { isDefault: false, from: '11-01', to: '11-03', out: '10, 1' },
      { isDefault: false, from: '11-04', to: '11-05', out: '20, 2' },
      { isDefault: true, from: '', to: '', out: '0, 0' },
    ])
  })

  it('OR 连接符与函数调用字段能还原', () => {
    const dsl = nodesToDsl(OPTIONS('PURE', {
      conditions: [
        { field: 'cancel_ratio', op: '>', value: '0.85', logic: 'AND' },
        { field: 'DaysOverdue(deadline)', op: '>', value: '5', logic: 'OR' },
      ],
    }))
    const back = dslToNodes(dsl)
    expect(back.error).toBeNull()
    expect(back.nodes.filter(n => n.type === 'condition').map(n => n.data.logic)).toEqual(['AND', 'OR'])
    expect(back.nodes.filter(n => n.type === 'condition')[1].data.field).toBe('DaysOverdue(deadline)')
  })

  it('兼容旧版 rule … when … then 语法', () => {
    const back = dslToNodes('rule MyRule on Account when cancel_ratio > 0.85 then { severity: WARNING emit: "high rate" }')
    expect(back.error).toBeNull()
    expect(back.nodes.find(n => n.type === 'entity')?.data.entity).toBe('Account')
    expect(back.nodes.filter(n => n.type === 'condition')).toHaveLength(1)
  })

  it('无法映射到画布的 DSL 返回错误而不是抛异常', () => {
    expect(dslToNodes('not a rule').error).toBeTruthy()
    expect(dslToNodes('').nodes).toHaveLength(0)
    // 多事实模式（模式 B 的完整形态）超出画布子集 → 明确报错
    const complex = [
      'rule "X" stateful {',
      '    when: $a: Account(a > 1) $b: Order(b > 2)',
      '    then: yield DENY(code: "E", reason: "r")',
      '}',
    ].join('\n')
    expect(dslToNodes(complex).error).toBeTruthy()
  })

  it('§5 用例 1（stream）能载入画布的关键属性', () => {
    const dsl = [
      'entity Seat(key: seat_id) {',
      '    states: [OPEN, FROZEN]',
      '    initial: OPEN',
      '    terminal: [FROZEN]',
      '}',
      'contract SeatFloodProtection on Entity[Seat] stream {',
      '    key: seat_id',
      '    state var frozen_until: Timestamp = 0',
      '    guard IsNotFrozen on Event[OrderIntent, CancelIntent] {',
      '        when: now() < frozen_until',
      '        verdict: DENY(',
      '            code: "ERR_SEAT_FROZEN",',
      '            reason: "席位处于惩罚租约冻结期内")',
      '    }',
      '    metric window_order_count = sum(SeatActions[OrderIntent].count)',
      '    invariant MaxFrequencyLimit on Event[OrderIntent, CancelIntent] {',
      '        when: window_order_count > 20 or window_cancel_count > 10',
      '        verdict: DENY(',
      '            code: "ERR_SEAT_FLOOD",',
      '            reason: "5 秒滑动窗口内报单 > 20 笔或撤单 > 10 笔")',
      '            , LeaseUpdate(frozen_until = now() + 60s)',
      '    }',
      '}',
    ].join('\n')
    const back = dslToNodes(dsl)
    expect(back.error).toBeNull()
    expect(back.mode).toBe('STREAM')
    expect(back.nodes.find(n => n.type === 'entity').data).toMatchObject({
      entity: 'Seat', key: 'seat_id', states: 'OPEN, FROZEN', initial: 'OPEN', terminal: 'FROZEN',
    })
    const action = back.nodes.find(n => n.type === 'action')
    expect(action.data.code).toBe('ERR_SEAT_FROZEN')
    // 该用例有 2 个策略块（guard IsNotFrozen + invariant MaxFrequencyLimit），
    // 画布只呈现第 1 个 —— 必须给出明确告警而**不是**静默丢弃
    expect(back.warning).toContain('2 个策略块')
    expect(action.data.leaseTarget).toBe('')
  })

  it('examples/seat_flood_protection.rules（§5 原文）可载入并告警', () => {
    const dsl = readFileSync(
      join(process.cwd(), '..', 'examples', 'seat_flood_protection.rules'), 'utf8',
    )
    const back = dslToNodes(dsl)
    expect(back.error).toBeNull()
    expect(back.mode).toBe('STREAM')
    expect(back.name).toBe('SeatFloodProtection')
    // 原文含 guard IsNotFrozen + invariant MaxFrequencyLimit 两个策略块
    expect(back.warning).toContain('2 个策略块')
    // 第 1 个策略块（快筛）无租约，租约在第 2 个块上 —— 画布如实呈现为空
    expect(back.nodes.find(n => n.type === 'action').data.leaseTarget).toBe('')
  })

  it('单策略块的 DSL 不产生丢失告警', () => {
    expect(dslToNodes(nodesToDsl(OPTIONS('PURE'))).warning).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// 变量绑定提取（FR8.3）
// ---------------------------------------------------------------------------

describe('extractBindingTargets', () => {
  it('裸标识符进入 fields，派生信号进入 vars', () => {
    const dsl = 'contract R on Entity[Account] pure { guard G on Event[E] { when: cancel_ratio > 0.85 and trade_count >= 100 verdict: DENY(code: "E", reason: "r") } }'
    expect(extractBindingTargets(dsl)).toEqual({ vars: [], fields: ['cancel_ratio', 'trade_count'] })
  })

  it('零元 metric 声明单独归入 vars', () => {
    const dsl = [
      'metric cancel_ratio := Cancels.count() / Trades.count()',
      'contract R on Entity[Account] pure { guard G on Event[E] { when: cancel_ratio > 0.8 verdict: DENY(code: "E", reason: "r") } }',
    ].join('\n')
    expect(extractBindingTargets(dsl)).toEqual({ vars: ['cancel_ratio'], fields: [] })
  })

  it('state var（租约账本）不算外部列', () => {
    const dsl = [
      'contract R on Entity[Seat] stream {',
      '  state var frozen_until: Timestamp = 0',
      '  guard G on Event[O] { when: now() < frozen_until and seat_ratio > 0.5 verdict: DENY(code: "E", reason: "r") }',
      '}',
    ].join('\n')
    const { vars, fields } = extractBindingTargets(dsl)
    expect(vars).not.toContain('frozen_until')
    expect(fields).not.toContain('frozen_until')
    expect(fields).toContain('seat_ratio')
  })

  it('排除关键字、状态名、let 元组、决策表列名与内置函数', () => {
    const dsl = [
      'entity Company(key: code) { states: [NORMAL, SUSPENDED] initial: NORMAL terminal: [SUSPENDED] }',
      'stream Semi := Event[DisclosureEvent].filter(e => e.type == "SEMI_ANNUAL")',
      'contract C on Entity[Company] decision_table {',
      '  decision_table T(req_time: Timestamp) -> (amount: Int) {',
      '    hit_policy: UNIQUE',
      '    rules: [ in [11-01 .. 11-03] => (10), default => (0) ]',
      '  }',
      '  invariant Check on Event[Issue] {',
      '    let amount = T(event.timestamp)',
      '    when: event.requested != amount and now() > 100000.0 and DaysOverdue(deadline) > 5',
      '    verdict: DENY(code: "E", reason: "a > b")',
      '  }',
      '}',
    ].join('\n')
    const { vars, fields } = extractBindingTargets(dsl)
    expect(vars).toEqual([])
    expect(fields).not.toContain('amount')
    expect(fields).not.toContain('req_time')
    expect(fields).not.toContain('NORMAL')
    expect(fields).not.toContain('now')
    expect(fields).not.toContain('Deadline')
    // emit 文案里的 "a > b" 不能被当成比较式
    expect(fields).not.toContain('a')
  })
})

// ---------------------------------------------------------------------------
// FR10：禁止浏览器原生弹窗
// ---------------------------------------------------------------------------

describe('FR10 交互规范', () => {
  function walk(dir, out = []) {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry)
      if (statSync(full).isDirectory()) walk(full, out)
      else if (/\.(vue|js)$/.test(entry)) out.push(full)
    }
    return out
  }

  it('src 下不存在 alert / confirm / prompt 等原生弹窗调用', () => {
    const offenders = []
    for (const file of walk(join(process.cwd(), 'src'))) {
      const source = readFileSync(file, 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/^\s*\/\/.*$/gm, '')
      if (/(^|[^.\w])(window\.)?(alert|prompt)\s*\(/.test(source)) offenders.push(file)
      if (/(^|[^.\w])(window\.)?confirm\s*\(/.test(source)) offenders.push(file)
    }
    expect(offenders).toEqual([])
  })

  it('所有确认/提示都走 Element Plus（ElMessage / ElMessageBox）', () => {
    const home = join(process.cwd(), 'src', 'views', 'RulesView.vue')
    const source = readFileSync(home, 'utf8')
    expect(source).toContain('ElMessageBox.confirm')
    expect(source).toContain('ElMessage.')
  })
})
