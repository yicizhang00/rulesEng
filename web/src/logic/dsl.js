/**
 * 画布 ↔ DSL 双向转换（v1.0，FR10 / AC6）。
 *
 * 四模同构：同一套画布节点在不同模式下渲染出不同形态的 DSL——
 *
 * | 模式 | 画布链路 | 生成语法 |
 * |---|---|---|
 * | PURE     | Entity → Condition* → Action | `contract N on Entity[E] pure { guard N on Event[E] { when … verdict DENY(…) } }` |
 * | STREAM   | 同上（Action 可带惩罚租约）      | `contract N on Entity[E] stream { state var t: Timestamp = 0  invariant N on Event[E] { when … verdict DENY(…), LeaseUpdate(…) } }` |
 * | DMN      | Entity → Dmn → Condition* → Action | `decision_table T(…) -> (…) { hit_policy … rules: [ … ] }` + `let (…) = T(…)` |
 * | STATEFUL | Entity → Condition* → Action | `rule "N" stateful { when: $e: E(…) then: yield DENY(…) }` |
 *
 * 生成的文本必须能被 `rules-cli verify` 接受，并且 `dslToNodes(nodesToDsl(g))`
 * 能还原出同一张画布（AC6 的双向无损）。
 */

export const MODES = [
  { value: 'PURE', dsl: 'pure', label: '模式 A · Verified 纯函数', hint: '单调状态格 + Z3 死区/冲突/除零证明' },
  { value: 'STATEFUL', dsl: 'stateful', label: '模式 B · Drools 兼容', hint: '会话级工作内存 + DAG 无环 + 32 步熔断' },
  { value: 'STREAM', dsl: 'stream', label: '模式 C · 流式滑动窗口', hint: 'O(1) 窗口淘汰 + LeaseUpdate 惩罚租约' },
  { value: 'DMN', dsl: 'decision_table', label: '模式 D · DMN 决策表', hint: 'UNIQUE/FIRST/PRIORITY/COLLECT 命中策略' },
]

export const STATUSES = ['DRAFT', 'VERIFIED', 'PUBLISHED', 'ARCHIVED']
export const HIT_POLICIES = ['UNIQUE', 'FIRST', 'PRIORITY', 'COLLECT']
export const TYPES = ['Int', 'Float', 'Bool', 'String', 'Timestamp', 'BitVec']
export const OPS = ['>', '>=', '<', '<=', '==', '!=']

const IDENT = /^[A-Za-z][A-Za-z0-9_]*$/
/** 字段 token：支持 `a.b.c`、`DaysOverdue(x)` 与零参调用 `now()`。 */
const FIELD = /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*(?:\((?:[A-Za-z][A-Za-z0-9_.]*)?\))?$/
const VALUE = /^(?:-?\d+(?:\.\d+)?|true|false|[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*|"(?:[^"\\]|\\.)*")$/
/** 决策表区间端点：额外允许 `MM-DD` 这类"日历口径"裸词（FR3）。 */
const DMN_BOUND = /^(?:-?\d+(?:\.\d+)?|true|false|[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*|"(?:[^"\\]|\\.)*"|\d{2}-\d{2})$/

export function sanitizeIdent(name, fallback = 'Rule') {
  if (!name) return fallback
  if (IDENT.test(name)) return name
  let hash = 0
  for (const char of name) hash = (hash * 31 + char.charCodeAt(0)) >>> 0
  return `${fallback}_${hash.toString(36)}`
}

function isIdent(value) {
  return IDENT.test(String(value ?? '').trim())
}

// ---------------------------------------------------------------------------
// 转义
// ---------------------------------------------------------------------------

export function quote(text) {
  return `"${String(text ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r?\n/g, '\\n')}"`
}

function unquote(raw) {
  // 单趟反转义：`\n` → 换行，`\"` → 引号，`\\` → 反斜杠，其余原样
  return String(raw ?? '').replace(/\\(.)/g, (_, c) => (c === 'n' ? '\n' : c === 't' ? '\t' : c))
}

function splitList(text) {
  return String(text ?? '')
    .split(',')
    .map(item => item.trim())
    .filter(Boolean)
}

/**
 * 按**顶层**逗号切分：括号 / 方括号 / 引号内部的逗号不参与切分。
 * 决策表规则行 `in [a .. b] => (10, 1)` 必须整体作为一个条目。
 */
function splitTopLevel(text) {
  const out = []
  let depth = 0
  let current = ''
  const src = String(text ?? '')
  for (let i = 0; i < src.length; i++) {
    const char = src[i]
    if (char === '"') {
      current += char
      i++
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\') {
          current += src[i]
          i++
        }
        current += src[i]
        i++
      }
      current += src[i] ?? ''
      continue
    }
    if (char === '(' || char === '[') depth++
    if (char === ')' || char === ']') depth--
    if (char === ',' && depth === 0) {
      if (current.trim()) out.push(current.trim())
      current = ''
      continue
    }
    current += char
  }
  if (current.trim()) out.push(current.trim())
  return out
}

// ---------------------------------------------------------------------------
// 画布图校验
// ---------------------------------------------------------------------------

const DMN_MODES = new Set(['DMN'])

export function graphOf(nodes, edges) {
  const entities = nodes.filter(node => node.type === 'entity')
  const actions = nodes.filter(node => node.type === 'action')
  const dmns = nodes.filter(node => node.type === 'dmn')
  const conditions = nodes.filter(node => node.type === 'condition')
  return { entities, actions, dmns, conditions }
}

/**
 * 从 Entity 出发按连线走出唯一链路，返回 `{ entity, dmn, conditions, action }`。
 * 任何结构性问题都返回 `{ error }`。
 */
export function connectedChain(nodes, edges, mode = 'PURE') {
  const { entities, actions, dmns, conditions } = graphOf(nodes, edges)
  if (entities.length !== 1) return { error: '画布必须有且只有一个 Entity 节点' }
  if (actions.length !== 1) return { error: '画布必须有且只有一个 Action 节点' }
  if (DMN_MODES.has(mode)) {
    if (dmns.length > 1) return { error: 'DMN 模式只能有一个决策表节点' }
  } else if (dmns.length) {
    return { error: `决策表节点只在模式 D（DMN）下可用，当前模式为 ${mode}` }
  }

  const byId = new Map(nodes.map(node => [node.id, node]))
  const outgoing = new Map()
  const incoming = new Map()
  for (const edge of edges) {
    if (!byId.has(edge.source) || !byId.has(edge.target)) return { error: '连线引用了不存在的节点' }
    outgoing.set(edge.source, [...(outgoing.get(edge.source) || []), edge.target])
    incoming.set(edge.target, [...(incoming.get(edge.target) || []), edge.source])
  }
  const nextOf = (node, allowed) => {
    const next = outgoing.get(node.id) || []
    if (next.length !== 1) return { error: `${labelOf(node)} 必须恰好连到一个下游节点` }
    const target = byId.get(next[0])
    if (!target || !allowed.includes(target.type)) return { error: '连线必须按 Entity → DMN? → Condition* → Action 的顺序连接' }
    if ((incoming.get(target.id) || []).length !== 1) return { error: `${labelOf(target)} 必须恰好有一条上游连线` }
    return { node: target }
  }

  const entity = entities[0]
  const action = actions[0]
  const visited = new Set([entity.id])
  const chain = []
  let current = entity
  let dmn = dmns[0] || null
  let first = true
  while (current.id !== action.id) {
    const allowed = first ? ['condition', 'action', ...(dmn ? ['dmn'] : [])] : ['condition', 'action']
    const step = nextOf(current, allowed)
    if (step.error) return step
    if (visited.has(step.node.id)) return { error: '画布连线不能形成环' }
    visited.add(step.node.id)
    if (step.node.type === 'condition') chain.push(step.node)
    if (step.node.type === 'dmn') {
      if (!dmn) dmn = step.node
      // DMN 节点之后只允许接 Condition 或 Action
    }
    current = step.node
    first = false
  }
  if ((outgoing.get(action.id) || []).length) return { error: 'Action 节点不能再连接下游节点' }
  if (visited.size !== nodes.length) return { error: '所有节点都必须连接在 Entity 到 Action 的链路上' }
  if (chain.length !== conditions.length) return { error: '存在未连接的 Condition 节点' }
  if (dmn && !visited.has(dmn.id)) return { error: '决策表节点未连接在链路上' }
  return { entity, dmn, conditions: chain, action }
}

function labelOf(node) {
  return node.type === 'entity' ? 'Entity 节点'
    : node.type === 'action' ? 'Action 节点'
      : node.type === 'dmn' ? 'DMN 决策表节点' : 'Condition 节点'
}

export function validateCanvas({ mode = 'PURE', nodes = [], edges = [] }) {
  const graph = connectedChain(nodes, edges, mode)
  if (graph.error) return graph.error
  if (!isIdent(graph.entity.data?.entity)) return 'Entity 名称必须是有效标识符'
  const key = String(graph.entity.data?.key ?? '').trim()
  if (key && !isIdent(key)) return '主键字段必须是有效标识符'

  const states = splitList(graph.entity.data?.states)
  for (const state of states) {
    if (!isIdent(state)) return `状态名「${state}」必须是有效标识符`
  }
  const initial = String(graph.entity.data?.initial ?? '').trim()
  if (initial && !states.includes(initial)) return `初始状态「${initial}」必须出现在状态列表中`
  for (const terminal of splitList(graph.entity.data?.terminal)) {
    if (!isIdent(terminal)) return `终态名「${terminal}」必须是有效标识符`
    if (states.length && !states.includes(terminal)) return `终态「${terminal}」必须出现在状态列表中`
  }

  for (const condition of graph.conditions) {
    const { field, op, value } = condition.data || {}
    if (!FIELD.test(field || '')) return 'Condition 字段必须是有效标识符'
    if (!OPS.includes(op)) return `不支持的比较符：${op}`
    if (!VALUE.test(String(value ?? ''))) return `Condition「${field || '未命名'}」的值格式无效`
  }

  if (mode === 'STATEFUL') {
    if (!String(graph.action.data?.code ?? '').trim()) return '模式 B 的 yield 必须给出裁决错误码（code）'
    return null
  }

  if (!['DENY', 'ALLOW'].includes(graph.action.data?.verdict)) return '请选择裁决类型（DENY / ALLOW）'
  if (graph.action.data?.verdict === 'DENY' && !String(graph.action.data?.code ?? '').trim()) {
    return 'DENY 裁决必须填写错误码（code）'
  }
  if (graph.action.data?.verdict === 'DENY' && !String(graph.action.data?.reason ?? '').trim()) {
    return 'DENY 裁决必须填写拒绝理由（reason）'
  }
  const from = graph.action.data?.transitionFrom || ''
  const to = graph.action.data?.transitionTo || ''
  if (Boolean(from) !== Boolean(to)) return '状态转移需要同时填写起始状态和目标状态'
  if (from && (!isIdent(from) || !isIdent(to))) return '状态名称必须是有效标识符'
  if (from && states.length && (!states.includes(from) || !states.includes(to))) {
    return '状态转移的起止状态必须出现在 Entity 的状态列表中'
  }

  if (mode === 'STREAM') {
    const lease = String(graph.action.data?.leaseTarget ?? '').trim()
    if (lease && !isIdent(lease)) return '租约变量名必须是有效标识符'
    const seconds = graph.action.data?.leaseSeconds
    if (lease && !(Number(seconds) > 0)) return '惩罚租约必须填写大于 0 的秒数'
  }

  if (mode === 'DMN') {
    if (!graph.dmn) return '模式 D 需要连线一个 DMN 决策表节点'
    const table = String(graph.dmn.data?.table ?? '').trim()
    if (!isIdent(table)) return '决策表名称必须是有效标识符'
    if (!isIdent(graph.dmn.data?.param)) return '决策表入参名必须是有效标识符'
    const outputs = (graph.dmn.data?.outputs || []).map(name => String(name ?? '').trim())
    if (!outputs.length) return '决策表至少要有一个输出列'
    if (outputs.some(name => !isIdent(name))) return '决策表输出列名必须是有效标识符'
    if (!HIT_POLICIES.includes(graph.dmn.data?.hitPolicy)) return '请选择有效的命中策略'
    const rows = graph.dmn.data?.rows || []
    if (!rows.length) return '决策表至少需要一行规则'
    if (!rows.some(row => row.isDefault)) return '决策表必须有一行 default 兜底'
    for (const row of rows) {
      if (row.isDefault) continue
      if (!String(row.from ?? '').trim() || !String(row.to ?? '').trim()) return '区间行必须同时填写下界与上界'
      if (!DMN_BOUND.test(String(row.from).trim()) || !DMN_BOUND.test(String(row.to).trim())) return '区间上下界格式无效'
      if (!String(row.out ?? '').trim()) return '规则行必须填写输出值'
    }
  }
  return null
}

// ---------------------------------------------------------------------------
// 画布 → DSL
// ---------------------------------------------------------------------------

function conditionExpression(conditions) {
  if (!conditions.length) return 'true'
  return conditions
    .map((node, index) => {
      const { field = '', op = '>', value = '0', logic = 'AND' } = node.data || {}
      const condition = `${field} ${op} ${value}`.trim()
      return index === 0 ? condition : `${logic === 'OR' ? 'or' : 'and'} ${condition}`
    })
    .join(' ')
}

function renderEntity({ entity, key, states, initial, terminal, transition }) {
  const head = `entity ${entity}${key ? `(key: ${key})` : ''} {`
  const lines = [head]
  if (states.length) lines.push(`    states: [${states.join(', ')}]`)
  if (initial) lines.push(`    initial: ${initial}`)
  if (terminal.length) lines.push(`    terminal: [${terminal.join(', ')}]`)
  if (transition) {
    lines.push('')
    lines.push(`    transition ${transition.name} {`)
    lines.push(`        from: ${transition.from}`)
    lines.push(`        to: ${transition.to}`)
    if (transition.on) lines.push(`        on: ${transition.on}`)
    lines.push('    }')
  }
  lines.push('}')
  return lines.join('\n')
}

function renderVerdict(data, indent, effects) {
  const pad = ' '.repeat(indent)
  if (data.verdict === 'ALLOW') {
    const tail = effects.filter(Boolean)
    return `${pad}verdict: ALLOW()${tail.length ? `\n${tail.map(item => `${pad}    , ${item}`).join('\n')}` : ''}`
  }
  const lines = [`${pad}verdict: DENY(`, `${pad}    code: ${quote(data.code)},`, `${pad}    reason: ${quote(data.reason)})`]
  for (const effect of effects.filter(Boolean)) lines.push(`${pad}    , ${effect}`)
  return lines.join('\n')
}

function nodeToDsl({ name, mode, nodes = [], edges = [] }) {
  const graph = connectedChain(nodes, edges, mode)
  if (graph.error) return ''
  const ruleName = sanitizeIdent(name, 'Rule')
  const policyName = `${ruleName}Check`
  const entityName = sanitizeIdent(graph.entity.data?.entity, 'Entity')
  const key = String(graph.entity.data?.key ?? '').trim()
  const states = splitList(graph.entity.data?.states)
  const initial = String(graph.entity.data?.initial ?? '').trim()
  const terminal = splitList(graph.entity.data?.terminal).filter(item => !states.length || states.includes(item))
  const events = splitList(graph.entity.data?.events)
  const onClause = events.length ? ` on Event[${events.join(', ')}]` : ''
  const action = graph.action.data || {}
  const from = String(action.transitionFrom ?? '').trim()
  const to = String(action.transitionTo ?? '').trim()
  // `transition ... on:` 必须指向**已声明的策略名**（verifier 会做 UNDEFINED_TRANSITION_DRIVER 检查）；
  // 模式 B 的规则体不是策略块，因此不挂驱动（`on:` 在语法上可选）。
  const transition = from && to
    ? { name: `${ruleName}Transition`, from, to, on: mode === 'STATEFUL' ? '' : policyName }
    : null
  const entityBlock = renderEntity({ entity: entityName, key, states, initial, terminal, transition })

  if (mode === 'STATEFUL') {
    const patterns = graph.conditions.length
      ? graph.conditions.map(node => {
          const { field = '', op = '>', value = '0' } = node.data || {}
          return `${field} ${op} ${value}`.trim()
        }).join(', ')
      : ''
    return [
      entityBlock,
      '',
      `rule ${quote(name)} stateful {`,
      '    when:',
      `        $e: ${entityName}(${patterns})`,
      '    then:',
      '        yield DENY(',
      `            code: ${quote(action.code)},`,
      `            reason: ${quote(action.reason)})`,
      '}',
    ].join('\n')
  }

  const body = [`contract ${ruleName} on Entity[${entityName}] ${modeDslOf(mode)} {`]
  if (key) body.push(`    key: ${key}`)
  if (states.length) body.push(`    states: [${states.join(', ')}]`)
  if (initial) body.push(`    initial: ${initial}`)
  const lease = mode === 'STREAM' ? String(action.leaseTarget ?? '').trim() : ''
  if (lease) {
    body.push('')
    body.push(`    state var ${lease}: Timestamp = 0`)
  }
  body.push('')

  if (mode === 'DMN') {
    const table = sanitizeIdent(graph.dmn.data?.table, 'LookupTable')
    const param = String(graph.dmn.data?.param ?? 'input').trim()
    const paramType = String(graph.dmn.data?.paramType ?? 'Int')
    const outputs = (graph.dmn.data?.outputs || []).map(item => String(item ?? '').trim())
    const outputTypes = (graph.dmn.data?.outputTypes || [])
    const rows = graph.dmn.data?.rows || []
    body.push(`    decision_table ${table}(${param}: ${paramType}) -> (${outputs.map((out, i) => `${out}: ${outputTypes[i] || 'Int'}`).join(', ')}) {`)
    body.push(`        hit_policy: ${graph.dmn.data?.hitPolicy || 'UNIQUE'}`)
    body.push('        rules: [')
    rows.forEach((row, index) => {
      const comma = index + 1 === rows.length ? '' : ','
      if (row.isDefault) body.push(`            default => (${String(row.out || '0').trim()})${comma}`)
      else body.push(`            in [${String(row.from).trim()} .. ${String(row.to).trim()}] => (${String(row.out).trim()})${comma}`)
    })
    body.push('        ]')
    body.push('    }')
    body.push('')
    body.push(`    ${mode === 'DMN' ? 'invariant' : 'guard'} ${policyName}${onClause} {`)
    const lookup = String(graph.dmn.data?.lookupArg ?? 'event.timestamp').trim()
    body.push(`        let ${outputs.length > 1 ? `(${outputs.join(', ')})` : outputs[0]} = ${table}(${lookup})`)
  } else {
    body.push(`    ${mode === 'STREAM' ? 'invariant' : 'guard'} ${policyName}${onClause} {`)
  }

  body.push(`        when: ${conditionExpression(graph.conditions)}`)
  const effects = []
  if (lease) effects.push(`LeaseUpdate(${lease} = now() + ${Number(action.leaseSeconds)}s)`)
  if (String(action.emit ?? '').trim()) effects.push(`Emit(${quote(action.emit)})`)
  body.push(renderVerdict({ ...action, verdict: action.verdict || 'DENY' }, 8, effects))
  body.push('    }')
  body.push('}')
  return [entityBlock, '', ...body].join('\n')
}

function modeDslOf(mode) {
  return (MODES.find(item => item.value === mode) || MODES[0]).dsl
}

/**
 * 拖拽生成的画布 → DSL 文本。结构不合法时返回 `''`（错误由 `validateCanvas` 给出）。
 */
export function nodesToDsl({ name = 'Untitled', mode = 'PURE', nodes = [], edges = [] }) {
  return nodeToDsl({ name, mode, nodes, edges })
}

// ---------------------------------------------------------------------------
// DSL → 画布
// ---------------------------------------------------------------------------

/** 跳过 `//` 行注释与字符串字面量，找到与 `openIdx` 处 `open` 配对的 `close`。 */
function matchPair(src, openIdx, open = '{', close = '}') {
  let depth = 0
  for (let i = openIdx; i < src.length; i++) {
    const char = src[i]
    if (char === '"') {
      i++
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\') i++
        i++
      }
      continue
    }
    if (char === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i++
      continue
    }
    if (char === open) depth++
    else if (char === close) {
      depth--
      if (depth === 0) return i
    }
  }
  return -1
}

function matchBraces(src, openIdx) {
  return matchPair(src, openIdx, '{', '}')
}

/** 取出 `key: [ … ]` 的方括号内容（括号内可嵌套 `[a .. b]`，必须配对匹配）。 */
function bracketAfterKey(src, key) {
  const header = new RegExp(`\\b${key}\\s*:\\s*\\[`).exec(src)
  if (!header) return ''
  const openIdx = header.index + header[0].length - 1
  const close = matchPair(src, openIdx, '[', ']')
  return close < 0 ? '' : src.slice(openIdx + 1, close)
}

function blockAfter(src, headerMatch) {
  const openIdx = headerMatch.index + headerMatch[0].length - 1
  if (src[openIdx] !== '{') return null
  const close = matchBraces(src, openIdx)
  if (close < 0) return null
  return { body: src.slice(openIdx + 1, close), start: headerMatch.index, end: close + 1 }
}

function parseEntityDecl(src, entityName) {
  const re = /(?:^|\n)\s*entity\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?\s*(?:pure|stateful|stream|decision_table)?\s*\{/g
  let match
  while ((match = re.exec(src)) !== null) {
    if (entityName && match[1] !== entityName) continue
    const block = blockAfter(src, match)
    if (!block) continue
    const key = String(match[2] || '').match(/\bkey\s*:\s*([A-Za-z_][A-Za-z0-9_]*)/)?.[1] || ''
    const states = splitList(bracketAfterKey(block.body, 'states'))
    const initial = block.body.match(/\binitial\s*:\s*([A-Za-z_][A-Za-z0-9_]*)/)?.[1] || ''
    const terminal = splitList(bracketAfterKey(block.body, 'terminal'))
    const transition = block.body.match(/\btransition\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([\s\S]*?)\}/)
    return {
      entity: match[1],
      key,
      states,
      initial,
      terminal,
      transitionFrom: transition?.[2].match(/\bfrom\s*:\s*([A-Za-z_][A-Za-z0-9_]*)/)?.[1] || '',
      transitionTo: transition?.[2].match(/\bto\s*:\s*([A-Za-z_][A-Za-z0-9_]*)/)?.[1] || '',
      transitionOn: transition?.[2].match(/\bon\s*:\s*([A-Za-z_][A-Za-z0-9_]*)/)?.[1] || '',
    }
  }
  return null
}

function parseVerdict(text) {
  if (/\bverdict\s*:\s*ALLOW\s*\(\s*\)/.test(text)) return { verdict: 'ALLOW', code: '', reason: '' }
  const deny = text.match(/\bverdict\s*:\s*DENY\s*\(\s*code\s*:\s*"((?:[^"\\]|\\.)*)"\s*,\s*reason\s*:\s*"((?:[^"\\]|\\.)*)"\s*\)/)
  if (deny) return { verdict: 'DENY', code: unquote(deny[1]), reason: unquote(deny[2]) }
  const yieldDeny = text.match(/\byield\s+DENY\s*\(\s*code\s*:\s*"((?:[^"\\]|\\.)*)"\s*,\s*reason\s*:\s*"((?:[^"\\]|\\.)*)"\s*\)/)
  if (yieldDeny) return { verdict: 'DENY', code: unquote(yieldDeny[1]), reason: unquote(yieldDeny[2]) }
  const yieldAllow = text.match(/\byield\s+ALLOW\s*\(\s*\)/)
  if (yieldAllow) return { verdict: 'ALLOW', code: '', reason: '' }
  return null
}

function parseEffects(text) {
  const effects = { leaseTarget: '', leaseSeconds: '', emit: '' }
  const lease = text.match(/LeaseUpdate\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*now\s*\(\s*\)\s*\+\s*(\d+)\s*s\s*\)/)
  if (lease) {
    effects.leaseTarget = lease[1]
    effects.leaseSeconds = lease[2]
  }
  const emit = text.match(/\bEmit\s*\(\s*"((?:[^"\\]|\\.)*)"\s*\)/)
  if (emit) effects.emit = unquote(emit[1])
  return effects
}

/**
 * 条件 token：连接词被一并捕获（只靠「两个匹配之间的空隙」判断连接词会丢信息）。
 * 允许 `now()` 这类零参调用字段。
 */
const WHEN_TOKEN = /\s*(?:(and|or)\s+)?([A-Za-z][A-Za-z0-9_.]*(?:\((?:[A-Za-z][A-Za-z0-9_.]*)?\))?)\s*(>=|<=|==|!=|>|<)\s*(-?\d+(?:\.\d+)?|true|false|[A-Za-z][A-Za-z0-9_.]*|"(?:[^"\\]|\\.)*")/i

/**
 * 把 `a > 1 or b <= 2` 拆成条件数组。
 *
 * 逐段**连续**匹配：任何一段无法识别（例如 `has(x)`、`a + b > 1`）都直接报错，
 * 绝不静默丢条件——画布做不到无损就不接手，这是 AC6 的前提。
 */
function parseWhen(rawWhen) {
  const when = String(rawWhen || '').trim()
  if (!when || when === 'true') return { conditions: [], error: null }
  const re = new RegExp(WHEN_TOKEN.source, 'gi')
  const conditions = []
  let cursor = 0
  while (when.slice(cursor).trim()) {
    re.lastIndex = cursor
    const match = re.exec(when)
    if (!match || match.index !== cursor) {
      return { conditions: [], error: 'DSL 条件包含画布暂不支持的表达式' }
    }
    conditions.push({
      field: match[2],
      op: match[3],
      value: match[4],
      logic: (match[1] || 'AND').toUpperCase(),
    })
    cursor = re.lastIndex
  }
  if (!conditions.length) return { conditions: [], error: 'DSL 条件包含画布暂不支持的表达式' }
  conditions[0].logic = 'AND'
  return { conditions, error: null }
}

function makeNodes(entityInfo, conditions, actionData, dmnData, mode) {
  const nodes = [{
    id: 'entity_1',
    type: 'entity',
    position: { x: 80, y: 200 },
    data: {
      entity: entityInfo.entity,
      key: entityInfo.key,
      states: (entityInfo.states || []).join(', '),
      initial: entityInfo.initial,
      terminal: (entityInfo.terminal || []).join(', '),
      events: (entityInfo.events || []).join(', '),
    },
  }]
  const edges = []
  let previous = nodes[0]
  if (dmnData && mode === 'DMN') {
    const node = { id: 'dmn_1', type: 'dmn', position: { x: 360, y: 200 }, data: dmnData }
    nodes.push(node)
    edges.push({ id: `edge-${previous.id}-${node.id}`, source: previous.id, target: node.id })
    previous = node
  }
  conditions.forEach((data, index) => {
    const node = { id: `condition_${index + 1}`, type: 'condition', position: { x: 600, y: 60 + index * 150 }, data }
    nodes.push(node)
    edges.push({ id: `edge-${previous.id}-${node.id}`, source: previous.id, target: node.id })
    previous = node
  })
  const action = { id: 'action_1', type: 'action', position: { x: 860, y: 200 }, data: actionData }
  nodes.push(action)
  edges.push({ id: `edge-${previous.id}-${action.id}`, source: previous.id, target: action.id })
  return { nodes, edges }
}

/**
 * DSL → 画布。支持四种模式 + 旧版 `spec` / `rule … when … then` 兼容语法。
 * 返回 `{ nodes, edges, error, mode, name }`。
 */
export function dslToNodes(dsl = '') {
  const src = String(dsl || '')
  const empty = { nodes: [], edges: [], error: null, warning: null, mode: 'PURE', name: '' }
  if (!src.trim()) return { ...empty, error: null }

  // ---- 模式 B：rule "<name>" stateful { when: … then: … } ----
  const statefulHeader = /(?:^|\n)\s*rule\s+"((?:[^"\\]|\\.)*)"\s+stateful\s*\{/.exec(src)
  if (statefulHeader) {
    const block = blockAfter(src, statefulHeader)
    if (!block) return { ...empty, error: 'stateful 规则块不完整' }
    const name = unquote(statefulHeader[1])
    // `when:` 与 `then:` 之间的事实模式必须**恰好一条**——多条模式超出画布子集，
    // 静默只取第一条会造成 DSL 丢失，因此直接报错。
    const whenSection = block.body.match(/\bwhen\s*:\s*([\s\S]*?)\bthen\s*:/)?.[1] ?? ''
    const patternCount = (whenSection.match(/\$[A-Za-z_][A-Za-z0-9_]*\s*:/g) || []).length
    if (patternCount !== 1) {
      return {
        ...empty,
        mode: 'STATEFUL',
        name,
        error: patternCount === 0
          ? '模式 B 的 when 里没有事实模式（$e: Type(...)）'
          : `模式 B 画布只支持单事实模式，该规则含 ${patternCount} 条（多事实需要手写 DSL）`,
      }
    }
    const pattern = whenSection.match(/\$([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/)
    if (!pattern) return { ...empty, mode: 'STATEFUL', name, error: '模式 B 只支持 $e: Type(约束) 的画布形式' }
    const entityName = pattern[2]
    const conditions = splitList(pattern[3]).map((text, index) => {
      const parsed = /^([A-Za-z][A-Za-z0-9_.]*)\s*(>=|<=|==|!=|>|<)\s*(.+)$/.exec(text)
      if (!parsed) return null
      return { field: parsed[1], op: parsed[2], value: parsed[3].trim(), logic: index === 0 ? 'AND' : 'AND' }
    })
    if (conditions.some(item => !item)) {
      return { ...empty, mode: 'STATEFUL', name, error: '模式 B 的模式约束含画布暂不支持的表达式' }
    }
    const verdict = parseVerdict(block.body)
    if (!verdict) return { ...empty, mode: 'STATEFUL', name, error: '未能解析 yield 裁决' }
    const entityInfo = parseEntityDecl(src, entityName) || { entity: entityName, key: '', states: [], initial: '' }
    const graph = makeNodes(
      { ...entityInfo, events: entityInfo.transitionOn ? [entityInfo.transitionOn] : [] },
      conditions,
      {
        ...verdict,
        emit: '',
        transitionFrom: entityInfo.transitionFrom || '',
        transitionTo: entityInfo.transitionTo || '',
        leaseTarget: '',
        leaseSeconds: '',
      },
      null,
      'STATEFUL',
    )
    return { ...graph, error: null, warning: null, mode: 'STATEFUL', name }
  }

  // ---- 模式 D：contract … decision_table { decision_table … } ----
  // ---- 模式 A/C：contract … <mode> { guard|invariant … } ----
  const contractHeader = /(?:^|\n)\s*(?:contract|spec)\s+([A-Za-z_][A-Za-z0-9_]*)\s+on\s+(?:Entity\[([A-Za-z_][A-Za-z0-9_]*)\]|([A-Za-z_][A-Za-z0-9_]*)(?:\s*:\s*([A-Za-z_][A-Za-z0-9_]*))?)\s*(pure|stateful|stream|decision_table)?\s*\{/.exec(src)
  if (contractHeader) {
    const block = blockAfter(src, contractHeader)
    if (!block) return { ...empty, error: 'contract 块不完整' }
    const name = contractHeader[1]
    const entityName = contractHeader[2] || contractHeader[4] || contractHeader[3]
    const modifiers = String(contractHeader[5] || '').toLowerCase()
    const tableBlock = /decision_table\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*->\s*\(([^)]*)\)\s*\{/.exec(block.body)
    const mode = tableBlock || modifiers === 'decision_table' ? 'DMN'
      : modifiers === 'stream' ? 'STREAM'
        : modifiers === 'stateful' ? 'STATEFUL' : 'PURE'

    // policy 块（guard / invariant 均可，取第一个带 when/guard 的）
    const policyHeader = /(?:^|\n)\s*(?:guard|invariant)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:on\s+Event\s*\[([^\]]*)\])?\s*\{/.exec(block.body)
    const policy = policyHeader ? blockAfter(block.body, policyHeader) : null
    if (!policy) return { ...empty, mode, name, error: '未找到 guard / invariant 策略块' }
    const policyBody = policy.body
    const rawWhen = policyBody.match(/\bwhen\s*:\s*([^\n]*)/)?.[1] ?? policyBody.match(/\bguard\s*:\s*([^\n]*)/)?.[1] ?? 'true'
    const { conditions, error: whenError } = parseWhen(rawWhen)
    if (whenError) return { ...empty, mode, name, error: whenError }

    const legacy = policyBody.match(/\binvariant\s*:\s*always\s*\(\s*not\s*\(([\s\S]*?)\)\s*\)/)
    const legacyConditions = legacy ? parseWhen(legacy[1]) : null
    const effectiveConditions = legacyConditions && !legacyConditions.error ? legacyConditions.conditions : conditions

    const verdict = parseVerdict(policyBody) || { verdict: 'DENY', code: '', reason: '' }
    const effects = parseEffects(policyBody)
    const severity = String(policyBody.match(/\bseverity\s*:\s*(INFO|WARNING|CRITICAL)\b/i)?.[1] || '').toUpperCase()
    const transition = policyBody.match(/\btransition\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*->\s*([A-Za-z_][A-Za-z0-9_]*)/)
    const emitField = policyBody.match(/\bemit\s*:\s*"((?:[^"\\]|\\.)*)"/)

    const entityInfo = parseEntityDecl(src, entityName) || { entity: entityName, key: '', states: [], initial: '' }
    const events = splitList(policyHeader?.[2]).length
      ? splitList(policyHeader[2])
      : (entityInfo.transitionOn ? [entityInfo.transitionOn] : [])
    const actionData = {
      verdict: verdict.verdict,
      code: verdict.code,
      reason: verdict.reason,
      severity,
      emit: effects.emit || (emitField ? unquote(emitField[1]) : ''),
      transitionFrom: transition?.[1] || entityInfo.transitionFrom || '',
      transitionTo: transition?.[2] || entityInfo.transitionTo || '',
      leaseTarget: effects.leaseTarget,
      leaseSeconds: effects.leaseSeconds,
    }

    let dmnData = null
    if (mode === 'DMN') {
      if (!tableBlock) return { ...empty, mode, name, error: '模式 D 缺少 decision_table 声明' }
      const tableBody = blockAfter(block.body, tableBlock)
      if (!tableBody) return { ...empty, mode, name, error: 'decision_table 块不完整' }
      const param = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*$/.exec(tableBlock[2])
      const outputs = splitList(tableBlock[3]).map(text => {
        const parsed = /^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)$/.exec(text)
        return parsed ? { name: parsed[1], type: parsed[2] } : null
      })
      if (!param || outputs.some(item => !item)) return { ...empty, mode, name, error: '决策表入参/输出列格式无效' }
      const rowsRaw = bracketAfterKey(tableBody.body, 'rules')
      const rows = splitTopLevel(rowsRaw).map(text => {
        const def = /^default\s*=>\s*\(([^)]*)\)$/.exec(text)
        if (def) return { isDefault: true, from: '', to: '', out: splitList(def[1]).join(', ') }
        const range = /^in\s*\[\s*(.+?)\s*\.\.\s*(.+?)\s*\]\s*=>\s*\(([^)]*)\)$/.exec(text)
        if (range) return { isDefault: false, from: range[1], to: range[2], out: splitList(range[3]).join(', ') }
        return null
      })
      if (!rows.length || rows.some(item => !item)) {
        return { ...empty, mode, name, error: '决策表规则行含画布暂不支持的写法' }
      }
      const lookup = policyBody.match(/let\s+(?:\([^)]*\)|[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]*)\)/)
      dmnData = {
        table: tableBlock[1],
        param: param[1],
        paramType: param[2],
        outputs: outputs.map(item => item.name),
        outputTypes: outputs.map(item => item.type),
        hitPolicy: String(tableBody.body.match(/hit_policy\s*:\s*([A-Za-z_]+)/)?.[1] || 'UNIQUE').toUpperCase(),
        rows,
        lookupArg: lookup ? lookup[1].trim() : 'event.timestamp',
        events,
      }
    }

    const graph = makeNodes(
      { ...entityInfo, events },
      effectiveConditions,
      actionData,
      dmnData,
      mode,
    )
    // 画布子集是「单策略块」的：多于一个策略块时**不静默丢弃**，而是明确告知，
    // 由调用方决定是否允许在画布上保存（否则会造成 DSL 丢失）。
    const policyCount = (block.body.match(/(?:^|\n)\s*(?:guard|invariant)\s+[A-Za-z_][A-Za-z0-9_]*/g) || []).length
    const warning = policyCount > 1
      ? `该 DSL 含 ${policyCount} 个策略块（guard / invariant），画布只呈现第 1 个；在画布上保存会丢失其余策略块。`
      : null
    return { ...graph, error: null, warning, mode, name }
  }

  // ---- 旧版兼容：rule X on E when P then { … } ----
  const legacyRule = /(?:^|\n)\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s+on\s+([A-Za-z_][A-Za-z0-9_]*)\s+when\s+([\s\S]*?)\s+then\s*\{/.exec(src)
  if (legacyRule) {
    const { conditions, error } = parseWhen(legacyRule[3])
    if (error) return { ...empty, error }
    const body = blockAfter(src, legacyRule)
    const verdict = parseVerdict(body ? body.body : '') || parseVerdict(src) || { verdict: 'DENY', code: '', reason: '' }
    const severity = String(src.match(/\bseverity\s*:\s*(INFO|WARNING|CRITICAL)\b/i)?.[1] || '').toUpperCase()
    const emit = src.match(/\bemit\s*:\s*"((?:[^"\\]|\\.)*)"/)
    const graph = makeNodes(
      { entity: legacyRule[2], key: '', states: [], initial: '' },
      conditions,
      {
        ...verdict,
        severity,
        emit: emit ? unquote(emit[1]) : '',
        transitionFrom: '',
        transitionTo: '',
        leaseTarget: '',
        leaseSeconds: '',
      },
      null,
      'PURE',
    )
    return { ...graph, error: null, warning: null, mode: 'PURE', name: legacyRule[1] }
  }

  return { ...empty, error: '当前画布只支持 contract / decision_table / rule … stateful 语法' }
}

// ---------------------------------------------------------------------------
// 变量 → 数据源列绑定（FR8.3）
// ---------------------------------------------------------------------------

const KEYWORDS = new Set([
  'and', 'or', 'not', 'implies', 'when', 'then', 'else', 'rule', 'contract', 'spec', 'on',
  'invariant', 'guard', 'violation', 'severity', 'emit', 'transition', 'verdict', 'effects',
  'code', 'reason', 'entity', 'stream', 'var', 'let', 'state', 'states', 'initial', 'terminal',
  'from', 'to', 'key', 'in', 'default', 'rules', 'hit_policy', 'decision_table', 'bind',
  'pure', 'stateful', 'decision_table', 'Datasource', 'Table', 'Event', 'Stream',
  'exists', 'forall', 'always', 'eventually', 'historically', 'until', 'within', 'once', 'since', 'next',
  'true', 'false', 'event', 'sum', 'count', 'avg', 'min', 'max', 'distinct', 'union', 'join',
  'coGroup', 'filter', 'map', 'window', 'fold', 'sliding', 'tumbling',
  'Int', 'Float', 'Bool', 'String', 'Timestamp', 'Duration', 'BitVec',
  'int', 'float', 'bool', 'string', 'timestamp', 'duration', 'bitvec', 'type',
  'INFO', 'WARNING', 'CRITICAL', 'DENY', 'ALLOW', 'LeaseUpdate', 'Emit', 'insert', 'retract', 'yield',
  'UNIQUE', 'FIRST', 'PRIORITY', 'COLLECT',
])

const BUILTIN_FUNCS = new Set([
  'now', 'today', 'len', 'abs', 'ratio', 'days_between', 'DaysOverdue', 'DaysSince',
])

function matchAll(source, regex, group = 1) {
  const out = []
  let match
  regex.lastIndex = 0
  while ((match = regex.exec(source)) !== null) out.push(match[group])
  return out
}

/** 从 DSL 中剔除所有"已声明符号"（实体/流/指标/规格/let/形参/状态）。 */
function declaredNames(dsl) {
  const names = new Set()
  const patterns = [
    /\bentity\s+([A-Za-z][A-Za-z0-9_]*)/g,
    /\bstream\s+([A-Za-z][A-Za-z0-9_]*)/g,
    /\b(?:metric|signal)\s+([A-Za-z][A-Za-z0-9_]*)/g,
    /\b(?:spec|contract|rule)\s+([A-Za-z][A-Za-z0-9_]*)/g,
    /\b(?:guard|invariant)\s+([A-Za-z][A-Za-z0-9_]*)/g,
    /\bdecision_table\s+([A-Za-z][A-Za-z0-9_]*)/g,
    /\blet\s+([A-Za-z][A-Za-z0-9_]*)/g,
    /\bstate\s+var\s+([A-Za-z][A-Za-z0-9_]*)/g,
    /([A-Za-z][A-Za-z0-9_]*)\s*=>/g,
    /\(\s*([A-Za-z][A-Za-z0-9_]*)\s*,\s*([A-Za-z][A-Za-z0-9_]*)\s*\)\s*=>/g,
    /\(([^)]*)\)\s*:/g,
  ]
  for (const pattern of patterns) for (const name of matchAll(dsl, pattern)) names.add(name)
  // `let (a, b) = T(...)` 的元组绑定
  for (const list of matchAll(dsl, /\blet\s*\(([^)]*)\)\s*=/g)) for (const name of splitList(list)) names.add(name)
  for (const list of matchAll(dsl, /\b(?:states|terminal)\s*:\s*\[([^\]]*)\]/g)) {
    for (const name of splitList(list)) names.add(name.split('=')[0].trim())
  }
  return names
}

const COMPARISON = /([A-Za-z0-9_.]+|"[^"]*"|[A-Za-z][A-Za-z0-9_]*\([^)]*\))\s*(?:>=|<=|==|!=|>|<)\s*([A-Za-z0-9_.]+|"[^"]*"|[A-Za-z][A-Za-z0-9_]*\([^)]*\))/g

function comparisonIdentifiers(token, out) {
  if (!token) return
  const value = token.trim()
  if (!value) return
  const call = value.match(/^([A-Za-z][A-Za-z0-9_]*)\s*\(/)
  if (call) {
    out.push(call[1])
    return
  }
  if (value.startsWith('"')) return
  if (value.includes('.')) return // event.type 属于事件字段，不做列绑定
  if (/^[A-Za-z][A-Za-z0-9_]*$/.test(value)) out.push(value)
}

/**
 * 提取 DSL 中需要绑定到数据源列的变量与裸标识符。
 *
 * - `vars`：零元 `metric name := …`（含旧写法 `var name = …`）声明的派生信号；
 * - `fields`：比较表达式中出现的裸标识符（排除关键字、内置函数、实体/状态/let 等已声明符号）。
 */
export function extractBindingTargets(dsl = '') {
  // `state var <name>: <Type> = …` 是租约账本（内部状态），不是外部列 —— 先剔除
  const varScan = String(dsl).replace(/\bstate\s+var\s+[A-Za-z][A-Za-z0-9_]*\s*:\s*[A-Za-z][A-Za-z0-9_]*/g, '')
  const vars = [...new Set([
    ...matchAll(varScan, /\bmetric\s+([A-Za-z][A-Za-z0-9_]*)\s*:=/g),
    ...matchAll(varScan, /\bvar\s+([A-Za-z][A-Za-z0-9_]*)/g),
  ])].sort()
  const excluded = new Set([...KEYWORDS, ...BUILTIN_FUNCS, ...vars, ...declaredNames(dsl)])
  // 先把字符串字面量替换为 ""，避免 emit 文案里的 "a > b" 被误判成比较式
  const scanText = dsl.replace(/"(?:[^"\\]|\\.)*"/g, '""')
  const found = []
  let match
  COMPARISON.lastIndex = 0
  while ((match = COMPARISON.exec(scanText)) !== null) {
    comparisonIdentifiers(match[1], found)
    comparisonIdentifiers(match[2], found)
  }
  const fields = [...new Set(found.filter(name => !excluded.has(name)))].sort()
  return { vars, fields }
}
