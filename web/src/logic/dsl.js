// 从 Vue Flow 节点和连线生成 DSL 文本（纯函数，可单测）
//
// 节点类型：
//   - entity:    { data: { entity: 'Company' } }
//   - condition: { data: { field, op, value, logic: 'AND' | 'OR' } }
//   - action:    { data: { severity: 'WARNING'|'CRITICAL'|'INFO', emit: '...' } }
//
// 连线方向：entity -> condition* -> action

// 把任意字符串 sanitize 成 DSL 合法 ident（字母开头，只含字母数字下划线）
function sanitizeIdent(name) {
  if (!name) return 'Rule'
  // 合法 ident 直接用
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return name
  // 否则转成 Rule_ + 简单 hash
  let h = 0
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0
  return 'Rule_' + h.toString(36)
}

export function nodesToDsl({ name = 'Untitled', nodes = [], edges = [] }) {
  const entity = nodes.find(n => n.type === 'entity')
  const conditions = nodes.filter(n => n.type === 'condition')
  const action = nodes.find(n => n.type === 'action')

  const entityName = entity?.data?.entity || 'Company'
  const condParts = conditions.map(c => {
    const { field, op = '>', value = '0', logic = 'AND' } = c.data || {}
    return { text: `${field} ${op} ${value}`, logic }
  })
  const whenExpr = condParts.length
    ? condParts.map((c, i) => (i === 0 ? c.text : `${c.logic} ${c.text}`)).join(' ')
    : 'true'

  const severity = action?.data?.severity || 'WARNING'
  const emit = action?.data?.emit || '规则触发'

  return `rule ${sanitizeIdent(name)} on ${entityName} when ${whenExpr} then {
  severity: ${severity}
  emit: "${emit}"
}`
}

// 反向：从 DSL 文本解析回节点（编辑已有规则时用）
export function dslToNodes(dsl = '') {
  const nodes = []
  const edges = []

  const ruleMatch = dsl.match(/rule\s+(\w+)\s+on\s+(\w+)\s+when\s+(.+?)\s+then\s*\{/s)
  if (ruleMatch) {
    const [, name, entity, whenExpr] = ruleMatch
    nodes.push({ id: 'e1', type: 'entity', position: { x: 0, y: 100 }, data: { entity, ruleName: name } })

    // 解析 when 里的条件（按 AND/OR 切分）
    const condRe = /(\w+)\s*(>=|<=|==|!=|>|<)\s*([\d.]+)/g
    let m, idx = 0, prevId = 'e1'
    while ((m = condRe.exec(whenExpr)) !== null) {
      const id = `c${++idx}`
      nodes.push({
        id, type: 'condition', position: { x: 220, y: 50 + idx * 80 },
        data: { field: m[1], op: m[2], value: m[3], logic: 'AND' },
      })
      edges.push({ id: `e-${prevId}-${id}`, source: prevId, target: id })
      prevId = id
    }

    const sevMatch = dsl.match(/severity:\s*(\w+)/)
    const emitMatch = dsl.match(/emit:\s*"([^"]*)"/)
    nodes.push({
      id: 'a1', type: 'action', position: { x: 480, y: 150 },
      data: { severity: sevMatch?.[1] || 'WARNING', emit: emitMatch?.[1] || '' },
    })
    edges.push({ id: `e-${prevId}-a1`, source: prevId, target: 'a1' })
  }
  return { nodes, edges }
}
