import { describe, it, expect } from 'vitest'
import { nodesToDsl, dslToNodes } from '../src/logic/dsl.js'

describe('nodesToDsl', () => {
  it('generates DSL from entity + condition + action', () => {
    const dsl = nodesToDsl({
      name: 'CancelRatioAlert',
      nodes: [
        { id: 'e1', type: 'entity', data: { entity: 'Account' } },
        { id: 'c1', type: 'condition', data: { field: 'cancel_ratio', op: '>', value: '0.85', logic: 'AND' } },
        { id: 'a1', type: 'action', data: { severity: 'CRITICAL', emit: '高撤单率' } },
      ],
      edges: [],
    })
    expect(dsl).toContain('rule CancelRatioAlert on Account')
    expect(dsl).toContain('cancel_ratio > 0.85')
    expect(dsl).toContain('severity: CRITICAL')
    expect(dsl).toContain('emit: "高撤单率"')
  })

  it('joins multiple conditions with AND', () => {
    const dsl = nodesToDsl({
      name: 'R',
      nodes: [
        { id: 'e1', type: 'entity', data: { entity: 'Company' } },
        { id: 'c1', type: 'condition', data: { field: 'a', op: '>', value: '1', logic: 'AND' } },
        { id: 'c2', type: 'condition', data: { field: 'b', op: '<', value: '2', logic: 'AND' } },
      ],
      edges: [],
    })
    expect(dsl).toContain('a > 1 AND b < 2')
  })

  it('handles empty conditions as true', () => {
    const dsl = nodesToDsl({ name: 'X', nodes: [{ id: 'e1', type: 'entity', data: { entity: 'Company' } }] })
    expect(dsl).toContain('when true then')
  })

  it('sanitizes non-ascii rule name to valid ident', () => {
    const dsl = nodesToDsl({ name: '未命名规则', nodes: [{ id: 'e1', type: 'entity', data: { entity: 'Company' } }] })
    // 必须是合法 ident（字母开头，无空格无中文）
    expect(dsl).toMatch(/rule [A-Za-z_][A-Za-z0-9_]* on Company/)
    expect(dsl).not.toContain('未命名规则')
  })
})

describe('dslToNodes', () => {
  it('parses DSL back to nodes', () => {
    const { nodes, edges } = dslToNodes('rule MyRule on Account when cancel_ratio > 0.85 then { severity: WARNING emit: "hi" }')
    expect(nodes.find(n => n.type === 'entity')?.data.entity).toBe('Account')
    expect(nodes.filter(n => n.type === 'condition')).toHaveLength(1)
    expect(nodes.find(n => n.type === 'action')?.data.severity).toBe('WARNING')
    expect(edges.length).toBe(2)
  })

  it('returns empty on invalid DSL', () => {
    const { nodes } = dslToNodes('not a rule')
    expect(nodes).toHaveLength(0)
  })
})
