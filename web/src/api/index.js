import axios from 'axios'

const api = axios.create({ baseURL: '/', timeout: 15000 })

/**
 * 统一响应处理：后端以 `{error, errors, warnings}` 表达业务失败。
 * 失败时抛出携带完整 payload 的 Error，调用方可以读取 errors/warnings 明细。
 */
const data = (request) => request.then((response) => {
  if (response.data?.error) {
    const error = new Error(response.data.error)
    error.payload = response.data
    throw error
  }
  return response.data
})

/** 四模目录 + 生命周期状态（GET /api/modes）。 */
export const Meta = {
  modes: () => data(api.get('/api/modes')),
}

export const Groups = {
  list: () => data(api.get('/api/groups')),
  create: (payload) => data(api.post('/api/groups', payload)),
  update: (id, payload) => data(api.put(`/api/groups/${id}`, payload)),
  remove: (id) => data(api.delete(`/api/groups/${id}`)),
}

export const Rules = {
  list: (groupId) => data(api.get('/api/rules', { params: groupId ? { group_id: groupId } : {} })),
  get: (id) => data(api.get(`/api/rules/${id}`)),
  create: (payload) => data(api.post('/api/rules', payload)),
  update: (id, payload) => data(api.put(`/api/rules/${id}`, payload)),
  remove: (id) => data(api.delete(`/api/rules/${id}`)),
  versions: (id) => data(api.get(`/api/rules/${id}/versions`)),
  /** 决策表 → DMN 1.3 XML（FR3）。 */
  exportDmn: (id) => data(api.post(`/api/rules/${id}/export-dmn`)),
  /** 针对已落库规则求反例参数（AC1）。 */
  counterexample: (id, dslContent) => data(api.post(
    `/api/rules/${id}/counterexample`,
    dslContent ?? '',
    { headers: { 'Content-Type': 'text/plain' } },
  )),
}

export const Dmn = {
  /** DMN 1.3 XML → DSL + AST（FR3）。 */
  import: (xml) => data(api.post('/api/dmn/import', { xml })),
}

export const DecisionTables = {
  /** 决策表试算（FR3 / AC4）。payload: { rule_id } 或 { dsl_content, table, args } */
  trial: (payload) => data(api.post('/api/decision-tables/trial', payload)),
}

export const Datasources = {
  list: () => data(api.get('/api/datasources')),
  create: (payload) => data(api.post('/api/datasources', payload)),
  update: (id, payload) => data(api.put(`/api/datasources/${id}`, payload)),
  remove: (id) => data(api.delete(`/api/datasources/${id}`)),
  test: (id) => data(api.post(`/api/datasources/${id}/test`)),
  schema: (id) => data(api.get(`/api/datasources/${id}/schema`)),
}

export const Bindings = {
  list: (ruleId) => data(api.get('/api/variable-bindings', { params: ruleId ? { rule_id: ruleId } : {} })),
  upsert: (payload) => data(api.post('/api/bindings', payload)),
  remove: (id) => data(api.delete(`/api/bindings/${id}`)),
}

export const Actions = {
  list: (ruleId) => data(api.get('/api/actions', { params: ruleId ? { rule_id: ruleId } : {} })),
  create: (payload) => data(api.post('/api/actions', payload)),
  remove: (id) => data(api.delete(`/api/actions/${id}`)),
}

/** 实时语法校验（仅 parse）。 */
export const parseDsl = (dsl) => data(api.post('/parse', dsl, { headers: { 'Content-Type': 'text/plain' } }))

/**
 * 形式化校验（parse + verify），返回分级报告：
 * `{ ok, status: 'PASS'|'FAIL', errors: [...], warnings: [...] }`
 * 每条 issue 含 `counterexample: [{var, value}]` 与 `counterexample_text`（AC1）。
 */
export const verifyDsl = (dsl, ruleId) => data(api.post(
  '/verify',
  dsl,
  { params: ruleId ? { rule_id: ruleId } : {}, headers: { 'Content-Type': 'text/plain' } },
))

/** 反例诊断（AC1）：不落库也能拿到反例参数。 */
export const counterexampleDsl = (dsl) => data(api.post(
  '/api/counterexample',
  dsl,
  { headers: { 'Content-Type': 'text/plain' } },
))
