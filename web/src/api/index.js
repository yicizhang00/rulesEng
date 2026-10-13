import axios from 'axios'

const api = axios.create({ baseURL: '/', timeout: 10000 })

export const Groups = {
  list: () => api.get('/api/groups').then(r => r.data),
  create: (data) => api.post('/api/groups', data).then(r => r.data),
  update: (id, data) => api.put(`/api/groups/${id}`, data).then(r => r.data),
  remove: (id) => api.delete(`/api/groups/${id}`).then(r => r.data),
}

export const Rules = {
  list: (groupId) => api.get('/api/rules', { params: groupId ? { group_id: groupId } : {} }).then(r => r.data),
  create: (data) => api.post('/api/rules', data).then(r => r.data),
  update: (id, data) => api.put(`/api/rules/${id}`, data).then(r => r.data),
  remove: (id) => api.delete(`/api/rules/${id}`).then(r => r.data),
}

export const Datasources = {
  list: () => api.get('/api/datasources').then(r => r.data),
  create: (data) => api.post('/api/datasources', data).then(r => r.data),
}

export const Bindings = {
  list: () => api.get('/api/bindings').then(r => r.data),
  create: (data) => api.post('/api/bindings', data).then(r => r.data),
}

export const Actions = {
  list: () => api.get('/api/actions').then(r => r.data),
  create: (data) => api.post('/api/actions', data).then(r => r.data),
}

export const verifyDsl = (dsl) => api.post('/parse', dsl).then(r => r.data)
