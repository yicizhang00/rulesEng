<template>
  <div style="padding:24px; max-width:1080px; margin:0 auto">
    <div style="display:flex; justify-content:space-between; margin-bottom:16px">
      <h2>数据源管理</h2>
      <el-button type="primary" @click="openCreate">+ 注册数据源</el-button>
    </div>
    <el-table :data="list" border stripe>
      <el-table-column prop="id" label="ID" width="60" />
      <el-table-column prop="name" label="名称" />
      <el-table-column prop="ds_type" label="类型" width="110" />
      <el-table-column prop="host" label="主机" />
      <el-table-column prop="port" label="端口" width="80" />
      <el-table-column prop="username" label="账号" width="120" />
      <el-table-column prop="database_name" label="库 / Schema" />
      <el-table-column label="操作" width="230">
        <template #default="{ row }">
          <el-button text size="small" @click="testConnection(row)">测试连接</el-button>
          <el-button text size="small" @click="viewSchema(row)">结构</el-button>
          <el-button text size="small" @click="openEdit(row)">编辑</el-button>
          <el-button text size="small" type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <FormDialog v-model="dialog.visible" :title="dialog.title" :fields="dialog.fields" :initial="dialog.initial"
                @submit="submit" />

    <el-dialog v-model="schemaDialog.visible" :title="`表结构 · ${schemaDialog.title}`" width="640px">
      <div v-if="schemaDialog.loading">加载中…</div>
      <div v-else-if="!schemaDialog.tables.length" class="empty">未获取到表结构（请先确认数据源连通）</div>
      <div v-else class="schema-tree">
        <div v-for="table in schemaDialog.tables" :key="table.table" class="schema-table">
          <div class="schema-table-name">📋 {{ table.table }}</div>
          <div class="schema-columns">
            <el-tag v-for="column in table.columns" :key="column.name" size="small" type="info">
              {{ column.name }}:{{ column.type }}
            </el-tag>
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Datasources } from '../api'
import FormDialog from '../components/FormDialog.vue'
import { ElMessage, ElMessageBox } from 'element-plus'

const list = ref([])
const editingId = ref(null)
const schemaDialog = ref({ visible: false, title: '', loading: false, tables: [] })

const emptyForm = () => ({ name: '', ds_type: 'MYSQL', host: '127.0.0.1', port: 3306, username: 'root', password: '', database_name: '' })

const fields = (isEdit) => [
  { prop: 'name', label: '名称', placeholder: '如：生产库' },
  { prop: 'ds_type', label: '类型', type: 'select', options: [{ label: 'MySQL', value: 'MYSQL' }, { label: 'PostgreSQL', value: 'POSTGRESQL' }, { label: 'Kafka 元数据', value: 'KAFKA' }] },
  { prop: 'host', label: '主机' },
  { prop: 'port', label: '端口' },
  { prop: 'username', label: '账号' },
  { prop: 'password', label: '密码', placeholder: isEdit ? '留空表示不修改' : '数据库密码（加密存储）' },
  { prop: 'database_name', label: '库 / Schema' },
]

const dialog = ref({ visible: false, title: '注册数据源', initial: emptyForm(), fields: fields(false) })

function openCreate() {
  editingId.value = null
  dialog.value = { visible: true, title: '注册数据源', initial: emptyForm(), fields: fields(false) }
}

function openEdit(row) {
  editingId.value = row.id
  dialog.value = {
    visible: true,
    title: `编辑数据源 #${row.id}`,
    initial: { ...emptyForm(), ...row, password: '', ds_type: row.ds_type || 'MYSQL' },
    fields: fields(true),
  }
}

async function load() {
  try { list.value = await Datasources.list() }
  catch (e) { ElMessage.error('加载失败: ' + (e.payload?.error || e.message)) }
}

async function submit(form) {
  try {
    form.port = Number(form.port) || 3306
    if (editingId.value) await Datasources.update(editingId.value, form)
    else await Datasources.create(form)
    ElMessage.success(editingId.value ? '数据源已更新' : '数据源已注册')
    dialog.value.visible = false
    load()
  } catch (e) {
    ElMessage.error('保存失败: ' + (e.payload?.error || e.message))
  }
}

async function remove(row) {
  try { await ElMessageBox.confirm(`删除数据源「${row.name}」？已绑定的规则会失去该列映射。`, '删除数据源', { type: 'warning' }) }
  catch { return }
  try {
    await Datasources.remove(row.id)
    ElMessage.success('数据源已删除')
    load()
  } catch (e) { ElMessage.error('删除失败: ' + (e.payload?.error || e.message)) }
}

async function testConnection(row) {
  try {
    const result = await Datasources.test(row.id)
    if (result.ok) ElMessage.success(result.message || '连接成功')
    else ElMessage.error(result.error || '连接失败')
  } catch (e) { ElMessage.error('连接失败: ' + (e.payload?.error || e.message)) }
}

async function viewSchema(row) {
  schemaDialog.value = { visible: true, title: row.name, loading: true, tables: [] }
  try {
    const result = await Datasources.schema(row.id)
    schemaDialog.value = { visible: true, title: row.name, loading: false, tables: result.tables || [] }
  } catch (e) {
    schemaDialog.value = { visible: true, title: row.name, loading: false, tables: [] }
    ElMessage.error('拉取结构失败: ' + (e.payload?.error || e.message))
  }
}

onMounted(load)
</script>

<style scoped>
.empty { text-align:center; color:#9ca3af; padding:20px; font-size:13px; }
.schema-tree { max-height:60vh; overflow:auto; }
.schema-table { margin-bottom:12px; }
.schema-table-name { font-weight:600; font-size:13px; margin-bottom:6px; }
.schema-columns { display:flex; flex-wrap:wrap; gap:6px; }
</style>
