<template>
  <div style="padding:24px; max-width:1000px; margin:0 auto">
    <div style="display:flex; justify-content:space-between; margin-bottom:16px">
      <h2>数据源管理</h2>
      <el-button type="primary" @click="dialog.visible = true">+ 注册数据源</el-button>
    </div>
    <el-table :data="list" border stripe>
      <el-table-column prop="id" label="ID" width="60" />
      <el-table-column prop="name" label="名称" />
      <el-table-column prop="db_type" label="类型" width="100" />
      <el-table-column prop="host" label="主机" />
      <el-table-column prop="port" label="端口" width="80" />
      <el-table-column prop="username" label="账号" width="120" />
      <el-table-column prop="schema_name" label="Schema" />
    </el-table>

    <FormDialog v-model="dialog.visible" title="注册数据源" :fields="dialog.fields" :initial="dialog.initial"
                @submit="submit" />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Datasources } from '../api'
import FormDialog from '../components/FormDialog.vue'
import { ElMessage } from 'element-plus'

const list = ref([])
const dialog = ref({
  visible: false,
  initial: { name: '', db_type: 'mysql', host: '127.0.0.1', port: 3306, username: 'root', password: '', schema_name: '' },
  fields: [
    { prop: 'name', label: '名称', placeholder: '如：生产库' },
    { prop: 'db_type', label: '类型', type: 'select', options: [{ label: 'MySQL', value: 'mysql' }, { label: 'Postgres', value: 'postgres' }] },
    { prop: 'host', label: '主机' },
    { prop: 'port', label: '端口' },
    { prop: 'username', label: '账号' },
    { prop: 'password', label: '密码', placeholder: '数据库密码（加密存储）' },
    { prop: 'schema_name', label: 'Schema' },
  ],
})

async function load() {
  try { list.value = await Datasources.list() }
  catch (e) { ElMessage.error('加载失败: ' + (e.response?.data?.error || e.message)) }
}
async function submit(form) {
  try {
    await Datasources.create(form)
    ElMessage.success('数据源已注册')
    dialog.value.visible = false
    load()
  } catch (e) {
    ElMessage.error('注册失败: ' + (e.response?.data?.error || e.message))
  }
}
onMounted(load)
</script>
