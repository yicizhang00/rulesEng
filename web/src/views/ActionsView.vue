<template>
  <div style="padding:24px; max-width:1000px; margin:0 auto">
    <div style="display:flex; justify-content:space-between; margin-bottom:16px">
      <h2>告警动作</h2>
      <el-button type="primary" @click="openCreate">+ 新增动作</el-button>
    </div>
    <el-table :data="list" border stripe>
      <el-table-column prop="id" label="ID" width="60" />
      <el-table-column prop="rule_id" label="规则ID" width="100" />
      <el-table-column prop="action_type" label="类型" width="140" />
      <el-table-column prop="config" label="配置" />
      <el-table-column label="操作" width="90">
        <template #default="{ row }">
          <el-button text size="small" type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <FormDialog v-model="dialog.visible" title="新增动作" :fields="dialog.fields" :initial="dialog.initial"
                @submit="submit" />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Actions } from '../api'
import FormDialog from '../components/FormDialog.vue'
import { ElMessage, ElMessageBox } from 'element-plus'

const list = ref([])
const dialog = ref({
  visible: false,
  initial: { rule_id: 0, action_type: 'sms', config: '{}' },
  fields: [
    { prop: 'rule_id', label: '规则ID' },
    { prop: 'action_type', label: '类型', type: 'select', options: [
      { label: '短信', value: 'sms' }, { label: 'HTTP 回调', value: 'http' },
      { label: '邮件', value: 'email' }, { label: '状态流转', value: 'state_transition' },
    ]},
    { prop: 'config', label: 'JSON 配置', placeholder: '如 {"url":"https://..."}' },
  ],
})

function openCreate() {
  dialog.value.visible = true
  dialog.value.initial = { rule_id: 0, action_type: 'sms', config: '{}' }
}

async function load() {
  try { list.value = await Actions.list() }
  catch (e) { ElMessage.error('加载失败: ' + (e.payload?.error || e.message)) }
}

async function submit(form) {
  try {
    form.rule_id = Number(form.rule_id) || 0
    try { JSON.parse(form.config) } catch { ElMessage.warning('配置不是合法 JSON，已按原样保存') }
    await Actions.create(form)
    ElMessage.success('动作已新增')
    dialog.value.visible = false
    load()
  } catch (e) {
    ElMessage.error('新增失败: ' + (e.payload?.error || e.message))
  }
}

async function remove(row) {
  try { await ElMessageBox.confirm(`删除动作 #${row.id}（${row.action_type}）？`, '删除动作', { type: 'warning' }) }
  catch { return }
  try {
    await Actions.remove(row.id)
    ElMessage.success('动作已删除')
    load()
  } catch (e) { ElMessage.error('删除失败: ' + (e.payload?.error || e.message)) }
}

onMounted(load)
</script>
