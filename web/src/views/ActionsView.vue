<template>
  <div style="padding:24px; max-width:1000px; margin:0 auto">
    <div style="display:flex; justify-content:space-between; margin-bottom:16px">
      <h2>告警动作</h2>
      <el-button type="primary" @click="dialog.visible = true">+ 新增动作</el-button>
    </div>
    <el-table :data="list" border stripe>
      <el-table-column prop="id" label="ID" width="60" />
      <el-table-column prop="rule_id" label="规则ID" width="100" />
      <el-table-column prop="action_type" label="类型" width="120" />
      <el-table-column prop="config" label="配置" />
    </el-table>

    <FormDialog v-model="dialog.visible" title="新增动作" :fields="dialog.fields" :initial="dialog.initial"
                @submit="submit" />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Actions } from '../api'
import FormDialog from '../components/FormDialog.vue'
import { ElMessage } from 'element-plus'

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
    { prop: 'config', label: 'JSON 配置' },
  ],
})

async function load() {
  try { list.value = await Actions.list() }
  catch (e) { ElMessage.error('加载失败: ' + (e.response?.data?.error || e.message)) }
}
async function submit(form) {
  try {
    form.rule_id = Number(form.rule_id)
    await Actions.create(form)
    ElMessage.success('动作已新增')
    dialog.value.visible = false
    load()
  } catch (e) {
    ElMessage.error('新增失败: ' + (e.response?.data?.error || e.message))
  }
}
onMounted(load)
</script>
