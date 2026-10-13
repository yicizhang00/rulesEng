<template>
  <div class="verify-view">
    <div class="toolbar">
      <h2>校验报告</h2>
      <el-select v-model="ruleId" placeholder="选择规则" style="width:320px" filterable @change="onSelect">
        <el-option v-for="r in rules" :key="r.id" :label="`#${r.id} ${r.name}（${r.mode || 'PURE'} · v${r.version || '1.0.0'}）`" :value="r.id" />
      </el-select>
      <el-button :disabled="!ruleId" :loading="loading" @click="run">重新校验</el-button>
    </div>

    <el-empty v-if="!ruleId" description="选择一条规则查看 Z3 静态校验报告与版本历史" />

    <template v-else>
      <el-alert v-if="report" :type="report.ok ? 'success' : 'error'"
                :title="report.ok ? '✓ 校验通过（可入库）' : '✗ 校验未通过（禁止入库）'"
                :description="`status = ${report.status}`" :closable="false" show-icon />

      <div class="grid">
        <el-card shadow="never">
          <template #header>Errors（阻断入库）· {{ report?.errors?.length || 0 }}</template>
          <ul v-if="report?.errors?.length" class="issue-list errors">
            <li v-for="(issue, i) in report.errors" :key="`e${i}`">
              <el-tag size="small" type="danger">{{ issue.kind }}</el-tag>
              <span>{{ issue.message }}</span>
              <span v-if="issue.specs?.length" class="specs">[{{ issue.specs.join(', ') }}]</span>
              <div v-if="issue.counterexample_text" class="witness">反例参数：{{ issue.counterexample_text }}</div>
            </li>
          </ul>
          <div v-else class="empty">无</div>
        </el-card>

        <el-card shadow="never">
          <template #header>Warnings（需复核，不阻断）· {{ report?.warnings?.length || 0 }}</template>
          <ul v-if="report?.warnings?.length" class="issue-list warnings">
            <li v-for="(issue, i) in report.warnings" :key="`w${i}`">
              <el-tag size="small" type="warning">{{ issue.kind }}</el-tag>
              <span>{{ issue.message }}</span>
              <div v-if="issue.counterexample_text" class="witness">反例参数：{{ issue.counterexample_text }}</div>
            </li>
          </ul>
          <div v-else class="empty">无</div>
        </el-card>
      </div>

      <el-card shadow="never" style="margin-top:16px">
        <template #header>版本历史（rule_versions）· {{ versions.length }}</template>
        <el-table :data="versions" border size="small">
          <el-table-column prop="version" label="版本" width="70" />
          <el-table-column prop="submitted_by" label="提交人" width="120" />
          <el-table-column label="校验结论" width="120">
            <template #default="{ row }">
              <el-tag size="small" :type="versionStatus(row) === 'PASS' ? 'success' : 'danger'">
                {{ versionStatus(row) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="DSL 快照" min-width="320">
            <template #default="{ row }">
              <pre class="mini-dsl">{{ row.dsl_text }}</pre>
            </template>
          </el-table-column>
        </el-table>
        <div v-if="!versions.length" class="empty">暂无版本快照（保存规则后自动生成）</div>
      </el-card>
    </template>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Rules, verifyDsl } from '../api'
import { ElMessage } from 'element-plus'

const rules = ref([])
const ruleId = ref(null)
const report = ref(null)
const versions = ref([])
const loading = ref(false)

async function loadRules() {
  try { rules.value = await Rules.list() }
  catch (e) { ElMessage.error('加载规则失败: ' + (e.payload?.error || e.message)) }
}

function versionStatus(row) {
  try {
    const parsed = typeof row.verify_report === 'string' ? JSON.parse(row.verify_report) : row.verify_report
    return parsed?.status || 'UNKNOWN'
  } catch { return row.verify_report ? 'FAIL' : 'UNKNOWN' }
}

async function onSelect() {
  report.value = null
  versions.value = []
  await run()
}

async function run() {
  if (!ruleId.value) return
  loading.value = true
  try {
    const rule = await Rules.get(ruleId.value)
    const dsl = rule.dsl_content || rule.dsl || ''
    if (!dsl.trim()) {
      report.value = { ok: false, status: 'FAIL', errors: [{ kind: 'EMPTY_DSL', message: '规则还没有 DSL 内容', specs: [], counterexample_text: '' }], warnings: [] }
    } else {
      report.value = await verifyDsl(dsl, ruleId.value)
    }
    versions.value = await Rules.versions(ruleId.value)
  } catch (e) {
    ElMessage.error('校验失败: ' + (e.payload?.error || e.message))
  } finally { loading.value = false }
}

onMounted(loadRules)
</script>

<style scoped>
.verify-view { padding:24px; max-width:1200px; margin:0 auto; height:100%; overflow:auto; }
.toolbar { display:flex; align-items:center; gap:12px; margin-bottom:16px; }
.grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-top:16px; }
.issue-list { list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:8px; font-size:13px; }
.issue-list li { display:flex; align-items:flex-start; gap:8px; line-height:1.5; }
.issue-list.errors { color:#b91c1c; }
.issue-list.warnings { color:#b45309; }
.specs { color:#6b7280; font-size:12px; }
.witness { color:#7c2d12; background:#fef3c7; border-radius:4px; padding:2px 6px; font-family:Consolas,monospace; font-size:12px; }
.empty { color:#9ca3af; font-size:13px; }
.mini-dsl { margin:0; background:#f9fafb; padding:6px; border-radius:4px; font-size:11px; max-height:120px; overflow:auto; white-space:pre-wrap; }
@media (max-width: 900px) { .grid { grid-template-columns:1fr; } }
</style>
