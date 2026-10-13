<template>
  <div class="rules-view">
    <aside class="sidebar">
      <div class="side-head">
        <span>规则分组</span>
        <el-button size="small" type="primary" plain @click="openGroupDialog()">+ 分组</el-button>
      </div>
      <div class="group-list">
        <div v-for="g in groups" :key="g.id"
             :class="['group-item', { active: g.id === curGroupId }]"
             @click="selectGroup(g.id)">
          <span>📁 {{ g.name }}</span>
          <span class="ops">
            <el-button text size="small" @click.stop="openGroupDialog(g)">✎</el-button>
            <el-button text size="small" type="danger" @click.stop="removeGroup(g.id)">✕</el-button>
          </span>
        </div>
      </div>

      <div class="side-head" style="margin-top:12px">
        <span>规则</span>
        <el-button size="small" type="primary" @click="newRule">+ 新建</el-button>
      </div>
      <div class="rule-list">
        <div v-for="r in rules" :key="r.id"
             :class="['rule-item', { active: r.id === curRuleId }]"
             @click="selectRule(r)">
          <span>{{ r.name }}</span>
          <el-button text size="small" type="danger" @click.stop="removeRule(r.id)">✕</el-button>
        </div>
        <div v-if="!rules.length" class="empty">该分组下暂无规则</div>
      </div>
    </aside>

    <div class="center">
      <div class="palette">
        <div class="palette-title">添加节点</div>
        <div class="palette-item" @click="addNode('entity')">🏢 Entity</div>
        <div class="palette-item" @click="addNode('condition')">⚖ Condition</div>
        <div class="palette-item" @click="addNode('action')">🚨 Action</div>
        <span class="hint">点击添加 → 从节点右侧圆点拖线到下一节点左侧圆点</span>
      </div>
      <div class="canvas-wrap" ref="canvasRef">
        <VueFlow :nodes="nodes" :edges="edges" :node-types="nodeTypes"
                 :default-viewport="{ zoom: 1 }"
                 @connect="onConnect">
          <Controls />
          <MiniMap />
        </VueFlow>
      </div>
    </div>

    <aside class="right">
      <div class="side-head"><span>DSL 实时预览</span></div>
      <pre class="dsl-preview">{{ dslText }}</pre>
      <el-alert v-if="parseStatus" :type="parseStatus.ok ? 'success' : 'error'"
                :title="parseStatus.ok ? '✓ 语法校验通过' : '✗ 语法错误'"
                :description="parseStatus.error" :closable="false" style="margin-top:8px" />
      <div class="save-bar">
        <el-input v-model="ruleName" size="small" placeholder="规则名称" style="margin-bottom:8px" />
        <el-button type="primary" style="width:100%" @click="saveRule">保存规则</el-button>
      </div>
    </aside>

    <FormDialog v-model="groupDialog.visible" :title="groupDialog.title" :fields="groupDialog.fields"
                :initial="groupDialog.initial" @submit="submitGroup" />
  </div>
</template>

<script setup>
import { ref, computed, markRaw, onMounted } from 'vue'
import { VueFlow } from '@vue-flow/core'
import { Controls } from '@vue-flow/controls'
import { MiniMap } from '@vue-flow/minimap'
import { ElMessage, ElMessageBox } from 'element-plus'
import EntityNode from '../components/EntityNode.vue'
import ConditionNode from '../components/ConditionNode.vue'
import ActionNode from '../components/ActionNode.vue'
import FormDialog from '../components/FormDialog.vue'
import { Groups, Rules, verifyDsl } from '../api'
import { nodesToDsl, dslToNodes } from '../logic/dsl.js'

// markRaw 防止 Vue 把组件变成响应式代理（Vue Flow 要求 nodeTypes 是原始组件）
const nodeTypes = markRaw({ entity: EntityNode, condition: ConditionNode, action: ActionNode })

const groups = ref([])
const rules = ref([])
const curGroupId = ref(1)
const curRuleId = ref(null)
const nodes = ref([])
const edges = ref([])
const ruleName = ref('未命名规则')
const parseStatus = ref(null)
const canvasRef = ref(null)

const groupDialog = ref({ visible: false, title: '', fields: [], initial: {}, editingId: null })

async function safe(promise, okMsg) {
  try { const r = await promise; if (okMsg) ElMessage.success(okMsg); return r }
  catch (e) { ElMessage.error('请求失败: ' + (e.response?.data?.error || e.message)); throw e }
}

async function loadGroups() { groups.value = await safe(Groups.list()) }
async function loadRules() { rules.value = await safe(Rules.list(curGroupId.value)) }

function selectGroup(id) {
  curGroupId.value = id; curRuleId.value = null; nodes.value = []; edges.value = []
  loadRules()
}
async function selectRule(r) {
  curRuleId.value = r.id; ruleName.value = r.name
  const p = dslToNodes(r.dsl || '')
  nodes.value = p.nodes; edges.value = p.edges
  validateDsl()
}

function openGroupDialog(g) {
  groupDialog.value = {
    visible: true, title: g ? '重命名分组' : '新建分组', editingId: g?.id || null,
    initial: g ? { name: g.name, description: g.description || '' } : { name: '', description: '' },
    fields: [
      { prop: 'name', label: '名称', placeholder: '如：融资融券' },
      { prop: 'description', label: '描述', placeholder: '可选' },
    ],
  }
}
async function submitGroup(form) {
  if (groupDialog.value.editingId) await safe(Groups.update(groupDialog.value.editingId, form), '分组已更新')
  else await safe(Groups.create(form), '分组已创建')
  loadGroups()
}
async function removeGroup(id) {
  await ElMessageBox.confirm('删除分组？组内规则会移到默认分组', '确认', { type: 'warning' })
  await safe(Groups.remove(id), '分组已删除')
  if (curGroupId.value === id) curGroupId.value = 1
  loadGroups(); loadRules()
}

async function newRule() {
  const r = await safe(Rules.create({ name: '未命名规则', group_id: curGroupId.value, dsl: '', mode: 'LIFECYCLE', cron: '' }), '规则已创建')
  await loadRules(); selectRule({ id: r.id, name: r.name, dsl: '' })
}
async function removeRule(id) {
  await ElMessageBox.confirm('删除这条规则？', '确认', { type: 'warning' })
  await safe(Rules.remove(id), '规则已删除')
  curRuleId.value = null; nodes.value = []; edges.value = []; loadRules()
}

const dslText = computed(() => nodesToDsl({ name: ruleName.value, nodes: nodes.value, edges: edges.value }))
async function validateDsl() {
  if (!dslText.value.trim()) { parseStatus.value = null; return }
  try { parseStatus.value = await verifyDsl(dslText.value) } catch { parseStatus.value = null }
}

async function saveRule() {
  if (!curRuleId.value) { ElMessage.warning('请先新建规则'); return }
  await safe(Rules.update(curRuleId.value, {
    name: ruleName.value, group_id: curGroupId.value, dsl: dslText.value, mode: 'LIFECYCLE', cron: '',
  }), '规则已保存')
  loadRules()
}

function addNode(type) {
  const id = `${type}_${Date.now()}_${Math.floor(Math.random()*1000)}`
  const data = type === 'entity' ? { entity: 'Company' }
    : type === 'condition' ? { field: 'cancel_ratio', op: '>', value: '0.85', logic: 'AND' }
    : { severity: 'WARNING', emit: '规则触发' }
  // 瀑布流排列：按已有节点数错开位置
  const i = nodes.value.length
  nodes.value.push({ id, type, position: { x: 100 + (i % 4) * 250, y: 80 + Math.floor(i / 4) * 120 }, data })
  setTimeout(validateDsl, 100)
}
function onDragStart(e, type) { e.dataTransfer.setData('nodeType', type) }
function onDrop(e) {
  e.preventDefault()
  const type = e.dataTransfer.getData('nodeType')
  if (!type || !canvasRef.value) return
  const rect = canvasRef.value.getBoundingClientRect()
  const id = `${type}_${Date.now()}`
  const data = type === 'entity' ? { entity: 'Company' }
    : type === 'condition' ? { field: 'cancel_ratio', op: '>', value: '0.85', logic: 'AND' }
    : { severity: 'WARNING', emit: '规则触发' }
  nodes.value.push({ id, type, position: { x: e.clientX - rect.left - 90, y: e.clientY - rect.top - 40 }, data })
  setTimeout(validateDsl, 100)
}
function onConnect(params) {
  edges.value.push({ id: `e-${params.source}-${params.target}`, source: params.source, target: params.target })
  setTimeout(validateDsl, 100)
}

onMounted(async () => { await loadGroups(); await loadRules() })
</script>

<style scoped>
.rules-view { display:grid; grid-template-columns:240px 1fr 300px; height:calc(100vh - 56px); }
.sidebar { background:#fff; border-right:1px solid #e5e7eb; padding:12px; overflow:auto; }
.side-head { display:flex; justify-content:space-between; align-items:center; font-size:12px; color:#6b7280; margin-bottom:8px; }
.group-item { padding:7px 10px; border-radius:6px; cursor:pointer; font-size:13px; display:flex; justify-content:space-between; align-items:center; }
.group-item:hover { background:#f3f4f6; }
.group-item.active { background:#eff6ff; color:#1d4ed8; }
.ops { display:none; gap:2px; }
.group-item:hover .ops { display:flex; }
.rule-item { padding:6px 10px; font-size:12px; border-radius:6px; cursor:pointer; display:flex; justify-content:space-between; }
.rule-item:hover { background:#f3f4f6; }
.rule-item.active { background:#dbeafe; color:#1d4ed8; }
.empty { text-align:center; color:#9ca3af; font-size:12px; padding:20px; }

.center { display:flex; flex-direction:column; min-width:0; }
.palette { padding:10px; background:#fafbfc; border-bottom:1px solid #e5e7eb; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.palette-title { font-size:11px; color:#9ca3af; margin-right:8px; }
.palette-item { padding:6px 12px; background:#fff; border:1px solid #d1d5db; border-radius:6px; font-size:12px; cursor:grab; }
.palette-item:hover { border-color:#3b82f6; background:#eff6ff; }
.hint { font-size:11px; color:#9ca3af; margin-left:auto; }
.canvas-wrap { flex:1; min-height:500px; position:relative; }
.canvas-wrap :deep(.vue-flow) { background:#fafbfc; }

.right { background:#fff; border-left:1px solid #e5e7eb; padding:12px; display:flex; flex-direction:column; overflow:auto; }
.dsl-preview { background:#1f2937; color:#e5e7eb; padding:12px; border-radius:6px; font-family:Consolas,monospace; font-size:12px; flex:1; overflow:auto; }
.save-bar { margin-top:12px; }
</style>
