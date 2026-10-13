<template>
  <div class="rules-view">
    <!-- ============ 左：分组 / 规则 ============ -->
    <aside class="sidebar">
      <div class="side-head">
        <span>规则分组</span>
        <el-button size="small" type="primary" plain @click="openGroupDialog()">+ 分组</el-button>
      </div>
      <div class="group-list">
        <div v-for="g in displayGroups" :key="g.id"
             :class="['group-item', { active: Number(g.id) === Number(curGroupId) }]"
             :style="{ paddingLeft: `${10 + g.depth * 16}px` }"
             @click="selectGroup(g.id)">
          <span>{{ g.depth ? '└ ' : '📁 ' }}{{ g.name }}</span>
          <span class="ops">
            <el-button text size="small" aria-label="重命名分组" @click.stop="openGroupDialog(g)">✎</el-button>
            <el-button text size="small" type="danger" aria-label="删除分组" :disabled="Number(g.id) === 1" @click.stop="removeGroup(g.id)">✕</el-button>
          </span>
        </div>
      </div>

      <div class="side-head" style="margin-top:12px">
        <span>规则</span>
        <el-button size="small" type="primary" :disabled="!curGroupId || busy" @click="openNewRuleDialog">+ 新建</el-button>
      </div>
      <div class="rule-list">
        <div v-for="r in rules" :key="r.id"
             :class="['rule-item', { active: Number(r.id) === Number(curRuleId) }]"
             @click="selectRule(r)">
          <span class="rule-name">{{ r.name }}</span>
          <el-tag size="small" :type="modeTagType(r.mode)">{{ r.mode }}</el-tag>
          <span class="rule-mode">v{{ r.version || '1.0.0' }}</span>
          <el-button text size="small" type="danger" aria-label="删除规则" @click.stop="removeRule(r.id)">✕</el-button>
        </div>
        <div v-if="!rules.length" class="empty">该分组下暂无规则</div>
      </div>
    </aside>

    <!-- ============ 中：连线画布 ============ -->
    <div class="center">
      <div class="palette">
        <div class="palette-title">执行模式</div>
        <el-select :model-value="ruleMode" size="small" style="width:230px" :disabled="!curRuleId" @change="onModeChange">
          <el-option v-for="m in MODES" :key="m.value" :label="`${m.label}（${m.dsl}）`" :value="m.value" />
        </el-select>
        <div class="palette-title" style="margin-left:12px">添加节点</div>
        <el-button size="small" @click="addNode('entity')">🏢 Entity</el-button>
        <el-button size="small" @click="addNode('condition')">⚖ Condition</el-button>
        <el-button size="small" :disabled="ruleMode !== 'DMN'" @click="addNode('dmn')">📊 DMN</el-button>
        <el-button size="small" @click="addNode('action')">🚨 Action</el-button>
        <span class="hint">
          点击添加节点、拖动圆点连线；节点必须形成
          Entity → {{ ruleMode === 'DMN' ? 'DMN → ' : '' }}Condition* → Action 的单链路。
          {{ modeHint }}
        </span>
      </div>
      <div class="canvas-wrap">
        <VueFlow v-model:nodes="nodes" v-model:edges="edges" :node-types="nodeTypes"
                 :default-viewport="{ zoom: 0.8 }" fit-view-on-init
                 :connection-radius="30" @connect="onConnect">
          <Controls />
          <MiniMap />
        </VueFlow>
        <div v-if="!curRuleId" class="canvas-empty">先选择分组并新建规则，画布才可以编辑</div>
      </div>
    </div>

    <!-- ============ 右：属性 / 校验 / DMN / 绑定 ============ -->
    <aside class="right">
      <el-tabs v-model="rightTab" class="right-tabs">
        <!-- ---------- 画布属性 ---------- -->
        <el-tab-pane label="画布属性" name="props">
          <div class="section">
            <div class="section-title">规则</div>
            <el-input v-model="ruleName" size="small" placeholder="规则名称" :disabled="!curRuleId" />
            <div class="grid2">
              <el-input v-model="ruleVersion" size="small" placeholder="版本 1.0.0" :disabled="!curRuleId" />
              <el-select v-model="ruleStatus" size="small" :disabled="!curRuleId">
                <el-option v-for="s in STATUSES" :key="s" :label="s" :value="s" />
              </el-select>
            </div>
            <div class="section-hint">{{ modeHint }}</div>
          </div>

          <div class="section">
            <div class="section-title">实体（Entity 节点）</div>
            <template v-if="entityNode">
              <el-input v-model="entityNode.data.entity" size="small" placeholder="实体名 Company" />
              <el-input v-model="entityNode.data.key" size="small" placeholder="主键字段 code" style="margin-top:6px" />
              <el-input v-model="entityNode.data.states" size="small" placeholder="状态列表，逗号分隔：NORMAL, SUSPENDED" style="margin-top:6px" />
              <div class="grid2">
                <el-input v-model="entityNode.data.initial" size="small" placeholder="初始状态" />
                <el-input v-model="entityNode.data.terminal" size="small" placeholder="终态（可选）" />
              </div>
              <el-input v-model="entityNode.data.events" size="small" placeholder="事件类型，逗号分隔：TradeIntent" style="margin-top:6px" />
            </template>
            <div v-else class="empty">画布上没有 Entity 节点</div>
          </div>

          <div class="section">
            <div class="section-title">
              条件（Condition 节点）
              <el-button text size="small" :disabled="!curRuleId" @click="addNode('condition')">+</el-button>
            </div>
            <div v-if="!conditionNodes.length" class="empty">无条件节点：动作在链路到达时直接生效</div>
            <div v-for="(node, index) in conditionNodes" :key="node.id" class="condition-row">
              <el-input v-model="node.data.field" size="small" placeholder="字段" style="width:38%" />
              <el-select v-model="node.data.op" size="small" style="width:22%">
                <el-option v-for="o in OPS" :key="o" :label="o" :value="o" />
              </el-select>
              <el-input v-model="node.data.value" size="small" placeholder="值" style="width:26%" />
              <el-select v-model="node.data.logic" size="small" style="width:14%" :disabled="index === 0">
                <el-option label="且" value="AND" />
                <el-option label="或" value="OR" />
              </el-select>
            </div>
          </div>

          <div class="section">
            <div class="section-title">裁决 / 效果（Action 节点）</div>
            <template v-if="actionNode">
              <template v-if="ruleMode !== 'STATEFUL'">
                <el-select v-model="actionNode.data.verdict" size="small" style="width:100%">
                  <el-option label="DENY（拒绝 / 阻断）" value="DENY" />
                  <el-option label="ALLOW（显式放行）" value="ALLOW" />
                </el-select>
                <template v-if="actionNode.data.verdict !== 'ALLOW'">
                  <el-input v-model="actionNode.data.code" size="small" placeholder="错误码 ERR_XXX" style="margin-top:6px" />
                  <el-input v-model="actionNode.data.reason" size="small" placeholder="拒绝理由" style="margin-top:6px" />
                </template>
              </template>
              <template v-else>
                <el-input v-model="actionNode.data.code" size="small" placeholder="错误码 ERR_XXX" />
                <el-input v-model="actionNode.data.reason" size="small" placeholder="拒绝理由" style="margin-top:6px" />
              </template>
              <el-input v-model="actionNode.data.emit" size="small" placeholder="告警文案 Emit(&quot;…&quot;)" style="margin-top:6px" />
              <div class="grid2">
                <el-input v-model="actionNode.data.transitionFrom" size="small" placeholder="迁移起始状态" />
                <el-input v-model="actionNode.data.transitionTo" size="small" placeholder="迁移目标状态" />
              </div>
              <template v-if="ruleMode === 'STREAM'">
                <div class="grid2">
                  <el-input v-model="actionNode.data.leaseTarget" size="small" placeholder="租约变量 frozen_until" />
                  <el-input v-model="actionNode.data.leaseSeconds" size="small" placeholder="冻结秒数 60" />
                </div>
                <div class="section-hint">惩罚租约由 LeaseUpdate 单调推进；解冻靠引擎时钟，无后台定时器。</div>
              </template>
            </template>
            <div v-else class="empty">画布上没有 Action 节点</div>
          </div>
        </el-tab-pane>

        <!-- ---------- DMN ---------- -->
        <el-tab-pane label="DMN 决策表" name="dmn" :disabled="ruleMode !== 'DMN'">
          <div class="section">
            <div class="section-title">决策表定义</div>
            <template v-if="dmnNode">
              <el-input v-model="dmnNode.data.table" size="small" placeholder="决策表名 DetermineAmount" />
              <div class="grid2">
                <el-input v-model="dmnNode.data.param" size="small" placeholder="入参名 req_time" />
                <el-select v-model="dmnNode.data.paramType" size="small">
                  <el-option v-for="t in TYPES" :key="t" :label="t" :value="t" />
                </el-select>
              </div>
              <el-select v-model="dmnNode.data.hitPolicy" size="small" style="width:100%; margin-top:6px">
                <el-option v-for="p in HIT_POLICIES" :key="p" :label="`命中策略 ${p}`" :value="p" />
              </el-select>
              <el-input v-model="dmnNode.data.lookupArg" size="small" placeholder="查表入参表达式 event.timestamp" style="margin-top:6px" />
              <div class="grid2">
                <el-input v-model="dmnOutputsText" size="small" placeholder="输出列，逗号分隔：amount, phase" />
                <el-input v-model="dmnOutputTypesText" size="small" placeholder="输出类型：Int, Int" />
              </div>
              <el-table :data="dmnNode.data.rows" size="small" style="margin-top:8px">
                <el-table-column label="下界" width="86">
                  <template #default="scope">
                    <el-input v-model="scope.row.from" size="small" :disabled="scope.row.isDefault" />
                  </template>
                </el-table-column>
                <el-table-column label="上界" width="86">
                  <template #default="scope">
                    <el-input v-model="scope.row.to" size="small" :disabled="scope.row.isDefault" />
                  </template>
                </el-table-column>
                <el-table-column label="输出">
                  <template #default="scope">
                    <el-input v-model="scope.row.out" size="small" />
                  </template>
                </el-table-column>
                <el-table-column label="兜底" width="52">
                  <template #default="scope">
                    <el-checkbox v-model="scope.row.isDefault" size="small" @change="onDefaultToggle(scope.row)" />
                  </template>
                </el-table-column>
                <el-table-column width="46">
                  <template #default="scope">
                    <el-button text size="small" type="danger" @click="removeDmnRow(scope.$index)">✕</el-button>
                  </template>
                </el-table-column>
              </el-table>
              <el-button size="small" style="margin-top:6px" @click="addDmnRow">+ 规则行</el-button>
            </template>
            <div v-else class="empty">请先添加并连线 DMN 决策表节点</div>
          </div>

          <div class="section">
            <div class="section-title">DMN 1.3 互通</div>
            <div class="button-row">
              <el-button size="small" :disabled="!curRuleId" @click="exportDmn">导出 DMN XML</el-button>
              <el-button size="small" @click="openImportDialog">导入 DMN XML</el-button>
              <el-button v-if="curRuleId" size="small" @click="loadRuleDmnXml">查看已存 XML</el-button>
            </div>
            <div class="section-hint">导出会同时把 XML 缓存进 rules.dmn_xml；导入的 XML 会转成 DSL 覆盖当前画布。</div>
          </div>

          <div class="section">
            <div class="section-title">决策表试算（AC4）</div>
            <el-input v-model="trialArg" size="small" placeholder="入参值，如 11-02 或 1793577600" />
            <el-date-picker v-if="dmnParamType === 'Timestamp'" v-model="trialDate" type="datetime"
                            size="small" style="width:100%; margin-top:6px" placeholder="按日期试算（折算为 epoch 秒）" />
            <el-button size="small" type="primary" style="margin-top:6px" :disabled="!curRuleId" @click="runTrial">试算</el-button>
            <div v-if="trialResult" class="trial-result">
              <div v-if="trialResult.ok">
                <div>命中行：<b>{{ trialResult.row == null ? 'default 兜底' : `第 ${trialResult.row + 1} 行` }}</b>
                  （命中 {{ trialResult.hit_count }} 行，策略 {{ trialResult.hit_policy }}）</div>
                <div v-for="col in trialResult.result" :key="col.name">
                  {{ col.name }} ({{ col.type }}) = <b>{{ col.value }}</b>
                </div>
              </div>
              <div v-else class="issue errors">试算失败：{{ trialResult.error }}</div>
            </div>
          </div>
        </el-tab-pane>

        <!-- ---------- 校验 ---------- -->
        <el-tab-pane label="校验" name="verify">
          <div class="section">
            <div class="section-title">
              形式化校验
              <el-button text size="small" :disabled="!curRuleId || !!graphError" @click="runVerify">重新校验</el-button>
            </div>
            <el-alert v-if="!verifyReport" type="info" title="尚未校验" :closable="false" />
            <template v-else>
              <el-alert :type="verifyReport.ok ? 'success' : 'error'"
                        :title="verifyReport.ok ? '✓ 校验通过（可入库）' : '✗ 校验未通过（禁止入库）'"
                        :closable="false" />
              <ul v-if="verifyReport.errors?.length" class="issue-list errors">
                <li v-for="(issue, i) in verifyReport.errors" :key="`e${i}`">
                  <b>{{ issue.kind }}</b>：{{ issue.message }}
                  <div v-if="issue.counterexample_text" class="witness">反例参数：{{ issue.counterexample_text }}</div>
                </li>
              </ul>
              <ul v-if="verifyReport.warnings?.length" class="issue-list warnings">
                <li v-for="(issue, i) in verifyReport.warnings" :key="`w${i}`">
                  <b>{{ issue.kind }}</b>：{{ issue.message }}
                  <div v-if="issue.counterexample_text" class="witness">反例参数：{{ issue.counterexample_text }}</div>
                </li>
              </ul>
              <div v-if="!verifyReport.errors?.length && !verifyReport.warnings?.length" class="empty">无错误、无警告</div>
            </template>
          </div>

          <div class="section">
            <div class="section-title">DSL 实时预览</div>
            <el-alert v-if="loadWarning" type="error" title="画布只呈现了部分 DSL" :description="loadWarning" :closable="false" show-icon />
            <pre class="dsl-preview">{{ dslText || '请连接 Entity 和 Action 节点' }}</pre>
            <el-alert v-if="graphError" type="warning" title="画布结构不完整" :description="graphError" :closable="false" />
          </div>

          <div class="section">
            <div class="section-title">版本历史</div>
            <el-button size="small" :disabled="!curRuleId" @click="loadVersions">刷新版本</el-button>
            <div v-if="versions.length" class="version-list">
              <div v-for="v in versions" :key="v.id">v{{ v.version }} · {{ v.submitted_by || '匿名' }} · {{ v.verify_report ? '有校验报告' : '—' }}</div>
            </div>
          </div>
        </el-tab-pane>

        <!-- ---------- 绑定 ---------- -->
        <el-tab-pane label="变量绑定" name="bindings">
          <div class="section">
            <div class="section-title">
              变量 → 数据源列（FR8）
              <el-button text size="small" :disabled="!curRuleId || !bindingRows.length" @click="saveBindings">保存</el-button>
            </div>
            <div v-if="!bindingRows.length" class="empty">当前 DSL 没有待绑定的变量或裸标识符</div>
            <div v-for="row in bindingRows" :key="row.name" class="binding-row">
              <div class="binding-name">
                <el-tag size="small" :type="row.kind === 'var' ? 'primary' : 'warning'">{{ row.kind }}</el-tag>
                <span>{{ row.name }}</span>
              </div>
              <el-select v-model="row.datasource_id" size="small" placeholder="数据源" style="width:100%"
                         @change="onDatasourceChange(row)">
                <el-option v-for="ds in datasources" :key="ds.id" :label="ds.name" :value="ds.id" />
              </el-select>
              <el-select v-model="row.table_name" size="small" placeholder="表" style="width:100%"
                         :disabled="!row.datasource_id" @change="row.column_name = ''">
                <el-option v-for="t in tableOptions(row)" :key="t" :label="t" :value="t" />
              </el-select>
              <el-select v-model="row.column_name" size="small" placeholder="列" style="width:100%" :disabled="!row.table_name">
                <el-option v-for="c in columnOptions(row)" :key="c" :label="c" :value="c" />
              </el-select>
            </div>
          </div>
        </el-tab-pane>
      </el-tabs>

      <div class="save-bar">
        <el-button type="primary" style="width:100%" :disabled="!curRuleId || busy || !!graphError || !!loadWarning" :loading="saving" @click="saveRule">
          保存规则（生成版本快照）
        </el-button>
      </div>
    </aside>

    <!-- ============ 对话框（全部走 Element Plus，禁用浏览器原生弹窗） ============ -->
    <FormDialog v-model="groupDialog.visible" :title="groupDialog.title" :fields="groupDialog.fields"
                :initial="groupDialog.initial" @submit="submitGroup" />

    <el-dialog v-model="newRuleDialog.visible" title="新建规则" width="460px">
      <el-form label-width="76px">
        <el-form-item label="名称">
          <el-input v-model="newRuleDialog.name" placeholder="如：席位洪水防护" />
        </el-form-item>
        <el-form-item label="执行模式">
          <el-select v-model="newRuleDialog.mode" style="width:100%">
            <el-option v-for="m in MODES" :key="m.value" :label="`${m.label}（${m.dsl}）`" :value="m.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="版本">
          <el-input v-model="newRuleDialog.version" placeholder="1.0.0" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="newRuleDialog.visible = false">取消</el-button>
        <el-button type="primary" :loading="busy" @click="confirmNewRule">创建</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="importDialog.visible" title="导入 DMN 1.3 XML" width="640px">
      <el-input v-model="importDialog.xml" type="textarea" :rows="14"
                placeholder="粘贴 DMN 1.3 XML（<definitions> … <decisionTable> …）" />
      <template #footer>
        <el-button @click="importDialog.visible = false">取消</el-button>
        <el-button type="primary" :loading="busy" @click="confirmImport">解析并载入画布</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="xmlDialog.visible" title="rules.dmn_xml（已缓存）" width="700px">
      <pre class="xml-preview">{{ xmlDialog.xml || '（空）' }}</pre>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, markRaw, onMounted, watch } from 'vue'
import { VueFlow } from '@vue-flow/core'
import { Controls } from '@vue-flow/controls'
import { MiniMap } from '@vue-flow/minimap'
import { ElMessage, ElMessageBox } from 'element-plus'
import EntityNode from '../components/EntityNode.vue'
import ConditionNode from '../components/ConditionNode.vue'
import DmnNode from '../components/DmnNode.vue'
import ActionNode from '../components/ActionNode.vue'
import FormDialog from '../components/FormDialog.vue'
import { Groups, Rules, Datasources, Bindings, Dmn, DecisionTables, verifyDsl } from '../api'
import {
  MODES, STATUSES, HIT_POLICIES, TYPES, OPS,
  dslToNodes, nodesToDsl, validateCanvas, extractBindingTargets,
} from '../logic/dsl.js'

const nodeTypes = markRaw({ entity: EntityNode, condition: ConditionNode, dmn: DmnNode, action: ActionNode })
const groups = ref([])
const rules = ref([])
const curGroupId = ref(null)
const curRuleId = ref(null)
const nodes = ref([])
const edges = ref([])
const ruleName = ref('')
const ruleMode = ref('PURE')
const ruleVersion = ref('1.0.0')
const ruleStatus = ref('DRAFT')
const rightTab = ref('props')
const verifyReport = ref(null)
const verifying = ref(false)
const saving = ref(false)
const busy = ref(false)
const versions = ref([])
const groupDialog = ref({ visible: false, title: '', fields: [], initial: {}, editingId: null })
const newRuleDialog = ref({ visible: false, name: '', mode: 'PURE', version: '1.0.0' })
const importDialog = ref({ visible: false, xml: '' })
const xmlDialog = ref({ visible: false, xml: '' })
const trialArg = ref('')
const trialDate = ref('')
const trialResult = ref(null)
const loadWarning = ref('')

const datasources = ref([])
const savedBindings = ref([])
const bindingRows = ref([])
const schemaCache = ref({})

let listRequest = 0
let validationRequest = 0
let validationTimer

const canvas = computed(() => ({ nodes: nodes.value, edges: edges.value }))
const graphError = computed(() => curRuleId.value ? validateCanvas({ mode: ruleMode.value, ...canvas.value }) : '')
const dslText = computed(() => graphError.value ? ''
  : nodesToDsl({ name: ruleName.value, mode: ruleMode.value, ...canvas.value }))
const modeHint = computed(() => MODES.find(m => m.value === ruleMode.value)?.hint || '')

const entityNode = computed(() => nodes.value.find(n => n.type === 'entity'))
const actionNode = computed(() => nodes.value.find(n => n.type === 'action'))
const dmnNode = computed(() => nodes.value.find(n => n.type === 'dmn'))
const conditionNodes = computed(() => nodes.value.filter(n => n.type === 'condition'))
const dmnParamType = computed(() => dmnNode.value?.data?.paramType || 'Int')

const dmnOutputsText = computed({
  get: () => (dmnNode.value?.data?.outputs || []).join(', '),
  set: (value) => {
    if (dmnNode.value) dmnNode.value.data.outputs = String(value).split(',').map(s => s.trim()).filter(Boolean)
  },
})
const dmnOutputTypesText = computed({
  get: () => (dmnNode.value?.data?.outputTypes || []).join(', '),
  set: (value) => {
    if (dmnNode.value) dmnNode.value.data.outputTypes = String(value).split(',').map(s => s.trim()).filter(Boolean)
  },
})

const displayGroups = computed(() => {
  const byParent = new Map()
  for (const group of groups.value) {
    const parent = group.parent_id == null ? null : String(group.parent_id)
    byParent.set(parent, [...(byParent.get(parent) || []), group])
  }
  const result = []
  const visit = (parentId, depth, path = new Set()) => {
    for (const group of byParent.get(parentId) || []) {
      if (path.has(String(group.id))) continue
      result.push({ ...group, depth })
      visit(String(group.id), depth + 1, new Set([...path, String(group.id)]))
    }
  }
  visit(null, 0)
  // A malformed/orphaned group should remain visible so it can still be managed.
  for (const group of groups.value) if (!result.some(item => String(item.id) === String(group.id))) result.push({ ...group, depth: 0 })
  return result
})

function modeTagType(mode) {
  return { PURE: 'primary', STATEFUL: 'warning', STREAM: 'success', DMN: 'danger' }[mode] || 'info'
}

async function safe(request, successMessage) {
  try {
    const result = await request
    if (successMessage) ElMessage.success(successMessage)
    return result
  } catch (error) {
    const payload = error.payload
    if (payload?.errors || payload?.warnings) verifyReport.value = { ok: false, status: payload.status || 'FAIL', ...payload }
    ElMessage.error(`操作失败：${payload?.error || error.message}`)
    throw error
  }
}

async function loadGroups() {
  const result = await safe(Groups.list())
  groups.value = Array.isArray(result) ? result : []
  if (!groups.value.some(group => Number(group.id) === Number(curGroupId.value))) {
    curGroupId.value = Number(groups.value.find(group => Number(group.id) === 1)?.id ?? groups.value[0]?.id ?? 0) || null
  }
}

async function loadRules(groupId = curGroupId.value) {
  const requestId = ++listRequest
  const result = await safe(Rules.list(groupId))
  if (requestId === listRequest && Number(groupId) === Number(curGroupId.value)) {
    rules.value = Array.isArray(result) ? result : []
  }
}

async function loadDatasources() {
  try { datasources.value = await Datasources.list() } catch { datasources.value = [] }
}

function clearEditor() {
  curRuleId.value = null
  ruleName.value = ''
  ruleMode.value = 'PURE'
  ruleVersion.value = '1.0.0'
  ruleStatus.value = 'DRAFT'
  nodes.value = []
  edges.value = []
  verifyReport.value = null
  versions.value = []
  trialResult.value = null
  loadWarning.value = ''
  savedBindings.value = []
  bindingRows.value = []
}

async function loadBindings(ruleId) {
  try {
    savedBindings.value = await Bindings.list(ruleId)
    rebuildBindingRows()
  } catch { savedBindings.value = [] }
}

async function selectGroup(id) {
  if (Number(id) === Number(curGroupId.value) && rules.value.length) return
  curGroupId.value = Number(id)
  listRequest++
  clearEditor()
  rules.value = []
  try { await loadRules(curGroupId.value) } catch { /* safe() has shown the API error */ }
}

async function selectRule(rule) {
  curRuleId.value = rule.id
  ruleName.value = rule.name || ''
  ruleMode.value = rule.mode || 'PURE'
  ruleVersion.value = rule.version || '1.0.0'
  ruleStatus.value = rule.status || 'DRAFT'
  // 列表接口为了轻量不带 dmn_xml，详情才有；画布只需要 dsl_content
  const parsed = dslToNodes(rule.dsl_content || rule.dsl || '')
  nodes.value = parsed.nodes
  edges.value = parsed.edges
  verifyReport.value = null
  versions.value = []
  trialResult.value = null
  loadWarning.value = parsed.warning || ''
  if (parsed.error) {
    ElMessage.warning(`画布无法完整还原该 DSL：${parsed.error}`)
  } else {
    await loadBindings(rule.id)
    runVerify()
  }
}

function openGroupDialog(group) {
  const parentOptions = displayGroups.value
    .filter(item => !group || Number(item.id) !== Number(group.id))
    .map(item => ({ label: `${'　'.repeat(item.depth)}${item.name}`, value: Number(item.id) }))
  groupDialog.value = {
    visible: true,
    title: group ? '编辑分组' : '新建分组',
    editingId: group?.id ?? null,
    initial: group ? { name: group.name, description: group.description || '', parent_id: group.parent_id ?? '' }
      : { name: '', description: '', parent_id: curGroupId.value ?? '' },
    fields: [
      { prop: 'name', label: '名称', placeholder: '如：融资融券' },
      ...(Number(group?.id) === 1 ? [] : [{ prop: 'parent_id', label: '上级分组', type: 'select', options: [{ label: '顶级分组', value: '' }, ...parentOptions] }]),
      { prop: 'description', label: '描述', placeholder: '可选' },
    ],
  }
}

async function submitGroup(form) {
  busy.value = true
  try {
    const payload = { ...form, parent_id: form.parent_id === '' ? null : Number(form.parent_id) }
    const result = groupDialog.value.editingId
      ? await safe(Groups.update(groupDialog.value.editingId, payload), '分组已更新')
      : await safe(Groups.create(payload), '分组已创建')
    groupDialog.value.visible = false
    await loadGroups()
    if (!groupDialog.value.editingId && result?.id) await selectGroup(result.id)
    else await loadRules(curGroupId.value)
  } catch { /* safe() has shown the API error; keep the dialog open for correction */ }
  finally { busy.value = false }
}

async function removeGroup(id) {
  try {
    await ElMessageBox.confirm('删除分组后，其中的规则会移入默认分组。', '删除分组', { type: 'warning' })
  } catch { return }
  busy.value = true
  try {
    await safe(Groups.remove(id), '分组已删除')
    const wasSelected = Number(curGroupId.value) === Number(id)
    await loadGroups()
    if (wasSelected) {
      clearEditor()
      rules.value = []
    }
    await loadRules(curGroupId.value)
  } catch { /* safe() has shown the API error */ }
  finally { busy.value = false }
}

// ---------------------------------------------------------------------------
// 起手画布：每种模式给一张能立刻通过形式化校验的最小画布
// ---------------------------------------------------------------------------

function defaultEntity(mode) {
  return {
    entity: 'Account',
    key: 'account_id',
    states: mode === 'STREAM' ? 'OPEN, FROZEN' : 'NORMAL, RESTRICTED',
    initial: mode === 'STREAM' ? 'OPEN' : 'NORMAL',
    terminal: mode === 'STREAM' ? 'FROZEN' : 'RESTRICTED',
    events: 'TradeIntent',
  }
}

function starterCanvas(mode) {
  const entity = { id: 'entity_1', type: 'entity', position: { x: 60, y: 200 }, data: defaultEntity(mode) }
  const condition = {
    id: 'condition_1', type: 'condition', position: { x: 560, y: 90 },
    data: { field: 'cancel_ratio', op: '>', value: '0.85', logic: 'AND' },
  }
  const action = {
    id: 'action_1', type: 'action', position: { x: 880, y: 200 },
    data: {
      verdict: 'DENY',
      code: 'ERR_CANCEL_RATIO',
      reason: '撤单率异常',
      severity: 'CRITICAL',
      emit: '撤单率异常',
      transitionFrom: entity.data.initial,
      transitionTo: entity.data.terminal,
      leaseTarget: mode === 'STREAM' ? 'frozen_until' : '',
      leaseSeconds: mode === 'STREAM' ? '60' : '',
    },
  }
  const nodes = [entity]
  const edges = []
  let previous = entity
  if (mode === 'DMN') {
    const dmn = {
      id: 'dmn_1', type: 'dmn', position: { x: 320, y: 200 },
      data: {
        table: 'DetermineAmount',
        param: 'req_time',
        paramType: 'Timestamp',
        outputs: ['amount'],
        outputTypes: ['Int'],
        hitPolicy: 'UNIQUE',
        lookupArg: 'event.timestamp',
        rows: [
          { isDefault: false, from: '11-01', to: '11-03', out: '10' },
          { isDefault: false, from: '11-04', to: '11-05', out: '20' },
          { isDefault: true, from: '', to: '', out: '0' },
        ],
      },
    }
    nodes.push(dmn)
    edges.push({ id: 'edge-entity-dmn', source: previous.id, target: dmn.id })
    previous = dmn
  }
  nodes.push(condition)
  edges.push({ id: 'edge-to-condition', source: previous.id, target: condition.id })
  nodes.push(action)
  edges.push({ id: 'edge-to-action', source: condition.id, target: action.id })
  return { nodes, edges }
}

function openNewRuleDialog() {
  if (!curGroupId.value) { ElMessage.warning('请先创建或选择一个规则分组'); return }
  newRuleDialog.value = { visible: true, name: `新规则_${Date.now()}`, mode: 'PURE', version: '1.0.0' }
}

async function confirmNewRule() {
  const { name, mode, version } = newRuleDialog.value
  if (!String(name).trim()) { ElMessage.warning('请输入规则名称'); return }
  busy.value = true
  try {
    const draft = starterCanvas(mode)
    const dsl = nodesToDsl({ name, mode, ...draft })
    const result = await safe(Rules.create({
      name: name.trim(), group_id: curGroupId.value, mode, version: version.trim() || '1.0.0',
      status: 'DRAFT', dsl_content: dsl, owner: '',
    }), '规则已创建（含版本快照）')
    newRuleDialog.value.visible = false
    await loadRules(curGroupId.value)
    curRuleId.value = result.id
    ruleName.value = name.trim()
    ruleMode.value = mode
    ruleVersion.value = version.trim() || '1.0.0'
    ruleStatus.value = 'DRAFT'
    nodes.value = draft.nodes
    edges.value = draft.edges
    savedBindings.value = []
    bindingRows.value = []
    trialResult.value = null
    loadWarning.value = ''
    runVerify()
  } catch { /* safe() has shown the API error */ }
  finally { busy.value = false }
}

async function removeRule(id) {
  try { await ElMessageBox.confirm('删除这条规则？版本快照与绑定会一并删除。', '删除规则', { type: 'warning' }) }
  catch { return }
  busy.value = true
  try {
    await safe(Rules.remove(id), '规则已删除')
    if (Number(curRuleId.value) === Number(id)) clearEditor()
    await loadRules(curGroupId.value)
  } catch { /* safe() has shown the API error */ }
  finally { busy.value = false }
}

/**
 * 切换执行模式：重建起手画布（DMN ↔ 其余模式需要增删 DMN 节点，直接重建最稳）。
 */
function onModeChange(mode) {
  const changed = ruleMode.value !== mode
  ruleMode.value = mode
  if (!curRuleId.value || !changed) return
  if (!nodes.value.length) return
  const rebuild = starterCanvas(mode)
  nodes.value = rebuild.nodes
  edges.value = rebuild.edges
  trialResult.value = null
  ElMessage.info(`已切换为 ${MODES.find(m => m.value === mode)?.label}，画布已重建为起手模板`)
}

async function runVerify() {
  const source = dslText.value
  if (!source || graphError.value) { verifyReport.value = null; return false }
  const requestId = ++validationRequest
  verifying.value = true
  try {
    const report = await verifyDsl(source, curRuleId.value)
    if (requestId !== validationRequest || source !== dslText.value) return false
    verifyReport.value = report
    return Boolean(report.ok)
  } catch (error) {
    if (requestId === validationRequest && source === dslText.value) {
      verifyReport.value = {
        ok: false, status: 'FAIL',
        errors: [{ kind: 'REQUEST_FAILED', message: error.message, specs: [], counterexample_text: '' }],
        warnings: [],
      }
    }
    return false
  } finally {
    if (requestId === validationRequest) verifying.value = false
  }
}

async function loadVersions() {
  if (!curRuleId.value) return
  try { versions.value = await Rules.versions(curRuleId.value) } catch { versions.value = [] }
}

// ---------------------------------------------------------------------------
// DMN
// ---------------------------------------------------------------------------

function addDmnRow() {
  if (!dmnNode.value) return
  const rows = dmnNode.value.data.rows
  const last = rows[rows.length - 1]
  const blank = { isDefault: false, from: '', to: '', out: '' }
  if (last?.isDefault) rows.splice(rows.length - 1, 0, blank)
  else rows.push(blank)
}

function removeDmnRow(index) {
  if (!dmnNode.value) return
  dmnNode.value.data.rows.splice(index, 1)
}

function onDefaultToggle(row) {
  if (!dmnNode.value) return
  if (row.isDefault) {
    // default 行必须唯一，且习惯上排在最后
    for (const other of dmnNode.value.data.rows) if (other !== row) other.isDefault = false
    const rows = dmnNode.value.data.rows
    rows.splice(rows.indexOf(row), 1)
    rows.push(row)
  }
}

async function exportDmn() {
  if (!curRuleId.value) return
  busy.value = true
  try {
    const result = await safe(Rules.exportDmn(curRuleId.value))
    xmlDialog.value = { visible: true, xml: result.xml }
    ElMessage.success(`已导出决策表 ${(result.tables || []).join(', ')}`)
  } catch { /* safe() has shown the API error */ }
  finally { busy.value = false }
}

function openImportDialog() {
  importDialog.value = { visible: true, xml: importDialog.value.xml || '' }
}

async function confirmImport() {
  const xml = String(importDialog.value.xml || '').trim()
  if (!xml) { ElMessage.warning('请粘贴 DMN XML'); return }
  busy.value = true
  try {
    const result = await safe(Dmn.import(xml))
    const parsed = dslToNodes(result.dsl_content)
    if (parsed.error) {
      ElMessage.error(`DMN 已解析，但画布无法还原：${parsed.error}`)
      return
    }
    // DMN 导入必然带决策表：保留用户原本的实体与动作名称，只替换决策表节点与条件
    const keepName = ruleName.value
    ruleMode.value = 'DMN'
    nodes.value = parsed.nodes
    edges.value = parsed.edges
    ruleName.value = keepName
    importDialog.value.visible = false
    ElMessage.success(`已载入决策表：${(result.tables || []).map(t => t.name).join(', ')}`)
    runVerify()
  } catch { /* safe() has shown the API error */ }
  finally { busy.value = false }
}

async function loadRuleDmnXml() {
  if (!curRuleId.value) return
  try {
    const detail = await Rules.get(curRuleId.value)
    xmlDialog.value = { visible: true, xml: detail.dmn_xml || '' }
  } catch { /* safe() has shown the API error */ }
}

async function runTrial() {
  if (!curRuleId.value) return
  const args = []
  if (trialDate.value) {
    args.push(Math.floor(new Date(trialDate.value).getTime() / 1000))
  } else if (String(trialArg.value).trim()) {
    const raw = String(trialArg.value).trim()
    const numeric = Number(raw)
    args.push(Number.isFinite(numeric) ? numeric : raw)
  }
  busy.value = true
  try {
    trialResult.value = await safe(DecisionTables.trial({
      rule_id: curRuleId.value,
      table: dmnNode.value?.data?.table || '',
      args,
    }))
  } catch (error) {
    trialResult.value = { ok: false, error: error.payload?.error || error.message }
  } finally { busy.value = false }
}

// ---------------------------------------------------------------------------
// 变量 → 列绑定
// ---------------------------------------------------------------------------

const bindingTargets = computed(() => extractBindingTargets(dslText.value || ''))

function rebuildBindingRows() {
  const { vars, fields } = bindingTargets.value
  const byName = new Map(savedBindings.value.map(row => [row.var_name, row]))
  const previous = new Map(bindingRows.value.map(row => [row.name, row]))
  const names = [...vars, ...fields]
  bindingRows.value = names.map(name => {
    const saved = byName.get(name)
    const prev = previous.get(name)
    return {
      name,
      kind: vars.includes(name) ? 'var' : 'field',
      datasource_id: prev?.datasource_id ?? saved?.datasource_id ?? null,
      table_name: prev?.table_name ?? saved?.table_name ?? '',
      column_name: prev?.column_name ?? saved?.column_name ?? '',
    }
  })
}

async function ensureSchema(datasourceId) {
  if (!datasourceId || schemaCache.value[datasourceId]) return
  try {
    const result = await Datasources.schema(datasourceId)
    schemaCache.value = { ...schemaCache.value, [datasourceId]: result.tables || [] }
  } catch (error) {
    ElMessage.warning(`拉取表结构失败：${error.payload?.error || error.message}`)
    schemaCache.value = { ...schemaCache.value, [datasourceId]: [] }
  }
}

function tableOptions(row) {
  return (schemaCache.value[row.datasource_id] || []).map(table => table.table)
}

function columnOptions(row) {
  const table = (schemaCache.value[row.datasource_id] || []).find(item => item.table === row.table_name)
  return table ? table.columns.map(column => column.name) : []
}

function onDatasourceChange(row) {
  row.table_name = ''
  row.column_name = ''
  ensureSchema(row.datasource_id)
}

async function saveBindings() {
  if (!curRuleId.value) { ElMessage.warning('请先新建或选择规则'); return }
  const pending = bindingRows.value.filter(row => row.datasource_id && row.table_name && row.column_name)
  if (!pending.length) { ElMessage.warning('请至少完整填写一条绑定（数据源 / 表 / 列）'); return }
  busy.value = true
  try {
    for (const row of pending) {
      await safe(Bindings.upsert({
        rule_id: curRuleId.value,
        var_name: row.name,
        datasource_id: Number(row.datasource_id),
        table_name: row.table_name,
        column_name: row.column_name,
      }))
    }
    await loadBindings(curRuleId.value)
    await runVerify()
    ElMessage.success(`已保存 ${pending.length} 条绑定`)
  } catch { /* safe() has shown the API error */ }
  finally { busy.value = false }
}

watch([bindingTargets, savedBindings], rebuildBindingRows)

watch(dslText, () => {
  clearTimeout(validationTimer)
  validationRequest++
  if (!dslText.value || graphError.value) {
    verifyReport.value = null
    verifying.value = false
    return
  }
  validationTimer = setTimeout(runVerify, 250)
})

async function saveRule() {
  if (!curRuleId.value) { ElMessage.warning('请先新建或选择规则'); return }
  if (graphError.value) { ElMessage.warning(graphError.value); return }
  if (loadWarning.value) { ElMessage.error(loadWarning.value); return }
  if (!ruleName.value.trim()) { ElMessage.warning('请输入规则名称'); return }
  saving.value = true
  try {
    const valid = await runVerify()
    if (!valid) { ElMessage.error('规则未通过形式化校验，禁止入库'); return }
    await safe(Rules.update(curRuleId.value, {
      name: ruleName.value.trim(),
      group_id: curGroupId.value,
      mode: ruleMode.value,
      version: ruleVersion.value.trim() || '1.0.0',
      status: ruleStatus.value,
      dsl_content: dslText.value,
      owner: '',
    }), '规则已保存（已生成版本快照）')
    await loadRules(curGroupId.value)
    await loadVersions()
  } catch { /* safe() has shown the API error */ }
  finally { saving.value = false }
}

// ---------------------------------------------------------------------------
// 画布增删连线
// ---------------------------------------------------------------------------

function makeNode(type, index) {
  const data = type === 'entity' ? defaultEntity(ruleMode.value)
    : type === 'condition' ? { field: 'cancel_ratio', op: '>', value: '0.85', logic: 'AND' }
      : type === 'dmn' ? {
        table: 'LookupTable', param: 'input', paramType: 'Int',
        outputs: ['value'], outputTypes: ['Int'], hitPolicy: 'UNIQUE',
        lookupArg: 'event.timestamp',
        rows: [{ isDefault: true, from: '', to: '', out: '0' }],
      }
        : {
          verdict: ruleMode.value === 'STATEFUL' ? 'DENY' : 'DENY',
          code: 'ERR_RULE_VIOLATION', reason: '规则命中', severity: 'WARNING', emit: '',
          transitionFrom: '', transitionTo: '',
          leaseTarget: ruleMode.value === 'STREAM' ? 'frozen_until' : '',
          leaseSeconds: ruleMode.value === 'STREAM' ? '60' : '',
        }
  const x = type === 'entity' ? 60 : type === 'dmn' ? 320 : type === 'action' ? 880 : 560
  return { id: `${type}_${Date.now()}_${index}`, type, position: { x, y: 100 + index * 140 }, data }
}

function addNode(type) {
  if (!curRuleId.value) { ElMessage.warning('请先新建或选择规则'); return }
  if (type === 'dmn' && ruleMode.value !== 'DMN') { ElMessage.warning('决策表节点只在模式 D（DMN）下可用'); return }
  const existing = nodes.value.filter(node => node.type === type)
  if ((type === 'entity' || type === 'action') && existing.length) {
    ElMessage.warning(`每张画布只能有一个 ${type === 'entity' ? 'Entity' : 'Action'} 节点`)
    return
  }
  if (type === 'dmn' && existing.length) { ElMessage.warning('每张画布只能有一个决策表节点'); return }
  const node = makeNode(type, nodes.value.length)
  nodes.value.push(node)
  const action = nodes.value.find(item => item.type === 'action' && item.id !== node.id)
  if (type === 'entity') {
    const first = nodes.value.find(item => item.type !== 'entity')
    if (first) edges.value.push({ id: `edge-${node.id}-${first.id}`, source: node.id, target: first.id })
  } else if (type === 'action') {
    const previous = [...nodes.value].reverse().find(item => item.type !== 'action')
    if (previous) edges.value.push({ id: `edge-${previous.id}-${node.id}`, source: previous.id, target: node.id })
  } else {
    const previousConditions = nodes.value.filter(item => item.type === 'condition' && item.id !== node.id)
    const previous = previousConditions.at(-1) || nodes.value.find(item => item.type === 'entity')
    if (previous) edges.value = edges.value.filter(edge => !(edge.source === previous.id && edge.target === action?.id))
    if (previous) edges.value.push({ id: `edge-${previous.id}-${node.id}`, source: previous.id, target: node.id })
    if (action) edges.value.push({ id: `edge-${node.id}-${action.id}`, source: node.id, target: action.id })
  }
}

function onConnect({ source, target }) {
  if (source === target) return
  const sourceNode = nodes.value.find(node => node.id === source)
  const targetNode = nodes.value.find(node => node.id === target)
  if (!sourceNode || !targetNode) return
  if (sourceNode.type === 'action' || targetNode.type === 'entity') {
    ElMessage.warning('请按 Entity → DMN? → Condition → Action 的方向连线')
    return
  }
  edges.value = edges.value.filter(edge => edge.source !== source && edge.target !== target)
  edges.value.push({ id: `edge-${source}-${target}`, source, target })
}

onMounted(async () => {
  try {
    await loadDatasources()
    await loadGroups()
    if (curGroupId.value) await loadRules(curGroupId.value)
  } catch { /* safe() has shown the API error */ }
})
</script>

<style scoped>
.rules-view { display:grid; grid-template-columns:250px minmax(400px, 1fr) 440px; height:100%; min-height:0; overflow:hidden; }
.sidebar { background:#fff; border-right:1px solid #e5e7eb; padding:12px; overflow:auto; }
.side-head { display:flex; justify-content:space-between; align-items:center; font-size:12px; color:#6b7280; margin-bottom:8px; }
.group-item { padding:7px 10px; border-radius:6px; cursor:pointer; font-size:13px; display:flex; justify-content:space-between; align-items:center; }
.group-item:hover { background:#f3f4f6; }
.group-item.active { background:#eff6ff; color:#1d4ed8; }
.ops { display:none; gap:2px; }
.group-item:hover .ops { display:flex; }
.rule-item { padding:6px 10px; font-size:12px; border-radius:6px; cursor:pointer; display:flex; justify-content:space-between; align-items:center; gap:6px; }
.rule-item:hover { background:#f3f4f6; }
.rule-item.active { background:#dbeafe; color:#1d4ed8; }
.rule-name { flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.rule-mode { color:#9ca3af; font-size:11px; }
.empty { text-align:center; color:#9ca3af; font-size:12px; padding:10px; }
.center { display:flex; flex-direction:column; min-width:0; }
.palette { padding:10px; background:#fafbfc; border-bottom:1px solid #e5e7eb; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.palette-title { font-size:11px; color:#9ca3af; margin-right:4px; }
.hint { flex:1 1 100%; font-size:11px; color:#6b7280; }
.canvas-wrap { flex:1; min-height:500px; position:relative; }
.canvas-wrap :deep(.vue-flow) { background:#fafbfc; }
.canvas-empty { position:absolute; inset:0; display:grid; place-items:center; color:#6b7280; background:#f9fafb99; pointer-events:none; z-index:5; }
.right { background:#fff; border-left:1px solid #e5e7eb; padding:8px 12px 0; display:flex; flex-direction:column; overflow:hidden; }
.right-tabs { flex:1; min-height:0; overflow:auto; }
.section { border-bottom:1px dashed #eef0f3; padding:8px 0 12px; }
.section-title { display:flex; justify-content:space-between; align-items:center; font-size:12px; font-weight:600; color:#374151; margin-bottom:6px; }
.section-hint { font-size:11px; color:#9ca3af; margin-top:6px; line-height:1.5; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:6px; margin-top:6px; }
.condition-row { display:flex; gap:4px; margin-bottom:6px; }
.dsl-preview { background:#1f2937; color:#e5e7eb; padding:10px; border-radius:6px; font-family:Consolas,monospace; font-size:11px; min-height:120px; max-height:280px; overflow:auto; white-space:pre-wrap; }
.xml-preview { background:#111827; color:#e5e7eb; padding:12px; border-radius:6px; font-family:Consolas,monospace; font-size:11px; max-height:52vh; overflow:auto; white-space:pre-wrap; }
.issue-list { margin:6px 0 0; padding-left:16px; font-size:12px; line-height:1.5; }
.issue-list.errors { color:#b91c1c; }
.issue-list.warnings { color:#b45309; }
.witness { color:#7c2d12; background:#fef3c7; border-radius:4px; padding:2px 6px; margin-top:2px; display:inline-block; font-family:Consolas,monospace; }
.bindings { display:flex; flex-direction:column; gap:8px; }
.binding-row { display:flex; flex-direction:column; gap:4px; border:1px solid #e5e7eb; border-radius:6px; padding:6px; }
.binding-name { display:flex; align-items:center; gap:6px; font-size:12px; }
.button-row { display:flex; gap:6px; flex-wrap:wrap; }
.trial-result { margin-top:8px; font-size:12px; line-height:1.7; background:#f9fafb; border:1px solid #e5e7eb; border-radius:6px; padding:8px; }
.version-list { font-size:12px; color:#4b5563; line-height:1.8; }
.save-bar { padding:10px 0; border-top:1px solid #e5e7eb; background:#fff; }
@media (max-width: 1280px) {
  .rules-view { grid-template-columns:210px minmax(0, 1fr); grid-template-rows:minmax(480px, 1fr) auto; min-height:0; }
  .canvas-wrap { min-height:0; }
  .right { grid-column:1 / -1; max-height:none; min-height:0; border-left:0; border-top:1px solid #e5e7eb; }
}
</style>
