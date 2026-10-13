<template>
  <div class="node-card action-node">
    <Handle type="target" :position="Position.Left" />
    <div class="node-title">{{ isStateful ? '⚙ Yield' : '🚨 Verdict' }}</div>
    <template v-if="!isStateful">
      <el-select v-model="data.verdict" size="small" style="width:100%">
        <el-option label="DENY（拒绝 / 阻断）" value="DENY" />
        <el-option label="ALLOW（显式放行）" value="ALLOW" />
      </el-select>
      <el-input v-if="data.verdict !== 'ALLOW'" v-model="data.code" size="small" placeholder="错误码 ERR_XXX" style="margin-top:4px" />
      <el-input v-if="data.verdict !== 'ALLOW'" v-model="data.reason" size="small" placeholder="拒绝理由" style="margin-top:4px" />
    </template>
    <template v-else>
      <el-input v-model="data.code" size="small" placeholder="错误码 ERR_XXX" />
      <el-input v-model="data.reason" size="small" placeholder="拒绝理由" style="margin-top:4px" />
    </template>
    <div v-if="effectSummary" class="node-sub">{{ effectSummary }}</div>
    <div v-if="data.transitionFrom && data.transitionTo" class="node-sub">transition: {{ data.transitionFrom }} → {{ data.transitionTo }}</div>
    <Handle type="source" :position="Position.Right" />
  </div>
</template>
<script setup>
import { computed } from 'vue'
import { Handle, Position } from '@vue-flow/core'
const props = defineProps(['data', 'mode'])
const isStateful = computed(() => props.mode === 'STATEFUL')
const effectSummary = computed(() => {
  const parts = []
  if (props.data?.leaseTarget) parts.push(`LeaseUpdate(${props.data.leaseTarget} = now() + ${props.data.leaseSeconds || 0}s)`)
  if (props.data?.emit) parts.push(`Emit("${props.data.emit}")`)
  return parts.join('  ')
})
</script>
<style scoped>
.node-card { padding:10px 14px; border-radius:8px; background:#fff; border:2px solid #ef4444; min-width:200px; font-size:12px; box-shadow:0 2px 8px rgba(0,0,0,0.08); }
.node-title { font-weight:600; color:#ef4444; margin-bottom:6px; font-size:12px; }
.node-sub { color:#6b7280; font-size:11px; margin-top:4px; word-break:break-all; }
</style>
