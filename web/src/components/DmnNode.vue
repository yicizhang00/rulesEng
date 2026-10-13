<template>
  <div class="node-card dmn-node">
    <Handle type="target" :position="Position.Left" />
    <div class="node-title">📊 DMN 决策表</div>
    <div class="node-value">{{ data.table || '未命名决策表' }}</div>
    <div class="node-sub">{{ data.hitPolicy || 'UNIQUE' }} · {{ rowCount }} 行 · 输出 {{ (data.outputs || []).join(' / ') || '—' }}</div>
    <div class="node-sub">入参 {{ data.param || '—' }}: {{ data.paramType || 'Int' }}</div>
    <Handle type="source" :position="Position.Right" />
  </div>
</template>
<script setup>
import { computed } from 'vue'
import { Handle, Position } from '@vue-flow/core'
const props = defineProps(['data'])
const rowCount = computed(() => (props.data?.rows || []).length)
</script>
<style scoped>
.node-card { padding:10px 14px; border-radius:8px; background:#fff; border:2px solid #8b5cf6; min-width:210px; font-size:12px; box-shadow:0 2px 8px rgba(0,0,0,0.08); }
.node-title { font-weight:600; color:#8b5cf6; margin-bottom:6px; font-size:12px; }
.node-value { font-weight:600; color:#111827; word-break:break-all; }
.node-sub { color:#6b7280; font-size:11px; margin-top:2px; word-break:break-all; }
</style>
