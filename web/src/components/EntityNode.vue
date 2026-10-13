<template>
  <div class="node-card entity-node">
    <Handle type="target" :position="Position.Left" />
    <div class="node-title">🏢 Entity</div>
    <div class="node-value">{{ data.entity || '未命名实体' }}</div>
    <div v-if="data.key" class="node-sub">key: {{ data.key }}</div>
    <div v-if="stateList.length" class="node-sub">states: {{ stateList.join(' / ') }}</div>
    <Handle type="source" :position="Position.Right" />
  </div>
</template>
<script setup>
import { computed } from 'vue'
import { Handle, Position } from '@vue-flow/core'
const props = defineProps(['data'])
const stateList = computed(() => String(props.data?.states || '').split(',').map(s => s.trim()).filter(Boolean))
</script>
<style scoped>
.node-card { padding:10px 14px; border-radius:8px; background:#fff; border:2px solid #3b82f6; min-width:180px; font-size:12px; box-shadow:0 2px 8px rgba(0,0,0,0.08); }
.node-title { font-weight:600; color:#3b82f6; margin-bottom:6px; font-size:12px; }
.node-value { font-weight:600; color:#111827; word-break:break-all; }
.node-sub { color:#6b7280; font-size:11px; margin-top:2px; word-break:break-all; }
</style>
