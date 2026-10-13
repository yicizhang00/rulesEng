<template>
  <div class="node-card entity-node">
    <Handle type="target" :position="Position.Left" />
    <div class="node-title">🏢 Entity</div>
    <el-input v-model="data.entity" size="small" placeholder="Company" />
    <Handle type="source" :position="Position.Right" />
  </div>
</template>
<script setup>
import { Handle, Position } from '@vue-flow/core'
defineProps(['data'])
</script>
<style scoped>
.node-card { padding:10px 14px; border-radius:8px; background:#fff; border:2px solid #3b82f6; min-width:180px; font-size:12px; box-shadow:0 2px 8px rgba(0,0,0,0.08); }
.node-title { font-weight:600; color:#3b82f6; margin-bottom:6px; font-size:12px; }
</style>
