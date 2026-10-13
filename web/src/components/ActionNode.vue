<template>
  <div class="node-card action-node">
    <Handle type="target" :position="Position.Left" />
    <div class="node-title">🚨 Action</div>
    <el-select v-model="data.severity" size="small" style="width:100%">
      <el-option label="INFO" value="INFO" />
      <el-option label="WARNING" value="WARNING" />
      <el-option label="CRITICAL" value="CRITICAL" />
    </el-select>
    <el-input v-model="data.emit" size="small" placeholder="告警文案" style="margin-top:4px" />
  </div>
</template>
<script setup>
import { Handle, Position } from '@vue-flow/core'
defineProps(['data'])
</script>
<style scoped>
.node-card { padding:10px 14px; border-radius:8px; background:#fff; border:2px solid #ef4444; min-width:200px; font-size:12px; box-shadow:0 2px 8px rgba(0,0,0,0.08); }
.node-title { font-weight:600; color:#ef4444; margin-bottom:6px; font-size:12px; }
</style>
