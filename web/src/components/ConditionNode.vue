<template>
  <div class="node-card cond-node">
    <Handle type="target" :position="Position.Left" />
    <div class="node-title">⚖ Condition</div>
    <el-input v-model="data.field" size="small" placeholder="cancel_ratio" />
    <div style="display:flex; gap:4px; margin-top:4px">
      <el-select v-model="data.op" size="small" style="width:70px">
        <el-option v-for="o in ['>','>=','<','<=','==','!=']" :key="o" :label="o" :value="o" />
      </el-select>
      <el-input v-model="data.value" size="small" placeholder="0.85" />
    </div>
    <el-select v-model="data.logic" size="small" style="width:100%; margin-top:4px">
      <el-option label="AND" value="AND" />
      <el-option label="OR" value="OR" />
    </el-select>
    <Handle type="source" :position="Position.Right" />
  </div>
</template>
<script setup>
import { Handle, Position } from '@vue-flow/core'
defineProps(['data'])
</script>
<style scoped>
.node-card { padding:10px 14px; border-radius:8px; background:#fff; border:2px solid #10b981; min-width:200px; font-size:12px; box-shadow:0 2px 8px rgba(0,0,0,0.08); }
.node-title { font-weight:600; color:#10b981; margin-bottom:6px; font-size:12px; }
</style>
