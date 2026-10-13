<template>
  <el-container style="height:100vh">
    <el-header class="topbar">
      <div class="logo">rules<span>Eng</span></div>
      <el-menu mode="horizontal" :default-active="route" style="border-bottom:none; flex:1" @select="onNav">
        <el-menu-item index="/">规则管理</el-menu-item>
        <el-menu-item index="/verify">校验报告</el-menu-item>
        <el-menu-item index="/datasources">数据源管理</el-menu-item>
        <el-menu-item index="/actions">告警动作</el-menu-item>
      </el-menu>
    </el-header>
    <el-main style="padding:0;background:#f5f7fa;min-height:0;overflow:hidden">
      <RulesView v-if="route === '/'" />
      <VerifyReportView v-else-if="route === '/verify'" />
      <DatasourcesView v-else-if="route === '/datasources'" />
      <ActionsView v-else-if="route === '/actions'" />
    </el-main>
  </el-container>
</template>

<script setup>
import { ref } from 'vue'
import RulesView from './views/RulesView.vue'
import VerifyReportView from './views/VerifyReportView.vue'
import DatasourcesView from './views/DatasourcesView.vue'
import ActionsView from './views/ActionsView.vue'

const route = ref(window.location.hash.replace('#', '') || '/')
window.addEventListener('hashchange', () => {
  route.value = window.location.hash.replace('#', '') || '/'
})
function onNav(idx) { window.location.hash = idx }
</script>

<style>
.topbar { display:flex; align-items:center; background:#fff; border-bottom:1px solid #e5e7eb; padding:0 24px; height:56px; }
.logo { font-weight:600; font-size:16px; margin-right:32px; }
.logo span { color:#3b82f6; }
</style>
