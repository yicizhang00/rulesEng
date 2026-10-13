<template>
  <el-dialog v-model="visible" :title="title" width="420px" @close="$emit('close')">
    <el-form :model="form" label-width="80px">
      <el-form-item v-for="f in fields" :key="f.prop" :label="f.label">
        <el-input v-if="f.type !== 'select'" v-model="form[f.prop]" :placeholder="f.placeholder" />
        <el-select v-else v-model="form[f.prop]" style="width:100%">
          <el-option v-for="o in f.options" :key="o.value" :label="o.label" :value="o.value" />
        </el-select>
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" @click="submit">确定</el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, watch } from 'vue'

const props = defineProps({
  modelValue: Boolean,
  title: String,
  fields: Array,
  initial: Object,
})
const emit = defineEmits(['update:modelValue', 'submit', 'close'])

const visible = ref(props.modelValue)
const form = ref({})
watch(() => props.modelValue, (v) => {
  visible.value = v
  if (v) form.value = { ...(props.initial || {}) }
})
watch(visible, (v) => emit('update:modelValue', v))

function submit() {
  emit('submit', { ...form.value })
  visible.value = false
}
</script>
