<template>
  <div>
    <n-form ref="formRef" :model :rules>
      <n-form-item path="username" label="Username" class="auth-field">
        <n-input
          v-model:value="model.username"
          placeholder="Insert your Username"
          :input-props="{ autocomplete: 'username' }"
          size="large"
          @keydown.enter="signIn"
        />
      </n-form-item>
      <n-form-item path="password" label="Password" class="auth-field">
        <n-input
          v-model:value="model.password"
          type="password"
          show-password-on="click"
          placeholder="Insert your password"
          :input-props="{ autocomplete: 'current-password' }"
          size="large"
          @keydown.enter="signIn"
        />
      </n-form-item>
      <div class="flex flex-col items-end gap-6">
        <div class="w-full">
          <n-button type="primary" class="w-full!" size="large" :loading :disabled="!isValid" @click="signIn">
            Sign in
          </n-button>
        </div>
      </div>
    </n-form>
  </div>
</template>

<script lang="ts" setup>
import type { FormInst, FormRules, FormValidationError } from "naive-ui"
import type { LoginPayload } from "@/types/auth.d"
import { NButton, NForm, NFormItem, NInput, useMessage } from "naive-ui"
import { computed, ref, watch } from "vue"
import { useRouter } from "vue-router"
import { useAuthStore } from "@/stores/auth"

interface ModelType {
  username: string | null
  password: string | null
}

const loading = ref(false)
const router = useRouter()
const formRef = ref<FormInst | null>(null)
const message = useMessage()
const model = ref<ModelType>({
  username: null,
  password: null,
})
const authStore = useAuthStore()

const rules: FormRules = {
  username: [
    {
      required: true,
      trigger: ["blur"],
      message: "Username is required",
    },
  ],
  password: [
    {
      required: true,
      trigger: ["blur"],
      message: "Password is required",
    },
  ],
}

const isValid = computed(() => model.value.username && model.value.password)

function signIn(e: Event) {
  e.preventDefault()
  formRef.value?.validate((errors: Array<FormValidationError> | undefined) => {
    if (!errors) {
      loading.value = true

      const payload: LoginPayload = {
        username: model.value.username || "",
        password: model.value.password || "",
      }

      authStore
        .login(payload)
        .then(() => router.push({ path: "/", replace: true }))
        .catch((err) => {
          message.error(err?.message || "An error occurred. Please try again later.")
        })
        .finally(() => {
          loading.value = false
        })
    } else {
      message.error("Invalid credentials")
    }
  })
}

watch(isValid, (val) => {
  if (val) {
    formRef.value?.validate()
  }
})
</script>

<style scoped>
.auth-field :deep(.n-form-item-label) {
  color: #64748b;
  font-weight: 600;
  letter-spacing: 0.01em;
}

.auth-field :deep(.n-input) {
  border-radius: 999px;
  border: 1px solid rgba(250, 224, 71, 0.4);
  background: rgba(250, 224, 71, 0.08);
  color: #0f172a;
}

.auth-field :deep(.n-input input) {
  color: #0f172a;
  font-weight: 600;
}

.auth-field :deep(.n-input input::placeholder) {
  color: rgba(15, 23, 42, 0.4);
  font-weight: 500;
}

.auth-field :deep(.n-input:hover),
.auth-field :deep(.n-input:not(.n-input--disabled):focus-within) {
  border-color: rgba(250, 224, 71, 0.8);
  box-shadow: 0 0 0 2px rgba(250, 224, 71, 0.2);
}
</style>
