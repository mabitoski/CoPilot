<template>
	<div class="grid-auto-fit-250 grid gap-2">
		<CardKV v-for="item of propsSanitized" :key="item.key">
			<template #key>
				{{ item.key }}
			</template>
			<template #value>
				<template v-if="item.key === 'customer_code'">
					<template v-if="item.val !== '-'">
						<code class="text-primary cursor-pointer" @click="gotoCustomer({ code: item.val })">
							{{ item.val }}
							<Icon :name="LinkIcon" :size="13" class="relative top-0.5" />
						</code>
					</template>
					<template v-else>
						<n-select
							v-if="customerOptions.length"
							size="small"
							class="assign-select"
							:options="customerOptions"
							:loading="assigning"
							placeholder="Assign customer"
							@update:value="value => assignCustomer(value as string)"
						/>
						<n-tag v-else size="small" type="default" :bordered="false">No customers</n-tag>
					</template>
				</template>
				<template v-else-if="item.key === 'velociraptor_id'">
					<AgentVelociraptorIdForm v-model:velociraptor-id="item.val" :agent @updated="emit('updated')" />
				</template>
				<template v-else>
					{{ item.val ?? "-" }}
				</template>
			</template>
		</CardKV>
	</div>
</template>

<script setup lang="ts">
import type { Agent } from "@/types/agents.d"
import type { Customer } from "@/types/customers.d"
import type { SelectOption } from "naive-ui"
import { computed, onBeforeMount, ref, toRefs } from "vue"
import CardKV from "@/components/common/cards/CardKV.vue"
import Icon from "@/components/common/Icon.vue"
import { useGoto } from "@/composables/useGoto"
import { useSettingsStore } from "@/stores/settings"
import { formatDate } from "@/utils"
import AgentVelociraptorIdForm from "./AgentVelociraptorIdForm.vue"
import Api from "@/api"
import { useMessage, NSelect, NTag } from "naive-ui"

const props = defineProps<{
	agent: Agent
}>()

const emit = defineEmits<{
	(e: "updated"): void
}>()

const { agent } = toRefs(props)

const LinkIcon = "carbon:launch"
const dFormats = useSettingsStore().dateFormat
const { gotoCustomer } = useGoto()
const message = useMessage()
const customers = ref<Customer[]>([])
const assigning = ref(false)

const customerOptions = computed<SelectOption[]>(() =>
	customers.value.map(customer => ({
		label: `${customer.customer_code} — ${customer.customer_name}`,
		value: customer.customer_code
	}))
)

const propsSanitized = computed(() => {
	const obj = []
	for (const key in agent.value) {
		if (["wazuh_last_seen", "velociraptor_last_seen"].includes(key)) {
			obj.push({ key, val: formatDate(Reflect.get(agent.value, key), dFormats.datetime) || "-" })
		} else {
			obj.push({ key, val: Reflect.get(agent.value, key) || "-" })
		}
	}

	return obj
})

function loadCustomers() {
	Api.customers
		.getCustomers()
		.then(res => {
			if (res.data.success) {
				const list = res.data.customers || (res.data.customer ? [res.data.customer] : [])
				customers.value = list || []
			}
		})
		.catch(() => {
			customers.value = []
		})
}

function assignCustomer(customerCode: string) {
	if (!customerCode || assigning.value) return
	assigning.value = true
	Api.agents
		.updateAgentCustomerCode(agent.value.agent_id, customerCode)
		.then(res => {
			if (res.data.success) {
				agent.value.customer_code = customerCode
				message.success(res.data.message || "Customer assigned successfully")
				emit("updated")
			} else {
				message.error(res.data?.message || "Failed to assign customer")
			}
		})
		.catch(err => {
			message.error(err.response?.data?.message || "Failed to assign customer")
		})
		.finally(() => {
			assigning.value = false
		})
}

onBeforeMount(() => {
	if (!agent.value.customer_code) {
		loadCustomers()
	}
})
</script>
