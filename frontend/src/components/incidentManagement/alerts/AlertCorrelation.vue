<template>
	<div class="flex grow flex-col gap-5">
		<div class="flex flex-wrap items-center justify-between gap-3">
			<n-select
				v-if="assetOptions.length > 1"
				size="small"
				class="w-full sm:w-60"
				:options="assetOptions"
				:value="selectedAssetId"
				@update:value="handleAssetChange"
			/>
			<n-tag v-else-if="assetOptions.length === 1" size="small" type="info" :bordered="false">
				{{ assetOptions[0].label }}
			</n-tag>
		</div>

		<n-spin :show="correlationLoading" class="min-h-40 grow" content-style="display:flex;flex-direction:column;gap:24px;">
			<n-empty
				v-if="!selectedAsset"
				description="This alert has no associated assets."
			/>

			<template v-else>
				<template v-if="correlation && hasCorrelationData">
					<section v-if="correlation.agent" class="correlation-section">
						<h4 class="section-title">Agent Overview</h4>
						<div class="grid gap-3 md:grid-cols-2">
							<div v-for="item in agentOverview" :key="item.label" class="info-kv">
								<div class="info-kv__label">{{ item.label }}</div>
								<div class="info-kv__value">{{ item.value }}</div>
							</div>
						</div>
					</section>

					<section v-if="correlation.vulnerabilities.length" class="correlation-section">
						<h4 class="section-title">Top Vulnerabilities</h4>
						<n-table size="small" :single-line="false">
							<thead>
								<tr>
									<th>CVE</th>
									<th>Severity</th>
									<th>Title</th>
									<th>Status</th>
									<th>Discovered</th>
								</tr>
							</thead>
							<tbody>
								<tr v-for="v in correlation.vulnerabilities" :key="v.id || v.cve_id">
									<td>{{ v.cve_id || "-" }}</td>
									<td>
										<n-tag :type="severityTagType(v.severity)" size="small" round>
											{{ v.severity || "-" }}
										</n-tag>
									</td>
									<td>{{ v.title || "-" }}</td>
									<td>{{ v.status || "-" }}</td>
									<td>{{ formatDateTime(v.discovered_at) }}</td>
								</tr>
							</tbody>
						</n-table>
					</section>

					<section v-if="correlation.recent_alerts.length" class="correlation-section">
						<h4 class="section-title">Recent Alerts (24h)</h4>
						<n-table size="small" :single-line="false">
							<thead>
								<tr>
									<th>Timestamp</th>
									<th>Rule</th>
									<th>Level</th>
									<th>Message</th>
								</tr>
							</thead>
							<tbody>
								<tr v-for="item in correlation.recent_alerts" :key="item.id || item.timestamp">
									<td>{{ formatDateTime(item.timestamp) }}</td>
									<td>{{ item.rule_description || "-" }}</td>
									<td>{{ item.syslog_level || "-" }}</td>
									<td>{{ item.message || "-" }}</td>
								</tr>
							</tbody>
						</n-table>
					</section>

					<section v-if="correlation.cases.length" class="correlation-section">
						<h4 class="section-title">Related Cases</h4>
						<n-table size="small" :single-line="false">
							<thead>
								<tr>
									<th>ID</th>
									<th>Case Name</th>
									<th>Status</th>
									<th>Created</th>
								</tr>
							</thead>
							<tbody>
								<tr v-for="caseItem in correlation.cases" :key="caseItem.id">
									<td>#{{ caseItem.id }}</td>
									<td>{{ caseItem.case_name }}</td>
									<td>{{ caseItem.status || "-" }}</td>
									<td>{{ formatDateTime(caseItem.created_at) }}</td>
								</tr>
							</tbody>
						</n-table>
					</section>
				</template>
				<n-empty
					v-else-if="!correlationLoading"
					:description="correlationError || correlationMessage || 'No correlation data available'"
				/>
			</template>
		</n-spin>
	</div>
</template>

<script setup lang="ts">
import type { Alert, AlertAsset, AlertCorrelation } from "@/types/incidentManagement/alerts.d"
import { computed, onBeforeMount, ref, toRefs, watch } from "vue"
import { NEmpty, NSelect, NSpin, NTable, NTag, useMessage } from "naive-ui"
import Api from "@/api"
import dayjs from "@/utils/dayjs"
import { useSettingsStore } from "@/stores/settings"

const props = defineProps<{
	alert: Alert
}>()

const { alert } = toRefs(props)

const dFormats = useSettingsStore().dateFormat
const message = useMessage()
const correlation = ref<AlertCorrelation | null>(null)
const correlationLoading = ref(false)
const correlationError = ref<string | null>(null)
const correlationMessage = ref<string | null>(null)
const selectedAssetId = ref<number | null>(null)

const selectedAsset = computed<AlertAsset | null>(() => {
	if (!alert.value?.assets?.length || selectedAssetId.value === null) return null
	return alert.value.assets.find(item => item.id === selectedAssetId.value) || null
})

const assetOptions = computed(() =>
	(alert.value?.assets || []).map(assetItem => ({
		label: `${assetItem.asset_name} (${assetItem.customer_code || "n/a"})`,
		value: assetItem.id
	}))
)

const hasCorrelationData = computed(() => {
	const data = correlation.value
	if (!data) return false
	return Boolean(
		data.agent ||
		(data.vulnerabilities && data.vulnerabilities.length) ||
		(data.recent_alerts && data.recent_alerts.length) ||
		(data.cases && data.cases.length)
	)
})

const agentOverview = computed(() => {
	const data = correlation.value?.agent
	if (!data) return []
	return [
		{ label: "Hostname", value: data.hostname || "-" },
		{ label: "IP Address", value: data.ip_address || "-" },
		{ label: "Customer", value: data.customer_code || "-" },
		{ label: "Wazuh Status", value: data.wazuh_agent_status || "-" },
		{ label: "Last Seen", value: formatDateTime(data.wazuh_last_seen) },
		{ label: "Operating System", value: data.os || "-" },
		{ label: "Velociraptor ID", value: data.velociraptor_id || "-" },
		{ label: "Velociraptor Last Seen", value: formatDateTime(data.velociraptor_last_seen) },
		{ label: "Critical Asset", value: formatBoolean(data.critical_asset) }
	]
})

watch(
	() => alert.value?.assets,
	assets => {
		if (assets && assets.length) {
			selectedAssetId.value = assets[0].id
		}
	},
	{ immediate: true }
)

watch(selectedAsset, assetValue => {
	correlation.value = null
	correlationError.value = null
	correlationMessage.value = null
	if (assetValue) {
		fetchCorrelation(assetValue)
	}
})

function handleAssetChange(value: number) {
	selectedAssetId.value = value
}

function fetchCorrelation(assetValue: AlertAsset) {
	correlationLoading.value = true
	correlationError.value = null
	correlationMessage.value = null

	Api.incidentManagement.alerts
		.getAlertCorrelation(assetValue.index_id, assetValue.index_name, alert.value.id, assetValue.agent_id)
		.then(res => {
			if (res.data.success) {
				correlation.value = {
					agent: res.data.agent || null,
					vulnerabilities: res.data.vulnerabilities || [],
					recent_alerts: res.data.recent_alerts || [],
					cases: res.data.cases || []
				}
				correlationMessage.value = res.data.message || null
			} else {
				correlationError.value = res.data.message || "Failed to load correlation data."
			}
		})
		.catch(err => {
			const text =
				err.response?.data?.message || err.response?.data?.detail || "Failed to load correlation data."
			correlationError.value = text
			message.error(text)
		})
		.finally(() => {
			correlationLoading.value = false
		})
}

function formatDateTime(value?: string | null) {
	if (!value) return "-"
	const parsed = dayjs(value)
	return parsed.isValid() ? parsed.format(dFormats.datetime) : value
}

function formatBoolean(value?: boolean | null) {
	if (value === true) return "Yes"
	if (value === false) return "No"
	return "-"
}

function severityTagType(severity?: string | null) {
	if (!severity) return "default"
	switch (severity.toLowerCase()) {
		case "critical":
		case "high":
			return "error"
		case "medium":
			return "warning"
		case "low":
			return "primary"
		default:
			return "default"
	}
}

onBeforeMount(() => {
	if (alert.value?.assets?.length) {
		selectedAssetId.value = alert.value.assets[0].id
	}
})
</script>

<style scoped>
.correlation-section + .correlation-section {
	margin-top: calc(var(--spacing) * 4);
}

.section-title {
	font-weight: 600;
	font-size: var(--text-sm);
	margin-bottom: calc(var(--spacing) * 2);
}

.info-kv {
	display: flex;
	flex-direction: column;
	gap: calc(var(--spacing));
}

.info-kv__label {
	font-size: var(--text-2xs);
	text-transform: uppercase;
	color: var(--text-secondary-color);
}

.info-kv__value {
	font-family: var(--font-family-mono);
	word-break: break-word;
}
</style>
