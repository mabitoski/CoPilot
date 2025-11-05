<template>
	<div>
		<div v-if="badge" class="alert-assets-badge" @click="showDetails = true">
			<code>
				<span>{{ asset.asset_name }}</span>
				<Icon :name="ViewIcon" :size="14" />
			</code>
		</div>
		<CardEntity v-else :embedded hoverable clickable @click="showDetails = true">
			<template #default>{{ asset.asset_name }}</template>
			<template #mainExtra>
				<div class="flex flex-wrap items-center gap-3">
					<Badge type="splitted">
						<template #label>Index</template>
						<template #value>
							<div class="flex h-full items-center">
								<code
									class="text-primary cursor-pointer leading-none"
									@click.stop="gotoIndex(asset.index_name)"
								>
									{{ asset.index_name }}
									<Icon :name="LinkIcon" :size="14" class="relative top-0.5" />
								</code>
							</div>
						</template>
					</Badge>

					<Badge type="splitted">
						<template #label>Agent</template>
						<template #value>
							<div class="flex h-full items-center">
								<code
									class="text-primary cursor-pointer leading-none"
									@click.stop="gotoAgent(asset.agent_id)"
								>
									{{ asset.agent_id }}
									<Icon :name="LinkIcon" :size="14" class="relative top-0.5" />
								</code>
							</div>
						</template>
					</Badge>
				</div>
			</template>
		</CardEntity>

		<n-modal
			v-model:show="showDetails"
			preset="card"
			content-class="!p-0"
			:style="{ maxWidth: 'min(800px, 90vw)', minHeight: 'min(550px, 90vh)', overflow: 'hidden' }"
			:bordered="false"
			:title="assetNameTruncated"
			segmented
		>
			<LicenseFeatureCheck
				feature="SOCFORTRESS AI"
				@response="
					(() => {
						licenseChecked = true
						licenseResponse = $event
					})()
				"
			/>
			<n-spin :show="!licenseChecked" content-class="flex flex-wrap justify-end gap-3 p-6" :size="18">
				<AIVelociraptorArtifactRecommendationButton
					:index-id="asset.index_id"
					:index-name="asset.index_name"
					:agent-id="asset.agent_id"
					:alert-id="asset.alert_linked"
					:force-license-response="licenseResponse"
				/>
				<AIWazuhExclusionRuleButton
					:index-id="asset.index_id"
					:index-name="asset.index_name"
					:alert-id="asset.alert_linked"
					:force-license-response="licenseResponse"
				/>
				<AIAnalystButton
					:index-id="asset.index_id"
					:index-name="asset.index_name"
					:alert-id="asset.alert_linked"
					:force-license-response="licenseResponse"
				/>
			</n-spin>

			<n-divider class="!my-0" />

		<n-tabs v-model:value="activeTab" type="line" animated :tabs-padding="24">
				<n-tab-pane name="Info" tab="Info" display-directive="show">
					<AlertAssetInfo :asset />
				</n-tab-pane>
				<n-tab-pane name="Context" tab="Context" display-directive="show">
					<n-spin :show="loading" class="min-h-40">
						<div v-if="alertContext" class="p-7 pt-4">
							<div class="mb-4 flex flex-wrap gap-3">
								<Badge type="splitted">
									<template #label>id</template>
									<template #value>#{{ alertContext.id }}</template>
								</Badge>
								<Badge type="splitted">
									<template #label>source</template>
									<template #value>
										{{ alertContext.source }}
									</template>
								</Badge>
							</div>

							<CodeSource :code="alertContext.context" lang="json" />
						</div>
					</n-spin>
				</n-tab-pane>
			<n-tab-pane
				v-if="isInvestigationAvailable"
				name="Investigate"
				tab="Investigate"
				display-directive="show:lazy"
			>
					<div class="p-7 pt-4">
						<div class="flex flex-wrap gap-2">
							<ThreatIntelProcessEvaluationProvider
								v-for="pn of processNameList"
								:key="pn"
								v-slot="{ openEvaluation }"
								:process-name="pn"
							>
								<n-card
									size="small"
									embedded
									class="hover:border-primary cursor-pointer overflow-hidden"
									@click="openEvaluation()"
								>
									{{ pn }}
								</n-card>
							</ThreatIntelProcessEvaluationProvider>
						</div>
				</div>
			</n-tab-pane>
			<n-tab-pane name="Correlation" tab="Correlation" display-directive="show:lazy">
				<div class="p-7 pt-2">
					<n-spin :show="correlationLoading" class="min-h-40">
						<template v-if="correlation && hasCorrelationData">
							<div class="flex flex-col gap-6">
								<div v-if="correlationMessage" class="text-secondary text-xs">
									{{ correlationMessage }}
								</div>
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
											<tr v-for="item in correlation.recent_alerts" :key="item.id">
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
							</div>
						</template>
						<n-empty
							v-else-if="!correlationLoading"
							:description="correlationError || correlationMessage || 'No correlation data available'"
						/>
					</n-spin>
				</div>
			</n-tab-pane>
			<n-tab-pane name="Artifact Collection" tab="Artifact Collection" display-directive="show:lazy">
				<div class="p-7 pt-2">
					<ArtifactsCollect
						:hostname="asset.asset_name"
						:artifacts-filter="{ hostname: asset.asset_name }"
							hide-hostname-field
							velociraptor-id="string"
							hide-velociraptor-id-field
						/>
					</div>
				</n-tab-pane>
				<n-tab-pane name="Alert Timeline" tab="Alert Timeline" display-directive="show:lazy">
					<div class="p-7 pt-2">
						<AlertDetailTimeline :asset />
					</div>
				</n-tab-pane>
			</n-tabs>
		</n-modal>
	</div>
</template>

<script setup lang="ts">
import type { AlertAsset, AlertContext, AlertCorrelation } from "@/types/incidentManagement/alerts.d"
import _truncate from "lodash/truncate"
import { NCard, NDivider, NEmpty, NModal, NSpin, NTabPane, NTable, NTag, NTabs, useMessage } from "naive-ui"
import { computed, defineAsyncComponent, ref, watch } from "vue"
import Api from "@/api"
import Badge from "@/components/common/Badge.vue"
import CardEntity from "@/components/common/cards/CardEntity.vue"
import Icon from "@/components/common/Icon.vue"
import { useGoto } from "@/composables/useGoto"
import { useSettingsStore } from "@/stores/settings"
import dayjs from "@/utils/dayjs"

const { asset, embedded, badge } = defineProps<{ asset: AlertAsset; embedded?: boolean; badge?: boolean }>()

const AlertAssetInfo = defineAsyncComponent(() => import("./AlertAssetInfo.vue"))
const AlertDetailTimeline = defineAsyncComponent(() => import("./AlertDetailTimeline.vue"))
// const ArtifactRecommendation = defineAsyncComponent(() => import("@/components/artifacts/ArtifactRecommendation.vue"))
const AIAnalystButton = defineAsyncComponent(() => import("@/components/threatIntel/AIAnalystButton.vue"))
const AIWazuhExclusionRuleButton = defineAsyncComponent(
	() => import("@/components/threatIntel/AIWazuhExclusionRuleButton.vue")
)
const AIVelociraptorArtifactRecommendationButton = defineAsyncComponent(
	() => import("@/components/threatIntel/AIVelociraptorArtifactRecommendationButton.vue")
)
const ThreatIntelProcessEvaluationProvider = defineAsyncComponent(
	() => import("@/components/threatIntel/ThreatIntelProcessEvaluationProvider.vue")
)
const ArtifactsCollect = defineAsyncComponent(() => import("@/components/artifacts/ArtifactsCollect.vue"))
const CodeSource = defineAsyncComponent(() => import("@/components/common/CodeSource.vue"))
const LicenseFeatureCheck = defineAsyncComponent(() => import("@/components/license/LicenseFeatureCheck.vue"))

const ViewIcon = "iconoir:eye-solid"
const LinkIcon = "carbon:launch"
const { gotoAgent, gotoIndex } = useGoto()
const message = useMessage()
const loading = ref(false)
const showDetails = ref(false)
const assetNameTruncated = computed(() => _truncate(asset.asset_name, { length: 50 }))
const alertContext = ref<AlertContext | null>(null)
const processNameList = computed<string[]>(() => alertContext.value?.context?.process_name || [])
const isInvestigationAvailable = computed(() => processNameList.value.length)
const dFormats = useSettingsStore().dateFormat
const activeTab = ref("Info")
const correlation = ref<AlertCorrelation | null>(null)
const correlationLoading = ref(false)
const correlationError = ref<string | null>(null)
const correlationMessage = ref<string | null>(null)

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

const licenseChecked = ref(false)
const licenseResponse = ref(false)

watch(showDetails, val => {
	if (val) {
		if (!alertContext.value) {
			getAlertContext(asset.alert_context_id)
		}
		if (activeTab.value === "Correlation") {
			ensureCorrelationLoaded()
		}
	} else {
		activeTab.value = "Info"
	}
})

watch(activeTab, value => {
	if (value === "Correlation" && showDetails.value) {
		ensureCorrelationLoaded()
	}
})

watch(
	() => asset.alert_linked,
	() => {
		correlation.value = null
		correlationError.value = null
		correlationMessage.value = null
		correlationLoading.value = false
	},
)

function getAlertContext(alertContextId: number) {
	loading.value = true

	Api.incidentManagement.alerts
		.getAlertContext(alertContextId)
		.then(res => {
			if (res.data.success) {
				alertContext.value = res.data?.alert_context || null
			} else {
				message.warning(res.data?.message || "An error occurred. Please try again later.")
			}
		})
		.catch(err => {
			message.error(err.response?.data?.message || "An error occurred. Please try again later.")
		})
		.finally(() => {
			loading.value = false
		})
}

function ensureCorrelationLoaded() {
	if (correlation.value || correlationLoading.value) return
	fetchCorrelation()
}

function fetchCorrelation() {
	correlationLoading.value = true
	correlationError.value = null
	correlationMessage.value = null

	Api.incidentManagement.alerts
		.getAlertCorrelation(asset.index_id, asset.index_name, asset.alert_linked, asset.agent_id)
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
			correlationError.value =
				err.response?.data?.message || err.response?.data?.detail || "Failed to load correlation data."
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
</script>

<style lang="scss" scoped>
.alert-assets-badge {
	color: var(--primary-color);
	line-height: 1;
	cursor: pointer;

	code {
		display: flex;
		align-items: center;
		gap: 7px;
		padding: 2px 5px;
	}
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

	&__label {
		font-size: var(--text-2xs);
		text-transform: uppercase;
		color: var(--text-secondary-color);
	}

	&__value {
		font-family: var(--font-family-mono);
		word-break: break-word;
	}
}
</style>
