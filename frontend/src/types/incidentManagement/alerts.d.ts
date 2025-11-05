import type { Case } from "./cases.d"

export type AlertsFilter =
	| { status: AlertStatus }
	| { assetName: string }
	| { assignedTo: string }
	| { tag: string | string[] }
	| { title: string }
	| { customerCode: string }
	| { source: string }
	| { source: string }
	| { iocValue: string }

export interface Alert {
	id: number
	alert_creation_time: Date
	alert_description: string
	alert_name: string
	assigned_to: null | string
	customer_code: string
	source: string
	status: AlertStatus
	time_closed: Date | null
	comments: AlertComment[]
	assets: AlertAsset[]
	tags: AlertTag[]
	linked_cases: Omit<Case, "alerts">[]
	iocs: AlertIOC[]
}

export interface AlertIOC {
	id: number
	description: string
	type: string
	value: string
}

export type AlertStatus = "OPEN" | "CLOSED" | "IN_PROGRESS"

export interface AlertAsset {
	id: number
	agent_id: string
	alert_context_id: number
	alert_linked: number
	asset_name: string
	customer_code: string
	index_id: string
	index_name: string
	velociraptor_id: string
}

export interface AlertComment {
	id: number
	alert_id: number
	comment: string
	created_at: Date
	user_name: string
}

export interface AlertTag {
	id: number
	tag: string
}

export interface AlertContext {
	id: number
	source: string
	context: AlertContextDetails
}

export interface AlertContextDetails {
	[key: string]: string | string[] | number | object
	process_name: string[]
}

export interface AlertDetails {
	asset_type_id: null | number
	ioc_value: null | string
	ioc_type: null | string
	time_field: string
	syslog_type: string
	_index: string
	_version: number
	_id: string
	_source: {
		[key: string]: string | string[] | number | object
	}
}

export interface AlertTimeline {
	_index: string
	_id: string
	_score: number
	_source: {
		rule_description: string
		timestamp: string
		[key: string]: string | string[] | number | object
	}
}

export interface AlertCorrelationAgent {
	agent_id?: string | null
	hostname?: string | null
	ip_address?: string | null
	os?: string | null
	label?: string | null
	wazuh_agent_status?: string | null
	wazuh_last_seen?: string | null
	velociraptor_id?: string | null
	velociraptor_last_seen?: string | null
	customer_code?: string | null
	critical_asset?: boolean | null
}

export interface AlertCorrelationVulnerability {
	id?: number | null
	cve_id?: string | null
	severity?: string | null
	title?: string | null
	status?: string | null
	discovered_at?: string | null
	epss_score?: string | null
	epss_percentile?: string | null
}

export interface AlertCorrelationAlert {
	index?: string | null
	id?: string | null
	timestamp?: string | null
	rule_description?: string | null
	syslog_level?: string | null
	message?: string | null
}

export interface AlertCorrelationCase {
	id: number
	case_name: string
	status?: string | null
	created_at?: string | null
}

export interface AlertCorrelation {
	agent?: AlertCorrelationAgent | null
	vulnerabilities: AlertCorrelationVulnerability[]
	recent_alerts: AlertCorrelationAlert[]
	cases: AlertCorrelationCase[]
}
