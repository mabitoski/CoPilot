import type { FlaskBaseResponse } from "@/types/flask.d"
import type { Organization } from "@/types/n8n.d"
import { HttpClient } from "../httpClient"

export default {
	getOrganizations() {
		return HttpClient.get<FlaskBaseResponse & { data: Organization[]; total_count: number }>(
			`/n8n/organizations?connector_name=N8N`
		)
	},
	getOrganization(organizationId: string) {
		return HttpClient.get<FlaskBaseResponse & { data: Organization }>(
			`/n8n/organizations/${organizationId}?connector_name=N8N`
		)
	}
}
