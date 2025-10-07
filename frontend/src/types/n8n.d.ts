export interface OrganizationAuth {
	token: string
}

export interface Organization {
	id: string
	name: string
	description?: string | null
	org_auth: OrganizationAuth
}
