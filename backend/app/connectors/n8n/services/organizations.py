from fastapi import HTTPException
from loguru import logger

from app.connectors.n8n.schema.organizations import DetailedOrganizationResponse
from app.connectors.n8n.schema.organizations import Organization
from app.connectors.n8n.schema.organizations import OrganizationAuth
from app.connectors.n8n.schema.organizations import OrganizationResponse
from app.connectors.n8n.schema.organizations import OrganizationsListResponse
from app.connectors.n8n.services.workflows import get_workflows
from app.connectors.utils import get_connector_info_from_db
from app.db.db_session import get_db_session


async def _get_api_token(connector_name: str) -> str:
    async with get_db_session() as session:
        attributes = await get_connector_info_from_db(connector_name, session)
    if not attributes or not attributes.get("connector_api_key"):
        raise HTTPException(status_code=404, detail="N8N connector credentials not found")
    return attributes["connector_api_key"]


class OrganizationsService:
    """Service class for exposing N8N workflows to the UI as organizations."""

    @staticmethod
    async def list_organizations(connector_name: str = "N8N") -> OrganizationsListResponse:
        logger.info("Listing N8N workflows as organizations")
        workflows_response = await get_workflows()
        api_token = await _get_api_token(connector_name)

        organizations = [
            Organization(
                id=workflow.id,
                name=workflow.name,
                description=f"Active: {workflow.active}",
                org_auth=OrganizationAuth(token=api_token),
            )
            for workflow in workflows_response.workflows
        ]

        return OrganizationsListResponse(
            success=True,
            message="Successfully retrieved organizations from N8N",
            data=organizations,
            total_count=len(organizations),
        )

    @staticmethod
    async def get_organization_by_id(org_id: str, connector_name: str = "N8N") -> DetailedOrganizationResponse:
        logger.info("Retrieving N8N workflow {} by identifier", org_id)
        organizations = await OrganizationsService.list_organizations(connector_name)

        for organization in organizations.data:
            if organization.id == org_id:
                return DetailedOrganizationResponse(
                    success=True,
                    message="Organization retrieved successfully",
                    data=organization,
                )

        raise HTTPException(status_code=404, detail=f"Organization with ID {org_id} not found")

    @staticmethod
    async def get_organization_by_name(org_name: str, connector_name: str = "N8N") -> OrganizationResponse:
        logger.info("Retrieving N8N workflow {} by name", org_name)
        organizations = await OrganizationsService.list_organizations(connector_name)

        for organization in organizations.data:
            if organization.name.lower() == org_name.lower():
                return OrganizationResponse(
                    success=True,
                    message="Organization retrieved successfully",
                    data=organization,
                )

        raise HTTPException(status_code=404, detail=f"Organization with name '{org_name}' not found")
