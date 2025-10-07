from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Query
from loguru import logger

from app.auth.utils import AuthHandler
from app.connectors.n8n.schema.organizations import DetailedOrganizationResponse
from app.connectors.n8n.schema.organizations import OrganizationResponse
from app.connectors.n8n.schema.organizations import OrganizationsListResponse
from app.connectors.n8n.services.organizations import OrganizationsService

n8n_organizations_router = APIRouter()
auth_handler = AuthHandler()


@n8n_organizations_router.get(
    "",
    response_model=OrganizationsListResponse,
    description="Retrieve all N8N workflows exposed as organizations",
    dependencies=[Depends(auth_handler.require_any_scope("admin", "analyst"))],
)
async def list_organizations(connector_name: str = Query("N8N", description="Name of the N8N connector to use")):
    logger.info("Listing organizations for connector {}", connector_name)
    try:
        return await OrganizationsService.list_organizations(connector_name)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error in list_organizations: {}", exc)
        raise HTTPException(status_code=500, detail=f"Internal server error: {exc}")


@n8n_organizations_router.get(
    "/{org_id}",
    response_model=DetailedOrganizationResponse,
    description="Retrieve a specific organization by ID",
    dependencies=[Depends(auth_handler.require_any_scope("admin", "analyst"))],
)
async def get_organization_by_id(
    org_id: str,
    connector_name: str = Query("N8N", description="Name of the N8N connector to use"),
):
    logger.info("Fetching organization {} for connector {}", org_id, connector_name)
    try:
        return await OrganizationsService.get_organization_by_id(org_id, connector_name)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error in get_organization_by_id: {}", exc)
        raise HTTPException(status_code=500, detail=f"Internal server error: {exc}")


@n8n_organizations_router.get(
    "/name/{org_name}",
    response_model=OrganizationResponse,
    description="Retrieve a specific organization by name",
    dependencies=[Depends(auth_handler.require_any_scope("admin", "analyst"))],
)
async def get_organization_by_name(
    org_name: str,
    connector_name: str = Query("N8N", description="Name of the N8N connector to use"),
):
    logger.info("Fetching organization {} by name for connector {}", org_name, connector_name)
    try:
        return await OrganizationsService.get_organization_by_name(org_name, connector_name)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error in get_organization_by_name: {}", exc)
        raise HTTPException(status_code=500, detail=f"Internal server error: {exc}")
