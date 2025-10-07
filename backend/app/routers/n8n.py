from fastapi import APIRouter

from app.connectors.n8n.routes.integrations import n8n_integrations_router
from app.connectors.n8n.routes.organizations import n8n_organizations_router
from app.connectors.n8n.routes.workflows import n8n_workflows_router

router = APIRouter()

router.include_router(
    n8n_workflows_router,
    prefix="/n8n/workflows",
    tags=["n8n-workflows"],
)

router.include_router(
    n8n_integrations_router,
    prefix="/n8n/integrations",
    tags=["n8n-integrations"],
)

router.include_router(
    n8n_organizations_router,
    prefix="/n8n/organizations",
    tags=["n8n-organizations"],
)
