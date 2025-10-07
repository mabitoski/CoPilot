from fastapi import APIRouter
from fastapi import Security
from loguru import logger

from app.auth.utils import AuthHandler
from app.connectors.n8n.schema.integrations import ExecuteWorkflowRequest
from app.connectors.n8n.schema.integrations import IntegrationRequest
from app.connectors.n8n.services.integrations import execute_integration
from app.connectors.n8n.services.integrations import execute_workflow

n8n_integrations_router = APIRouter()


@n8n_integrations_router.post(
    "/execute",
    description="Execute an N8N workflow with an arbitrary payload.",
    dependencies=[Security(AuthHandler().require_any_scope("admin", "analyst"))],
)
async def execute_integration_route(request: IntegrationRequest):
    """
    Execute a workflow.

    Args:
        request (IntegrationRequest): The request object containing the workflow ID.

    Returns:
        dict: The response containing the execution ID.
    """
    logger.info("Executing N8N integration workflow {}", request.workflow_id)
    return await execute_integration(request)


@n8n_integrations_router.post(
    "/invoke-workflow",
    description="Invoke an N8N workflow.",
    dependencies=[Security(AuthHandler().require_any_scope("admin", "analyst"))],
)
async def invoke_workflow_route(request: ExecuteWorkflowRequest):
    """
    Execute a workflow.

    Args:
        request (IntegrationRequest): The request object containing the workflow ID.

    Returns:
        dict: The response containing the execution ID.
    """
    logger.info("Executing N8N workflow {}", request.workflow_id)
    return await execute_workflow(request)
