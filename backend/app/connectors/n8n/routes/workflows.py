from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Security
from loguru import logger

from app.auth.utils import AuthHandler
from app.connectors.n8n.schema.workflows import RequestWorkflowExecutionModel
from app.connectors.n8n.schema.workflows import RequestWorkflowExecutionResponse
from app.connectors.n8n.schema.workflows import WorkflowsResponse
from app.connectors.n8n.schema.workflows import WorkflowExecutionResponseModel
from app.connectors.n8n.services.workflows import execute_workflow
from app.connectors.n8n.services.workflows import get_workflow_execution_overview
from app.connectors.n8n.services.workflows import get_workflows

n8n_workflows_router = APIRouter()
auth_handler = AuthHandler()


async def validate_workflow_id(workflow_id: str) -> None:
    workflows = await get_workflows()
    for workflow in workflows.workflows:
        if workflow.id == workflow_id:
            logger.info("Workflow {} validated successfully", workflow_id)
            return
    raise HTTPException(status_code=404, detail="Workflow not found")


@n8n_workflows_router.get(
    "",
    response_model=WorkflowsResponse,
    description="Get all workflows",
    dependencies=[Security(auth_handler.require_any_scope("admin", "analyst"))],
)
async def get_all_workflows() -> WorkflowsResponse:
    return await get_workflows()


@n8n_workflows_router.get(
    "/executions",
    response_model=WorkflowExecutionResponseModel,
    description="Get latest execution for each workflow",
    dependencies=[Security(auth_handler.require_any_scope("admin", "analyst"))],
)
async def get_all_workflow_executions() -> WorkflowExecutionResponseModel:
    overview = await get_workflow_execution_overview()
    if not overview.workflows:
        raise HTTPException(status_code=404, detail="No workflows found")
    return overview


@n8n_workflows_router.post(
    "/execute",
    response_model=RequestWorkflowExecutionResponse,
    description="Execute a workflow",
    dependencies=[Security(auth_handler.require_any_scope("admin", "analyst"))],
)
async def execute_workflow_request(
    workflow_execution_body: RequestWorkflowExecutionModel,
) -> RequestWorkflowExecutionResponse:
    await validate_workflow_id(workflow_execution_body.workflow_id)
    return await execute_workflow(workflow_execution_body)
