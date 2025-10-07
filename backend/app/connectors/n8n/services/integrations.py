from loguru import logger

from app.connectors.n8n.schema.integrations import ExecuteWorkflowRequest
from app.connectors.n8n.schema.integrations import IntegrationRequest
from app.connectors.n8n.utils.universal import send_post_request


async def execute_integration(request: IntegrationRequest) -> dict:
    """
    Trigger an arbitrary N8N workflow with the supplied payload.
    """
    logger.info("Executing N8N integration workflow {}", request.workflow_id)
    response = await send_post_request(
        f"/rest/workflows/{request.workflow_id}/run",
        {"payload": request.payload},
    )
    logger.info("Integration workflow {} responded with {}", request.workflow_id, response)
    return response


async def execute_workflow(request: ExecuteWorkflowRequest) -> dict:
    """
    Execute an N8N workflow using the supplied execution arguments.
    """
    logger.info("Executing N8N workflow {} with arguments {}", request.workflow_id, request.execution_arguments)
    response = await send_post_request(
        f"/rest/workflows/{request.workflow_id}/run",
        {"payload": request.execution_arguments or {}},
    )
    logger.info("Workflow {} execution response {}", request.workflow_id, response)
    return response
