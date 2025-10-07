from typing import List
from typing import Sequence

from loguru import logger

from app.connectors.n8n.schema.workflows import N8nWorkflow
from app.connectors.n8n.schema.workflows import RequestWorkflowExecutionModel
from app.connectors.n8n.schema.workflows import RequestWorkflowExecutionResponse
from app.connectors.n8n.schema.workflows import WorkflowsResponse
from app.connectors.n8n.schema.workflows import WorkflowExecutionItem
from app.connectors.n8n.schema.workflows import WorkflowExecutionResponseModel
from app.connectors.n8n.schema.workflows import WorkflowExecutionStatusResponseModel
from app.connectors.n8n.utils.universal import send_get_request
from app.connectors.n8n.utils.universal import send_post_request


def _extract_workflows(raw_response: dict) -> Sequence[dict]:
    data = raw_response.get("data", raw_response)
    if isinstance(data, dict):
        return data.get("data", [])
    if isinstance(data, list):
        return data
    return []


def _map_workflow(payload: dict) -> N8nWorkflow:
    return N8nWorkflow(
        id=str(payload.get("id", "")),
        name=payload.get("name", ""),
        active=payload.get("active", False),
        tags=[tag.get("name", str(tag)) for tag in payload.get("tags", [])],
    )


async def get_workflows() -> WorkflowsResponse:
    logger.info("Retrieving workflows from N8N")
    response = await send_get_request("/rest/workflows")
    workflows = [_map_workflow(item) for item in _extract_workflows(response)]
    return WorkflowsResponse(
        success=response.get("success", True),
        message=response.get("message", f"Retrieved {len(workflows)} workflows"),
        workflows=workflows,
    )


async def _get_latest_execution_status(workflow_id: str) -> WorkflowExecutionStatusResponseModel:
    logger.info("Fetching latest execution for workflow {}", workflow_id)
    response = await send_get_request(
        "/rest/executions",
        params={"workflowId": workflow_id, "limit": 1, "lastId": 0},
    )
    executions = _extract_workflows(response)
    if executions:
        latest = executions[0]
        status = latest.get("status") or latest.get("finished") or "unknown"
        execution_id = str(latest.get("id", ""))
        return WorkflowExecutionStatusResponseModel(last_run=str(status), execution_id=execution_id)
    return WorkflowExecutionStatusResponseModel(last_run="No executions found", execution_id=None)


async def get_workflow_executions(workflow_id: str) -> WorkflowExecutionStatusResponseModel:
    return await _get_latest_execution_status(workflow_id)


async def get_workflow_execution_overview() -> WorkflowExecutionResponseModel:
    workflows_response = await get_workflows()
    overview_items: List[WorkflowExecutionItem] = []

    for workflow in workflows_response.workflows:
        status = await _get_latest_execution_status(workflow.id)
        overview_items.append(
            WorkflowExecutionItem(
                workflow_id=workflow.id,
                workflow_name=workflow.name,
                status=status,
            ),
        )

    return WorkflowExecutionResponseModel(
        success=True,
        message="Successfully fetched workflow executions",
        workflows=overview_items,
    )


async def execute_workflow(request: RequestWorkflowExecutionModel) -> RequestWorkflowExecutionResponse:
    logger.info("Triggering workflow {} via N8N API", request.workflow_id)
    response = await send_post_request(
        f"/rest/workflows/{request.workflow_id}/run",
        {"payload": request.execution_arguments or {}},
    )
    return RequestWorkflowExecutionResponse(
        success=response.get("success", False),
        message=response.get("message", "Workflow executed"),
        data=response.get("data", response),
    )
