from __future__ import annotations

from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from pydantic import BaseModel
from pydantic import Field


class N8nWorkflow(BaseModel):
    """
    Minimal representation of an N8N workflow.
    """

    id: str = Field(..., description="Workflow identifier as stored in N8N")
    name: str = Field(..., description="Human readable workflow name")
    active: bool = Field(default=False, description="Flag indicating if the workflow is active")
    tags: List[str] = Field(default_factory=list, description="Associated workflow tags")


class WorkflowsResponse(BaseModel):
    success: bool
    message: str
    workflows: List[N8nWorkflow] = Field(default_factory=list)


class WorkflowExecutionStatusResponseModel(BaseModel):
    """
    Lightweight representation of the latest workflow execution status.
    """

    last_run: Optional[str] = Field(default=None, description="Status of the latest workflow execution")
    execution_id: Optional[str] = Field(default=None, description="Identifier of the latest execution")


class WorkflowExecutionItem(BaseModel):
    workflow_id: str
    workflow_name: str
    status: WorkflowExecutionStatusResponseModel


class WorkflowExecutionResponseModel(BaseModel):
    success: bool
    message: str
    workflows: List[WorkflowExecutionItem] = Field(default_factory=list)


class RequestWorkflowExecutionModel(BaseModel):
    workflow_id: str = Field(..., description="Unique identifier for the workflow to execute")
    execution_arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="Payload forwarded to the workflow execution",
    )


class RequestWorkflowExecutionResponse(BaseModel):
    success: bool
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)
