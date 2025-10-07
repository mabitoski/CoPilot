from typing import List
from typing import Optional

from pydantic import BaseModel
from pydantic import Field


class OrganizationAuth(BaseModel):
    token: str = Field(..., description="API token used by the frontend search widget")


class Organization(BaseModel):
    id: str = Field(..., description="Identifier exposed to the UI")
    name: str = Field(..., description="Display name")
    description: Optional[str] = Field(default=None, description="Optional textual description")
    org_auth: OrganizationAuth


class OrganizationsListResponse(BaseModel):
    success: bool
    message: str
    data: List[Organization] = Field(default_factory=list)
    total_count: int = Field(default=0, description="Total number of organizations returned")


class OrganizationResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Organization] = None


class DetailedOrganizationResponse(OrganizationResponse):
    pass
