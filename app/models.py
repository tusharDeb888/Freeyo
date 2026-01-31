"""
Pydantic models for request/response validation.
"""
from pydantic import BaseModel
from typing import Optional


class ShareRequest(BaseModel):
    """Request model for creating a new share."""
    type: str  # 'text' or 'file'
    content: Optional[str] = None  # text content
    expiry_minutes: int = 60
    burn_after_read: bool = False


class ShareResponse(BaseModel):
    """Response model after creating a share."""
    code: str
    expires_at: str


class AccessRequest(BaseModel):
    """Request model for accessing a share."""
    code: str


class AccessResponse(BaseModel):
    """Response model for accessed content."""
    type: str
    content: Optional[str] = None
    filename: Optional[str] = None
    expires_at: str
    views_left: int
