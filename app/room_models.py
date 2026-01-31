"""
Pydantic models for Common Room feature.
"""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class RoomCreate(BaseModel):
    """Request to create a new room."""
    pass  # No params needed, room key auto-generated


class RoomInfo(BaseModel):
    """Room status information."""
    room_key: str
    user_count: int
    max_users: int
    expires_at: str
    created_at: str


class RoomMessage(BaseModel):
    """Message in a room."""
    type: str  # 'text', 'file', 'system'
    sender: Optional[str] = None
    content: Optional[str] = None
    filename: Optional[str] = None
    file_id: Optional[str] = None
    file_size: Optional[int] = None
    event: Optional[str] = None  # For system messages
    user_count: Optional[int] = None
    timestamp: str
