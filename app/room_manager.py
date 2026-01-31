"""
Room Manager - WebSocket-based real-time room management.
Production-grade architecture with zero-latency broadcast.
"""
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, Set, Optional
from dataclasses import dataclass, field
from fastapi import WebSocket, WebSocketDisconnect
import secrets


@dataclass
class Room:
    """Represents a single collaborative room."""
    room_key: str
    created_at: datetime
    expires_at: datetime
    max_users: int = 5
    connections: Set[WebSocket] = field(default_factory=set)
    user_names: Dict[WebSocket, str] = field(default_factory=dict)
    message_history: list = field(default_factory=list)
    
    @property
    def user_count(self) -> int:
        return len(self.connections)
    
    @property
    def is_full(self) -> bool:
        return self.user_count >= self.max_users
    
    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at
    
    @property
    def is_empty(self) -> bool:
        return self.user_count == 0


class ConnectionManager:
    """
    Manages WebSocket connections and room lifecycle.
    Optimized for zero-latency message broadcast.
    """
    
    def __init__(self):
        self.rooms: Dict[str, Room] = {}
        self._cleanup_task: Optional[asyncio.Task] = None
    
    def generate_room_key(self) -> str:
        """Generate unique room key (format: XXX-XXX)."""
        alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
        part1 = "".join(secrets.choice(alphabet) for _ in range(3))
        part2 = "".join(secrets.choice(alphabet) for _ in range(3))
        return f"{part1}-{part2}"
    
    def create_room(self, expiry_minutes: int = 30) -> Room:
        """Create a new room with unique key."""
        for _ in range(10):
            room_key = self.generate_room_key()
            if room_key not in self.rooms:
                break
        
        now = datetime.utcnow()
        room = Room(
            room_key=room_key,
            created_at=now,
            expires_at=now + timedelta(minutes=expiry_minutes)
        )
        self.rooms[room_key] = room
        return room
    
    def get_room(self, room_key: str) -> Optional[Room]:
        """Get room by key, returns None if not found or expired."""
        room = self.rooms.get(room_key.upper())
        if room and room.is_expired:
            self._delete_room(room_key)
            return None
        return room
    
    def _delete_room(self, room_key: str):
        """Remove room and cleanup resources."""
        if room_key in self.rooms:
            del self.rooms[room_key]
    
    async def connect(self, websocket: WebSocket, room_key: str, user_name: str) -> Optional[Room]:
        """
        Connect user to room.
        Returns Room if successful, None if room full/invalid.
        """
        room = self.get_room(room_key)
        if not room:
            return None
        
        if room.is_full:
            return None
        
        await websocket.accept()
        room.connections.add(websocket)
        room.user_names[websocket] = user_name
        
        # Broadcast join event
        await self._broadcast_system(room, "user_joined", user_name)
        
        return room
    
    async def disconnect(self, websocket: WebSocket, room_key: str):
        """Disconnect user from room, cleanup if empty."""
        room = self.rooms.get(room_key)
        if not room:
            return
        
        user_name = room.user_names.get(websocket, "Unknown")
        
        room.connections.discard(websocket)
        room.user_names.pop(websocket, None)
        
        if room.is_empty:
            # Room empty - delete immediately
            self._delete_room(room_key)
        else:
            # Broadcast leave event
            await self._broadcast_system(room, "user_left", user_name)
    
    async def broadcast_text(self, room: Room, sender: str, content: str):
        """Broadcast text message to all room members."""
        message = {
            "type": "text",
            "sender": sender,
            "content": content,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store in history (limit to last 100 messages)
        room.message_history.append(message)
        if len(room.message_history) > 100:
            room.message_history.pop(0)
        
        await self._broadcast(room, message)
    
    async def broadcast_file(self, room: Room, sender: str, filename: str, 
                            file_id: str, file_size: int):
        """Broadcast file notification to all room members."""
        message = {
            "type": "file",
            "sender": sender,
            "filename": filename,
            "file_id": file_id,
            "file_size": file_size,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        room.message_history.append(message)
        if len(room.message_history) > 100:
            room.message_history.pop(0)
        
        await self._broadcast(room, message)
    
    async def _broadcast_system(self, room: Room, event: str, user_name: str = None):
        """Broadcast system event to all room members."""
        message = {
            "type": "system",
            "event": event,
            "user_name": user_name,
            "user_count": room.user_count,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self._broadcast(room, message)
    
    async def _broadcast(self, room: Room, message: dict):
        """
        Zero-latency broadcast to all connections.
        Uses asyncio.gather for parallel send.
        """
        if not room.connections:
            return
        
        data = json.dumps(message)
        
        # Send to all connections in parallel
        tasks = [
            self._safe_send(ws, data)
            for ws in room.connections
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _safe_send(self, websocket: WebSocket, data: str):
        """Send with error handling."""
        try:
            await websocket.send_text(data)
        except Exception:
            pass  # Connection may be closing
    
    async def cleanup_expired_rooms(self):
        """Background task to cleanup expired rooms."""
        while True:
            try:
                now = datetime.utcnow()
                expired = [
                    key for key, room in self.rooms.items()
                    if room.is_expired
                ]
                for key in expired:
                    room = self.rooms.get(key)
                    if room:
                        # Close all connections
                        for ws in list(room.connections):
                            try:
                                await ws.close(code=1000, reason="Room expired")
                            except Exception:
                                pass
                        self._delete_room(key)
            except Exception as e:
                print(f"Cleanup error: {e}")
            
            await asyncio.sleep(60)  # Check every minute
    
    def start_cleanup_task(self):
        """Start background cleanup task."""
        if not self._cleanup_task:
            self._cleanup_task = asyncio.create_task(self.cleanup_expired_rooms())


# Global connection manager instance
room_manager = ConnectionManager()
