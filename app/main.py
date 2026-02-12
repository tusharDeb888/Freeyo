"""
FastAPI application for secure file and text sharing.
Security-hardened version with rate limiting, CORS, and input validation.
"""
import asyncio
import uuid
import os
import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from database import init_db, get_db
from cleanup import cleanup_loop
from utils.code_generator import ensure_unique_code
from room_manager import room_manager
from security import (
    validate_path_traversal, 
    sanitize_input, 
    sanitize_filename,
    validate_file_extension,
    log_security_event
)

# ============ ENVIRONMENT CONFIG ============
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
PRODUCTION_DOMAIN = os.getenv("PRODUCTION_DOMAIN", "freeyo.debtushar.in")

# Configure logging
logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO)
logger = logging.getLogger(__name__)

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)


# ============ LIFESPAN CONTEXT ============
@asynccontextmanager
async def lifespan(app):
    """Initialize database and start cleanup workers on startup."""
    await init_db()
    asyncio.create_task(cleanup_loop())
    room_manager.start_cleanup_task()
    logger.info("Freeyo started successfully")
    yield
    logger.info("Freeyo shutting down")


app = FastAPI(title="Freeyo", docs_url=None, redoc_url=None, lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Configuration - production origins only
ALLOWED_ORIGINS = [
    f"https://{PRODUCTION_DOMAIN}",
    f"https://www.{PRODUCTION_DOMAIN}",
] + (["http://localhost:8000", "http://127.0.0.1:8000"] if DEBUG else [])

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Prevent content type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Control referrer info
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Content Security Policy - critical for XSS prevention
        # Content Security Policy - critical for XSS prevention
        # Broadened for Spline 3D viewer requirements (needs unsafe-eval/blob/wasm)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' https://unpkg.com https://*.spline.design https://esm.sh https://cdnjs.cloudflare.com https://cdn.jsdelivr.net blob:; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob: https://*.spline.design; "
            "connect-src 'self' ws: wss: https://*.spline.design https://unpkg.com https://esm.sh https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.gstatic.com blob:; "
            "worker-src 'self' blob:; "
            "frame-src 'self' https://*.spline.design; "
            "frame-ancestors 'none';"
        )
        # HSTS - enforce HTTPS in production
        if not DEBUG:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Trusted Host Middleware - prevent host header attacks
ALLOWED_HOSTS = [PRODUCTION_DOMAIN, f"*.{PRODUCTION_DOMAIN}"] + (["localhost", "127.0.0.1"] if DEBUG else [])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


TEMPLATES_PATH = Path(__file__).parent / "templates"
STORAGE_PATH = Path(__file__).parent / "storage"
STATIC_PATH = Path(__file__).parent / "static"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_REQUEST_SIZE = 15 * 1024 * 1024  # 15MB total request

templates = Jinja2Templates(directory=TEMPLATES_PATH)

# Ensure directories exist
STORAGE_PATH.mkdir(exist_ok=True)
STATIC_PATH.mkdir(exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_PATH), name="static")


# Startup is now handled by lifespan context manager above


@app.get("/", response_class=HTMLResponse)
async def landing_page(request: Request):
    """Serve the SEO landing page."""
    return templates.TemplateResponse("home.html", {"request": request})


@app.get("/sitemap.xml", include_in_schema=False)
async def sitemap():
    """Serve sitemap.xml for SEO."""
    return FileResponse(STATIC_PATH / "sitemap.xml", media_type="application/xml")


@app.get("/robots.txt", include_in_schema=False)
async def robots():
    """Serve robots.txt for SEO."""
    return FileResponse(STATIC_PATH / "robots.txt", media_type="text/plain")


@app.get("/share", response_class=HTMLResponse)
async def upload_page(request: Request):
    """Serve the upload/share page."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/access", response_class=HTMLResponse)
async def access_page(request: Request):
    """Serve the access page."""
    return templates.TemplateResponse("access.html", {"request": request})


@app.post("/share")
@limiter.limit("10/minute")  # Rate limit: 10 shares per minute
async def create_share(
    request: Request,
    type: str = Form(...),
    content: Optional[str] = Form(None),
    expiry_minutes: int = Form(60),
    burn_after_read: bool = Form(False),
    file: Optional[UploadFile] = File(None)
):
    """
    Create a new share.
    """
    # Validate type immediately
    if type not in ["text", "file"]:
        raise HTTPException(status_code=400, detail="Invalid type")

    db = await get_db()
    try:
        # Generate unique code
        code = await ensure_unique_code(db)
        
        # Validate expiry (max 24 hours)
        expiry_minutes = min(max(expiry_minutes, 1), 1440)
        
        # Calculate expiry
        expires_at = datetime.utcnow() + timedelta(minutes=expiry_minutes)
        views_left = 1 if burn_after_read else 999999
        
        original_filename = None
        stored_content = None
        
        if type == "text":
            if not content:
                raise HTTPException(status_code=400, detail="Content required for text share")
            # Sanitize text content
            stored_content = sanitize_input(content, max_length=100000)
            
        elif type == "file":
            if not file:
                raise HTTPException(status_code=400, detail="File required for file share")
            
            # Sanitize filename
            safe_filename = sanitize_filename(file.filename or "unnamed")
            
            # Validate file extension
            if not validate_file_extension(safe_filename):
                log_security_event("blocked_file_type", {"filename": file.filename})
                raise HTTPException(status_code=400, detail="File type not allowed")
            
            # Check file size
            file_content = await file.read()
            if len(file_content) > MAX_FILE_SIZE:
                raise HTTPException(status_code=400, detail="File too large (max 10MB)")
            
            # Store file with UUID name (prevents path traversal)
            file_uuid = str(uuid.uuid4())
            file_path = STORAGE_PATH / file_uuid
            with open(file_path, "wb") as f:
                f.write(file_content)
            
            original_filename = safe_filename
            stored_content = file_uuid
        
        # Insert into database
        await db.execute(
            """
            INSERT INTO shares (code, type, content, original_filename, expires_at, views_left)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (code, type, stored_content, original_filename, expires_at.isoformat(), views_left)
        )
        await db.commit()
        
        return JSONResponse({
            "code": code,
            "expires_at": expires_at.isoformat()
        })
        
    finally:
        await db.close()


@app.post("/access")
@limiter.limit("30/minute")  # Rate limit: 30 access attempts per minute
async def access_share(request: Request):
    """Access a share by code."""
    try:
        body = await request.json()
        code = sanitize_input(body.get("code", ""), max_length=10).strip().upper()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        logger.warning(f"Access request error: {e}")
        raise HTTPException(status_code=400, detail="Invalid request")
    
    if not code or len(code) < 4:
        raise HTTPException(status_code=400, detail="Valid code required")
    
    db = await get_db()
    try:
        now = datetime.utcnow().isoformat()
        
        # Atomic update: Decrement view count ONLY if valid and has views left
        # This prevents the race condition where multiple requests read views_left=1 before one updates it
        cursor = await db.execute(
            """
            UPDATE shares 
            SET views_left = views_left - 1 
            WHERE code = ? AND expires_at > ? AND views_left > 0
            RETURNING type, content, original_filename, expires_at, views_left
            """,
            (code, now)
        )
        row = await cursor.fetchone()
        await db.commit()
        
        if not row:
            # If no row returned, it means either code is invalid, expired, or views_left was 0
            # Check if it was a brute force attempt (code doesn't exist) or just expired
            check_cursor = await db.execute("SELECT 1 FROM shares WHERE code = ?", (code,))
            if not await check_cursor.fetchone():
                 log_security_event("invalid_access_code", {"code": code[:3] + "***"})
            
            raise HTTPException(status_code=404, detail="Invalid or expired code")
        
        share_type = row["type"]
        
        if share_type == "text":
            return JSONResponse({
                "type": "text",
                "content": row["content"],
                "expires_at": row["expires_at"],
                "views_left": row["views_left"]  # Already decremented
            })
        elif share_type == "file":
            # Validate path (file UUID is stored, not user input)
            try:
                file_path = validate_path_traversal(STORAGE_PATH, row["content"])
            except ValueError:
                log_security_event("path_traversal_attempt", {"content": row["content"]})
                raise HTTPException(status_code=404, detail="File not found")
            
            if not file_path.exists():
                raise HTTPException(status_code=404, detail="File not found")
            
            return FileResponse(
                path=file_path,
                filename=sanitize_filename(row["original_filename"] or "download"),
                media_type="application/octet-stream"
            )
            
    finally:
        await db.close()


# ============ COMMON ROOM ENDPOINTS ============

@app.get("/room", response_class=HTMLResponse)
async def room_landing(request: Request):
    """Serve the room landing page."""
    return templates.TemplateResponse("room.html", {"request": request})


@app.get("/room/{room_key}", response_class=HTMLResponse)
async def room_page(request: Request, room_key: str):
    """Serve the room page for a specific room."""
    return templates.TemplateResponse("room.html", {"request": request, "room_key": room_key})


@app.post("/room/create")
@limiter.limit("5/minute")  # Rate limit room creation
async def create_room(request: Request):
    """Create a new room with unique key."""
    room = room_manager.create_room(expiry_minutes=30)
    return JSONResponse({
        "room_key": room.room_key,
        "expires_at": room.expires_at.isoformat(),
        "max_users": room.max_users
    })


@app.get("/room/{room_key}/info")
async def get_room_info(room_key: str):
    """Get room status information."""
    room = room_manager.get_room(room_key)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found or expired")
    
    return JSONResponse({
        "room_key": room.room_key,
        "user_count": room.user_count,
        "max_users": room.max_users,
        "expires_at": room.expires_at.isoformat(),
        "created_at": room.created_at.isoformat()
    })


@app.websocket("/ws/room/{room_key}")
async def websocket_room(websocket: WebSocket, room_key: str, user: str = Query("Anonymous")):
    """
    WebSocket endpoint for real-time room communication.
    Connect with: ws://host/ws/room/ABC-123?user=YourName
    """
    # Sanitize username to prevent XSS
    safe_user = sanitize_input(user, max_length=50) or "Anonymous"
    
    room = await room_manager.connect(websocket, room_key, safe_user)
    
    if not room:
        await websocket.close(code=4001, reason="Room not found or full")
        return
    
    try:
        # Send message history on join
        if room.message_history:
            await websocket.send_text(json.dumps({
                "type": "history",
                "messages": room.message_history[-50:]  # Last 50 messages
            }))
        
        # Rate limiting: 5 messages per 2 seconds
        import time
        message_history_timestamps = []
        
        # Listen for messages
        while True:
            data = await websocket.receive_text()
            
            # Rate limit check
            now = time.time()
            message_history_timestamps = [t for t in message_history_timestamps if now - t < 2.0]
            
            if len(message_history_timestamps) >= 5:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "content": "Rate limit exceeded. Please slow down."
                }))
                continue
            
            message_history_timestamps.append(now)

            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                continue  # Ignore malformed messages
            
            msg_type = message.get("type", "text")
            
            if msg_type == "text":
                # Sanitize message content
                content = sanitize_input(message.get("content", ""), max_length=5000).strip()
                if content:
                    await room_manager.broadcast_text(room, safe_user, content)
            
            elif msg_type == "file":
                # File metadata only, actual file via HTTP
                # Sanitize filename
                safe_filename = sanitize_filename(message.get("filename", "file"))
                await room_manager.broadcast_file(
                    room, safe_user,
                    safe_filename,
                    sanitize_input(message.get("file_id", ""), max_length=100),
                    min(message.get("file_size", 0), MAX_FILE_SIZE)
                )
    
    except WebSocketDisconnect:
        await room_manager.disconnect(websocket, room_key)
    except Exception as e:
        await room_manager.disconnect(websocket, room_key)


@app.post("/room/{room_key}/upload")
@limiter.limit("20/minute")  # Rate limit room file uploads
async def upload_room_file(request: Request, room_key: str, file: UploadFile = File(...)):
    """Upload a file to share in the room."""
    room = room_manager.get_room(room_key)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    
    # Sanitize and validate filename
    safe_filename = sanitize_filename(file.filename or "unnamed")
    if not validate_file_extension(safe_filename):
        log_security_event("blocked_room_file", {"filename": file.filename, "room": room_key})
        raise HTTPException(status_code=400, detail="File type not allowed")
    
    file_content = await file.read()
    if len(file_content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    
    # Store with UUID to prevent path traversal
    file_id = str(uuid.uuid4())
    file_path = STORAGE_PATH / f"room_{file_id}"
    with open(file_path, "wb") as f:
        f.write(file_content)
    
    logger.info(f"Room file uploaded: {file_id} in room {room_key}")
    
    return JSONResponse({
        "file_id": file_id,
        "filename": safe_filename,
        "size": len(file_content)
    })


@app.get("/room/file/{file_id}")
@limiter.limit("60/minute")  # Rate limit file downloads
async def download_room_file(request: Request, file_id: str, filename: str = Query("download")):
    """Download a file shared in a room."""
    # Validate file_id format (should be UUID only)
    sanitized_id = sanitize_input(file_id, max_length=50)
    
    # Validate path traversal
    try:
        file_path = validate_path_traversal(STORAGE_PATH, f"room_{sanitized_id}")
    except ValueError:
        log_security_event("room_file_path_traversal", {"file_id": file_id})
        raise HTTPException(status_code=404, detail="File not found")
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        path=file_path,
        filename=sanitize_filename(filename),
        media_type="application/octet-stream"
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
