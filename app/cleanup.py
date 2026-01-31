"""
Background cleanup worker for expired shares.
"""
import asyncio
import os
from datetime import datetime
from pathlib import Path
from database import get_db

STORAGE_PATH = Path(__file__).parent / "storage"


async def cleanup_expired():
    """Delete expired shares and their associated files."""
    db = await get_db()
    try:
        now = datetime.utcnow().isoformat()
        
        # Find expired file shares to delete files
        cursor = await db.execute(
            """
            SELECT content, type FROM shares 
            WHERE expires_at < ? OR views_left <= 0
            """,
            (now,)
        )
        expired = await cursor.fetchall()
        
        # Delete associated files
        for row in expired:
            if row["type"] == "file" and row["content"]:
                file_path = STORAGE_PATH / row["content"]
                if file_path.exists():
                    try:
                        os.remove(file_path)
                    except OSError:
                        pass  # File may already be deleted
        
        # Delete expired records
        await db.execute(
            """
            DELETE FROM shares 
            WHERE expires_at < ? OR views_left <= 0
            """,
            (now,)
        )
        await db.commit()
    finally:
        await db.close()


async def cleanup_loop():
    """Run cleanup every 60 seconds."""
    while True:
        try:
            await cleanup_expired()
        except Exception as e:
            print(f"Cleanup error: {e}")
        await asyncio.sleep(60)
