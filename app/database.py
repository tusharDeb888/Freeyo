"""
SQLite async database connection and initialization.
"""
import aiosqlite
from pathlib import Path

# Secure database location (outside static/code paths)
DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)
DATABASE_PATH = DATA_DIR / "shares.db"


async def get_db():
    """Get database connection."""
    db = await aiosqlite.connect(DATABASE_PATH)
    db.row_factory = aiosqlite.Row
    return db


async def init_db():
    """Initialize database with required tables."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                type TEXT NOT NULL,
                content TEXT,
                original_filename TEXT,
                expires_at TIMESTAMP NOT NULL,
                views_left INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_shares_code ON shares(code)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_shares_expires ON shares(expires_at)
        """)
        await db.commit()
