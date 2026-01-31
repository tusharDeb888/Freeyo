"""
Cryptographically secure code generation for share access.
"""
import secrets
import string

# Exclude ambiguous characters: 0, 1, O, I, L
ALPHABET = "".join(c for c in string.ascii_uppercase + string.digits 
                   if c not in "01OIL")


def generate_code(length: int = 6) -> str:
    """
    Generate a secure random code in format XXX-XXX.
    
    Uses the `secrets` module for cryptographic security.
    Excludes ambiguous characters (0, 1, O, I, L) for readability.
    
    Returns:
        str: A code like "9QK-X7M"
    """
    part1 = "".join(secrets.choice(ALPHABET) for _ in range(length // 2))
    part2 = "".join(secrets.choice(ALPHABET) for _ in range(length // 2))
    return f"{part1}-{part2}"


async def ensure_unique_code(db) -> str:
    """
    Generate a code and verify it's unique in the database.
    
    Args:
        db: Database connection
        
    Returns:
        str: A unique code not already in use
    """
    for _ in range(10):  # Max 10 attempts
        code = generate_code()
        cursor = await db.execute(
            "SELECT 1 FROM shares WHERE code = ?", (code,)
        )
        if not await cursor.fetchone():
            return code
    raise RuntimeError("Failed to generate unique code after 10 attempts")
