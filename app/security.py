"""
Security utilities for Celare application.
Provides path traversal protection, input sanitization, and file validation.
"""
import html
import re
import logging
from pathlib import Path
from typing import Set, Optional

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
security_logger = logging.getLogger('security')

# Allowed file extensions (safe types only - no executable or XSS vectors)
ALLOWED_EXTENSIONS: Set[str] = {
    # Documents
    '.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt',
    # Images (NO SVG - can contain JavaScript)
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.ico',
    # Data
    '.csv', '.json', '.xml', '.xlsx', '.xls',
    # Archives
    '.zip', '.tar', '.gz', '.7z', '.rar',
    # Media
    '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv', '.webm',
    # Safe text formats (NO HTML/JS - XSS risk)
    '.md', '.yml', '.yaml', '.ini', '.cfg', '.log'
}

# Dangerous patterns in filenames
DANGEROUS_PATTERNS = [
    r'\.\.', r'/', r'\\', r'\x00',  # Path traversal
    r'<', r'>', r':', r'"', r'\|', r'\?', r'\*'  # Windows special chars
]


def validate_path_traversal(base_path: Path, requested_path: str) -> Path:
    """
    Validate that a file path doesn't escape the base directory.
    
    Args:
        base_path: The allowed base directory
        requested_path: The user-provided path/filename
        
    Returns:
        Safe resolved path
        
    Raises:
        ValueError: If path traversal detected
    """
    # Clean the requested path
    clean_path = requested_path.replace('..', '').replace('/', '').replace('\\', '')
    
    # Resolve the full path
    full_path = (base_path / clean_path).resolve()
    
    # Ensure it's within base_path
    try:
        full_path.relative_to(base_path.resolve())
    except ValueError:
        security_logger.warning(f"Path traversal attempt: {requested_path}")
        raise ValueError("Invalid file path")
    
    return full_path


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent XSS and injection attacks.
    
    Args:
        text: Raw user input
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text
    """
    if not text:
        return ""
    
    # Truncate to max length
    text = text[:max_length]
    
    # HTML escape to prevent XSS
    text = html.escape(text)
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    return text


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal and injection.
    
    Args:
        filename: Original filename
        
    Returns:
        Safe filename
    """
    if not filename:
        return "unnamed_file"
    
    # Remove dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        filename = re.sub(pattern, '', filename)
    
    # Remove leading/trailing whitespace and dots
    filename = filename.strip('. \t\n\r')
    
    # Limit length
    if len(filename) > 255:
        name, ext = filename[:200], filename[-50:] if '.' in filename else ''
        filename = name + ext
    
    return filename or "unnamed_file"


def validate_file_extension(filename: str) -> bool:
    """
    Check if file extension is allowed.
    
    Args:
        filename: The filename to check
        
    Returns:
        True if extension is allowed
    """
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS or ext == ''


def validate_content_type(content_type: str) -> bool:
    """
    Validate content type is not executable/dangerous.
    
    Args:
        content_type: MIME type to check
        
    Returns:
        True if content type is safe
    """
    dangerous_types = {
        'application/x-executable',
        'application/x-msdownload',
        'application/x-msdos-program',
        'application/x-sh',
        'application/x-shellscript',
        'application/x-bat',
        'application/x-msi'
    }
    return content_type not in dangerous_types


def log_security_event(event_type: str, details: dict):
    """Log a security-relevant event."""
    security_logger.warning(f"SECURITY_EVENT: {event_type} - {details}")
