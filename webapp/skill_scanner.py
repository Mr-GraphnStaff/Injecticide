"""One scan implementation for the web fallback and isolated sandbox."""
from skill_sandbox.app import (
    scan_upload, MAX_UPLOAD_BYTES, MAX_FILE_BYTES, MAX_LARGE_ARTIFACT_BYTES,
    MAX_ARCHIVE_FILES as MAX_ZIP_FILES, MAX_ARCHIVE_TOTAL_BYTES as MAX_ZIP_TOTAL_BYTES,
)
