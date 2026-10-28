"""Bounded decoding as data, never execution or a declaration of intent.

Encoding/obfuscation threat context:
https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
Codec contracts: https://docs.python.org/3/library/base64.html
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re

MAX_CANDIDATES = 32
MAX_TOKEN_CHARS = 65536
MAX_DECODED_CHARS = 131072
TOKEN = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/_=-])")


def decoded_projections(text):
    projections, supplied, seen, limited = [], 0, set(), False
    examined = 0
    for match in TOKEN.finditer(text):
        if examined >= MAX_CANDIDATES:
            limited = True
            break
        examined += 1
        token = match[0]
        if len(token) > MAX_TOKEN_CHARS:
            limited = True
            continue
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
            decoded = raw.decode("utf-8")
        except (ValueError, UnicodeError, binascii.Error):
            continue
        if not decoded:
            continue
        if supplied + len(decoded) > MAX_DECODED_CHARS:
            limited = True
            break
        digest = hashlib.sha256(raw).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        supplied += len(decoded)
        projections.append({"text": decoded, "encoding": "base64", "decoded_sha256": digest,
            "encoded_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
            "start_character": match.start(), "end_character": match.end(),
            "source_line": text.count("\n", 0, match.start()) + 1})
    return projections, {"status": "partial" if limited else "complete_supported_candidates",
        "candidates_examined": examined, "decoded_projections": len(projections),
        "decoded_characters_supplied": supplied, "maximum_candidates": MAX_CANDIDATES,
        "maximum_token_characters": MAX_TOKEN_CHARS, "maximum_decoded_characters": MAX_DECODED_CHARS,
        "scope": "Single-layer bounded base64 UTF-8 projections; other encodings and deeper layers are not assessed."}
