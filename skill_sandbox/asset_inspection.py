"""Bounded asset structure and metadata inspection, without rendering or execution.

Sources (format contracts, not claims of exploit detection):
https://www.w3.org/TR/2025/REC-png-3-20250624/ (PNG chunks/CRC/text)
https://learn.microsoft.com/en-us/typography/opentype/spec/otff (sfnt directory/checksums)
https://learn.microsoft.com/en-us/typography/opentype/spec/name (name records)

An ``inspected`` status means only the listed checks ran. It is not full format
validation, image understanding, malware analysis, or safe renderer acceptance.
"""
from __future__ import annotations

import struct
import zlib
from pathlib import PurePosixPath

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SFNT_SIGNATURES = (b"\x00\x01\x00\x00", b"OTTO", b"true")
MAX_ASSET_BYTES = 16 * 1024 * 1024
MAX_PNG_CHUNKS = 2048
MAX_FONT_TABLES = 256
MAX_NAME_RECORDS = 1024
MAX_METADATA_BYTES = 128 * 1024


def _result(kind: str) -> dict:
    return {"format": kind, "status": "inspected", "checks": [], "findings": [],
            "text": "", "limitations": [], "bytes_supplied": 0,
            "binary_security_analysis": "not_performed"}


def _finding(result: dict, code: str, description: str, **evidence) -> None:
    result["findings"].append({"id": code, "severity": "review", "description": description, **evidence})
    result["status"] = "malformed"


def _partial(result: dict, description: str) -> None:
    if result["status"] != "malformed":
        result["status"] = "partial"
    if description not in result["limitations"]:
        result["limitations"].append(description)


def inspect_asset(data: bytes, path: str) -> dict | None:
    """Inspect PNG or standalone sfnt assets selected by signature or suffix.

    Unknown formats return None. A known suffix with the wrong signature is a
    measured format mismatch, not silently an unrecognized clean asset.
    """
    suffix = PurePosixPath(path.replace("\\", "/")).suffix.lower()
    if data.startswith(PNG_SIGNATURE) or suffix == ".png":
        kind = "png"
    elif data[:4] in SFNT_SIGNATURES or suffix in {".ttf", ".otf"}:
        kind = "sfnt_font"
    else:
        return None
    result = _result(kind)
    result["bytes_supplied"] = len(data)
    if len(data) > MAX_ASSET_BYTES:
        _partial(result, "Asset exceeds the bounded structural inspection byte budget.")
        return result
    if kind == "png":
        _inspect_png(data, result)
    else:
        _inspect_font(data, result)
    return result


def _inflate_metadata(data: bytes, budget: int) -> bytes:
    """Never decompress more than the remaining shared metadata budget + 1."""
    inflater = zlib.decompressobj()
    value = inflater.decompress(data, budget + 1)
    if len(value) > budget or inflater.unconsumed_tail:
        raise OverflowError("Compressed metadata exceeds the shared extraction budget.")
    if not inflater.eof or inflater.unused_data:
        raise ValueError("Compressed metadata has a truncated or trailing zlib stream.")
    return value


def _png_text(kind: bytes, body: bytes, budget: int) -> str:
    keyword, separator, remainder = body.partition(b"\x00")
    if not separator or not 1 <= len(keyword) <= 79:
        raise ValueError("PNG text keyword is missing or outside the 1..79 byte contract.")
    label = keyword.decode("latin-1")
    if kind == b"tEXt":
        raw = remainder
        encoding = "latin-1"
    elif kind == b"zTXt":
        if not remainder or remainder[0] != 0:
            raise ValueError("Unsupported or missing PNG text compression method.")
        raw = _inflate_metadata(remainder[1:], budget)
        encoding = "latin-1"
    else:
        if len(remainder) < 2 or remainder[0] not in (0, 1) or remainder[1] != 0:
            raise ValueError("Invalid iTXt compression flag or method.")
        flag, remainder = remainder[0], remainder[2:]
        language, separator, remainder = remainder.partition(b"\x00")
        translated, separator2, remainder = remainder.partition(b"\x00")
        if not separator or not separator2:
            raise ValueError("Missing iTXt language/translated keyword delimiters.")
        if len(keyword) + len(language) + len(translated) > budget:
            raise OverflowError("PNG metadata fields exceed the shared extraction budget.")
        language_text = language.decode("ascii")
        translated_text = translated.decode("utf-8")
        if language_text:
            label += f" [language={language_text}]"
        if translated_text:
            label += f" [translated={translated_text}]"
        remaining = budget - len((label + ": ").encode("utf-8"))
        if remaining < 0:
            raise OverflowError("PNG metadata fields exceed the shared extraction budget.")
        raw = _inflate_metadata(remainder, remaining) if flag else remainder
        encoding = "utf-8"
    if len(raw) + len(label.encode("utf-8")) + 2 > budget:
        raise OverflowError("PNG metadata exceeds the shared extraction budget.")
    value = label + ": " + raw.decode(encoding)
    if len(value.encode("utf-8")) > budget:
        raise OverflowError("PNG decoded metadata exceeds the shared extraction budget.")
    return value


def _inspect_png(data: bytes, result: dict) -> None:
    result["limitations"].extend([
        "Pixels, OCR, steganography, image decompression and renderer vulnerabilities are not assessed.",
        "Only tEXt, zTXt and iTXt textual metadata is decoded; other ancillary chunk contents are not parsed.",
    ])
    if not data.startswith(PNG_SIGNATURE):
        _finding(result, "asset_signature_mismatch", "PNG suffix does not match PNG signature.")
        return
    offset, count, seen_idat, ended_idat, seen_end = 8, 0, False, False, False
    text_parts, text_bytes, tags = [], 0, []
    color_type = None
    chunk_budget_reached = False
    while offset < len(data):
        if count >= MAX_PNG_CHUNKS:
            chunk_budget_reached = True
            _partial(result, "PNG chunk count inspection budget reached.")
            break
        if len(data) - offset < 12:
            _finding(result, "png_truncated_chunk", "PNG chunk header or CRC is truncated.", offset=offset)
            break
        size = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4:offset + 8]
        if size > 0x7fffffff or offset + size + 12 > len(data):
            _finding(result, "png_chunk_bounds", "PNG declared chunk length exceeds available bytes or format limit.", offset=offset)
            break
        body = data[offset + 8:offset + 8 + size]
        crc = struct.unpack_from(">I", data, offset + 8 + size)[0]
        if zlib.crc32(body, zlib.crc32(kind)) & 0xffffffff != crc:
            _finding(result, "png_crc_mismatch", "PNG chunk CRC does not match its type and data.", offset=offset)
        if any(not (65 <= byte <= 90 or 97 <= byte <= 122) for byte in kind) or not 65 <= kind[2] <= 90:
            _finding(result, "png_chunk_type", "PNG chunk type violates letter/reserved-bit encoding.", offset=offset)
        tag = kind.decode("ascii", errors="replace")
        if count == 0 and kind != b"IHDR":
            _finding(result, "png_header_order", "IHDR is not the first PNG chunk.")
        if kind == b"IHDR":
            if count != 0 or size != 13:
                _finding(result, "png_invalid_header", "IHDR is duplicated, misplaced or has invalid length.")
            else:
                width, height, depth, color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", body)
                result["dimensions"] = {"width": width, "height": height}
                allowed = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}
                if not 0 < width <= 0x7fffffff or not 0 < height <= 0x7fffffff or depth not in allowed.get(color_type, ()) or compression or filtering or interlace not in (0, 1):
                    _finding(result, "png_invalid_header", "PNG dimensions or IHDR encoding values are invalid.")
        elif kind == b"IDAT":
            if ended_idat:
                _finding(result, "png_data_order", "IDAT chunks are not consecutive.")
            seen_idat = True
        else:
            ended_idat |= seen_idat
        if kind == b"PLTE" and ("PLTE" in tags or seen_idat or not size or size % 3 or size > 768 or color_type in (0, 4)):
            _finding(result, "png_invalid_palette", "PLTE length, ordering or color-type contract is invalid.")
        if kind in (b"tEXt", b"zTXt", b"iTXt"):
            try:
                value = _png_text(kind, body, MAX_METADATA_BYTES - text_bytes)
                encoded_size = len(value.encode("utf-8")) + bool(text_parts)
                if text_bytes + encoded_size > MAX_METADATA_BYTES:
                    _partial(result, "PNG UTF-8 metadata extraction budget reached.")
                else:
                    text_parts.append(value)
                    text_bytes += encoded_size
            except OverflowError:
                # Failed decompression still consumes the remaining work budget.
                text_bytes = MAX_METADATA_BYTES
                _partial(result, "PNG metadata extraction budget reached.")
            except (ValueError, UnicodeError, zlib.error) as exc:
                _finding(result, "png_invalid_text", str(exc), offset=offset)
        if kind not in (b"IHDR", b"IDAT", b"IEND", b"PLTE") and kind and 65 <= kind[0] <= 90:
            _partial(result, "Unknown critical PNG chunk requires a format-specific decoder.")
        if kind in (b"acTL", b"fcTL", b"fdAT"):
            _partial(result, "APNG animation semantics are not validated.")
        if kind in (b"eXIf", b"iCCP", b"caBX"):
            _partial(result, "PNG contains EXIF, profile or content-provenance metadata whose text-bearing contents are not parsed.")
        tags.append(tag)
        count += 1
        offset += size + 12
        if kind == b"IEND":
            seen_end = True
            if size or offset != len(data):
                _finding(result, "png_invalid_end", "IEND is nonempty or bytes follow the PNG datastream.", trailing_bytes=len(data) - offset)
            break
    if not chunk_budget_reached and (not seen_end or not seen_idat):
        _finding(result, "png_missing_required_chunk", "PNG has no complete IEND or no IDAT chunk.")
    if color_type == 3 and "PLTE" not in tags:
        _finding(result, "png_missing_palette", "Indexed-color PNG has no PLTE chunk.")
    result["checks"] = ["signature", "chunk_bounds", "chunk_crc", "critical_chunk_order", "ihdr_values", "text_metadata"]
    result["chunks_inspected"] = count
    result["metadata_characters"] = len("\n".join(text_parts))
    result["text"] = "\n".join(text_parts)


def _checksum(data: bytes | memoryview) -> int:
    aligned = len(data) - len(data) % 4
    total = sum(value[0] for value in struct.iter_unpack(">I", memoryview(data)[:aligned]))
    if aligned < len(data):
        total += int.from_bytes(bytes(data[aligned:]) + b"\x00" * (4 - len(data) % 4), "big")
    return total & 0xffffffff


def _inspect_font(data: bytes, result: dict) -> None:
    result["limitations"].append("Glyph programs, shaping, rendering, embedded SVG/bitmap content and renderer vulnerabilities are not assessed.")
    if data[:4] not in SFNT_SIGNATURES:
        _finding(result, "asset_signature_mismatch", "Font suffix does not match a supported standalone sfnt signature.")
        return
    if len(data) < 12:
        _finding(result, "font_truncated_header", "Font offset table is truncated.")
        return
    count, search_range, entry_selector, range_shift = struct.unpack_from(">HHHH", data, 4)
    if not count or 12 + 16 * count > len(data):
        _finding(result, "font_directory_bounds", "Font table directory has zero entries or exceeds file bounds.")
        return
    if count > MAX_FONT_TABLES:
        _partial(result, "Font table count inspection budget reached.")
        return
    power = 1 << (count.bit_length() - 1)
    if (search_range, entry_selector, range_shift) != (power * 16, power.bit_length() - 1, count * 16 - power * 16):
        _finding(result, "font_search_fields", "Font directory search fields disagree with its table count.")
    ranges, tags, tables = [], [], []
    checksum_bytes = 0
    for index in range(count):
        tag, checksum, offset, size = struct.unpack_from(">4sIII", data, 12 + 16 * index)
        tag_name = tag.decode("ascii", errors="replace")
        tables.append({"tag": tag_name, "offset": offset, "length": size})
        if tag in tags or (tags and tag <= tags[-1]) or any(not 32 <= byte <= 126 for byte in tag):
            _finding(result, "font_table_tag", "Font table tags are duplicated, unsorted or not printable ASCII.", table=tag_name)
        tags.append(tag)
        if offset % 4 or offset < 12 + count * 16 or offset + size > len(data):
            _finding(result, "font_table_bounds", "Font table offset is unaligned, overlaps the directory or exceeds file bounds.", table=tag_name)
            continue
        ranges.append((offset, offset + size, tag_name))
        body = memoryview(data)[offset:offset + size]
        if checksum_bytes + len(body) > MAX_ASSET_BYTES:
            _partial(result, "Aggregate font table checksum byte budget reached.")
        else:
            checksum_bytes += len(body)
            calculated = _checksum(body)
            if tag == b"head" and len(body) >= 12:
                calculated = (calculated - struct.unpack_from(">I", body, 8)[0]) & 0xffffffff
            if calculated != checksum:
                _finding(result, "font_checksum_mismatch", "Font table checksum does not match the directory.", table=tag_name)
        if tag == b"name":
            _font_names(body, result)
        if tag in (b"SVG ", b"CBDT", b"sbix"):
            _partial(result, "Font contains embedded SVG/bitmap tables whose content is not parsed.")
    for previous, current in zip(sorted(ranges), sorted(ranges)[1:]):
        if current[0] < previous[1]:
            _finding(result, "font_table_overlap", "Font table byte ranges overlap.", tables=[previous[2], current[2]])
    result["checks"] = ["signature", "directory_bounds", "search_fields", "table_order", "table_bounds", "table_overlap", "table_checksums", "name_records"]
    result["tables_inspected"] = len(tables)
    result["checksum_bytes_inspected"] = checksum_bytes
    result["tables"] = tables
    result["metadata_characters"] = len(result["text"])


def _font_names(body: bytes | memoryview, result: dict) -> None:
    if len(body) < 6:
        _finding(result, "font_name_bounds", "Font naming table header is truncated.")
        return
    version, count, storage = struct.unpack_from(">HHH", body)
    if version not in (0, 1):
        _partial(result, "Unsupported font naming table version.")
        return
    directory_end = 6 + count * 12
    if directory_end > len(body) or storage < directory_end or storage > len(body):
        _finding(result, "font_name_bounds", "Font naming record directory or storage exceeds table bounds.")
        return
    if version == 1:
        if directory_end + 2 > len(body):
            _finding(result, "font_name_bounds", "Font language-tag count is truncated.")
            return
        language_count = struct.unpack_from(">H", body, directory_end)[0]
        if directory_end + 2 + language_count * 4 > storage:
            _finding(result, "font_name_bounds", "Font language-tag records overlap string storage.")
            return
        for index in range(min(language_count, MAX_NAME_RECORDS)):
            length, offset = struct.unpack_from(">HH", body, directory_end + 2 + index * 4)
            if storage + offset + length > len(body):
                _finding(result, "font_name_bounds", "Font language-tag string exceeds table bounds.")
        if language_count > MAX_NAME_RECORDS:
            _partial(result, "Font language-tag inspection budget reached.")
    if count > MAX_NAME_RECORDS:
        _partial(result, "Font name record extraction budget reached.")
    parts, used, records_seen = [], len(result["text"].encode("utf-8")), 0
    for index in range(min(count, MAX_NAME_RECORDS)):
        records_seen += 1
        platform, encoding, language, name_id, length, offset = struct.unpack_from(">HHHHHH", body, 6 + index * 12)
        if storage + offset + length > len(body):
            _finding(result, "font_name_bounds", "Font name string exceeds naming table bounds.", record=index)
            continue
        raw = body[storage + offset:storage + offset + length]
        codec = "utf-16-be" if platform == 0 or (platform == 3 and encoding in (0, 1, 10)) else "mac_roman" if platform == 1 and encoding == 0 else None
        if codec is None:
            _partial(result, "Some font name encodings are unsupported.")
            continue
        if used + len(raw) > MAX_METADATA_BYTES:
            _partial(result, "Font name text extraction byte budget reached.")
            break
        try:
            text = bytes(raw).decode(codec)
        except UnicodeError:
            _finding(result, "font_name_encoding", "Font name string is invalid for its declared encoding.", record=index)
            continue
        value = f"name[{name_id}] platform[{platform}] language[{language}]: {text}"
        encoded_size = len(value.encode("utf-8")) + 1
        if used + encoded_size > MAX_METADATA_BYTES:
            _partial(result, "Font name text extraction byte budget reached.")
            break
        used += encoded_size
        parts.append(value)
    result["name_records_declared"] = result.get("name_records_declared", 0) + count
    result["name_records_inspected"] = result.get("name_records_inspected", 0) + records_seen
    result["name_records_extracted"] = result.get("name_records_extracted", 0) + len(parts)
    result["text"] = "\n".join(part for part in [result["text"], *parts] if part)
