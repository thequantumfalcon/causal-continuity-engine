"""Reject known machine-readable content marks in exact Git objects.

The scanner recognizes the C2PA carriers implemented below; it is not a complete
C2PA 2.4 validator and does not validate signatures, claims, authorship, or
ownership.  Recognized C2PA-capable containers without an implemented parser
fail closed as inconclusive.  The scanner never fetches an external reference
and never rewrites content.

Hidden Unicode is a separate repository policy.  Source, configuration,
filenames, and Git metadata reject every format character, invisible filler,
annotation character, and variation selector outside an exact identified text
wrapper.  Prose permits only narrowly validated ordinary emoji presentation or
joiner sequences, non-ASCII linguistic joiners, and exactly one leading byte-order
mark.  Byte-order marks elsewhere and dangerous directional controls still fail,
and a suspicious finding is never described as C2PA.

Standard external-manifest locators in PNG, JPEG, and SVG XMP are parsed by
namespace, without substring matching.  Raw JUMBF stores are recognized by
structure even after a filename change; declared ``.c2pa`` sidecars that do
not parse are rejected as malformed.  No external reference or LFS object is
fetched.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
import subprocess
import sys
import tempfile
import unicodedata
import urllib.parse
import zlib
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from xml.parsers import expat

PRESENT = "PRESENT"
MALFORMED = "MALFORMED"
INCONCLUSIVE = "INCONCLUSIVE"
SUSPICIOUS = "SUSPICIOUS"

MAX_BLOB_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_XML_DEPTH = 64
MAX_XML_ELEMENTS = 100_000
MAX_HTML_ELEMENTS = 100_000
MAX_PNG_CHUNKS = 100_000
MAX_JPEG_SEGMENTS = 100_000
MAX_FINDINGS = 128
MAX_TOTAL_FINDINGS = 4_096
MAX_GIT_ENTRIES = 1_000_000
MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BLOB_BYTES = 256 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 30

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
LFS_VERSION_LINE = b"version https://git-lfs.github.com/spec/v1"
C2PA_UUID = bytes.fromhex("6332706100110010800000aa00389b71")
TEXT_MAGIC = b"C2PATXT\x00"
STRUCTURED_BEGIN = b"-----BEGIN " + b"C2PA MANIFEST-----"
STRUCTURED_END = b"-----END " + b"C2PA MANIFEST-----"
STRUCTURED_DATA_PREFIX = b"data:application/" + b"c2pa;base64,"

SVG_NAMESPACE = "http://www.w3.org/2000/svg"
C2PA_NAMESPACE = "http://c2pa.org/manifest"
DCTERMS_PROVENANCE = "http://purl.org/dc/terms/}provenance"
RDF_ROOT = "http://www.w3.org/1999/02/22-rdf-syntax-ns#}RDF"
RDF_DESCRIPTION = "http://www.w3.org/1999/02/22-rdf-syntax-ns#}Description"
RDF_RESOURCE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#}resource"
SVG_ROOT = SVG_NAMESPACE + "}svg"
SVG_METADATA = SVG_NAMESPACE + "}metadata"
SVG_MANIFEST = C2PA_NAMESPACE + "}manifest"
PNG_XMP_KEYWORD = b"XML:com.adobe.xmp"
JPEG_XMP_HEADER = b"http://ns.adobe.com/xap/1.0/\x00"
JPEG_EXTENDED_XMP_HEADER = b"http://ns.adobe.com/xmp/extension/\x00"

TEXT_SUFFIXES = {
    ".adoc",
    ".bash",
    ".bat",
    ".c",
    ".cfg",
    ".cmd",
    ".cpp",
    ".css",
    ".fish",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsonl",
    ".jsx",
    ".kt",
    ".md",
    ".php",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".rst",
    ".sh",
    ".sql",
    ".swift",
    ".tex",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".zsh",
}
TEXT_BASENAMES = {
    "Dockerfile",
    "Gemfile",
    "Justfile",
    "Makefile",
    "Procfile",
    "justfile",
}

PROSE_SUFFIXES = {".adoc", ".md", ".rst", ".txt"}

HTML_SUFFIXES = {".htm", ".html", ".xhtml"}
DECLARED_BINARY_SUFFIXES = {
    ".aac",
    ".avi",
    ".avif",
    ".docx",
    ".dng",
    ".eot",
    ".epub",
    ".gif",
    ".heic",
    ".heif",
    ".jar",
    ".jpe",
    ".jpeg",
    ".jpg",
    ".jxl",
    ".m4a",
    ".m4s",
    ".mov",
    ".mp4",
    ".odp",
    ".ods",
    ".odt",
    ".otf",
    ".pdf",
    ".png",
    ".pptx",
    ".tif",
    ".tiff",
    ".ttc",
    ".ttf",
    ".wav",
    ".webp",
    ".whl",
    ".woff",
    ".woff2",
    ".xlsx",
    ".zip",
}

_STORE_C2PA = "c2pa"
_STORE_OTHER = "other"
_STORE_MALFORMED = "malformed"


@dataclass(frozen=True, slots=True)
class Finding:
    """One deterministic scanner result."""

    status: str
    carrier: str
    path: str
    offset: int
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class _Box:
    kind: bytes
    payload_start: int
    end: int
    header_size: int


@dataclass(frozen=True, slots=True)
class _JpegSegment:
    marker: int
    offset: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class _BlobEntry:
    path: str
    oid: str | None
    issue: str | None = None


class _ParseError(ValueError):
    pass


class _GitError(RuntimeError):
    pass


def _finding(
    path: str,
    status: str,
    carrier: str,
    offset: int,
    code: str,
    detail: str,
) -> Finding:
    return Finding(status, carrier, path, max(offset, 0), code, detail)


def _parse_box(data: bytes, offset: int, limit: int) -> _Box:
    if offset < 0 or limit > len(data) or limit - offset < 8:
        raise _ParseError("truncated box header")
    size = int.from_bytes(data[offset : offset + 4], "big")
    kind = data[offset + 4 : offset + 8]
    header_size = 8
    if size == 1:
        if limit - offset < 16:
            raise _ParseError("truncated extended box header")
        size = int.from_bytes(data[offset + 8 : offset + 16], "big")
        header_size = 16
    elif size == 0:
        size = limit - offset
    if size < header_size or size > limit - offset:
        raise _ParseError("box length leaves its parent")
    return _Box(kind, offset + header_size, offset + size, header_size)


def _has_c2pa_prefix(data: bytes) -> bool:
    """Recognize a truncated standard-header store without guessing a UUID."""

    if len(data) < 8 or data[4:8] != b"jumb":
        return False
    description_offset = 16 if data[:4] == b"\x00\x00\x00\x01" else 8
    return (
        len(data) >= description_offset + 12
        and data[description_offset + 4 : description_offset + 8] == b"jumd"
        and data[description_offset + 8 : description_offset + 12] == C2PA_UUID[:4]
    )


def _probe_c2pa_store(data: bytes) -> str:
    """Identify only the outer C2PA store; do not validate its manifests."""

    prefix = _has_c2pa_prefix(data)
    try:
        outer = _parse_box(data, 0, len(data))
    except _ParseError:
        return _STORE_MALFORMED if prefix else _STORE_OTHER
    if outer.kind != b"jumb":
        return _STORE_OTHER
    try:
        description = _parse_box(data, outer.payload_start, outer.end)
    except _ParseError:
        return _STORE_MALFORMED if prefix else _STORE_OTHER
    if description.kind != b"jumd":
        return _STORE_OTHER
    payload = data[description.payload_start : description.end]
    if len(payload) < 16:
        if len(payload) >= 4 and C2PA_UUID.startswith(payload):
            return _STORE_MALFORMED
        return _STORE_OTHER
    if payload[:16] != C2PA_UUID:
        return _STORE_OTHER
    if outer.end != len(data) or len(payload) < 18:
        return _STORE_MALFORMED
    toggles = payload[16]
    if toggles & 0x03 != 0x03:
        return _STORE_MALFORMED
    label_end = payload.find(b"\x00", 17)
    if label_end < 0 or payload[17:label_end] != b"c2pa":
        return _STORE_MALFORMED
    return _STORE_C2PA


def _strict_base64(value: bytes) -> bytes:
    if len(value) > (MAX_MANIFEST_BYTES * 4 // 3) + 8:
        raise _ParseError("encoded manifest exceeds the size limit")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _ParseError("manifest is not strict Base64") from exc
    if len(decoded) > MAX_MANIFEST_BYTES:
        raise _ParseError("decoded manifest exceeds the size limit")
    return decoded


def _all_offsets(data: bytes, needle: bytes, limit: int = 3) -> list[int]:
    offsets: list[int] = []
    start = 0
    while len(offsets) < limit:
        offset = data.find(needle, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + 1
    return offsets


def _valid_external_reference(reference: bytes) -> bool:
    try:
        text = reference.decode("ascii")
    except UnicodeDecodeError:
        return False
    if any(ord(char) <= 0x20 or ord(char) == 0x7F for char in text):
        return False
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _scan_structured(path: str, data: bytes) -> list[Finding]:
    begins = _all_offsets(data, STRUCTURED_BEGIN)
    ends = _all_offsets(data, STRUCTURED_END)
    if not begins and not ends:
        return []
    offset = min(begins + ends)
    if len(begins) != 1 or len(ends) != 1:
        return [
            _finding(
                path,
                MALFORMED,
                "STRUCTURED",
                offset,
                "content.c2pa.structured.cardinality",
                "structured manifest delimiters are unpaired or repeated",
            )
        ]
    content_start = begins[0] + len(STRUCTURED_BEGIN)
    if ends[0] <= content_start:
        return [
            _finding(
                path,
                MALFORMED,
                "STRUCTURED",
                offset,
                "content.c2pa.structured.order",
                "structured manifest delimiters are out of order",
            )
        ]
    reference = data[content_start : ends[0]].strip(b" \t\r\n")
    if not reference:
        detail = "structured manifest reference is empty"
    elif reference.startswith(STRUCTURED_DATA_PREFIX):
        try:
            store = _strict_base64(reference[len(STRUCTURED_DATA_PREFIX) :])
        except _ParseError as exc:
            detail = str(exc)
        else:
            if _probe_c2pa_store(store) == _STORE_C2PA:
                return [
                    _finding(
                        path,
                        PRESENT,
                        "STRUCTURED",
                        begins[0],
                        "content.c2pa.structured.present",
                        "structured manifest data carrier is present",
                    )
                ]
            detail = "structured carrier does not contain a C2PA manifest store"
    elif _valid_external_reference(reference):
        return [
            _finding(
                path,
                PRESENT,
                "STRUCTURED",
                begins[0],
                "content.c2pa.structured.present",
                "structured external manifest carrier is present",
            )
        ]
    else:
        detail = "structured manifest reference has no supported resolution form"
    return [
        _finding(
            path,
            MALFORMED,
            "STRUCTURED",
            begins[0],
            "content.c2pa.structured.malformed",
            detail,
        )
    ]


def _is_variation_selector(codepoint: int) -> bool:
    return 0xFE00 <= codepoint <= 0xFE0F or 0xE0100 <= codepoint <= 0xE01EF


def _selector_byte(codepoint: int) -> int:
    if 0xFE00 <= codepoint <= 0xFE0F:
        return codepoint - 0xFE00
    if 0xE0100 <= codepoint <= 0xE01EF:
        return codepoint - 0xE0100 + 16
    raise _ParseError("not a variation selector")


def _utf8_width(codepoint: int) -> int:
    if codepoint <= 0x7F:
        return 1
    if codepoint <= 0x7FF:
        return 2
    if codepoint <= 0xFFFF:
        return 3
    return 4


def _scan_text_wrappers(path: str, text: str) -> tuple[list[Finding], list[tuple[int, int]]]:
    findings: list[Finding] = []
    protected: list[tuple[int, int]] = []
    valid_count = 0
    index = 0
    byte_offset = 0
    while index < len(text):
        if len(findings) >= MAX_FINDINGS - 1:
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "TEXT_VS",
                    byte_offset,
                    "content.scan.text.finding_limit",
                    "text-wrapper finding-count limit was reached",
                )
            )
            break
        codepoint = ord(text[index])
        if codepoint != 0xFEFF:
            byte_offset += _utf8_width(codepoint)
            index += 1
            continue
        end = index + 1
        while end < len(text) and _is_variation_selector(ord(text[end])):
            end += 1
        run_length = end - index - 1
        prefix_length = min(run_length, 13)
        prefix = bytes(
            _selector_byte(ord(text[pos]))
            for pos in range(index + 1, index + 1 + prefix_length)
        )
        if prefix[:8] == TEXT_MAGIC:
            protected.append((index, end))
            detail: str | None = None
            if run_length > MAX_MANIFEST_BYTES + 13:
                detail = "text wrapper exceeds the manifest size limit"
            elif run_length < 13:
                detail = "text wrapper header is incomplete"
            else:
                wrapper = bytes(_selector_byte(ord(text[pos])) for pos in range(index + 1, end))
                declared = int.from_bytes(wrapper[9:13], "big")
                if wrapper[8] != 1:
                    detail = "text wrapper version is not supported"
                elif declared > MAX_MANIFEST_BYTES:
                    detail = "text wrapper declares an oversized manifest"
                elif len(wrapper) != 13 + declared:
                    detail = "text wrapper length does not match its declaration"
                elif _probe_c2pa_store(wrapper[13:]) != _STORE_C2PA:
                    detail = "text wrapper does not contain a C2PA manifest store"
            if detail is None:
                valid_count += 1
                findings.append(
                    _finding(
                        path,
                        PRESENT,
                        "TEXT_VS",
                        byte_offset,
                        "content.c2pa.text.present",
                        "variation-selector text carrier is present",
                    )
                )
            else:
                findings.append(
                    _finding(
                        path,
                        MALFORMED,
                        "TEXT_VS",
                        byte_offset,
                        "content.c2pa.text.malformed",
                        detail,
                    )
                )
            consumed = sum(_utf8_width(ord(text[pos])) for pos in range(index, end))
            byte_offset += consumed
            index = end
            continue
        byte_offset += _utf8_width(codepoint)
        index += 1
    if valid_count > 1:
        findings.append(
            _finding(
                path,
                MALFORMED,
                "TEXT_VS",
                findings[0].offset,
                "content.c2pa.text.multiple",
                "more than one valid text wrapper is present",
            )
        )
    return findings, protected


def _is_explicit_hidden(codepoint: int) -> bool:
    return (
        codepoint in {0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0}
        or 0x17B4 <= codepoint <= 0x17B5
        or 0x180B <= codepoint <= 0x180D
        or 0xFFF9 <= codepoint <= 0xFFFB
    )


def _presentation_selector_allowed(text: str, index: int) -> bool:
    codepoint = ord(text[index])
    if codepoint not in {0xFE0E, 0xFE0F} or index == 0:
        return False
    if index + 1 < len(text) and _is_variation_selector(ord(text[index + 1])):
        return False
    previous = text[index - 1]
    category = unicodedata.category(previous)
    return (
        not previous.isspace()
        and category not in {"Cc", "Cf", "Cs"}
        and _is_emoji_base(ord(previous))
    )


def _is_emoji_base(codepoint: int) -> bool:
    return (
        0x2600 <= codepoint <= 0x27BF
        or 0x1F1E6 <= codepoint <= 0x1F1FF
        or 0x1F300 <= codepoint <= 0x1FAFF
    )


def _emoji_joiner_allowed(text: str, index: int) -> bool:
    if ord(text[index]) != 0x200D or index == 0 or index + 1 >= len(text):
        return False
    left = index - 1
    while left >= 0 and (
        ord(text[left]) in {0xFE0E, 0xFE0F}
        or 0x1F3FB <= ord(text[left]) <= 0x1F3FF
    ):
        left -= 1
    return (
        left >= 0
        and _is_emoji_base(ord(text[left]))
        and _is_emoji_base(ord(text[index + 1]))
    )


def _linguistic_joiner_allowed(text: str, index: int) -> bool:
    if ord(text[index]) not in {0x200C, 0x200D} or index == 0 or index + 1 >= len(text):
        return False
    left = index - 1
    right = index + 1
    while left >= 0 and unicodedata.category(text[left]).startswith("M"):
        left -= 1
    while right < len(text) and unicodedata.category(text[right]).startswith("M"):
        right += 1
    if left < 0 or right >= len(text):
        return False
    return (
        unicodedata.category(text[left]).startswith("L")
        and unicodedata.category(text[right]).startswith("L")
        and ord(text[left]) > 0x7F
        and ord(text[right]) > 0x7F
    )


def _scan_hidden_unicode(
    path: str,
    text: str,
    protected: list[tuple[int, int]],
    *,
    allow_prose_sequences: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    protected_index = 0
    byte_offset = 0
    for index, char in enumerate(text):
        while (
            protected_index < len(protected)
            and index >= protected[protected_index][1]
        ):
            protected_index += 1
        if (
            protected_index < len(protected)
            and protected[protected_index][0] <= index < protected[protected_index][1]
        ):
            byte_offset += _utf8_width(ord(char))
            continue
        codepoint = ord(char)
        suspicious = False
        if (
            codepoint == 0xFEFF
            and allow_prose_sequences
            and index == 0
            and (len(text) == 1 or ord(text[1]) != 0xFEFF)
        ):
            suspicious = False
        elif codepoint in {0x200C, 0x200D}:
            suspicious = not (
                allow_prose_sequences
                and (
                    _emoji_joiner_allowed(text, index)
                    or _linguistic_joiner_allowed(text, index)
                )
            )
        elif unicodedata.category(char) == "Cf" or _is_explicit_hidden(codepoint):
            suspicious = True
        elif _is_variation_selector(codepoint):
            suspicious = not (
                allow_prose_sequences and _presentation_selector_allowed(text, index)
            )
        if suspicious and len(findings) < MAX_FINDINGS:
            if len(findings) >= MAX_FINDINGS - 1:
                findings.append(
                    _finding(
                        path,
                        INCONCLUSIVE,
                        "UNICODE",
                        byte_offset,
                        "content.scan.unicode.finding_limit",
                        "hidden-Unicode finding-count limit was reached",
                    )
                )
                break
            name = unicodedata.name(char, "UNNAMED")
            findings.append(
                _finding(
                    path,
                    SUSPICIOUS,
                    "UNICODE",
                    byte_offset,
                    "content.unicode.hidden",
                    f"strict hidden-Unicode policy rejects U+{codepoint:04X} {name}",
                )
            )
        byte_offset += _utf8_width(codepoint)
    return findings


def _scan_path(path: str) -> list[Finding]:
    findings: list[Finding] = []
    byte_offset = 0
    for index, char in enumerate(path):
        codepoint = ord(char)
        if 0xD800 <= codepoint <= 0xDFFF:
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "PATH",
                    byte_offset,
                    "content.scan.path.encoding",
                    "Git pathname is not valid UTF-8",
                )
            )
            return findings
        suspicious = (
            unicodedata.category(char) == "Cf"
            or _is_explicit_hidden(codepoint)
            or _is_variation_selector(codepoint)
        )
        if suspicious:
            if len(findings) >= MAX_FINDINGS - 1:
                findings.append(
                    _finding(
                        path,
                        INCONCLUSIVE,
                        "PATH",
                        byte_offset,
                        "content.scan.path.finding_limit",
                        "pathname finding-count limit was reached",
                    )
                )
                break
            name = unicodedata.name(char, "UNNAMED")
            findings.append(
                _finding(
                    path,
                    SUSPICIOUS,
                    "PATH",
                    byte_offset,
                    "content.path.hidden_unicode",
                    f"strict pathname policy rejects U+{codepoint:04X} {name}",
                )
            )
        byte_offset += len(char.encode("utf-8"))
    return findings


def _is_lfs_pointer(data: bytes) -> bool:
    first_line = data.split(b"\n", 1)[0].rstrip(b"\r")
    return first_line == LFS_VERSION_LINE


def _valid_uri_reference(value: str) -> bool:
    if not value or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in value):
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    if "\\" in value:
        return False
    for index, char in enumerate(value):
        if char == "%" and (
            index + 2 >= len(value)
            or any(item not in "0123456789ABCDEFabcdef" for item in value[index + 1 : index + 3])
        ):
            return False
    try:
        parsed = urllib.parse.urlsplit(value)
        parsed.port
    except ValueError:
        return False
    return True


def _scan_xmp(path: str, data: bytes, offset: int, host: str) -> list[Finding]:
    records: list[dict[str, object]] = []
    active: dict[str, object] | None = None
    stack: list[str] = []
    elements = 0
    parser = expat.ParserCreate(namespace_separator="}")

    def reject_declaration(*_args: object) -> None:
        raise _ParseError("XMP declarations and entities are not scanned")

    def start(name: str, attributes: dict[str, str]) -> None:
        nonlocal active, elements
        elements += 1
        if elements > MAX_XML_ELEMENTS or len(stack) >= MAX_XML_DEPTH:
            raise _ParseError("XMP structural limit was reached")
        if active is not None:
            active["nested"] = True
        in_rdf = RDF_ROOT in stack
        if (
            name == RDF_DESCRIPTION
            and in_rdf
            and DCTERMS_PROVENANCE in attributes
        ):
            records.append(
                {
                    "offset": parser.CurrentByteIndex,
                    "value": attributes[DCTERMS_PROVENANCE],
                    "nested": False,
                    "complete": True,
                }
            )
        if name == DCTERMS_PROVENANCE and stack and stack[-1] == RDF_DESCRIPTION and in_rdf:
            active = {
                "offset": parser.CurrentByteIndex,
                "depth": len(stack) + 1,
                "parts": [],
                "length": 0,
                "resource": attributes.get(RDF_RESOURCE),
                "nested": False,
                "complete": False,
            }
            records.append(active)
        stack.append(name)

    def character(value: str) -> None:
        if active is None:
            return
        length = int(active["length"]) + len(value)
        if length > 8192:
            raise _ParseError("XMP provenance locator exceeds the size limit")
        active["length"] = length
        parts = active["parts"]
        assert isinstance(parts, list)
        parts.append(value)

    def end(name: str) -> None:
        nonlocal active
        if active is not None and name == DCTERMS_PROVENANCE:
            parts = active["parts"]
            assert isinstance(parts, list)
            text = "".join(parts).strip()
            resource = active["resource"]
            active["value"] = resource if resource is not None else text
            if resource is not None and text:
                active["nested"] = True
            active["complete"] = True
            active = None
        if not stack or stack[-1] != name:
            raise _ParseError("XMP element stack is inconsistent")
        stack.pop()

    parser.StartElementHandler = start
    parser.CharacterDataHandler = character
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.UnparsedEntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = lambda *_args: 0
    try:
        parser.Parse(data, True)
    except (_ParseError, expat.ExpatError) as exc:
        # An XMP packet this scanner cannot finish reading is a packet it
        # cannot clear. Returning clean here let a real external-manifest
        # locator through: prefixing the packet with a DOCTYPE raises before
        # the first element is seen, so `records` was empty and the carrier
        # was never reported, while a stock XML parser still reads the
        # locator. SVG already fails closed on the same construct; this makes
        # PNG and JPEG match the scanner's stated contract.
        return [
            _finding(
                path,
                INCONCLUSIVE,
                "XMP_PROVENANCE",
                offset + max(parser.ErrorByteIndex, 0),
                "content.scan.xmp.malformed",
                f"{host} XMP provenance could not be scanned completely: {exc}",
            )
        ]
    if not records:
        return []
    if len(records) != 1:
        return [
            _finding(
                path,
                MALFORMED,
                "XMP_PROVENANCE",
                offset + int(records[1]["offset"]),
                "content.c2pa.xmp.multiple",
                f"{host} XMP contains more than one external-manifest locator",
            )
        ]
    record = records[0]
    value = record.get("value")
    if not record["complete"] or record["nested"] or not isinstance(value, str):
        valid = False
    else:
        valid = _valid_uri_reference(value)
    return [
        _finding(
            path,
            PRESENT if valid else MALFORMED,
            "XMP_PROVENANCE",
            offset + int(record["offset"]),
            (
                "content.c2pa.xmp.present"
                if valid
                else "content.c2pa.xmp.malformed"
            ),
            (
                f"{host} XMP external-manifest locator is present"
                if valid
                else f"{host} XMP external-manifest locator is malformed"
            ),
        )
    ]


def _png_xmp(path: str, payload: bytes, offset: int) -> list[Finding]:
    keyword, separator, fields = payload.partition(b"\x00")
    if keyword != PNG_XMP_KEYWORD:
        return []
    if not separator or len(fields) < 2:
        return [
            _finding(
                path,
                INCONCLUSIVE,
                "XMP_PROVENANCE",
                offset,
                "content.scan.xmp.png",
                "PNG XMP chunk framing is truncated",
            )
        ]
    compression, method, fields = fields[0], fields[1], fields[2:]
    language, separator, fields = fields.partition(b"\x00")
    translated, separator2, packet = fields.partition(b"\x00")
    if not separator or not separator2 or language or translated or compression != 0 or method != 0:
        return [
            _finding(
                path,
                INCONCLUSIVE,
                "XMP_PROVENANCE",
                offset,
                "content.scan.xmp.png",
                "PNG XMP chunk uses unsupported framing",
            )
        ]
    return _scan_xmp(path, packet, offset, "PNG")


def _scan_png(path: str, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    offset = len(PNG_SIGNATURE)
    chunk_count = 0
    carrier_offsets: list[int] = []
    saw_end = False
    first_kind: bytes | None = None
    while offset < len(data):
        if len(findings) >= MAX_FINDINGS:
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "PNG_CABX",
                    offset,
                    "content.scan.png.finding_limit",
                    "PNG finding-count limit was reached",
                )
            )
            break
        if chunk_count >= MAX_PNG_CHUNKS:
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "PNG_CABX",
                    offset,
                    "content.scan.png.limit",
                    "PNG chunk-count limit was reached",
                )
            )
            break
        if len(data) - offset < 12:
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "PNG_CABX",
                    offset,
                    "content.scan.png.truncated",
                    "PNG chunk framing is truncated",
                )
            )
            break
        length = int.from_bytes(data[offset : offset + 4], "big")
        kind = data[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        chunk_end = data_end + 4
        if data_end < data_start or chunk_end > len(data):
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "PNG_CABX",
                    offset,
                    "content.scan.png.length",
                    "PNG chunk length leaves the blob",
                )
            )
            break
        payload = data[data_start:data_end]
        expected_crc = int.from_bytes(data[data_end:chunk_end], "big")
        actual_crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
        crc_ok = expected_crc == actual_crc
        if first_kind is None:
            first_kind = kind
            if kind != b"IHDR":
                findings.append(
                    _finding(
                        path,
                        INCONCLUSIVE,
                        "PNG_CABX",
                        offset,
                        "content.scan.png.header",
                        "PNG does not begin with an IHDR chunk",
                    )
                )
        if kind == b"caBX":
            carrier_offsets.append(offset)
            state = _probe_c2pa_store(payload)
            if crc_ok and state == _STORE_C2PA:
                findings.append(
                    _finding(
                        path,
                        PRESENT,
                        "PNG_CABX",
                        offset,
                        "content.c2pa.png.present",
                        "PNG caBX carrier is present",
                    )
                )
            else:
                detail = (
                    "PNG caBX checksum is invalid"
                    if not crc_ok
                    else "PNG caBX payload is not a C2PA manifest store"
                )
                findings.append(
                    _finding(
                        path,
                        MALFORMED,
                        "PNG_CABX",
                        offset,
                        "content.c2pa.png.malformed",
                        detail,
                    )
                )
        elif kind == b"iTXt" and crc_ok:
            findings.extend(_png_xmp(path, payload, offset))
        elif not crc_ok:
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "PNG_CABX",
                    offset,
                    "content.scan.png.crc",
                    "PNG contains a chunk with an invalid checksum",
                )
            )
        chunk_count += 1
        offset = chunk_end
        if kind == b"IEND":
            saw_end = True
            if length != 0 or offset != len(data):
                findings.append(
                    _finding(
                        path,
                        INCONCLUSIVE,
                        "PNG_CABX",
                        offset,
                        "content.scan.png.end",
                        "PNG IEND framing is not canonical",
                    )
                )
            break
    if not saw_end:
        findings.append(
            _finding(
                path,
                INCONCLUSIVE,
                "PNG_CABX",
                min(offset, len(data)),
                "content.scan.png.no_end",
                "PNG has no complete IEND chunk",
            )
        )
    if len(carrier_offsets) > 1:
        findings.append(
            _finding(
                path,
                MALFORMED,
                "PNG_CABX",
                carrier_offsets[1],
                "content.c2pa.png.multiple",
                "PNG contains more than one caBX carrier",
            )
        )
    return findings


def _jpeg_segments(data: bytes) -> tuple[list[_JpegSegment], tuple[int, str] | None]:
    if not data.startswith(b"\xFF\xD8"):
        return [], (0, "JPEG start-of-image marker is missing")
    segments: list[_JpegSegment] = []
    offset = 2
    in_scan = False
    while offset < len(data):
        if len(segments) >= MAX_JPEG_SEGMENTS:
            return segments, (offset, "JPEG segment-count limit was reached")
        if in_scan:
            marker_start = data.find(b"\xFF", offset)
            while marker_start >= 0:
                cursor = marker_start + 1
                while cursor < len(data) and data[cursor] == 0xFF:
                    cursor += 1
                if cursor >= len(data):
                    return segments, (marker_start, "JPEG entropy marker is truncated")
                marker = data[cursor]
                if marker == 0x00 or 0xD0 <= marker <= 0xD7:
                    offset = cursor + 1
                    marker_start = data.find(b"\xFF", offset)
                    continue
                offset = marker_start
                break
            else:
                return segments, (len(data), "JPEG scan data has no terminating marker")
        if data[offset] != 0xFF:
            return segments, (offset, "JPEG marker prefix is missing")
        marker_offset = offset
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            return segments, (marker_offset, "JPEG marker is truncated")
        marker = data[offset]
        offset += 1
        if marker == 0x00:
            return segments, (marker_offset, "stuffed byte appears outside scan data")
        if marker == 0xD9:
            segments.append(_JpegSegment(marker, marker_offset, b""))
            if offset != len(data):
                return segments, (offset, "JPEG has trailing data after end-of-image")
            return segments, None
        if marker == 0x01 or 0xD0 <= marker <= 0xD8:
            segments.append(_JpegSegment(marker, marker_offset, b""))
            in_scan = False
            continue
        if len(data) - offset < 2:
            return segments, (marker_offset, "JPEG segment length is truncated")
        length = int.from_bytes(data[offset : offset + 2], "big")
        if length < 2 or length - 2 > len(data) - offset - 2:
            return segments, (marker_offset, "JPEG segment length leaves the blob")
        payload_start = offset + 2
        payload_end = payload_start + length - 2
        segments.append(_JpegSegment(marker, marker_offset, data[payload_start:payload_end]))
        offset = payload_end
        if marker == 0xDA:
            in_scan = True
        elif marker != 0xDC:
            in_scan = False
    return segments, (len(data), "JPEG has no complete end-of-image marker")


def _jpeg_continuation(
    segment: _JpegSegment,
    common_identifier: bytes,
    instance: bytes,
    sequence: int,
    box_header: bytes,
) -> tuple[bytes | None, str | None]:
    payload = segment.payload
    if segment.marker != 0xEB:
        return None, "JPEG-XT fragments are not contiguous"
    if len(payload) < 16:
        return None, "JPEG-XT continuation is truncated"
    if payload[:2] != common_identifier:
        return None, "JPEG-XT continuation changed the common identifier"
    if payload[2:4] != instance:
        return None, "JPEG-XT continuation changed box instance"
    if int.from_bytes(payload[4:8], "big") != sequence:
        return None, "JPEG-XT packet sequence is not contiguous"
    if payload[8:16] != box_header:
        return None, "JPEG-XT continuation changed the repeated box header"
    return payload[16:], None


def _scan_jpeg_xmp(path: str, segments: list[_JpegSegment]) -> list[Finding]:
    findings: list[Finding] = []
    extended: dict[bytes, list[tuple[int, int, bytes]]] = {}
    totals: dict[bytes, int] = {}
    extended_bytes = 0
    for segment in segments:
        if segment.marker != 0xE1:
            continue
        if segment.payload.startswith(JPEG_XMP_HEADER):
            findings.extend(
                _scan_xmp(
                    path,
                    segment.payload[len(JPEG_XMP_HEADER) :],
                    segment.offset,
                    "JPEG",
                )
            )
            continue
        if not segment.payload.startswith(JPEG_EXTENDED_XMP_HEADER):
            continue
        header = len(JPEG_EXTENDED_XMP_HEADER)
        fields = segment.payload[header:]
        if len(fields) < 40:
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "XMP_PROVENANCE",
                    segment.offset,
                    "content.scan.xmp.jpeg_extended",
                    "extended JPEG XMP header is truncated",
                )
            )
            continue
        guid = fields[:32]
        if any(byte not in b"0123456789ABCDEFabcdef" for byte in guid):
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "XMP_PROVENANCE",
                    segment.offset,
                    "content.scan.xmp.jpeg_extended",
                    "extended JPEG XMP identifier is malformed",
                )
            )
            continue
        total = int.from_bytes(fields[32:36], "big")
        offset = int.from_bytes(fields[36:40], "big")
        chunk = fields[40:]
        if (
            total > MAX_MANIFEST_BYTES
            or offset > total
            or len(chunk) > total - offset
            or (guid in totals and totals[guid] != total)
        ):
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "XMP_PROVENANCE",
                    segment.offset,
                    "content.scan.xmp.jpeg_extended",
                    "extended JPEG XMP bounds are inconsistent",
                )
            )
            continue
        totals[guid] = total
        extended.setdefault(guid, []).append((offset, segment.offset, chunk))
        extended_bytes += len(chunk)
        if extended_bytes > MAX_MANIFEST_BYTES:
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "XMP_PROVENANCE",
                    segment.offset,
                    "content.scan.xmp.jpeg_extended",
                    "extended JPEG XMP exceeds the aggregate size limit",
                )
            )
            return findings
    for guid, chunks in extended.items():
        cursor = 0
        parts: list[bytes] = []
        malformed_offset = chunks[0][1]
        complete = True
        for chunk_offset, segment_offset, chunk in sorted(chunks):
            if chunk_offset != cursor:
                malformed_offset = segment_offset
                complete = False
                break
            parts.append(chunk)
            cursor += len(chunk)
        if not complete or cursor != totals[guid]:
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "XMP_PROVENANCE",
                    malformed_offset,
                    "content.scan.xmp.jpeg_extended",
                    "extended JPEG XMP fragments are incomplete or overlap",
                )
            )
            continue
        findings.extend(_scan_xmp(path, b"".join(parts), chunks[0][1], "JPEG"))
    return findings


def _scan_jpeg(path: str, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    segments, parse_error = _jpeg_segments(data)
    findings.extend(_scan_jpeg_xmp(path, segments))
    carrier_offsets: list[int] = []
    index = 0
    while index < len(segments):
        if len(findings) >= MAX_FINDINGS:
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "JPEG_APP11",
                    segments[index].offset,
                    "content.scan.jpeg.finding_limit",
                    "JPEG finding-count limit was reached",
                )
            )
            break
        first = segments[index]
        payload = first.payload
        if (
            first.marker != 0xEB
            or len(payload) < 16
            or payload[12:16] != b"jumb"
        ):
            index += 1
            continue
        first_sequence = int.from_bytes(payload[4:8], "big")
        if first_sequence != 1:
            if _has_c2pa_prefix(payload[8:]):
                carrier_offsets.append(first.offset)
                findings.append(
                    _finding(
                        path,
                        MALFORMED,
                        "JPEG_APP11",
                        first.offset,
                        "content.c2pa.jpeg.sequence",
                        "JPEG-XT carrier does not begin with packet sequence one",
                    )
                )
            index += 1
            continue
        box_header = payload[8:16]
        reconstructed = bytearray(payload[8:])
        short_length = int.from_bytes(box_header[:4], "big")
        header_size = 8
        if short_length == 1:
            if len(reconstructed) < 16:
                index += 1
                continue
            declared = int.from_bytes(reconstructed[8:16], "big")
            header_size = 16
        else:
            declared = short_length
        if declared == 0 or declared < header_size or declared > MAX_MANIFEST_BYTES:
            if _has_c2pa_prefix(reconstructed):
                findings.append(
                    _finding(
                        path,
                        INCONCLUSIVE,
                        "JPEG_APP11",
                        first.offset,
                        "content.scan.jpeg.extended",
                        "C2PA JPEG-XT box uses an unsupported or oversized length",
                    )
                )
            index += 1
            continue
        next_index = index + 1
        sequence = 2
        problem: str | None = None
        while len(reconstructed) < declared:
            if next_index >= len(segments):
                problem = "JPEG-XT carrier ends before its declared box length"
                break
            addition, problem = _jpeg_continuation(
                segments[next_index], payload[:2], payload[2:4], sequence, box_header
            )
            if problem is not None:
                break
            assert addition is not None
            reconstructed.extend(addition)
            next_index += 1
            sequence += 1
        identity = _has_c2pa_prefix(reconstructed)
        if problem is None and len(reconstructed) > declared:
            problem = "JPEG-XT carrier exceeds its declared box length"
        if problem is None and len(reconstructed) == declared:
            state = _probe_c2pa_store(bytes(reconstructed))
            if state == _STORE_C2PA:
                carrier_offsets.append(first.offset)
                if payload[:2] == b"JP":
                    findings.append(
                        _finding(
                            path,
                            PRESENT,
                            "JPEG_APP11",
                            first.offset,
                            "content.c2pa.jpeg.present",
                            "JPEG APP11 carrier is present",
                        )
                    )
                else:
                    findings.append(
                        _finding(
                            path,
                            MALFORMED,
                            "JPEG_APP11",
                            first.offset,
                            "content.c2pa.jpeg.identifier",
                            "JPEG APP11 carrier has the wrong common identifier",
                        )
                    )
                if next_index < len(segments):
                    extra = segments[next_index]
                    if (
                        extra.marker == 0xEB
                        and len(extra.payload) >= 8
                        and extra.payload[:4] == payload[:4]
                        and int.from_bytes(extra.payload[4:8], "big") == sequence
                    ):
                        findings.append(
                            _finding(
                                path,
                                MALFORMED,
                                "JPEG_APP11",
                                extra.offset,
                                "content.c2pa.jpeg.extra_fragment",
                                "JPEG APP11 carrier has an extra continuation",
                            )
                        )
            elif state == _STORE_MALFORMED:
                carrier_offsets.append(first.offset)
                findings.append(
                    _finding(
                        path,
                        MALFORMED,
                        "JPEG_APP11",
                        first.offset,
                        "content.c2pa.jpeg.malformed",
                        "JPEG APP11 carrier has a malformed C2PA store description",
                    )
                )
        elif identity:
            carrier_offsets.append(first.offset)
            findings.append(
                _finding(
                    path,
                    MALFORMED,
                    "JPEG_APP11",
                    first.offset,
                    "content.c2pa.jpeg.malformed",
                    problem or "JPEG APP11 carrier is incomplete",
                )
            )
        elif problem is not None:
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "JPEG_APP11",
                    first.offset,
                    "content.scan.jpeg.fragment",
                    "JPEG-XT JUMBF box could not be reconstructed completely",
                )
            )
        index = max(index + 1, next_index)
    if len(carrier_offsets) > 1:
        findings.append(
            _finding(
                path,
                MALFORMED,
                "JPEG_APP11",
                carrier_offsets[1],
                "content.c2pa.jpeg.multiple",
                "JPEG contains more than one C2PA APP11 carrier",
            )
        )
    if parse_error is not None:
        findings.append(
            _finding(
                path,
                INCONCLUSIVE,
                "JPEG_APP11",
                parse_error[0],
                "content.scan.jpeg.malformed",
                parse_error[1],
            )
        )
    return findings


def _scan_svg(path: str, data: bytes, *, required: bool) -> list[Finding]:
    records: list[dict[str, object]] = []
    stack: list[str] = []
    active: dict[str, object] | None = None
    elements = 0
    root_name: str | None = None
    parser = expat.ParserCreate(namespace_separator="}")

    def reject_declaration(*_args: object) -> None:
        raise _ParseError("SVG declarations and entities are not scanned")

    def start(name: str, _attributes: dict[str, str]) -> None:
        nonlocal active, elements, root_name
        elements += 1
        if elements > MAX_XML_ELEMENTS:
            raise _ParseError("SVG element-count limit was reached")
        if len(stack) >= MAX_XML_DEPTH:
            raise _ParseError("SVG depth limit was reached")
        if active is not None:
            active["nested"] = True
        if root_name is None:
            root_name = name
        if (
            name == SVG_MANIFEST
            and stack
            and stack[0] == SVG_ROOT
            and stack[-1] == SVG_METADATA
        ):
            active = {
                "offset": parser.CurrentByteIndex,
                "depth": len(stack) + 1,
                "text": [],
                "length": 0,
                "nested": False,
                "complete": False,
            }
            records.append(active)
        stack.append(name)

    def character(value: str) -> None:
        if active is None:
            return
        length = int(active["length"]) + len(value)
        if length > (MAX_MANIFEST_BYTES * 4 // 3) + 8:
            raise _ParseError("SVG manifest text exceeds the size limit")
        active["length"] = length
        text_parts = active["text"]
        assert isinstance(text_parts, list)
        text_parts.append(value)

    def end(name: str) -> None:
        nonlocal active
        if not stack or stack[-1] != name:
            raise _ParseError("SVG element stack is inconsistent")
        if (
            active is not None
            and name == SVG_MANIFEST
            and len(stack) == int(active["depth"])
        ):
            active["complete"] = True
            active = None
        stack.pop()

    parser.StartElementHandler = start
    parser.CharacterDataHandler = character
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.UnparsedEntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = lambda *_args: 0

    parse_problem: str | None = None
    try:
        parser.Parse(data, True)
    except (_ParseError, expat.ExpatError) as exc:
        parse_problem = str(exc)

    findings: list[Finding] = []
    if root_name == SVG_ROOT:
        findings.extend(_scan_xmp(path, data, 0, "SVG"))
    if len(records) > 1:
        findings.append(
            _finding(
                path,
                MALFORMED,
                "SVG_MANIFEST",
                int(records[1]["offset"]),
                "content.c2pa.svg.multiple",
                "SVG contains more than one namespaced manifest carrier",
            )
        )
    for record in records[:1]:
        offset = int(record["offset"])
        if not record["complete"] or record["nested"]:
            detail = "SVG manifest element is incomplete or contains child elements"
        else:
            parts = record["text"]
            assert isinstance(parts, list)
            value = "".join(parts)
            value = value.translate({ord(char): None for char in " \t\r\n"})
            try:
                encoded = value.encode("ascii")
                store = _strict_base64(encoded)
            except (UnicodeEncodeError, _ParseError) as exc:
                detail = str(exc)
            else:
                if _probe_c2pa_store(store) == _STORE_C2PA:
                    findings.append(
                        _finding(
                            path,
                            PRESENT,
                            "SVG_MANIFEST",
                            offset,
                            "content.c2pa.svg.present",
                            "SVG namespaced manifest carrier is present",
                        )
                    )
                    continue
                detail = "SVG carrier does not contain a C2PA manifest store"
        findings.append(
            _finding(
                path,
                MALFORMED,
                "SVG_MANIFEST",
                offset,
                "content.c2pa.svg.malformed",
                detail,
            )
        )
    if parse_problem is not None and (required or root_name == SVG_ROOT or records):
        status = MALFORMED if records else INCONCLUSIVE
        findings.append(
            _finding(
                path,
                status,
                "SVG_MANIFEST",
                parser.ErrorByteIndex,
                "content.scan.svg.malformed",
                f"SVG could not be scanned completely: {parse_problem}",
            )
        )
    return findings


class _HtmlCarrierParser(HTMLParser):
    _VOID_TAGS = {
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements = 0
        self.stack: list[tuple[str, dict[str, str]]] = []
        self.records: list[dict[str, object]] = []
        self.active: dict[str, object] | None = None

    def _start(self, tag: str, attributes: list[tuple[str, str | None]]) -> None:
        self.elements += 1
        if self.elements > MAX_HTML_ELEMENTS or len(self.stack) >= MAX_XML_DEPTH:
            raise _ParseError("HTML structural limit was reached")
        names = [name.lower() for name, _ in attributes]
        duplicate_names = {name for name in names if names.count(name) > 1}
        values = {name.lower(): (value or "") for name, value in attributes}
        namespaces = dict(self.stack[-1][1]) if self.stack else {}
        for name, value in values.items():
            if name == "xmlns":
                namespaces[""] = value
            elif name.startswith("xmlns:"):
                namespaces[name[6:]] = value

        if self.active is not None:
            self.active["nested"] = True
        in_head = any(item[0] == "head" for item in self.stack)
        if tag == "script" and values.get("type", "").lower() == "application/c2pa":
            self.active = {
                "kind": "inline",
                "tag": tag,
                "text": [],
                "length": 0,
                "nested": False,
                "complete": False,
                "valid_context": in_head and "type" not in duplicate_names,
            }
            self.records.append(self.active)
        elif tag == "link":
            rel = {item.lower() for item in values.get("rel", "").split()}
            if "c2pa-manifest" in rel:
                self.records.append(
                    {
                        "kind": "external",
                        "value": values.get("href", ""),
                        "complete": True,
                        "nested": False,
                        "valid_context": (
                            in_head
                            and not ({"rel", "href", "type"} & duplicate_names)
                            and values.get("type", "application/c2pa").lower()
                            == "application/c2pa"
                        ),
                    }
                )

        prefix, separator, local = tag.partition(":")
        if not separator:
            prefix, local = "", tag
        parent = self.stack[-1][0] if self.stack else ""
        in_svg = any(
            item_tag.rpartition(":")[2] == "svg"
            and item_namespaces.get("") == SVG_NAMESPACE
            for item_tag, item_namespaces in self.stack
        )
        if (
            local == "manifest"
            and namespaces.get(prefix) == C2PA_NAMESPACE
            and parent.rpartition(":")[2] == "metadata"
            and in_svg
        ):
            self.active = {
                "kind": "svg",
                "tag": tag,
                "text": [],
                "length": 0,
                "nested": False,
                "complete": False,
                "valid_context": True,
            }
            self.records.append(self.active)
        if tag not in self._VOID_TAGS:
            self.stack.append((tag, namespaces))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag.lower(), attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag.lower(), attrs)
        self.handle_endtag(tag.lower())

    def handle_data(self, data: str) -> None:
        if self.active is None:
            return
        length = int(self.active["length"]) + len(data)
        if length > (MAX_MANIFEST_BYTES * 4 // 3) + 8:
            raise _ParseError("HTML manifest payload exceeds the size limit")
        self.active["length"] = length
        parts = self.active["text"]
        assert isinstance(parts, list)
        parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self.active is not None and tag == self.active["tag"]:
            self.active["complete"] = True
            self.active = None
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break


def _scan_html(path: str, text: str) -> list[Finding]:
    parser = _HtmlCarrierParser()
    parse_problem: str | None = None
    try:
        parser.feed(text)
        parser.close()
    except (_ParseError, ValueError) as exc:
        parse_problem = str(exc)
    findings: list[Finding] = []
    if len(parser.records) > 1:
        findings.append(
            _finding(
                path,
                MALFORMED,
                "HTML_MANIFEST",
                0,
                "content.c2pa.html.multiple",
                "HTML contains more than one C2PA manifest association",
            )
        )
    for record in parser.records[:1]:
        kind = str(record["kind"])
        valid = bool(record["complete"] and record["valid_context"] and not record["nested"])
        if kind == "external":
            valid = valid and _valid_uri_reference(str(record["value"]))
        else:
            parts = record["text"]
            assert isinstance(parts, list)
            value = "".join(parts)
            if kind == "svg":
                value = value.translate({ord(char): None for char in " \t\r\n"})
            else:
                value = value.strip(" \t\r\n")
            try:
                store = _strict_base64(value.encode("ascii"))
            except (UnicodeEncodeError, _ParseError):
                valid = False
            else:
                valid = valid and _probe_c2pa_store(store) == _STORE_C2PA
        findings.append(
            _finding(
                path,
                PRESENT if valid else MALFORMED,
                "HTML_MANIFEST",
                0,
                (
                    "content.c2pa.html.present"
                    if valid
                    else "content.c2pa.html.malformed"
                ),
                (
                    "HTML C2PA manifest association is present"
                    if valid
                    else "HTML C2PA manifest association is malformed"
                ),
            )
        )
    if parse_problem is not None:
        findings.append(
            _finding(
                path,
                INCONCLUSIVE,
                "HTML_MANIFEST",
                0,
                "content.scan.html.limit",
                f"HTML could not be scanned completely: {parse_problem}",
            )
        )
    return findings


def _unsupported_container(path: str, data: bytes) -> str | None:
    suffix = Path(path).suffix.lower()
    if len(data) >= 12 and data[:4] == b"RIFF":
        return "RIFF"
    if len(data) >= 8 and data[4:8] == b"ftyp":
        return "ISO BMFF"
    if data.startswith(b"%PDF-"):
        return "PDF"
    if data.startswith((b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+")):
        return "TIFF"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "ZIP"
    if data.startswith((b"OTTO", b"\x00\x01\x00\x00", b"true", b"typ1", b"ttcf", b"wOFF", b"wOF2")):
        return "font"
    if suffix in DECLARED_BINARY_SUFFIXES:
        return f"declared {suffix}"
    return None


def _looks_text_path(path: str) -> bool:
    parsed = Path(path)
    return parsed.suffix.lower() in TEXT_SUFFIXES or parsed.name in TEXT_BASENAMES


def _looks_prose_path(path: str) -> bool:
    return Path(path).suffix.lower() in PROSE_SUFFIXES


def _looks_html_path(path: str, data: bytes) -> bool:
    prefix = data[:4096]
    if prefix.startswith(b"\xEF\xBB\xBF"):
        prefix = prefix[3:]
    prefix = prefix.lstrip(b" \t\r\n").lower()
    return Path(path).suffix.lower() in HTML_SUFFIXES or prefix.startswith(
        (b"<!doctype html", b"<html")
    )


def _has_wide_unicode_bom(data: bytes) -> bool:
    return data.startswith((b"\x00\x00\xFE\xFF", b"\xFF\xFE\x00\x00", b"\xFE\xFF", b"\xFF\xFE"))


def _might_be_xml(data: bytes) -> bool:
    prefix = data[:4096]
    if prefix.startswith(b"\xEF\xBB\xBF"):
        prefix = prefix[3:]
    return prefix.lstrip(b" \t\r\n").startswith(b"<")


def _finish_findings(path: str, findings: list[Finding]) -> tuple[Finding, ...]:
    if len(findings) <= MAX_FINDINGS:
        return tuple(findings)
    limited = findings[: MAX_FINDINGS - 1]
    limited.append(
        _finding(
            path,
            INCONCLUSIVE,
            "SCAN",
            0,
            "content.scan.finding_limit",
            "additional findings were omitted after the reporting limit",
        )
    )
    return tuple(limited)


def scan_blob(
    path: str,
    data: bytes,
    *,
    text_required: bool = False,
) -> tuple[Finding, ...]:
    """Scan one named Git blob without reading any other state."""

    if len(data) > MAX_BLOB_BYTES:
        return (
            _finding(
                path,
                INCONCLUSIVE,
                "SCAN",
                0,
                "content.scan.blob.limit",
                f"blob exceeds the {MAX_BLOB_BYTES}-byte scan limit",
            ),
        )
    if not text_required and _is_lfs_pointer(data):
        return (
            _finding(
                path,
                INCONCLUSIVE,
                "LFS_POINTER",
                0,
                "content.scan.lfs.pointer",
                "Git blob is an LFS pointer; referenced content was not scanned",
            ),
        )
    findings: list[Finding] = []
    state = _STORE_OTHER if text_required else _probe_c2pa_store(data)
    if (
        state in {_STORE_C2PA, _STORE_MALFORMED}
        or (not text_required and path.lower().endswith(".c2pa"))
    ):
        status = PRESENT if state == _STORE_C2PA else MALFORMED
        code = (
            "content.c2pa.sidecar.present"
            if status == PRESENT
            else "content.c2pa.sidecar.malformed"
        )
        detail = (
            "raw C2PA JUMBF store is present"
            if status == PRESENT
            else "declared C2PA sidecar is not a well-formed manifest store"
        )
        return (_finding(path, status, "C2PA_SIDECAR", 0, code, detail),)
    if not text_required and data.startswith(PNG_SIGNATURE):
        findings.extend(_scan_png(path, data))
        return _finish_findings(path, findings)
    if not text_required and data.startswith(b"\xFF\xD8"):
        findings.extend(_scan_jpeg(path, data))
        return _finish_findings(path, findings)
    if not text_required:
        container = _unsupported_container(path, data)
        if container is not None:
            return (
                _finding(
                    path,
                    INCONCLUSIVE,
                    "CONTAINER",
                    0,
                    "content.scan.container.unsupported",
                    f"recognized {container} container is outside the scanner profile",
                ),
            )
    svg_suffix = path.lower().endswith(".svg")
    if not text_required and (svg_suffix or _might_be_xml(data)):
        findings.extend(_scan_svg(path, data, required=svg_suffix))
    if _has_wide_unicode_bom(data):
        findings.append(
            _finding(
                path,
                INCONCLUSIVE,
                "UNICODE",
                0,
                "content.scan.unicode.encoding",
                "wide-character text encoding is outside the scanner profile",
            )
        )
        return _finish_findings(path, findings)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        if text_required or _looks_text_path(path):
            findings.append(
                _finding(
                    path,
                    INCONCLUSIVE,
                    "UNICODE",
                    exc.start,
                    "content.scan.unicode.encoding",
                    "declared text path is not valid UTF-8",
                )
            )
        return _finish_findings(path, findings)
    if not text_required and _looks_html_path(path, data):
        findings.extend(_scan_html(path, text))
    findings.extend(_scan_structured(path, data))
    wrapper_findings, protected = _scan_text_wrappers(path, text)
    findings.extend(wrapper_findings)
    findings.extend(
        _scan_hidden_unicode(
            path,
            text,
            protected,
            allow_prose_sequences=(not text_required and _looks_prose_path(path)),
        )
    )
    return _finish_findings(path, findings)


def _scan_blob_safe(path: str, data: bytes, *, text_required: bool = False) -> tuple[Finding, ...]:
    try:
        return scan_blob(path, data, text_required=text_required)
    except Exception as exc:
        return (
            _finding(
                path,
                INCONCLUSIVE,
                "SCAN",
                0,
                "content.scan.internal",
                f"scanner could not complete: {type(exc).__name__}",
            ),
        )


def _scan_stdin(name: str, stream: object) -> tuple[Finding, ...]:
    read = getattr(stream, "read")
    data = read(MAX_BLOB_BYTES + 1)
    if len(data) > MAX_BLOB_BYTES:
        return (
            _finding(
                name,
                INCONCLUSIVE,
                "SCAN",
                0,
                "content.scan.stdin.limit",
                f"standard input exceeds the {MAX_BLOB_BYTES}-byte scan limit",
            ),
        )
    return _scan_blob_safe(name, data, text_required=True)


def _run_git(root: Path, arguments: list[str]) -> bytes:
    environment = dict(os.environ)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            result = subprocess.run(
                ["git", "--no-replace-objects", *arguments],
                cwd=root,
                stdout=output,
                stderr=errors,
                env=environment,
                check=False,
                timeout=GIT_TIMEOUT_SECONDS,
            )
            if output.tell() > MAX_GIT_OUTPUT_BYTES:
                raise _GitError("git output exceeds the aggregate size limit")
            output.seek(0)
            stdout = output.read(MAX_GIT_OUTPUT_BYTES + 1)
            errors.seek(0)
            stderr = errors.read(MAX_GIT_OUTPUT_BYTES + 1)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _GitError(f"git command failed to run: {exc}") from exc
    if result.returncode != 0:
        detail = stderr.decode("utf-8", "replace").strip()
        raise _GitError(detail or f"git exited {result.returncode}")
    return stdout


def _repository_root() -> Path:
    environment = dict(os.environ)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _GitError(f"repository lookup failed: {exc}") from exc
    if result.returncode != 0:
        raise _GitError("current directory is not inside a Git repository")
    return Path(os.fsdecode(result.stdout.rstrip(b"\r\n")))


def _decoded_path(raw_path: bytes) -> str:
    """Decode a Git pathname identically on every platform.

    `os.fsdecode` is not portable here: POSIX decodes with surrogateescape, so
    undecodable bytes survive as surrogates that `_scan_path` reports as
    `content.scan.path.encoding`, but Windows raises instead and the exception
    escaped as an exit-1 crash indistinguishable from a rejection. Decoding
    explicitly keeps one behavior everywhere and preserves that finding.
    """
    return raw_path.decode("utf-8", "surrogateescape")


def _index_entries(root: Path, paths: list[str]) -> list[_BlobEntry]:
    output = _run_git(root, ["ls-files", "--stage", "-z", "--", *paths])
    entries: list[_BlobEntry] = []
    unresolved: set[str] = set()
    for record in output.split(b"\x00"):
        if not record:
            continue
        if len(entries) >= MAX_GIT_ENTRIES:
            raise _GitError("Git index exceeds the entry-count limit")
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, oid, stage = metadata.decode("ascii").split(" ")
        except (ValueError, UnicodeDecodeError) as exc:
            raise _GitError("git returned a malformed index record") from exc
        path = _decoded_path(raw_path)
        if stage != "0":
            if path not in unresolved:
                entries.append(_BlobEntry(path, None, "index entry is unmerged"))
                unresolved.add(path)
            continue
        if mode == "160000":
            entries.append(_BlobEntry(path, None, "index entry is a gitlink"))
        else:
            entries.append(_BlobEntry(path, oid))
    return entries


def _tree_entries(root: Path, revision: str, paths: list[str]) -> list[_BlobEntry]:
    commit = _run_git(
        root,
        ["rev-parse", "--verify", "--end-of-options", revision + "^{commit}"],
    ).decode("ascii").strip()
    output = _run_git(root, ["ls-tree", "-r", "-z", "--full-tree", commit, "--", *paths])
    entries: list[_BlobEntry] = []
    for record in output.split(b"\x00"):
        if not record:
            continue
        if len(entries) >= MAX_GIT_ENTRIES:
            raise _GitError("Git tree exceeds the entry-count limit")
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split(" ")
        except (ValueError, UnicodeDecodeError) as exc:
            raise _GitError("git returned a malformed tree record") from exc
        path = _decoded_path(raw_path)
        if kind != "blob" or mode == "160000":
            entries.append(_BlobEntry(path, None, "tree entry is not a Git blob"))
        else:
            entries.append(_BlobEntry(path, oid))
    return entries


def _verify_object_id(oid: str, kind: str, data: bytes) -> None:
    algorithms = {40: hashlib.sha1, 64: hashlib.sha256}
    algorithm = algorithms.get(len(oid))
    if algorithm is None or any(char not in "0123456789abcdef" for char in oid):
        raise _GitError(f"object has an unsupported identifier {oid!r}")
    header = f"{kind} {len(data)}\0".encode("ascii")
    actual = algorithm(header + data).hexdigest()
    if actual != oid:
        raise _GitError(f"{kind} bytes do not match requested object {oid}")


def _read_object(root: Path, oid: str, kind: str) -> bytes:
    raw_size = _run_git(root, ["cat-file", "-s", oid])
    try:
        size = int(raw_size)
    except ValueError as exc:
        raise _GitError(f"object {oid} has a malformed size") from exc
    if size > MAX_BLOB_BYTES:
        raise _GitError(f"{kind} exceeds the {MAX_BLOB_BYTES}-byte scan limit")
    data = _run_git(root, ["cat-file", kind, oid])
    if len(data) != size:
        raise _GitError(f"{kind} {oid} changed size while it was read")
    _verify_object_id(oid, kind, data)
    return data


def _read_blob(root: Path, oid: str) -> bytes:
    return _read_object(root, oid, "blob")


def _read_commit(root: Path, revision: str) -> tuple[str, bytes]:
    try:
        oid = _run_git(
            root,
            ["rev-parse", "--verify", "--end-of-options", revision + "^{commit}"],
        ).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise _GitError("git returned a non-ASCII commit identifier") from exc
    return oid, _read_object(root, oid, "commit")


def _display_path(path: str) -> str:
    return ascii(path)


def _display_detail(detail: str) -> str:
    escaped = detail.replace("\\", "\\\\")
    return escaped.replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")


def _report(finding: Finding) -> None:
    print(
        f"{finding.status}\t{finding.carrier}\t{_display_path(finding.path)}:"
        f"{finding.offset}\t{finding.code}\t{_display_detail(finding.detail)}",
        file=sys.stderr,
    )


def _result_code(findings: list[Finding]) -> int:
    if any(item.status == INCONCLUSIVE for item in findings):
        return 2
    if any(item.status in {PRESENT, MALFORMED, SUSPICIOUS} for item in findings):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="scan exact Git objects for known content-mark carriers"
    )
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--index", action="store_true", help="scan blobs staged in the index")
    selector.add_argument("--tree", metavar="COMMIT", help="scan blobs in an exact commit tree")
    selector.add_argument(
        "--commit",
        metavar="COMMIT",
        help="scan the bounded raw commit object, including author and committer metadata",
    )
    selector.add_argument(
        "--stdin",
        metavar="NAME",
        dest="stdin_name",
        help="scan bounded raw metadata bytes from standard input",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="optional Git pathspecs evaluated from the repository root",
    )
    arguments = parser.parse_args(argv)

    if arguments.stdin_name is not None:
        if not arguments.stdin_name or arguments.paths:
            finding = _finding(
                arguments.stdin_name or "<stdin>",
                INCONCLUSIVE,
                "SCAN",
                0,
                "content.scan.stdin.selector",
                "standard-input scanning requires a non-empty name and no Git pathspecs",
            )
            _report(finding)
            return 2
        findings = list(_scan_stdin(arguments.stdin_name, sys.stdin.buffer))
        for finding in sorted(findings, key=lambda item: (item.offset, item.code)):
            _report(finding)
        result = _result_code(findings)
        if result == 0:
            print(f"content marks: clean ({_display_path(arguments.stdin_name)} scanned)")
        return result

    if arguments.commit is not None:
        if arguments.paths:
            finding = _finding(
                "<commit>",
                INCONCLUSIVE,
                "SCAN",
                0,
                "content.scan.commit.selector",
                "commit-object scanning does not accept Git pathspecs",
            )
            _report(finding)
            return 2
        try:
            root = _repository_root()
            oid, data = _read_commit(root, arguments.commit)
        except _GitError as exc:
            _report(
                _finding(
                    "<commit>",
                    INCONCLUSIVE,
                    "SCAN",
                    0,
                    "content.scan.git.commit",
                    str(exc),
                )
            )
            return 2
        label = f"<commit:{oid}>"
        findings = list(_scan_blob_safe(label, data, text_required=True))
        for finding in sorted(findings, key=lambda item: (item.offset, item.code)):
            _report(finding)
        result = _result_code(findings)
        if result == 0:
            print(f"content marks: clean ({_display_path(label)} scanned)")
        return result

    try:
        root = _repository_root()
        if arguments.index:
            entries = _index_entries(root, arguments.paths)
        else:
            entries = _tree_entries(root, arguments.tree, arguments.paths)
    except _GitError as exc:
        _report(
            _finding(
                "<repository>",
                INCONCLUSIVE,
                "SCAN",
                0,
                "content.scan.git.selector",
                str(exc),
            )
        )
        return 2

    findings: list[Finding] = []
    if arguments.paths and not entries:
        findings.append(
            _finding(
                "<pathspec>",
                INCONCLUSIVE,
                "SCAN",
                0,
                "content.scan.git.no_matches",
                "the requested pathspecs matched no Git entries",
            )
        )
    scanned = 0
    scanned_bytes = 0
    for entry in sorted(entries, key=lambda item: item.path):
        findings.extend(_scan_path(entry.path))
        if len(findings) >= MAX_TOTAL_FINDINGS:
            findings = findings[: MAX_TOTAL_FINDINGS - 1]
            findings.append(
                _finding(
                    "<repository>",
                    INCONCLUSIVE,
                    "SCAN",
                    0,
                    "content.scan.total_finding_limit",
                    "repository finding-count limit was reached",
                )
            )
            break
        if entry.issue is not None or entry.oid is None:
            findings.append(
                _finding(
                    entry.path,
                    INCONCLUSIVE,
                    "SCAN",
                    0,
                    "content.scan.git.entry",
                    entry.issue or "Git entry has no blob object",
                )
            )
            continue
        try:
            blob = _read_blob(root, entry.oid)
        except _GitError as exc:
            findings.append(
                _finding(
                    entry.path,
                    INCONCLUSIVE,
                    "SCAN",
                    0,
                    "content.scan.git.blob",
                    str(exc),
                )
            )
            continue
        if scanned_bytes + len(blob) > MAX_TOTAL_BLOB_BYTES:
            findings.append(
                _finding(
                    entry.path,
                    INCONCLUSIVE,
                    "SCAN",
                    0,
                    "content.scan.git.byte_limit",
                    "repository aggregate blob-byte limit was reached",
                )
            )
            break
        scanned += 1
        scanned_bytes += len(blob)
        findings.extend(_scan_blob_safe(entry.path, blob))

    for finding in sorted(findings, key=lambda item: (item.path, item.offset, item.code)):
        _report(finding)
    result = _result_code(findings)
    if result == 0:
        print(f"content marks: clean ({scanned} Git blobs scanned)")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
