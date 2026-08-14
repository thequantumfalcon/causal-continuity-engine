"""Focused tests for the exact-Git-blob content-mark scanner."""

import base64
import importlib.util
import io
import os
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / ".github" / "scripts" / "check_content_marks.py"
DIST_SCRIPT = ROOT / ".github" / "scripts" / "verify_distributions.py"


def _load_scanner():
    name = "cce_content_marks_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_distribution_verifier():
    name = "cce_content_marks_distribution_test"
    spec = importlib.util.spec_from_file_location(name, DIST_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def scanner():
    return _load_scanner()


@pytest.fixture(scope="module")
def distribution_verifier():
    return _load_distribution_verifier()


def _box(kind, payload):
    return (8 + len(payload)).to_bytes(4, "big") + kind + payload


def _store(uuid=None, *, toggles=3, label=b"c2pa"):
    if uuid is None:
        uuid = bytes.fromhex("6332706100110010800000aa00389b71")
    description = _box(b"jumd", uuid + bytes([toggles]) + label + b"\x00")
    return _box(b"jumb", description)


def _extended_store(*, toggles=3):
    description = _box(
        b"jumd",
        bytes.fromhex("6332706100110010800000aa00389b71")
        + bytes([toggles])
        + b"c2pa\x00",
    )
    return b"\x00\x00\x00\x01jumb" + (16 + len(description)).to_bytes(8, "big") + description


def _selector(value):
    if value < 16:
        return chr(0xFE00 + value)
    return chr(0xE0100 + value - 16)


def _text_wrapper(store=None, *, version=1, declared=None):
    store = _store() if store is None else store
    declared = len(store) if declared is None else declared
    wrapper = b"C2PATXT\x00" + bytes([version]) + declared.to_bytes(4, "big") + store
    return "\ufeff" + "".join(_selector(value) for value in wrapper)


def _delimiters():
    begin = b"-----BEGIN " + b"C2PA MANIFEST-----"
    end = b"-----END " + b"C2PA MANIFEST-----"
    return begin, end


def _structured(reference):
    begin, end = _delimiters()
    return b"# " + begin + b" " + reference + b" " + end + b"\n"


def _chunk(kind, payload, *, valid_crc=True):
    crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
    if not valid_crc:
        crc ^= 1
    return len(payload).to_bytes(4, "big") + kind + payload + crc.to_bytes(4, "big")


def _png(*extra_chunks):
    ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
    image = _chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\x00"))
    return b"\x89PNG\r\n\x1a\n" + ihdr + b"".join(extra_chunks) + image + _chunk(b"IEND", b"")


def _jpeg_segment(marker, payload):
    return b"\xFF" + bytes([marker]) + (len(payload) + 2).to_bytes(2, "big") + payload


def _jpeg_with_store(
    *,
    sequence=2,
    separator=b"",
    store=None,
    common_identifier=b"JP",
    first_sequence=1,
):
    store = _store() if store is None else store
    instance = b"\x02\x11"
    first = common_identifier + instance + first_sequence.to_bytes(4, "big") + store[:20]
    second = (
        common_identifier
        + instance
        + sequence.to_bytes(4, "big")
        + store[:8]
        + store[20:]
    )
    return (
        b"\xFF\xD8"
        + _jpeg_segment(0xEB, first)
        + separator
        + _jpeg_segment(0xEB, second)
        + b"\xFF\xD9"
    )


def _statuses(findings):
    return {finding.status for finding in findings}


def _codes(findings):
    return {finding.code for finding in findings}


def test_text_wrapper_is_exact_and_reports_raw_byte_offset(scanner):
    blob = ("é" + _text_wrapper()).encode()
    findings = scanner.scan_blob("note.txt", blob)
    assert _statuses(findings) == {scanner.PRESENT}
    assert findings[0].carrier == "TEXT_VS"
    assert findings[0].offset == 2


@pytest.mark.parametrize(
    "wrapper",
    [
        lambda: _text_wrapper(version=2),
        lambda: _text_wrapper(declared=len(_store()) + 1),
        lambda: _text_wrapper(store=_store(toggles=0)),
    ],
)
def test_text_wrapper_corruption_is_not_treated_as_absence(scanner, wrapper):
    findings = scanner.scan_blob("note.txt", ("visible" + wrapper()).encode())
    assert scanner.MALFORMED in _statuses(findings)
    assert "content.c2pa.text.malformed" in _codes(findings)


def test_text_wrapper_cardinality_is_pinned(scanner):
    wrapper = _text_wrapper()
    findings = scanner.scan_blob("note.txt", ("a" + wrapper + "b" + wrapper).encode())
    assert "content.c2pa.text.multiple" in _codes(findings)


def test_hidden_unicode_policy_distinguishes_common_presentation(scanner):
    family = "\U0001f469\u200d\U0001f469\u200d\U0001f467"
    heart = "\u2764\ufe0f"
    prose = f"family: {family}\nheart: {heart}\nPersian: می\u200cخواهم\nHindi: क्\u200dष\n"
    assert scanner.scan_blob("note.md", prose.encode()) == ()

    hidden = scanner.scan_blob("note.txt", "left\u200bright".encode())
    assert _statuses(hidden) == {scanner.SUSPICIOUS}
    assert hidden[0].code == "content.unicode.hidden"

    supplementary = scanner.scan_blob("note.txt", ("x" + chr(0xE0100)).encode())
    assert _statuses(supplementary) == {scanner.SUSPICIOUS}

    covert = scanner.scan_blob("note.txt", "a\ufe0fb\ufe0ec\ufe0f".encode())
    assert _statuses(covert) == {scanner.SUSPICIOUS}

    assert scanner.scan_blob("note.txt", "\ufeffordinary prose\n".encode()) == ()

    for name, value in (
        ("source.py", f"family = '{family}'\n"),
        ("config.toml", f"label = '{heart}'\n"),
        ("source.py", "\ufeffordinary source\n"),
        ("note.md", "\ufeff\ufeffdoubled prose BOM\n"),
        ("note.md", "left\u2066right\n"),
    ):
        assert scanner.SUSPICIOUS in _statuses(scanner.scan_blob(name, value.encode()))

    metadata = scanner.scan_blob(
        "<commit-metadata>", f"family: {family}\n".encode(), text_required=True
    )
    assert scanner.SUSPICIOUS in _statuses(metadata)


def test_structured_url_and_data_carriers_are_exact(scanner):
    url_findings = scanner.scan_blob(
        "config.toml", _structured(b"https://example.test/store.c2pa")
    )
    assert _statuses(url_findings) == {scanner.PRESENT}

    reference = (
        b"data:application/"
        + b"c2pa;base64,"
        + base64.b64encode(_store())
    )
    data_findings = scanner.scan_blob("source.py", _structured(reference))
    assert _statuses(data_findings) == {scanner.PRESENT}


def test_structured_delimiter_failures_are_malformed(scanner):
    begin, _end = _delimiters()
    findings = scanner.scan_blob("source.py", b"# " + begin + b" missing end\n")
    assert _statuses(findings) == {scanner.MALFORMED}
    assert "content.c2pa.structured.cardinality" in _codes(findings)


def test_structured_malformed_url_does_not_escape(scanner):
    findings = scanner.scan_blob("source.py", _structured(b"http://["))
    assert _statuses(findings) == {scanner.MALFORMED}


def test_png_cabx_is_structural_and_checksum_bound(scanner):
    present = scanner.scan_blob("image.png", _png(_chunk(b"caBX", _store())))
    assert _statuses(present) == {scanner.PRESENT}
    assert present[0].carrier == "PNG_CABX"

    malformed = scanner.scan_blob(
        "image.png", _png(_chunk(b"caBX", _store(), valid_crc=False))
    )
    assert scanner.MALFORMED in _statuses(malformed)
    assert "content.c2pa.png.malformed" in _codes(malformed)


def test_png_raw_substrings_in_other_chunks_are_clean(scanner):
    blob = _png(_chunk(b"tEXt", b"caBX\x00" + _store()))
    assert scanner.scan_blob("image.png", blob) == ()


def _xmp(provenance=None):
    attribute = "" if provenance is None else f' dcterms:provenance="{provenance}"'
    return (
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
        'xmlns:dcterms="http://purl.org/dc/terms/">'
        f"<rdf:Description{attribute}/></rdf:RDF></x:xmpmeta>"
    ).encode()


def _png_xmp(packet):
    return _chunk(b"iTXt", b"XML:com.adobe.xmp\x00\x00\x00\x00\x00" + packet)


def test_xmp_requires_exact_namespaced_provenance(scanner):
    assert scanner.scan_blob("image.png", _png(_png_xmp(_xmp()))) == ()
    present = scanner.scan_blob(
        "image.png", _png(_png_xmp(_xmp("asset.c2pa")))
    )
    assert _statuses(present) == {scanner.PRESENT}
    assert "content.c2pa.xmp.present" in _codes(present)

    literal = _xmp().replace(b"rdf:Description", b"rdf:Description note='dcterms:provenance'")
    assert scanner.scan_blob("image.png", _png(_png_xmp(literal))) == ()


def test_jpeg_xt_fragments_reconstruct_one_store(scanner):
    findings = scanner.scan_blob("image.jpg", _jpeg_with_store())
    assert _statuses(findings) == {scanner.PRESENT}
    assert findings[0].carrier == "JPEG_APP11"


@pytest.mark.parametrize(
    "blob",
    [
        _jpeg_with_store(sequence=3),
        _jpeg_with_store(separator=_jpeg_segment(0xFE, b"gap")),
    ],
)
def test_jpeg_xt_sequence_and_physical_contiguity_are_binding(scanner, blob):
    findings = scanner.scan_blob("image.jpg", blob)
    assert scanner.MALFORMED in _statuses(findings)
    assert "content.c2pa.jpeg.malformed" in _codes(findings)


def test_jpeg_xt_identity_and_first_sequence_corruption_are_malformed(scanner):
    wrong_identifier = scanner.scan_blob(
        "image.jpg", _jpeg_with_store(common_identifier=b"XX")
    )
    assert "content.c2pa.jpeg.identifier" in _codes(wrong_identifier)

    one_packet = b"XX" + b"\x02\x11" + (2).to_bytes(4, "big") + _store()
    wrong_sequence = b"\xFF\xD8" + _jpeg_segment(0xEB, one_packet) + b"\xFF\xD9"
    findings = scanner.scan_blob("image.jpg", wrong_sequence)
    assert "content.c2pa.jpeg.sequence" in _codes(findings)


def test_unbounded_jpeg_xt_box_is_inconclusive(scanner):
    store = b"\x00\x00\x00\x00" + _store()[4:]
    payload = b"JP" + b"\x02\x11" + (1).to_bytes(4, "big") + store
    blob = b"\xFF\xD8" + _jpeg_segment(0xEB, payload) + b"\xFF\xD9"
    findings = scanner.scan_blob("image.jpg", blob)
    assert _statuses(findings) == {scanner.INCONCLUSIVE}
    assert "content.scan.jpeg.extended" in _codes(findings)


def test_extended_length_jpeg_xt_uses_c2pa_identity_before_classification(scanner):
    def jpeg(common_identifier, sequence, store):
        payload = common_identifier + b"\x02\x11" + sequence.to_bytes(4, "big") + store
        return b"\xFF\xD8" + _jpeg_segment(0xEB, payload) + b"\xFF\xD9"

    present = scanner.scan_blob("image.jpg", jpeg(b"JP", 1, _extended_store()))
    assert _statuses(present) == {scanner.PRESENT}

    wrong_identifier = scanner.scan_blob(
        "image.jpg", jpeg(b"XX", 1, _extended_store())
    )
    assert "content.c2pa.jpeg.identifier" in _codes(wrong_identifier)

    wrong_sequence = scanner.scan_blob(
        "image.jpg", jpeg(b"JP", 2, _extended_store())
    )
    assert "content.c2pa.jpeg.sequence" in _codes(wrong_sequence)

    other = _extended_store().replace(
        bytes.fromhex("6332706100110010800000aa00389b71"), b"not-c2pa-format!"
    )
    assert scanner.scan_blob("image.jpg", jpeg(b"JP", 1, other)) == ()


def test_generic_jpeg_app11_and_entropy_substrings_are_clean(scanner):
    other = _store(uuid=b"not-c2pa-format!"[:16])
    generic = scanner.scan_blob("image.jpg", _jpeg_with_store(store=other))
    assert generic == ()

    scan_header = _jpeg_segment(0xDA, b"\x00")
    entropy = b"pixel\xFF\x00\xEBc2pa-data"
    blob = b"\xFF\xD8" + scan_header + entropy + b"\xFF\xD9"
    assert scanner.scan_blob("image.jpg", blob) == ()


def test_jpeg_xmp_and_trailing_bytes_are_fail_closed(scanner):
    header = b"http://ns.adobe.com/xap/1.0/\x00"
    ordinary = b"\xFF\xD8" + _jpeg_segment(0xE1, header + _xmp()) + b"\xFF\xD9"
    assert scanner.scan_blob("image.jpg", ordinary) == ()

    marked = (
        b"\xFF\xD8"
        + _jpeg_segment(0xE1, header + _xmp("https://example.test/a.c2pa"))
        + b"\xFF\xD9"
    )
    assert _statuses(scanner.scan_blob("image.jpg", marked)) == {scanner.PRESENT}

    trailing = b"\xFF\xD8\xFF\xD9" + _jpeg_with_store()
    findings = scanner.scan_blob("image.jpg", trailing)
    assert _statuses(findings) == {scanner.INCONCLUSIVE}
    assert "content.scan.jpeg.malformed" in _codes(findings)


def test_extended_jpeg_xmp_is_reconstructed_before_classification(scanner):
    header = b"http://ns.adobe.com/xmp/extension/\x00"
    guid = b"0123456789ABCDEF0123456789ABCDEF"
    for packet, expected in [(_xmp(), set()), (_xmp("asset.c2pa"), {scanner.PRESENT})]:
        split = len(packet) // 2
        chunks = []
        for offset, part in [(0, packet[:split]), (split, packet[split:])]:
            payload = (
                header
                + guid
                + len(packet).to_bytes(4, "big")
                + offset.to_bytes(4, "big")
                + part
            )
            chunks.append(_jpeg_segment(0xE1, payload))
        blob = b"\xFF\xD8" + b"".join(reversed(chunks)) + b"\xFF\xD9"
        assert _statuses(scanner.scan_blob("image.jpg", blob)) == expected


def test_svg_manifest_is_namespace_aware_and_prefix_independent(scanner):
    payload = base64.b64encode(_store()).decode()
    blob = (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:q="http://c2pa.org/manifest">'
        f"<metadata><q:manifest>{payload}</q:manifest></metadata></svg>"
    ).encode()
    findings = scanner.scan_blob("image.svg", blob)
    assert _statuses(findings) == {scanner.PRESENT}
    assert findings[0].carrier == "SVG_MANIFEST"

    nested = (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:q="http://c2pa.org/manifest"><g><metadata>'
        f"<q:manifest>{payload}</q:manifest></metadata></g></svg>"
    ).encode()
    assert _statuses(scanner.scan_blob("nested.svg", nested)) == {scanner.PRESENT}
    assert _statuses(scanner.scan_blob("renamed.dat", blob)) == {scanner.PRESENT}


def test_svg_literal_and_wrong_namespace_are_clean(scanner):
    blob = (
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:q="urn:wrong">'
        "<!-- <q:manifest>literal</q:manifest> -->"
        "<metadata><q:manifest>literal</q:manifest></metadata></svg>"
    ).encode()
    assert scanner.scan_blob("image.svg", blob) == ()

    embedded = (
        '<html xmlns="http://www.w3.org/1999/xhtml"><body>'
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:q="http://c2pa.org/manifest"><metadata>'
        f"<q:manifest>{base64.b64encode(_store()).decode()}</q:manifest>"
        "</metadata></svg></body></html>"
    ).encode()
    assert _statuses(scanner.scan_blob("page.xhtml", embedded)) == {scanner.PRESENT}


def test_html_manifest_associations_are_structural_and_bounded(scanner, monkeypatch):
    payload = base64.b64encode(_store()).decode()
    inline = (
        "<!doctype html><html><head>"
        f'<script type="application/c2pa">{payload}</script>'
        "</head><body></body></html>"
    ).encode()
    assert _statuses(scanner.scan_blob("page.html", inline)) == {scanner.PRESENT}

    external = (
        '<html><head><link rel="alternate c2pa-manifest" '
        'type="application/c2pa" href="asset.c2pa"></head></html>'
    ).encode()
    assert _statuses(scanner.scan_blob("page.html", external)) == {scanner.PRESENT}

    lookalike = b'<html><body data-type="application/c2pa">literal</body></html>'
    assert scanner.scan_blob("page.html", lookalike) == ()

    malformed = b'<html><head><script type="application/c2pa">bad!</script></head></html>'
    assert scanner.MALFORMED in _statuses(scanner.scan_blob("page.html", malformed))

    monkeypatch.setattr(scanner, "MAX_HTML_ELEMENTS", 1)
    limited = scanner.scan_blob("page.html", b"<html><head></head></html>")
    assert scanner.INCONCLUSIVE in _statuses(limited)


def test_svg_bad_payload_and_declaration_fail_closed(scanner):
    malformed = (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:q="http://c2pa.org/manifest">'
        "<metadata><q:manifest>not-base64!</q:manifest></metadata></svg>"
    ).encode()
    assert scanner.MALFORMED in _statuses(scanner.scan_blob("image.svg", malformed))

    declaration = b'<!DOCTYPE svg [<!ENTITY x "value">]><svg xmlns="http://www.w3.org/2000/svg"/>'
    assert scanner.INCONCLUSIVE in _statuses(
        scanner.scan_blob("image.svg", declaration)
    )


def test_svg_xmp_external_locator_is_namespace_aware(scanner):
    blob = (
        '<svg xmlns="http://www.w3.org/2000/svg"><metadata>'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
        'xmlns:dcterms="http://purl.org/dc/terms/">'
        '<rdf:Description dcterms:provenance="asset.c2pa"/>'
        "</rdf:RDF></metadata></svg>"
    ).encode()
    findings = scanner.scan_blob("renamed.xml", blob)
    assert _statuses(findings) == {scanner.PRESENT}
    assert "content.c2pa.xmp.present" in _codes(findings)


def test_malformed_binary_hosts_are_inconclusive(scanner):
    truncated_png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR"
    assert scanner.INCONCLUSIVE in _statuses(
        scanner.scan_blob("image.png", truncated_png)
    )

    truncated_jpeg = b"\xFF\xD8\xFF\xEB\x00\x20JP"
    assert scanner.INCONCLUSIVE in _statuses(
        scanner.scan_blob("image.jpg", truncated_jpeg)
    )

    renamed_wide = scanner.scan_blob("renamed.dat", b"\xFF\xFEw\x00i\x00d\x00e\x00")
    assert _statuses(renamed_wide) == {scanner.INCONCLUSIVE}
    assert "content.scan.unicode.encoding" in _codes(renamed_wide)


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("audio.wav", b"RIFF\x04\x00\x00\x00WAVE"),
        ("video.mp4", b"\x00\x00\x00\x18ftypisom"),
        ("document.pdf", b"%PDF-1.7\n"),
        ("image.tiff", b"II*\x00rest"),
        ("image.gif", b"GIF89a"),
        ("archive.zip", b"PK\x03\x04rest"),
        ("font.woff", b"wOFFrest"),
        ("declared.avif", b"not-a-container"),
    ],
)
def test_recognized_unimplemented_containers_fail_closed(scanner, name, payload):
    findings = scanner.scan_blob(name, payload)
    assert _statuses(findings) == {scanner.INCONCLUSIVE}
    assert _codes(findings) == {"content.scan.container.unsupported"}


def test_lfs_pointer_is_inconclusive(scanner):
    pointer = (
        b"version https://git-lfs.github.com/spec/v1\n"
        + b"oid sha256:"
        + b"0" * 64
        + b"\nsize 42\n"
    )
    findings = scanner.scan_blob("large.bin", pointer)
    assert _statuses(findings) == {scanner.INCONCLUSIVE}
    assert "content.scan.lfs.pointer" in _codes(findings)


def test_raw_c2pa_sidecar_is_structural(scanner):
    present = scanner.scan_blob("asset.c2pa", _store())
    assert _statuses(present) == {scanner.PRESENT}
    assert "content.c2pa.sidecar.present" in _codes(present)

    malformed = scanner.scan_blob("asset.c2pa", _store(toggles=0))
    assert _statuses(malformed) == {scanner.MALFORMED}
    assert "content.c2pa.sidecar.malformed" in _codes(malformed)

    renamed = scanner.scan_blob("asset.bin", _store())
    assert _statuses(renamed) == {scanner.PRESENT}

    renamed_malformed = scanner.scan_blob("asset.bin", _store(toggles=0))
    assert _statuses(renamed_malformed) == {scanner.MALFORMED}


def _git(cwd, *arguments):
    return subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _run_scanner(cwd, *arguments, input_data=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=cwd,
        input=input_data,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_cli_scans_index_and_tree_blobs_instead_of_worktree(tmp_path):
    _git(tmp_path, "init", "-q")
    marked = tmp_path / "marked.py"
    marked.write_bytes(_structured(b"https://example.test/store.c2pa"))
    _git(tmp_path, "add", "marked.py")

    marked.write_text("print('clean worktree')\n", encoding="utf-8")
    index_result = _run_scanner(tmp_path, "--index")
    assert index_result.returncode == 1
    assert b"content.c2pa.structured.present" in index_result.stderr

    _git(
        tmp_path,
        "-c",
        "user.name=Test User",
        "-c",
        "user.email=test@example.test",
        "commit",
        "-q",
        "-m",
        "test: add fixture",
    )
    marked.write_text("print('different worktree')\n", encoding="utf-8")
    tree_result = _run_scanner(tmp_path, "--tree", "HEAD")
    assert tree_result.returncode == 1
    assert b"content.c2pa.structured.present" in tree_result.stderr


def test_cli_ignores_replacement_refs_and_binds_blob_bytes(tmp_path):
    _git(tmp_path, "init", "-q")
    marked = tmp_path / "marked.py"
    marked.write_bytes(_structured(b"https://example.test/store.c2pa"))
    _git(tmp_path, "add", "marked.py")
    marked_oid = _git(tmp_path, "rev-parse", ":marked.py").stdout.strip().decode()
    clean_oid = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=tmp_path,
        input=b"print('clean')\n",
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip().decode()
    _git(tmp_path, "replace", marked_oid, clean_oid)

    result = _run_scanner(tmp_path, "--index")
    assert result.returncode == 1
    assert b"content.c2pa.structured.present" in result.stderr


def test_cli_scans_raw_committer_identity(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "clean.txt").write_text("clean\n", encoding="utf-8")
    _git(tmp_path, "add", "clean.txt")
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Clean Author",
            "GIT_AUTHOR_EMAIL": "author@example.test",
            "GIT_COMMITTER_NAME": "Hidden\u200bCommitter",
            "GIT_COMMITTER_EMAIL": "committer@example.test",
        }
    )
    subprocess.run(
        ["git", "commit", "-q", "-m", "clean message"],
        cwd=tmp_path,
        env=environment,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    result = _run_scanner(tmp_path, "--commit", "HEAD")
    assert result.returncode == 1
    assert b"content.unicode.hidden" in result.stderr


def test_cli_uses_exit_two_for_an_unresolvable_tree(tmp_path):
    _git(tmp_path, "init", "-q")
    result = _run_scanner(tmp_path, "--tree", "missing")
    assert result.returncode == 2
    assert b"INCONCLUSIVE" in result.stderr


def test_exit_status_keeps_suspicion_distinct_from_incomplete(scanner):
    suspicious = scanner.scan_blob("note.txt", "left\u200bright".encode())
    incomplete = scanner.scan_blob("note.txt", b"\xFF\xFEwide")
    assert scanner._result_code(list(suspicious)) == 1
    assert scanner._result_code(list(incomplete)) == 2
    assert scanner._result_code(list(suspicious + incomplete)) == 2
    assert scanner._result_code([]) == 0


def test_stdin_scans_bounded_raw_metadata_without_a_repository(tmp_path, scanner, monkeypatch):
    clean = _run_scanner(tmp_path, "--stdin", "commit-message", input_data=b"")
    assert clean.returncode == 0

    marked = _run_scanner(
        tmp_path,
        "--stdin",
        "pull-request-body",
        input_data=_structured(b"https://example.test/store.c2pa"),
    )
    assert marked.returncode == 1
    assert b"content.c2pa.structured.present" in marked.stderr

    invalid = _run_scanner(tmp_path, "--stdin", "identity", input_data=b"\xff")
    assert invalid.returncode == 2
    assert b"content.scan.unicode.encoding" in invalid.stderr

    monkeypatch.setattr(scanner, "MAX_BLOB_BYTES", 4)
    oversized = scanner._scan_stdin("metadata", io.BytesIO(b"12345"))
    assert _statuses(oversized) == {scanner.INCONCLUSIVE}
    assert "content.scan.stdin.limit" in _codes(oversized)


def test_stdin_rejects_git_pathspecs(tmp_path):
    result = _run_scanner(
        tmp_path,
        "--stdin",
        "message",
        "path.txt",
        input_data=b"clean",
    )
    assert result.returncode == 2
    assert b"content.scan.stdin.selector" in result.stderr


def test_unexpected_blob_parser_failure_is_inconclusive(scanner, monkeypatch):
    def fail(*_args, **_kwargs):
        raise RuntimeError("planted parser failure")

    monkeypatch.setattr(scanner, "scan_blob", fail)
    findings = scanner._scan_blob_safe("asset.bin", b"content")
    assert _statuses(findings) == {scanner.INCONCLUSIVE}
    assert "content.scan.internal" in _codes(findings)


def test_git_listing_and_entry_limits_fail_closed(tmp_path, scanner, monkeypatch):
    _git(tmp_path, "init", "-q")
    (tmp_path / "one.txt").write_text("one\n", encoding="utf-8")
    (tmp_path / "two.txt").write_text("two\n", encoding="utf-8")
    _git(tmp_path, "add", "one.txt", "two.txt")

    monkeypatch.setattr(scanner, "MAX_GIT_ENTRIES", 1)
    with pytest.raises(scanner._GitError, match="entry-count"):
        scanner._index_entries(tmp_path, [])

    monkeypatch.setattr(scanner, "MAX_GIT_OUTPUT_BYTES", 4)
    with pytest.raises(scanner._GitError, match="aggregate size"):
        scanner._run_git(tmp_path, ["rev-parse", "--git-dir"])


def test_repository_aggregate_blob_limit_is_inconclusive(scanner, monkeypatch):
    entries = [scanner._BlobEntry("one.txt", "one"), scanner._BlobEntry("two.txt", "two")]
    monkeypatch.setattr(scanner, "_repository_root", lambda: Path("."))
    monkeypatch.setattr(scanner, "_index_entries", lambda _root, _paths: entries)
    monkeypatch.setattr(scanner, "_read_blob", lambda _root, _oid: b"abc")
    monkeypatch.setattr(scanner, "MAX_TOTAL_BLOB_BYTES", 4)
    assert scanner.main(["--index"]) == 2


def test_cli_pathspec_is_exact_and_empty_match_is_inconclusive(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "clean.txt").write_text("clean\n", encoding="utf-8")
    (tmp_path / "marked.txt").write_bytes(
        _structured(b"https://example.test/store.c2pa")
    )
    _git(tmp_path, "add", "clean.txt", "marked.txt")

    clean = _run_scanner(tmp_path, "--index", "clean.txt")
    assert clean.returncode == 0
    assert b"1 Git blobs scanned" in clean.stdout

    empty = _run_scanner(tmp_path, "--index", "missing.txt")
    assert empty.returncode == 2
    assert b"content.scan.git.no_matches" in empty.stderr


def test_cli_hidden_and_undecodable_pathnames_fail_closed(tmp_path):
    _git(tmp_path, "init", "-q")
    hidden_name = "left\u200bright.txt"
    (tmp_path / hidden_name).write_text("clean\n", encoding="utf-8")
    _git(tmp_path, "add", hidden_name)
    hidden = _run_scanner(tmp_path, "--index")
    assert hidden.returncode == 1
    assert b"content.path.hidden_unicode" in hidden.stderr

    undecodable_root = tmp_path / "undecodable"
    undecodable_root.mkdir()
    _git(undecodable_root, "init", "-q")
    raw_name = b"bad-\xff.txt"
    oid = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=undecodable_root,
        input=b"clean\n",
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()
    subprocess.run(
        ["git", "update-index", "-z", "--index-info"],
        cwd=undecodable_root,
        input=b"100644 " + oid + b"\t" + raw_name + b"\x00",
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    undecodable = _run_scanner(undecodable_root, "--index")
    assert undecodable.returncode == 2
    assert b"content.scan.path.encoding" in undecodable.stderr


def test_cli_scans_symlink_payload_without_following_target(tmp_path):
    _git(tmp_path, "init", "-q")
    target = tmp_path / "target.py"
    target.write_bytes(_structured(b"https://example.test/store.c2pa"))
    oid = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=tmp_path,
        input=b"target.py",
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.decode().strip()
    _git(tmp_path, "update-index", "--add", "--cacheinfo", f"120000,{oid},link.py")

    result = _run_scanner(tmp_path, "--index", "link.py")
    assert result.returncode == 0
    assert b"1 Git blobs scanned" in result.stdout


def test_cli_unmerged_index_entry_is_inconclusive(tmp_path):
    _git(tmp_path, "init", "-q")
    oid = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=tmp_path,
        input=b"clean\n",
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.decode().strip()
    index_info = f"100644 {oid} 1\tconflict.txt\n100644 {oid} 2\tconflict.txt\n"
    subprocess.run(
        ["git", "update-index", "--index-info"],
        cwd=tmp_path,
        input=index_info.encode(),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    result = _run_scanner(tmp_path, "--index")
    assert result.returncode == 2
    assert b"index entry is unmerged" in result.stderr


def test_distribution_payload_gate_rejects_marks_and_incomplete_scans(
    distribution_verifier,
):
    distribution_verifier._scan_distribution_payloads(
        {"plain.txt": b"visible text\n"}, label="fixture"
    )

    marked = ("visible" + _text_wrapper()).encode("utf-8")
    with pytest.raises(SystemExit, match="contains prohibited content"):
        distribution_verifier._scan_distribution_payloads(
            {"marked.txt": marked}, label="fixture"
        )

    with pytest.raises(SystemExit, match="scan is incomplete"):
        distribution_verifier._scan_distribution_payloads(
            {"wide.dat": b"\xff\xfev\x00"}, label="fixture"
        )


def test_canonical_wheel_payload_is_scanned_before_acceptance(
    tmp_path, distribution_verifier
):
    epoch = 1_700_000_000
    wheel = tmp_path / "content-mark-fixture.whl"
    marked = ("visible" + _text_wrapper()).encode("utf-8")
    wheel.write_bytes(
        distribution_verifier._canonical_wheel_bytes({"marked.txt": marked}, epoch)
    )

    with pytest.raises(SystemExit, match="wheel contains prohibited content"):
        distribution_verifier._verify_wheel_envelope(wheel, expected_epoch=epoch)


def test_both_distribution_deciding_paths_call_the_same_payload_gate(
    distribution_verifier,
):
    wheel_names = set(distribution_verifier._verify_wheel_envelope.__code__.co_names)
    sdist_names = set(distribution_verifier._validated_sdist_payload.__code__.co_names)

    assert "_scan_distribution_payloads" in wheel_names
    assert "_scan_distribution_payloads" in sdist_names


def test_repository_deciding_paths_are_wired_without_false_hosted_authority():
    run_gates = (ROOT / ".github" / "scripts" / "run_gates.py").read_text()
    pre_commit = (ROOT / ".githooks" / "pre-commit").read_text()
    commit_msg = (ROOT / ".githooks" / "commit-msg").read_text()
    pre_commit_config = (ROOT / ".pre-commit-config.yaml").read_text()
    justfile = (ROOT / "justfile").read_text()
    push_workflow = (
        ROOT / ".github" / "workflows" / "content-integrity.yml"
    ).read_text()
    pr_workflow = (
        ROOT / ".github" / "workflows" / "content-integrity-pr.yml"
    ).read_text()
    ruleset = (ROOT / ".github" / "ruleset.json").read_text()

    assert '"content integrity"' in run_gates
    assert '"--tree",\n            "HEAD"' in run_gates
    assert '"commit metadata integrity"' in run_gates
    assert '"--commit",\n            "HEAD"' in run_gates
    assert "check_content_marks.py --index" in pre_commit
    assert "git var GIT_AUTHOR_IDENT" in commit_msg
    assert "git var GIT_COMMITTER_IDENT" in commit_msg
    assert "--stdin '<commit-message-and-identities>'" in commit_msg
    assert "check_content_marks.py --index" in pre_commit_config
    assert "content-integrity:" in justfile
    assert "push:" in push_workflow
    assert "pull_request_target" not in push_workflow
    assert "pull_request_target:" in pr_workflow
    assert "allow-unsafe-pr-checkout: true" in pr_workflow
    assert "python3 -I \"$scanner\"" in pr_workflow
    assert '--commit "$commit"' in push_workflow
    assert '--commit "$commit"' in pr_workflow
    assert "checks: write" not in pr_workflow
    assert '"context": "content-integrity"' not in ruleset
