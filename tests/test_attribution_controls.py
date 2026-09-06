"""Explicit authorship-credit policy and its enforcement paths."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_checker():
    path = ROOT / ".github" / "scripts" / "check_attribution.py"
    name = "causal_continuity_engine_test_attribution"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("kind", "parts"),
    [
        ("trailer", ("Co-Authored-By", ": ", "Codex <tool@example.invalid>")),
        ("prose", ("Generated", " with ", "Codex")),
        ("prose", ("Codex", " (", "Anthropic", ")")),
        ("prose", ("Senior Research Partner", ": ", "Codex")),
        ("trailer", ("Co-authored-by", ": ", "GPT-5 <tool@example.invalid>")),
        ("trailer", ("Co-authored-by", ": ", "AI Assistant <tool@example.invalid>")),
        ("identity", ("Release Helper", "\0", "noreply@claude.ai")),
    ],
    ids=(
        "known-trailer",
        "generated-with",
        "tool-byline",
        "role-byline",
        "gpt-trailer",
        "assistant-trailer",
        "automation-email",
    ),
)
def test_the_frozen_seven_credit_variants_are_rejected(kind, parts):
    checker = _load_checker()
    value = "".join(parts)
    if kind == "identity":
        name, email = value.split("\0")
        findings = checker.scan_identity(name, email, source="<test-identity>")
    else:
        findings = checker.scan_prose(value, source="<test-prose>")
    assert findings


@pytest.mark.parametrize(
    "parts",
    [
        ("Authored", " by ", "Claude"),
        ("Written", " with ", "ChatGPT"),
        ("Created", " using ", "Gemini"),
        ("Generated", " by ", "GPT-5"),
        ("This code was ", "AI", "-assisted"),
    ],
)
def test_other_frozen_authorship_grammars_are_rejected(parts):
    checker = _load_checker()
    assert checker.scan_prose("".join(parts), source="<test-prose>")


@pytest.mark.parametrize(
    "parts",
    [
        ("Generated", " with ", "[Codex](https://example.invalid/tool)"),
        ("Generated", " with ", "[Codex][tool]"),
        ("Generated", " with ", "[Codex][]"),
        ("Generated", " with ", "[Codex]"),
        ("Generated", " with ", "[Codex]()"),
        ("Generated", " with ", "[Codex](https://example.invalid/(nested))"),
        ("Generated", " with ", "[Codex][ tool ]"),
        (
            "Co-Authored-By: Human <human@example.invalid>",
            " and ",
            "Codex <tool@example.invalid>",
        ),
        ("Generated", " with ", "Human and Claude"),
        ("Generated", " with ", "Human, Codex, and Alice"),
        ("Generated", " with ", "Human, Codex, & Alice"),
        ("Generated", " with ", "Human,, Codex"),
        ("Generated", " with ", "Human/Codex"),
    ],
)
def test_linked_and_multi_actor_credits_are_rejected(parts):
    checker = _load_checker()
    assert checker.scan_prose("".join(parts), source="<test-prose>")


@pytest.mark.parametrize(
    ("source", "parts"),
    [
        ("module.py", ("# ", "Codex", " (Anthropic)")),
        ("script.sh", ("# Generated", " with ", "Codex")),
        ("workflow.yml", ("# Generated", " with ", "Codex")),
        ("module.js", ("// Generated", " with ", "Codex")),
        ("module.rs", ("/// Generated", " with ", "Codex")),
        ("module.c", ("/* Generated", " with ", "Codex */")),
        ("query.sql", ("-- Generated", " with ", "Codex")),
        ("settings.ini", ("; Generated", " with ", "Codex")),
        ("paper.tex", ("% Generated", " with ", "Codex")),
    ],
)
def test_code_comment_credits_remain_prohibited(source, parts):
    checker = _load_checker()
    assert checker.scan_prose("".join(parts), source=source)


@pytest.mark.parametrize(
    "parts",
    [
        ("1. Generated", " with ", "Codex"),
        ("1) Generated", " with ", "Codex"),
        ("- [ ] Generated", " with ", "Codex"),
        ("- [x] Generated", " with ", "Codex"),
    ],
)
def test_markdown_ordered_and_task_list_credits_are_rejected(parts):
    checker = _load_checker()
    assert checker.scan_prose("".join(parts), source="README.md")


@pytest.mark.parametrize(
    ("source", "parts"),
    [
        ("library.rs", ("//! Generated", " with ", "Codex")),
        ("library.rs", ("/*! Generated", " with ", "Codex */")),
    ],
)
def test_rust_doc_comment_credits_are_rejected(source, parts):
    checker = _load_checker()
    assert checker.scan_prose("".join(parts), source=source)


def test_ordinary_product_discussion_and_human_identities_remain_clean():
    checker = _load_checker()
    safe = "\n".join([
        "Claude Code, Cursor, and VS Code can read project state.",
        "GitHub retired Copilot Extensions in favor of MCP.",
        "fixture = {\"notice\": \"Generated with Claude\"}",
        "Generated by python -m causal_continuity_engine.capabilities.",
        "The policy rejects the phrase \"Written with ChatGPT\" as a byline.",
        "\"Codex (Anthropic)\" is the prohibited-byline example.",
        "{\"vendor\": \"Codex (Anthropic)\"}",
        "## Claude (Anthropic)",
        "- Claude (Anthropic)",
        "1. Claude (Anthropic)",
        "- [ ] Claude (Anthropic)",
        "> Codex (Anthropic)",
    ])
    assert checker.scan_prose(safe, source="README.md") == ()
    assert checker.scan_identity(
        "Claude Dupont", "claude.dupont@example.invalid", source="<human>"
    ) == ()


def test_raw_commit_scans_message_author_and_committer_as_separate_fields():
    checker = _load_checker()
    raw = (
        "tree " + "a" * 40 + "\n"
        "author Thomas Albrecht <owner@example.invalid> 1 +0000\n"
        "committer Codex <bot@example.invalid> 1 +0000\n\n"
        "fix: preserve the notification boundary\n"
    ).encode()
    findings = checker.scan_commit_object(raw, source="<commit>")
    assert [(finding.code, finding.source) for finding in findings] == [
        ("attribution.identity", "<commit>:committer")
    ]


@pytest.mark.parametrize(
    "parts",
    [
        ("// Generated", " with ", "Codex\n"),
        ("Codex", " (", "Anthropic", ")\n"),
    ],
)
def test_raw_commit_rejects_decorated_and_plain_message_bylines(parts):
    checker = _load_checker()
    raw = (
        "tree " + "a" * 40 + "\n"
        "author Thomas Albrecht <owner@example.invalid> 1 +0000\n"
        "committer Thomas Albrecht <owner@example.invalid> 1 +0000\n\n"
        + "".join(parts)
    ).encode()
    assert checker.scan_commit_object(raw, source="<commit>")


def test_attribution_policy_has_one_implementation_and_no_path_exemptions():
    workflow = (
        ROOT / ".github" / "workflows" / "no-ai-attribution.yml"
    ).read_text(encoding="utf-8")
    pre_commit = (ROOT / ".githooks" / "pre-commit").read_text(encoding="utf-8")
    commit_msg = (ROOT / ".githooks" / "commit-msg").read_text(encoding="utf-8")

    assert "check_attribution.py --index" in pre_commit
    assert "check_attribution.py --message-file" in commit_msg
    assert "check_attribution.py --tree" in workflow
    assert "check_attribution.py --commits" in workflow
    assert "--stdin '<pull-request-metadata>'" in workflow
    for source in (workflow, pre_commit, commit_msg):
        assert "PATTERN=" not in source
        assert ":(exclude)" not in source


def test_mutable_pull_request_metadata_is_rechecked_but_not_overclaimed():
    workflow = (
        ROOT / ".github" / "workflows" / "no-ai-attribution.yml"
    ).read_text(encoding="utf-8")
    assert "types: [opened, synchronize, reopened, edited]" in workflow
    assert "mutable" in workflow
    assert "advisory" in workflow
    assert "candidate tree's workflow and scanner" in workflow
    assert "owner review" in workflow
    assert "--stdin '<pull-request-metadata>' --input-format markdown" in workflow


def test_pr_metadata_requires_explicit_markdown_input_context():
    scanner = ROOT / ".github" / "scripts" / "check_attribution.py"
    body = "".join(("## Claude", " (", "Anthropic", ")\n"))
    command = [
        sys.executable,
        "-I",
        str(scanner),
        "--stdin",
        "<pull-request-metadata>",
    ]
    plain = subprocess.run(
        command,
        input=body,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )
    markdown = subprocess.run(
        [*command, "--input-format", "markdown"],
        input=body,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )
    assert plain.returncode == 1, plain.stderr
    assert markdown.returncode == 0, markdown.stderr


def _control_fixture(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    for relative in (
        ".gitleaks.toml",
        ".github/scripts/check_content_marks.py",
        ".github/workflows/no-ai-attribution.yml",
        ".githooks/commit-msg",
        ".githooks/pre-commit",
    ):
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    checker = ROOT / ".github" / "scripts" / "check_attribution.py"
    if checker.exists():
        destination = repository / ".github" / "scripts" / checker.name
        shutil.copy2(checker, destination)
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.name", "Local Test"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "local@example.invalid"],
        cwd=repository,
        check=True,
    )
    return repository


def _run_control(repository, *command):
    return subprocess.run(
        command,
        cwd=repository,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )


def test_real_hooks_reject_a_base_valid_bypass(tmp_path):
    repository = _control_fixture(tmp_path)
    attack = "".join(("Senior Research ", "Partner: ", "Codex\n"))
    artifact = repository / "artifact.txt"
    artifact.write_text(attack, encoding="utf-8")
    subprocess.run(["git", "add", "artifact.txt"], cwd=repository, check=True)

    pre_commit = _run_control(
        repository, "bash", "--posix", ".githooks/pre-commit")
    message = repository / "message.txt"
    message.write_text(attack, encoding="utf-8")
    commit_msg = _run_control(
        repository, "bash", "--posix", ".githooks/commit-msg", message.name)

    assert pre_commit.returncode == 1, pre_commit.stderr
    assert "attribution.credit" in pre_commit.stderr, pre_commit.stderr
    assert commit_msg.returncode == 1, commit_msg.stderr
    assert "attribution.credit" in commit_msg.stderr, commit_msg.stderr


def _run_push_workflow(repository):
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
    workflow = (
        repository / ".github" / "workflows" / "no-ai-attribution.yml"
    ).read_text(encoding="utf-8")
    _, separator, script = workflow.partition("        run: |\n")
    assert separator
    environment = dict(os.environ)
    environment.update({
        "BASE_SHA": "",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_SHA": head,
        "HEAD_SHA": "",
        "PR_BODY": "",
        "PR_TITLE": "",
    })
    return subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=repository,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )


def test_real_workflow_tree_path_rejects_a_base_valid_bypass(tmp_path):
    repository = _control_fixture(tmp_path)
    attack = "".join(("Senior Research ", "Partner: ", "Codex\n"))
    (repository / "artifact.txt").write_text(attack, encoding="utf-8")
    subprocess.run(["git", "add", "artifact.txt"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "--no-verify", "-q", "-m", "test: tree carrier"],
        cwd=repository,
        check=True,
    )
    result = _run_push_workflow(repository)
    assert result.returncode == 1, result.stderr


def test_real_workflow_commit_path_rejects_a_base_valid_bypass(tmp_path):
    repository = _control_fixture(tmp_path)
    attack = "".join(("Senior Research ", "Partner: ", "Codex\n"))
    (repository / "artifact.txt").write_text("clean fixture\n", encoding="utf-8")
    subprocess.run(["git", "add", "artifact.txt"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "--no-verify", "-q", "-m", attack],
        cwd=repository,
        check=True,
    )
    result = _run_push_workflow(repository)
    assert result.returncode == 1, result.stderr


def test_exact_index_tree_and_commit_selectors_reject_the_planted_credit(tmp_path):
    repository = _control_fixture(tmp_path)
    attack = "".join(("Senior Research ", "Partner: ", "Codex\n"))
    (repository / "artifact.txt").write_text(attack, encoding="utf-8")
    subprocess.run(["git", "add", "artifact.txt"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "--no-verify", "-q", "-m", attack],
        cwd=repository,
        check=True,
    )
    scanner = ".github/scripts/check_attribution.py"
    index = _run_control(repository, sys.executable, "-I", scanner, "--index")
    tree = _run_control(repository, sys.executable, "-I", scanner, "--tree", "HEAD")
    commits = _run_control(
        repository, sys.executable, "-I", scanner, "--commits", "HEAD")
    assert index.returncode == 1, index.stderr
    assert tree.returncode == 1, tree.stderr
    assert commits.returncode == 1, commits.stderr
