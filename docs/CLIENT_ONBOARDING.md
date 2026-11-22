# Mellyn Security — Client Onboarding Guide (Planes 1 & 2)

Adopt Mellyn Security's OWASP-aligned AI-assisted coding guardrails in **under 10 minutes** with **zero copy-pasted scripts**. Every control is pinned by full Git commit SHA so your team pulls updates deliberately and never suffers rule drift.

> **Before you start:** in the snippets below, `<owner>/<mellyn-repo>` is the Mellyn Security repository you were given access to, and `<MELLYN_COMMIT_SHA>` is the full 40-character commit SHA of the version you are adopting. Mellyn does not publish signed releases yet, so pin the exact commit you reviewed. If that repository is private, it must allow access from your organization's workflows (*Settings → Actions → General → Access*), or the gate cannot check out its rules. The reusable workflow relies on the `job.workflow_*` context, which GitHub Enterprise Server does not provide.

---

## 1. Add the Reusable GitHub Actions Security Gate (~10 Lines)

Create `.github/workflows/mellyn-security.yml` in your repository:

```yaml
name: Mellyn Security AI Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  mellyn-gate:
    uses: <owner>/<mellyn-repo>/.github/workflows/mellyn-reusable-ai-security-gate.yml@<MELLYN_COMMIT_SHA>
    with:
      min-package-age-days: 90
      check-agent-rules: true
      run-semgrep: true
      run-gitleaks: true
```

The gate runs the Gitleaks CLI directly (pinned and checksum-verified), so no Gitleaks license is needed. It checks out your code and Mellyn's rules into separate directories and always uses the rules from the exact Mellyn commit you pinned, never files from the pull request under review.

### What This Enforces Automatically on Every PR
1. **AI & Cloud Secret Scanning (Gitleaks)**: Blocks OpenAI, Anthropic, Gemini, HuggingFace, LangSmith, AWS, and GitHub credentials before merge.
2. **Anti-Slopsquatting Supply-Chain Check**: Verifies Python (`pyproject.toml`, `requirements*.txt`) and npm (`package.json`) dependencies exist on PyPI/npm, are older than `min-package-age-days` (default 90), use registry-only sources, and have meaningful version floors.
3. **OWASP AI-Targeted SAST (Semgrep)**: Catches classic LLM-generated flaws (`eval`/`exec`, `shell=True`, unsafe `pickle`/`yaml.load`/`torch.load`, SQL string building, weak crypto/randomness, and unsanitized HTML).
4. **Hidden-Unicode & Rules Sync Check**: Blocks invisible bidi/tag characters ("Rules File Backdoor" prompt injection) in AI assistant instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/`, `.github/copilot-instructions.md`, `.github/instructions/`, ...). If you also adopt the canonical `.agent/rules/owasp-secure-ai-coding.md`, it checks the generated copies are in sync.

### Suppressions are not honored

Code under review cannot switch the gate off. `# nosemgrep` and `# gitleaks:allow` comments are ignored, any `.semgrepignore` or `.gitleaksignore` in your repository is not used, and the gate supplies its own ignore list (`node_modules/`, `.venv/`, `venv/`, `vendor/`, `dist/`, `build/`, minified JS). `tests/` **is** scanned. A genuine false positive is fixed by changing the code, or by asking for a rule change in Mellyn, which then goes through review there. On pull requests Gitleaks scans the PR's commits; on pushes, the pushed commits (full history for a new branch).

---

## 2. Add the Versioned Local Pre-Commit Hooks

Add Mellyn Security to your repository's `.pre-commit-config.yaml` (pinned to the same commit SHA):

```yaml
repos:
  - repo: https://github.com/<owner>/<mellyn-repo>
    rev: <MELLYN_COMMIT_SHA>
    hooks:
      - id: mellyn-verify-dependencies
        args: [--online] # omit to skip the live registry lookups locally (CI always runs them)
      - id: mellyn-check-agent-rules
```

The hooks run with your `python3` (Python 3.12+, standard library only). Local hooks are a convenience; the CI gate is the enforcement point.

Then activate locally:

```bash
pre-commit install
pre-commit run --all-files
```

---

## 3. Lock Down Governance (Recommended)

1. Enable **Branch Protection** on `main` requiring the `mellyn-gate` status checks to pass before merge.
2. Add a `.github/CODEOWNERS` file requiring security/lead-engineer review on `.github/workflows/`, `.pre-commit-config.yaml`, `.agent/`, `CLAUDE.md`, `.cursorrules`, and `.claude/settings.json` so an AI coding agent cannot weaken its own guardrails.
3. Update Mellyn Security pins deliberately via `pre-commit autoupdate --freeze` and Dependabot for GitHub Actions.

---

## 4. Next Step: Runtime MCP Tool-Call Protection

Once your repositories are protected at commit and PR time, deploy Mellyn Security's **Self-Hosted MCP Tool-Call Authorizer & Network Egress Proxy** inside your own VPC or developer host—see [deploy/README.md](../deploy/README.md).
