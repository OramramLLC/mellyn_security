# Mellyn Security: AI Incident Drill & Patch Verification Report

**Drill ID:** `IR-DRILL-2026-001`\
**Drill Type:** Retrospective on a real pre-release finding, plus a live replay of the original reproduction against the vulnerable and patched code\
**Finding Detected:** 2026-11-27 17:21:13 UTC | **Fix Merged:** 2026-11-27 18:52:01 UTC | **Replay Executed:** 2026-11-27 21:33:33–21:34:43 UTC\
**System Under Test:** Human-approval channel: `mellyn approve` approval server (`src/mellyn/approvals.py`) and approval relay (`src/mellyn/approval_relay.py`)\
**Change Under Review:** [OramramLLC/mellyn_security#37](https://github.com/OramramLLC/mellyn_security/pull/37) (signed commit `ef55a89`, signed merge `2ef9ccd`)\
**Assigned Severity:** **SEV-3 (Medium)**: fail-closed loss of human-oversight availability, caught before release. It would have been **SEV-2** had it shipped (§1).\
**Incident Owner:** Project maintainer (OramramLLC). This is a single-maintainer project, so see `RSK-08` in [RISK_REGISTER.md](RISK_REGISTER.md).\
**Mapped Controls:** NIST AI RMF 1.0 (`MANAGE 2.3`, `MANAGE 4.3`, `MEASURE 2.7`, `GOVERN 4.3`) | ISO/IEC 42001 (`A.6.2.4`, `A.8.4`, clause `10.2`) | SOC 2 (`CC7.3`, `CC7.4`, `CC7.5`, `CC8.1`) | ISO/IEC 27001:2022 (`A.5.24`, `A.5.25`, `A.5.26`, `A.5.27`, `A.8.8`, `A.8.32`)

---

## Summary in Plain Terms
A security change meant to harden Mellyn's human-approval service introduced a new weakness. A process on the same machine could hold every connection slot open by sending data very slowly. A real approver could then no longer reach the service. Nothing unsafe could be approved this way: held tool calls simply stayed held. Human oversight would still have been unavailable, though.

An adversarial review found the weakness about five minutes after the change was submitted, before it was committed. It was fixed, regression-tested, independently checked in CI and merged about 90 minutes after detection. No released version of Mellyn contained it. This drill replays the original attack against both versions to show that the fix works and to measure what risk is left.

---

## 1. AI Incident Severity Tiers
Mellyn classifies agentic and MCP-layer incidents by blast radius and containment status:

| Tier | Classification | Trigger Condition | Containment SLA | Escalation |
| :--- | :--- | :--- | :--- | :--- |
| **SEV-1** | **Critical** | Active production data exfiltration, confirmed canary leak outside boundary, or unauthorized state-mutating tool execution. | **Immediate** *(Automated AAD kill switch: `AAD_FIRE`, `-32099` / exit `78`, downstream halt)* | System Owner, Security Lead, Legal/Privacy |
| **SEV-2** | **High** | Reproducible control or canary bypass discovered in staging/`mellyn-redteam`; unapproved schema drift (`mellyn pin` / `mellyn-pin` mismatch) blocked before prod egress; **or loss of the human-approval channel in a released version.** | **Under 1 hour** *(Freeze deployments / halt target tool)* | System Owner, Engineering Lead |
| **SEV-3** | **Medium** | Repeated taint-escalation triggers (`Authorizer` / `untrusted_content_tools`) or suspicious tool-call loops blocked by TOML policy (`mellyn.toml` / `mellyn-policy.toml`); **or a fail-closed weakness in a control found before release.** | **Under 24 hours** | On-call Engineer |
| **SEV-4** | **Low** | False-positive blocks causing workflow friction without security degradation. | **Next sprint** | Policy Maintainer |

**Why SEV-3:** The weakness fails closed: it denies approvals and never grants them. It also never reached `main` or a release. Had it shipped, any local process could have disabled human oversight on demand. That includes a process started by the supervised agent itself, which makes it SEV-2.

---

## 2. Root Cause

| | |
| :--- | :--- |
| **Weakness** | Approval-channel connection-slot exhaustion (CWE-400 uncontrolled resource consumption; "slow-loris" pattern). |
| **Introduced by** | The pre-audit hardening change itself. It added a cap of 32 concurrent connections (`BoundedSemaphore`) and a 10-second socket timeout to the approval server and relay. |
| **Root cause** | The 10-second timeout applied to **each read**, not to the **whole request**. A client that sends one header line every 4 seconds resets the timer forever, so it holds a slot indefinitely. Enough such clients fill the cap, and the server then refuses new connections, including the approver's. |
| **Before the change** | Commit `5a8f493` had no cap: threads were unbounded. That avoided slot starvation, but it exposed the host to unbounded thread creation. The cap was the right idea; it needed a total deadline to go with it. |
| **Fix** | `DeadlineRequestHandler` gives every connection a 30-second total deadline (`APPROVAL_REQUEST_DEADLINE_SECONDS`). A timer shuts the socket down at the deadline, waking any blocked read so the slot is released. The approval server and relay now share one `BoundedApprovalServer`, which removed duplicated semaphore code. |
| **Detection method** | Adversarial pre-merge review with an executable probe: two trickling clients against a server capped at 2, then a real approver request. Not detected by the change's own tests, which checked that the timeout was *set*, not that it *bounded* a slow client. |

---

## 3. Incident Timeline (all times UTC, 2026-11-27)

| Phase | Timestamp | Action & Observable Evidence | Evidence Source |
| :--- | :--- | :--- | :--- |
| **T0 — Change submitted for review** | 17:15:42 | Maintainer requests review of uncommitted pre-audit hardening changes on `main` (`5a8f493` + working tree). | Reviewer session log ¹ |
| **T1 — Detection** | 17:21:13 | Review probe `P3` reproduces the weakness: the approver request after 14 s of 2 trickling clients (cap 2) gets `ConnectionAbortedError`. | Reviewer session log ¹ |
| **T2 — Triage & report** | 17:22:54 | Finding reported to the maintainer, rated MEDIUM, with a recommended fix (an absolute per-request deadline). | Reviewer session log ¹ |
| **Containment** | (n/a) | Nothing to contain: the vulnerable code was uncommitted, so it was never on `main`, in a release, or on any deployment. The change was held until fixed. | `git log main` |
| **T3 — Remediation authorized** | 18:15:17 | Maintainer authorizes the fix ("Yes, fix them"). | Reviewer session log ¹ |
| **T4 — Fix verified locally** | 18:28:53 | 16 new regression tests, each confirmed by reverting its fix (9 of 9 caught). Full suite of 485 tests passes. Probe re-run shows the weakness closed. | Reviewer session log ¹ |
| **T5 — Fix committed** | 18:29:40 | Signed commit `ef55a89` (GitHub: `verified=true`). Its message carries a `SECURITY REVIEW:` callout for authorization and tool-execution changes. | GitHub commit API |
| **T6 — Independent verification** | 18:49:01–18:50:06 | PR #37 opened; all 7 required checks green: Python 3.12 and 3.14 tests on Linux, container build + Squid egress integration, Gitleaks ×2, SAST/lint/agent rules/dependency verification. | [CI run 46052241195](https://github.com/OramramLLC/mellyn_security/actions/runs/46052241195) |
| **T7 — Released to `main`** | 18:52:01 | Signed merge commit `2ef9ccd` (GitHub: `verified=true`), behind the `Protect main` ruleset (signed commits, PR-only, strict required checks). | PR #37 |
| **T8 — Post-merge verification** | 18:52:04–18:53:08 | `main` push CI green. | [CI run 46052597269](https://github.com/OramramLLC/mellyn_security/actions/runs/46052597269) |
| **T9 — Drill replay** | 21:33:33–21:34:43 | Original attack replayed against pre-patch and post-patch code (§5). | [`docs/grc/evidence/IR-DRILL-2026-001/`](docs/grc/evidence/IR-DRILL-2026-001/) |

¹ *The reviewer session log is the local review transcript and is not published. Steps T0–T4 can therefore only be checked by the maintainer. Steps T5–T8 can be checked independently on GitHub.*

### Response Metrics
| Metric | Interval | Elapsed |
| :--- | :--- | :--- |
| Time to detect | T0 → T1 | **5 min 31 s** |
| Time to report | T1 → T2 | **1 min 41 s** |
| Waiting for remediation authorization | T2 → T3 | **52 min 23 s** *(largest single delay; see §7)* |
| Time to remediate & verify locally | T3 → T4 | **13 min 36 s** |
| Detection to fix released on `main` | T1 → T7 | **1 h 30 min 48 s** |
| Production exposure | (n/a) | **None**: never released |

---

## 4. Verification Evidence
*   **Patch commit:** `ef55a89` ("Harden HTTP input, approval limits and downstream env before audit"), merged as `2ef9ccd`. 15 files, +1156 / −51.
*   **Permanent regression tests** in [`tests/test_pre_audit_review_fixes.py`](tests/test_pre_audit_review_fixes.py):
    *   `TestApprovalRequestDeadline.test_approval_server_frees_slots_at_the_deadline`
    *   `TestApprovalRequestDeadline.test_relay_frees_slots_at_the_deadline`
    *   `TestApprovalRequestDeadline.test_deadline_must_be_positive`
*   **Mutation check:** each of the 9 fixes in the change was reverted in turn. A regression test failed every time (9/9). This shows the tests check the fix, not just that the code runs.
*   **CI (Linux):** 7/7 required checks green on PR #37 and on the `main` push. The timer-based deadline was developed on Windows, so CI was its first Linux run.
*   **Re-run for this report (2026-11-27, Windows, Python 3.14, commit `2ef9ccd`):**
    *   The 21 test modules cited in [docs/grc/CONTROLS_MATRIX_AND_EVIDENCE.md](docs/grc/CONTROLS_MATRIX_AND_EVIDENCE.md) ran 250 tests: OK, 5 skipped for POSIX-only or symlink-privilege reasons, which CI covers on Linux.
    *   `mellyn-bench --surface both` passed (26/26 per surface).

---

## 5. Drill Replay: Pre-Patch vs. Post-Patch
**Procedure:** [`replay_slot_exhaustion.py`](docs/grc/evidence/IR-DRILL-2026-001/replay_slot_exhaustion.py) runs the following steps:
1. Start an approval server with its cap lowered to 2 to make the test fast. Production uses 32, which only changes how many attacker connections are needed.
2. Confirm that an approver request succeeds.
3. Open 2 attacker connections that each send one header line every 4 s.
4. Send a real approver request at +14 s and again at +34 s.

The script runs on loopback only and writes nothing to the repo. The pre-patch tree is the maintainer's local copy of the uncommitted change, which was never pushed. The post-patch tree is `2ef9ccd`.

| Observation | Pre-patch | Post-patch (`2ef9ccd`) |
| :--- | :--- | :--- |
| Baseline approver request | `200 OK` | `200 OK` |
| Approver request at +14 s (attackers active) | **Refused** (`ConnectionAbortedError`) | **Refused** (closed without reply), because the attackers are still inside the 30 s deadline |
| Server ends attacker connections | **Never**: both still held at +34 s | **At the 30 s deadline** (noticed by the attacker at its next 4 s poll, +33.5 s) |
| Approver request at +34 s | **Refused** (closed without reply) | **`200 OK`** |
| **Result** | Human oversight unavailable for as long as the attacker likes | Human oversight restored once the deadline passes |

Raw records with UTC timestamps: [`replay-pre-patch.jsonl`](docs/grc/evidence/IR-DRILL-2026-001/replay-pre-patch.jsonl) and [`replay-post-patch.jsonl`](docs/grc/evidence/IR-DRILL-2026-001/replay-post-patch.jsonl).

---

## 6. Residual Risk (Accepted, Tracked as `RSK-07`)
The fix turns *indefinite* starvation into *bounded competition*. In the post-patch replay, the approver was still refused at +14 s. An attacker who reconnects every 30 s can keep competing for slots, so approvals become unreliable but not impossible.

Options for reducing this further:
*   a per-peer connection limit;
*   reserving a slot for requests that carry a valid approver key;
*   moving the approval channel to an authenticated transport.

None of these is implemented yet. The residual risk is rated **Medium** and accepted for now, for two reasons. The attack needs local code execution on the approval host. And while it runs, nothing can be approved, so tool calls stay held instead of going ahead. See `RSK-07` in [RISK_REGISTER.md](RISK_REGISTER.md).

---

## 7. Lessons Learned (ISO/IEC 27001 `A.5.27`)
1.  **Hardening changes need adversarial review too.** This weakness was introduced by a security fix. The change's own tests checked that a setting existed, not that it stopped an attacker. Every new control should get at least one test that attacks it.
2.  **Executable probes beat checklist review.** Detection took 5½ minutes because the reviewer ran a working attack rather than reading the diff. Probes are kept and replayed (§5).
3.  **Authorization was the bottleneck.** 52 of the 91 minutes between detection and merge were spent waiting for the maintainer's go-ahead. For a single maintainer that is a reasonable cost of keeping a human in control of security fixes. In a team, a pre-agreed SLA for authorizing fixes to MEDIUM-or-higher findings would shorten it.
4.  **Single-maintainer limit.** The developer, reviewer-of-record and approver are the same person; an AI reviewer did the independent probing. This is recorded as `RSK-08`, not hidden.

---

## 8. Return-to-Service Gates
After any SEV-1 or SEV-2 AAD kill-switch event, the agentic workflow stays **fail-closed** until all five gates are verified and logged. Each gate's status for this incident is shown in brackets.

1.  **Reproducible Proof of Fix:** the original bypass payload is added permanently to `tests/` (and to `mellyn-bench` / `mellyn-redteam` where applicable), and it returns a deterministic `BLOCK` or `AAD_FIRE` verdict. *[Met: 3 regression tests plus the replay in §5.]*
2.  **No Policy or Scanner Regression:** `python -m unittest discover -s tests -v` and `mellyn bench --surface both --json` both pass with `0` false positives and `100%` canary recall on the benchmark corpus, confirming the patch does not break legitimate tool calls. *[Met: 485 tests locally, 7/7 CI checks, benchmark 26/26.]*
3.  **Schema Integrity Check:** `mellyn pin` or `mellyn-pin` confirms that all downstream MCP tool schemas match their pinned SHA-256 digests, with no unapproved drift. *[Not applicable: no MCP tool schemas changed.]*
4.  **Audit Trail Integrity:** `mellyn verify` and `mellyn-ir` confirm the `schema_version = 2` `mellyn-audit.jsonl` hash chain is intact for both the halt event and the post-patch verification run. *[Not applicable: no runtime ledger was involved. The change-control record, made of signed commits and CI runs, takes its place.]*
5.  **Organizational Sign-Off *(Outside Proxy)*:** the named System Owner (plus Legal/Compliance for SEV-1) formally approves lifting the AAD kill switch and documents the residual-risk acceptance. *[Met: the maintainer authorized the fix and the merge; residual risk accepted as `RSK-07`.]*
