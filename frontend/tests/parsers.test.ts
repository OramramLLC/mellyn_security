import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  RawNumber,
  canonicalJsonString,
  canonicalNumberText,
  parseAirlockInput,
  parseAssuranceReportJson,
  parseGatewayAuditJsonl,
  parseJsonPreservingNumbers,
  pythonFloatRepr,
  serializeExactSorted,
  validateLoopbackBaseUrl,
  verifyAndReconstructAirlockJsonl,
  verifyGatewayAuditJsonl,
} from "../src/lib/parsers.ts";

function canonicalHash(obj: unknown): string {
  return createHash("sha256").update(canonicalJsonString(obj), "utf-8").digest("hex");
}

function buildChain(events: Record<string, unknown>[]): string {
  let prev = "0".repeat(64);
  const lines: string[] = [];
  events.forEach((ev, seq) => {
    const entryHash = canonicalHash({ seq, prev_hash: prev, event: ev });
    const row = canonicalJsonString({ seq, prev_hash: prev, entry_hash: entryHash, event: ev });
    lines.push(row);
    prev = entryHash;
  });
  return `${lines.join("\n")}\n`;
}

test("verifyAndReconstructAirlockJsonl verifies valid confirmed AAD chain and detects tampering", async () => {
  const trigger = {
    event_id: "evt-0",
    timestamp_utc: "2026-11-23T18:00:00Z",
    zone: "airlock",
    action: "tools/list",
    verdict_allow: false,
    severity: "AAD_FIRE",
    rule_id: "airlock.agbom_pin_mismatch",
    reason: "Hash drift detected.",
    artifact_sha256: "a".repeat(64),
    tool_name: "read_file",
    request_id: 2,
    redactions: [],
    metadata: { session_id: "sess-1" },
  };
  const confirmed = {
    event_id: "evt-1",
    timestamp_utc: "2026-11-23T18:00:01Z",
    zone: "airlock",
    action: "airlock/containment",
    verdict_allow: false,
    severity: "INFO",
    rule_id: "airlock.aad_containment_confirmed",
    reason: "Reaped.",
    artifact_sha256: "a".repeat(64),
    tool_name: "read_file",
    request_id: 2,
    redactions: [],
    metadata: { session_id: "sess-1", trigger_event_id: "evt-0", downstream_returncode: -9 },
  };

  const validJsonl = buildChain([trigger, confirmed]);
  const validReport = await verifyAndReconstructAirlockJsonl(validJsonl, "good.jsonl");
  assert.equal(validReport.chain_valid, true);
  assert.equal(validReport.status, "AAD_CONTAINED");
  assert.equal(validReport.terminal_event?.containment_confirmed, true);
  assert.equal(validReport.terminal_event?.reason_code, "AGBOM_HASH_MISMATCH");

  // Single trigger without confirmation -> AAD_TRIGGERED_UNCONFIRMED
  const unconfirmedJsonl = buildChain([trigger]);
  const unconfirmed = await verifyAndReconstructAirlockJsonl(unconfirmedJsonl);
  assert.equal(unconfirmed.chain_valid, true);
  assert.equal(unconfirmed.status, "AAD_TRIGGERED_UNCONFIRMED");

  // Mid-log tamper -> INTEGRITY_COMPROMISED
  const tampered = validJsonl.replace("Hash drift detected.", "Hask drift detected.");
  const compromised = await verifyAndReconstructAirlockJsonl(tampered);
  assert.equal(compromised.chain_valid, false);
  assert.equal(compromised.status, "INTEGRITY_COMPROMISED");
  assert.equal(compromised.verification.first_invalid_seq, 0);
});

test("parseAirlockInput accepts mellyn-ir JSON directly", async () => {
  const preRendered = JSON.stringify({
    status: "OBSERVED_VIOLATIONS",
    chain_valid: true,
    verification: {
      ledger_path: "obs.jsonl",
      valid: true,
      entry_count: 1,
      last_seq: 0,
      last_hash: "b".repeat(64),
      first_invalid_seq: null,
      first_invalid_line: null,
      anchored: false,
      reason: null,
    },
    session_count: 1,
    total_events: 1,
    unconfirmed_aad_triggers: 0,
    observed_aad_count: 1,
    observed_block_count: 0,
    sessions: [],
    terminal_event: null,
  });
  const report = await parseAirlockInput(preRendered);
  assert.equal(report.status, "OBSERVED_VIOLATIONS");
  assert.equal(report.observed_aad_count, 1);
  // Nothing in the browser checked this report's verdict, so it must never be shown as verified.
  assert.equal(report.provenance, "imported_unverified");

  // A file cannot claim its own provenance.
  const claimed = JSON.stringify({ ...JSON.parse(preRendered), provenance: "server_verified" });
  assert.equal((await parseAirlockInput(claimed)).provenance, "imported_unverified");
});

test("parseGatewayAuditJsonl and parseAssuranceReportJson validate payloads", () => {
  const gw = parseGatewayAuditJsonl(
    '{"audit_id":"aud_1","timestamp":"2026-11-23T00:00:00Z","session_id":"s1","tool_name":"t","decision":"DENY"}\nnot-json\n',
  );
  assert.equal(gw.returned_count, 1);
  assert.equal(gw.malformed_lines, 1);

  assert.throws(() => parseAssuranceReportJson('{"overall_status":"pass"}'));
});

test("validateLoopbackBaseUrl refuses plaintext non-loopback or embedded credentials", () => {
  assert.equal(validateLoopbackBaseUrl(""), "");
  assert.equal(validateLoopbackBaseUrl("http://127.0.0.1:8080/"), "http://127.0.0.1:8080");
  assert.equal(validateLoopbackBaseUrl("http://localhost:8080"), "http://localhost:8080");
  assert.equal(validateLoopbackBaseUrl("https://mellyn.internal.example"), "https://mellyn.internal.example");
  assert.throws(() => validateLoopbackBaseUrl("http://10.0.0.5:8080"));
  assert.throws(() => validateLoopbackBaseUrl("http://user:pass@127.0.0.1:8080"));
});

// Written by the Python `AuditLedger` (src/mcp_airlock/core/audit.py), with float, big-int and -0.0 metadata.
const PYTHON_FLOAT_LEDGER = '{"entry_hash":"d6421c94ef66a0db18516e257221c7022b167f73ea09f4aa22b6afbb6754c3a1","event":{"action":"tools/call","artifact_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","event_id":"evt-f","metadata":{"big":1e+16,"huge_int":12345678901234567890,"neg_zero":0.0,"ratio":0.6666666666666666,"score":0.1,"session_id":"sess-f","small":1.5e-05,"tiny":0.0001,"whole":100.0},"reason":"Float metadata.","redactions":[],"request_id":7,"rule_id":"airlock.observe","severity":"INFO","timestamp_utc":"2026-11-24T00:00:00Z","tool_name":"read_file","verdict_allow":true,"zone":"airlock"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","seq":0}\n';

test("a Python-written ledger with float metadata verifies in the browser", async () => {
  const report = await verifyAndReconstructAirlockJsonl(PYTHON_FLOAT_LEDGER, "float.jsonl");
  assert.equal(report.chain_valid, true, report.verification.reason ?? "");
  assert.equal(report.provenance, "browser_verified");
  assert.equal(report.verification.entry_count, 1);
});

test("browser verification rejects the same edits Python's verify_ledger rejects", async () => {
  // The rejections below only mean something if the untouched ledger verifies.
  assert.equal((await verifyAndReconstructAirlockJsonl(PYTHON_FLOAT_LEDGER)).chain_valid, true);
  // Each variant was checked against verify_ledger_bytes, which rejects all of them.
  const variants: Record<string, string> = {
    neg_zero_on_disk: PYTHON_FLOAT_LEDGER.replace('"neg_zero":0.0', '"neg_zero":-0.0'),
    whole_as_int: PYTHON_FLOAT_LEDGER.replace('"whole":100.0', '"whole":100'),
    big_spelled_out: PYTHON_FLOAT_LEDGER.replace('"big":1e+16', '"big":10000000000000000.0'),
    huge_int_plus1: PYTHON_FLOAT_LEDGER.replace("12345678901234567890", "12345678901234567891"),
    extra_top_field: PYTHON_FLOAT_LEDGER.replace('"seq":0}', '"seq":0,"note":"x"}'),
    int_neg_zero: PYTHON_FLOAT_LEDGER.replace('"request_id":7', '"request_id":-0'),
    dup_key: PYTHON_FLOAT_LEDGER.replace('"seq":0}', '"seq":0,"seq":0}'),
    seq_as_float: PYTHON_FLOAT_LEDGER.replace('"seq":0}', '"seq":0.0}'),
  };
  for (const [name, text] of Object.entries(variants)) {
    assert.notEqual(text, PYTHON_FLOAT_LEDGER, `${name} did not change the fixture`);
    const report = await verifyAndReconstructAirlockJsonl(text, `${name}.jsonl`);
    assert.equal(report.chain_valid, false, `${name} should be rejected`);
    assert.equal(report.status, "INTEGRITY_COMPROMISED", name);
  }
});

test("pythonFloatRepr matches Python repr()", () => {
  const cases: [number, string][] = [
    [1e16, "1e+16"],
    [1e15, "1000000000000000.0"],
    [0.0001, "0.0001"],
    [0.00001, "1e-05"],
    [1.5e-5, "1.5e-05"],
    [100, "100.0"],
    [0, "0.0"],
    [-0, "0.0"],
    [0.1, "0.1"],
    [2 / 3, "0.6666666666666666"],
    [1.7976931348623157e308, "1.7976931348623157e+308"],
    [5e-324, "5e-324"],
  ];
  for (const [x, expected] of cases) {
    assert.equal(pythonFloatRepr(x), expected, `repr(${x})`);
  }
});

test("canonicalNumberText keeps ints exact and reads -0 as int 0", () => {
  assert.equal(canonicalNumberText(new RawNumber("12345678901234567890")), "12345678901234567890");
  assert.equal(canonicalNumberText(new RawNumber("-0")), "0");
  assert.equal(canonicalNumberText(new RawNumber("-0.0")), "0.0");
  assert.equal(canonicalNumberText(new RawNumber("1E2")), "100.0");
});

test("parseJsonPreservingNumbers is strict", () => {
  assert.throws(() => parseJsonPreservingNumbers('{"a":1,"a":2}'));
  assert.throws(() => parseJsonPreservingNumbers('{"a":1} trailing'));
  assert.throws(() => parseJsonPreservingNumbers("[1,]"));
  assert.throws(() => parseJsonPreservingNumbers("01"));
  assert.throws(() => parseJsonPreservingNumbers("[".repeat(100) + "]".repeat(100)));
  const obj = parseJsonPreservingNumbers('{"__proto__":{"x":1}}') as Record<string, unknown>;
  assert.equal(Object.getPrototypeOf(obj), null);
  assert.ok(Object.hasOwn(obj, "__proto__"));
});

test("an entry with an extra top-level field is rejected even when its hashes are correct", async () => {
  const event = {
    event_id: "evt-x",
    timestamp_utc: "2026-11-24T00:00:00Z",
    zone: "airlock",
    action: "tools/list",
    verdict_allow: true,
    severity: "INFO",
    rule_id: "airlock.observe",
    reason: "Plain entry.",
    artifact_sha256: "d".repeat(64),
    tool_name: null,
    request_id: null,
    redactions: [],
    metadata: {},
  };
  const valid = buildChain([event]);
  assert.equal((await verifyAndReconstructAirlockJsonl(valid)).chain_valid, true);
  // "note" is outside the hashed payload and placed in sorted-key position, so only the schema check can catch it.
  const extra = valid.replace(',"prev_hash":', ',"note":"x","prev_hash":');
  assert.notEqual(extra, valid);
  const report = await verifyAndReconstructAirlockJsonl(extra);
  assert.equal(report.chain_valid, false);
  assert.equal(report.status, "INTEGRITY_COMPROMISED");
});

test("verifyAndReconstructAirlockJsonl tracks observe-mode sessions and observed violations", async () => {
  const started = {
    event_id: "evt-start",
    timestamp_utc: "2026-11-24T14:00:00Z",
    zone: "airlock",
    action: "airlock/session",
    verdict_allow: true,
    severity: "WARN",
    rule_id: "airlock.session_started",
    reason: "Started observe-mode harness session.",
    artifact_sha256: "a".repeat(64),
    tool_name: null,
    request_id: null,
    redactions: [],
    metadata: { session_id: "obs-1", enforcement_mode: "observe" },
  };
  const obsBlock = {
    event_id: "evt-block",
    timestamp_utc: "2026-11-24T14:00:01Z",
    zone: "airlock",
    action: "tools/call",
    verdict_allow: false,
    severity: "BLOCK",
    rule_id: "airlock.path_boundary_violation",
    reason: "Access to sensitive file denied (observed).",
    artifact_sha256: "b".repeat(64),
    tool_name: "read_workspace_file",
    request_id: 4,
    redactions: [],
    metadata: { session_id: "obs-1", enforcement_mode: "observe" },
  };
  const obsAad = {
    event_id: "evt-aad",
    timestamp_utc: "2026-11-24T14:00:02Z",
    zone: "airlock",
    action: "tools/call",
    verdict_allow: false,
    severity: "AAD_FIRE",
    rule_id: "egress.canary_exfiltration",
    reason: "Canary detected in webhook (observed).",
    artifact_sha256: "c".repeat(64),
    tool_name: "post_webhook",
    request_id: 5,
    redactions: [],
    metadata: { session_id: "obs-1", enforcement_mode: "observe", would_terminate: true },
  };

  const jsonl = buildChain([started, obsBlock, obsAad]);
  const report = await verifyAndReconstructAirlockJsonl(jsonl, "observe.jsonl");
  assert.equal(report.chain_valid, true);
  assert.equal(report.status, "OBSERVED_VIOLATIONS");
  assert.equal(report.observed_block_count, 1);
  assert.equal(report.observed_aad_count, 1);
  assert.equal(report.sessions[0]?.enforcement_mode, "observe");
});

function buildGatewayChain(rows: Array<Record<string, unknown>>): string {
  let prev = "0".repeat(64);
  const out: string[] = [];
  rows.forEach((row, seq) => {
    const draft = { ...row, seq, prev_hash: prev };
    const entryHash = createHash("sha256").update(serializeExactSorted(draft), "utf-8").digest("hex");
    out.push(serializeExactSorted({ ...draft, entry_hash: entryHash }));
    prev = entryHash;
  });
  return `${out.join("\n")}\n`;
}

test("verifyGatewayAuditJsonl verifies chained gateway logs and detects tampering, swaps, gaps, and dup keys", async () => {
  const row0 = {
    args_sha256: "a".repeat(64),
    audit_id: "aud_0001",
    decision: "allow",
    enforcement_mode: "enforce",
    event_type: "authorization",
    grant_id: null,
    mcp_server: "github",
    policy_id: "github-read",
    reasons: ["Allowed by preset github", "NFKC-raw \uff2d check"],
    risk_tier: "low",
    session_id: "ses_abc",
    taint_count: 0,
    taint_sources: [],
    tainted: false,
    timestamp: "2026-11-24T15:00:00+00:00",
    tool_name: "get_issue",
  };
  const row1 = {
    args_sha256: "b".repeat(64),
    audit_id: "aud_0002",
    decision: "aad_fire",
    enforcement_mode: "enforce",
    event_type: "containment",
    grant_id: null,
    mcp_server: "github",
    policy_id: "scanner.egress",
    reasons: ["Blocked canary [REDACTED_CANARY]"],
    risk_tier: "high",
    session_id: "ses_abc",
    taint_count: 1,
    taint_sources: ["mcp:github"],
    tainted: true,
    timestamp: "2026-11-24T15:00:01+00:00",
    tool_name: "post_issue",
  };

  const chainedJsonl = buildGatewayChain([row0, row1]);
  const valid = await verifyGatewayAuditJsonl(chainedJsonl);
  assert.equal(valid.chain_valid, true, valid.chain_reason ?? "");
  assert.equal(valid.chain_reason, null);
  assert.equal(valid.events.length, 2);
  assert.equal(valid.events[0]?.seq, 0);
  assert.equal(valid.events[1]?.enforcement_mode, "enforce");

  // 1) Tampered field
  const tamperedField = chainedJsonl.replace('"decision":"aad_fire"', '"decision":"allow"');
  const resTamper = await verifyGatewayAuditJsonl(tamperedField);
  assert.equal(resTamper.chain_valid, false);
  assert.match(resTamper.chain_reason ?? "", /line 2/);

  // 2) Swapped lines
  const lines = chainedJsonl.trimEnd().split("\n");
  const swapped = `${lines[1]}\n${lines[0]}\n`;
  const resSwap = await verifyGatewayAuditJsonl(swapped);
  assert.equal(resSwap.chain_valid, false);

  // 3) Sequence gap (deleted line 0 -> starts at seq=1)
  const gapped = `${lines[1]}\n`;
  const resGap = await verifyGatewayAuditJsonl(gapped);
  assert.equal(resGap.chain_valid, false);

  // 4) Duplicate JSON key
  const dupKey = `${lines[0].replace('"seq":0', '"seq":0,"seq":0')}\n`;
  const resDup = await verifyGatewayAuditJsonl(dupKey);
  assert.equal(resDup.chain_valid, false);
  assert.match(resDup.chain_reason ?? "", /Duplicate key/);

  // 5) Legacy pre-chain JSONL returns chain_valid === null
  const legacyJsonl =
    '{"audit_id":"aud_legacy","timestamp":"2026-11-23T00:00:00Z","session_id":"s1","tool_name":"t","decision":"DENY"}\n';
  const resLegacy = await verifyGatewayAuditJsonl(legacyJsonl);
  assert.equal(resLegacy.chain_valid, null);
  assert.equal(resLegacy.chain_reason, null);
  assert.equal(resLegacy.events.length, 1);
});
