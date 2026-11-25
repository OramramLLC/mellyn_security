import type {
  ControlAssuranceReport,
  GatewayAuditEvent,
  GatewayAuditPayload,
  IncidentReport,
  IncidentStatus,
  SessionTimeline,
  Severity,
  TerminalTrigger,
  TimelineEvent,
  Zone,
} from "../types.ts";

const GENESIS_PREV_HASH = "0".repeat(64);
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const AAD_CONTAINMENT_CONFIRMED_RULE_ID = "airlock.aad_containment_confirmed";
const SESSION_STARTED_RULE_ID = "airlock.session_started";

const EXTRA_INVISIBLE_CODEPOINTS = new Set<number>([
  0x034f, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x180b, 0x180c, 0x180d, 0x180e, 0x200b, 0x200c, 0x200d, 0x2060,
  0x2800, 0x3164, 0xfeff, 0xffa0,
]);

const CF_FORMAT_RE = /\p{Cf}/u;

const REASON_CODE_MAP: Record<string, string> = {
  "airlock.agbom_pin_mismatch": "AGBOM_HASH_MISMATCH",
  "airlock.agbom_manifest_mismatch": "AGBOM_HASH_MISMATCH",
  "airlock.agbom_unpinned_tool": "AGBOM_UNPINNED_TOOL",
  "airlock.invisible_unicode_injection": "INVISIBLE_UNICODE_INJECTION",
  "airlock.instructions_pin_mismatch": "INSTRUCTIONS_PIN_MISMATCH",
  "airlock.unsolicited_response_id": "UNSOLICITED_RPC_ID",
  "airlock.invalid_tools_list_manifest": "INVALID_TOOLS_LIST_MANIFEST",
  "egress.canary_exfiltration": "CANARY_EXFILTRATION",
  "egress.response_canary_detected": "CANARY_EXFILTRATION",
};

export function mapReasonCode(ruleId: string): string {
  const mapped = REASON_CODE_MAP[ruleId];
  if (mapped !== undefined) {
    return mapped;
  }
  const idx = ruleId.lastIndexOf(".");
  return (idx >= 0 ? ruleId.slice(idx + 1) : ruleId).toUpperCase();
}

export function isInvisibleCodepoint(ch: string): boolean {
  const cp = ch.codePointAt(0);
  if (cp === undefined) {
    return false;
  }
  if (cp >= 0xe0000 && cp <= 0xe007f) {
    return true;
  }
  if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)) {
    return true;
  }
  if (CF_FORMAT_RE.test(ch)) {
    return true;
  }
  return EXTRA_INVISIBLE_CODEPOINTS.has(cp);
}

export function stripInvisible(text: string): string {
  let out = "";
  for (const ch of text) {
    if (!isInvisibleCodepoint(ch)) {
      out += ch;
    }
  }
  return out;
}

export function normalizeStr(text: string): string {
  return stripInvisible(stripInvisible(text).normalize("NFKC"));
}

export function hasInvisibleUnicode(value: unknown): boolean {
  if (typeof value === "string") {
    for (const ch of value) {
      if (isInvisibleCodepoint(ch)) {
        return true;
      }
    }
    return false;
  }
  if (Array.isArray(value)) {
    return value.some((item) => hasInvisibleUnicode(item));
  }
  if (value !== null && typeof value === "object") {
    return Object.entries(value).some(([k, v]) => hasInvisibleUnicode(k) || hasInvisibleUnicode(v));
  }
  return false;
}

function compareCodePoints(a: string, b: string): number {
  const iterA = a[Symbol.iterator]();
  const iterB = b[Symbol.iterator]();
  while (true) {
    const nextA = iterA.next();
    const nextB = iterB.next();
    if (nextA.done && nextB.done) {
      return 0;
    }
    if (nextA.done) {
      return -1;
    }
    if (nextB.done) {
      return 1;
    }
    const cpA = nextA.value.codePointAt(0) ?? 0;
    const cpB = nextB.value.codePointAt(0) ?? 0;
    if (cpA !== cpB) {
      return cpA - cpB;
    }
  }
}

/**
 * A JSON number kept as the text it was written with. The browser must re-serialize ledger lines exactly as
 * Python does; `JSON.parse` would turn `1.0` into `1` and lose that, so numbers are parsed into this wrapper.
 */
export class RawNumber {
  readonly raw: string;

  constructor(raw: string) {
    this.raw = raw;
  }

  get value(): number {
    return Number(this.raw);
  }

  /** Python's `json.loads` reads a number without `.`, `e` or `E` as an int, anything else as a float. */
  get isInteger(): boolean {
    return !/[.eE]/.test(this.raw);
  }
}

const MAX_JSON_DEPTH = 64;
const JSON_NUMBER_RE = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

function defineOwn(target: Record<string, unknown>, key: string, value: unknown): void {
  // defineProperty, not assignment, so a key such as "__proto__" stays an ordinary own property.
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

/**
 * Strict JSON parser that keeps numbers as `RawNumber` and rejects duplicate keys and trailing content.
 * Objects have no prototype, so ledger keys can never collide with `Object.prototype` members.
 */
export function parseJsonPreservingNumbers(text: string): unknown {
  let pos = 0;
  const fail = (message: string): never => {
    throw new Error(`${message} at offset ${pos}.`);
  };
  const skipWhitespace = (): void => {
    while (pos < text.length) {
      const c = text.charCodeAt(pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
        pos += 1;
      } else {
        break;
      }
    }
  };
  const parseString = (): string => {
    const start = pos;
    pos += 1;
    while (pos < text.length) {
      const c = text[pos];
      if (c === "\\") {
        pos += 2;
        continue;
      }
      if (c === '"') {
        pos += 1;
        // JSON.parse validates the escapes and rejects raw control characters inside the string.
        return JSON.parse(text.slice(start, pos)) as string;
      }
      pos += 1;
    }
    return fail("Unterminated string");
  };
  const parseValue = (depth: number): unknown => {
    if (depth > MAX_JSON_DEPTH) {
      fail("JSON is nested too deeply");
    }
    skipWhitespace();
    const c = text[pos];
    if (c === "{") {
      pos += 1;
      const obj = Object.create(null) as Record<string, unknown>;
      const seen = new Set<string>();
      skipWhitespace();
      if (text[pos] === "}") {
        pos += 1;
        return obj;
      }
      for (;;) {
        skipWhitespace();
        if (text[pos] !== '"') {
          fail("Expected a string key");
        }
        const key = parseString();
        if (seen.has(key)) {
          fail(`Duplicate key ${JSON.stringify(key)}`);
        }
        seen.add(key);
        skipWhitespace();
        if (text[pos] !== ":") {
          fail("Expected ':'");
        }
        pos += 1;
        defineOwn(obj, key, parseValue(depth + 1));
        skipWhitespace();
        if (text[pos] === ",") {
          pos += 1;
          continue;
        }
        if (text[pos] === "}") {
          pos += 1;
          return obj;
        }
        fail("Expected ',' or '}'");
      }
    }
    if (c === "[") {
      pos += 1;
      const arr: unknown[] = [];
      skipWhitespace();
      if (text[pos] === "]") {
        pos += 1;
        return arr;
      }
      for (;;) {
        arr.push(parseValue(depth + 1));
        skipWhitespace();
        if (text[pos] === ",") {
          pos += 1;
          continue;
        }
        if (text[pos] === "]") {
          pos += 1;
          return arr;
        }
        fail("Expected ',' or ']'");
      }
    }
    if (c === '"') {
      return parseString();
    }
    if (text.startsWith("true", pos)) {
      pos += 4;
      return true;
    }
    if (text.startsWith("false", pos)) {
      pos += 5;
      return false;
    }
    if (text.startsWith("null", pos)) {
      pos += 4;
      return null;
    }
    JSON_NUMBER_RE.lastIndex = pos;
    const match = JSON_NUMBER_RE.exec(text);
    if (match) {
      pos += match[0].length;
      return new RawNumber(match[0]);
    }
    return fail("Unexpected token");
  };
  const result = parseValue(0);
  skipWhitespace();
  if (pos !== text.length) {
    fail("Unexpected trailing content");
  }
  return result;
}

/**
 * Python's `repr(float)` (as `json.dumps` writes floats): shortest round-trip digits, fixed notation for
 * exponents -4..15 (always with a fractional part), otherwise `d.ddde±XX`. Zero is written `0.0` because the
 * ledger's canonical form maps -0.0 to 0.0.
 */
export function pythonFloatRepr(x: number): string {
  if (!Number.isFinite(x)) {
    throw new Error("Non-finite numbers are forbidden in canonical JSON.");
  }
  if (x === 0) {
    return "0.0";
  }
  const sign = x < 0 ? "-" : "";
  const [mantissa = "0", expText = "0"] = Math.abs(x).toExponential().split("e");
  const digits = mantissa.replace(".", "");
  const exp = Number(expText);
  if (exp < -4 || exp >= 16) {
    const m = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    const absExp = Math.abs(exp);
    return `${sign}${m}e${exp < 0 ? "-" : "+"}${absExp < 10 ? `0${absExp}` : String(absExp)}`;
  }
  if (exp >= 0) {
    const intLen = exp + 1;
    const intPart = digits.length >= intLen ? digits.slice(0, intLen) : digits + "0".repeat(intLen - digits.length);
    const frac = digits.length > intLen ? digits.slice(intLen) : "0";
    return `${sign}${intPart}.${frac}`;
  }
  return `${sign}0.${"0".repeat(-exp - 1)}${digits}`;
}

/** The text Python's canonical JSON writes for this number (ints via BigInt, floats via `pythonFloatRepr`). */
export function canonicalNumberText(value: RawNumber | number): string {
  if (value instanceof RawNumber) {
    return value.isInteger ? BigInt(value.raw).toString() : pythonFloatRepr(value.value);
  }
  return Number.isInteger(value) ? String(value) : pythonFloatRepr(value);
}

export function normalizeCanonicalValue(value: unknown): unknown {
  if (value === null || typeof value === "boolean" || value instanceof RawNumber) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Non-finite numbers are forbidden in canonical JSON.");
    }
    return value;
  }
  if (typeof value === "string") {
    return normalizeStr(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeCanonicalValue(item));
  }
  if (typeof value === "object") {
    const sortedEntries: [string, unknown][] = [];
    const seenKeys = new Set<string>();
    for (const [rawKey, rawVal] of Object.entries(value)) {
      const normKey = normalizeStr(rawKey);
      if (seenKeys.has(normKey)) {
        throw new Error(`Canonical key collision after normalization: ${normKey}`);
      }
      seenKeys.add(normKey);
      sortedEntries.push([normKey, normalizeCanonicalValue(rawVal)]);
    }
    sortedEntries.sort(([ka], [kb]) => compareCodePoints(ka, kb));
    const ordered = Object.create(null) as Record<string, unknown>;
    for (const [k, v] of sortedEntries) {
      defineOwn(ordered, k, v);
    }
    return ordered;
  }
  throw new Error(`Unsupported JSON value type: ${typeof value}`);
}

function serializeCanonical(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (value instanceof RawNumber || typeof value === "number") {
    return canonicalNumberText(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => serializeCanonical(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const parts = Object.entries(value as Record<string, unknown>).map(
      ([k, v]) => `${JSON.stringify(k)}:${serializeCanonical(v)}`,
    );
    return `{${parts.join(",")}}`;
  }
  throw new Error(`Unsupported JSON value type: ${typeof value}`);
}

/** Exact sorted JSON without NFKC normalization, matching Python `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. */
export function serializeExactSorted(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (value instanceof RawNumber || typeof value === "number") {
    return canonicalNumberText(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => serializeExactSorted(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const sorted = Object.entries(value as Record<string, unknown>).sort(([ka], [kb]) => compareCodePoints(ka, kb));
    const parts = sorted.map(([k, v]) => `${JSON.stringify(k)}:${serializeExactSorted(v)}`);
    return `{${parts.join(",")}}`;
  }
  throw new Error(`Unsupported JSON value type: ${typeof value}`);
}

/** Canonical JSON exactly as `mcp_airlock.core.normalize.canonical_json_bytes` writes it (as a string). */
export function canonicalJsonString(value: unknown): string {
  return serializeCanonical(normalizeCanonicalValue(value));
}

/** Convert parsed ledger data to ordinary JS values (numbers as `number`) for display. */
function toPlain(value: unknown): unknown {
  if (value instanceof RawNumber) {
    return value.value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => toPlain(item));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      defineOwn(out, k, toPlain(v));
    }
    return out;
  }
  return value;
}

async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof RawNumber);
}

const VALID_SEVERITIES = new Set<Severity>(["ALLOW", "INFO", "WARN", "BLOCK", "AAD_FIRE"]);
const VALID_ZONES = new Set<Zone>(["core", "egress", "airlock", "ir_lab"]);
const VALID_REDACTION_KINDS = new Set(["canary", "secret", "high_entropy", "blocked_pattern"]);

// Exact field sets of the Python models (`AuditLedgerEntry`, `ZoneEvent`, `RedactionRecord`). Python writes every
// field on every line and its schema forbids extras, so anything else means the line was not written by the ledger.
const ENTRY_KEYS = ["entry_hash", "event", "prev_hash", "seq"] as const;
const EVENT_KEYS = [
  "action",
  "artifact_sha256",
  "event_id",
  "metadata",
  "reason",
  "redactions",
  "request_id",
  "rule_id",
  "severity",
  "timestamp_utc",
  "tool_name",
  "verdict_allow",
  "zone",
] as const;
const REDACTION_KEYS = ["field_path", "kind", "match_sha256", "rule_id"] as const;

function hasExactKeys(obj: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(obj);
  return own.length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(obj, k));
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function validateRedaction(raw: unknown): boolean {
  return (
    isPlainRecord(raw) &&
    hasExactKeys(raw, REDACTION_KEYS) &&
    typeof raw.kind === "string" &&
    VALID_REDACTION_KINDS.has(raw.kind) &&
    isNonEmptyString(raw.rule_id) &&
    isNonEmptyString(raw.field_path) &&
    typeof raw.match_sha256 === "string" &&
    SHA256_HEX_RE.test(raw.match_sha256)
  );
}

function validateRawEvent(raw: unknown): raw is Record<string, unknown> {
  if (!isPlainRecord(raw) || !hasExactKeys(raw, EVENT_KEYS)) {
    return false;
  }
  if (
    !isNonEmptyString(raw.event_id) ||
    !isNonEmptyString(raw.timestamp_utc) ||
    typeof raw.zone !== "string" ||
    !VALID_ZONES.has(raw.zone as Zone) ||
    !isNonEmptyString(raw.action) ||
    typeof raw.verdict_allow !== "boolean" ||
    typeof raw.severity !== "string" ||
    !VALID_SEVERITIES.has(raw.severity as Severity) ||
    !isNonEmptyString(raw.rule_id) ||
    !isNonEmptyString(raw.reason) ||
    typeof raw.artifact_sha256 !== "string" ||
    !SHA256_HEX_RE.test(raw.artifact_sha256) ||
    !(raw.tool_name === null || typeof raw.tool_name === "string") ||
    !(raw.request_id === null || typeof raw.request_id === "string" ||
      (raw.request_id instanceof RawNumber && raw.request_id.isInteger)) ||
    !Array.isArray(raw.redactions) ||
    !raw.redactions.every((r) => validateRedaction(r)) ||
    !isPlainRecord(raw.metadata)
  ) {
    return false;
  }
  if ((raw.severity === "BLOCK" || raw.severity === "AAD_FIRE") && raw.verdict_allow) {
    return false;
  }
  return true;
}

function makeCompromisedReport(
  ledgerName: string,
  entryCount: number,
  firstInvalidSeq: number | null,
  reason: string,
): IncidentReport {
  return {
    status: "INTEGRITY_COMPROMISED",
    chain_valid: false,
    provenance: "browser_verified",
    verification: {
      ledger_path: ledgerName,
      valid: false,
      entry_count: entryCount,
      last_seq: entryCount > 0 ? entryCount - 1 : null,
      last_hash: null,
      first_invalid_seq: firstInvalidSeq,
      first_invalid_line: firstInvalidSeq !== null ? firstInvalidSeq + 1 : null,
      anchored: false,
      reason,
    },
    session_count: 0,
    total_events: 0,
    unconfirmed_aad_triggers: 0,
    observed_aad_count: 0,
    observed_block_count: 0,
    sessions: [],
    terminal_event: null,
  };
}

/**
 * Verify an `audit.jsonl` ledger in the browser with the same checks as Python's `verify_ledger`: exact schema
 * (no extra or missing fields), contiguous `seq`, the hash chain, each `entry_hash`, and that every line is in
 * canonical form, including Python's number spelling. It cannot check an external anchor, so tail truncation is
 * not detected; `mellyn-ir --anchor-seq/--anchor-hash` remains the authoritative check.
 */
export async function verifyAndReconstructAirlockJsonl(
  jsonlText: string,
  ledgerName = "uploaded-audit.jsonl",
): Promise<IncidentReport> {
  const normalizedNewlines = jsonlText.replace(/\r\n/g, "\n");
  if (!normalizedNewlines.trim()) {
    return {
      status: "CLEAN",
      chain_valid: true,
      provenance: "browser_verified",
      verification: {
        ledger_path: ledgerName,
        valid: true,
        entry_count: 0,
        last_seq: null,
        last_hash: null,
        first_invalid_seq: null,
        first_invalid_line: null,
        anchored: false,
        reason: null,
      },
      session_count: 0,
      total_events: 0,
      unconfirmed_aad_triggers: 0,
      observed_aad_count: 0,
      observed_block_count: 0,
      sessions: [],
      terminal_event: null,
    };
  }

  if (!normalizedNewlines.endsWith("\n")) {
    return makeCompromisedReport(ledgerName, 0, 0, "Audit ledger is truncated (missing trailing newline).");
  }

  const lines = normalizedNewlines.slice(0, -1).split("\n");
  let expectedPrev = GENESIS_PREV_HASH;
  let lastHash: string | null = null;
  const parsedEntries: Array<{ seq: number; event: Record<string, unknown> }> = [];

  for (let expectedSeq = 0; expectedSeq < lines.length; expectedSeq += 1) {
    const line = lines[expectedSeq] ?? "";
    if (!line) {
      return makeCompromisedReport(ledgerName, expectedSeq, expectedSeq, `Blank line encountered at seq ${expectedSeq}.`);
    }

    let obj: unknown;
    try {
      obj = parseJsonPreservingNumbers(line);
    } catch {
      return makeCompromisedReport(ledgerName, expectedSeq, expectedSeq, `Malformed JSON at seq ${expectedSeq}.`);
    }

    if (!isPlainRecord(obj) || hasInvisibleUnicode(obj)) {
      return makeCompromisedReport(
        ledgerName,
        expectedSeq,
        expectedSeq,
        `Invalid entry structure or invisible Unicode detected at seq ${expectedSeq}.`,
      );
    }

    if (
      !hasExactKeys(obj, ENTRY_KEYS) ||
      !(obj.seq instanceof RawNumber) ||
      !obj.seq.isInteger ||
      obj.seq.value < 0 ||
      typeof obj.prev_hash !== "string" ||
      !SHA256_HEX_RE.test(obj.prev_hash) ||
      typeof obj.entry_hash !== "string" ||
      !SHA256_HEX_RE.test(obj.entry_hash) ||
      !validateRawEvent(obj.event)
    ) {
      return makeCompromisedReport(
        ledgerName,
        expectedSeq,
        expectedSeq,
        `Schema validation failed at seq ${expectedSeq}.`,
      );
    }

    if (obj.seq.value !== expectedSeq) {
      return makeCompromisedReport(
        ledgerName,
        expectedSeq,
        expectedSeq,
        `Sequence mismatch at index ${expectedSeq}: found seq ${obj.seq.raw}.`,
      );
    }

    if (obj.prev_hash !== expectedPrev) {
      return makeCompromisedReport(
        ledgerName,
        expectedSeq,
        expectedSeq,
        `Hash chain break at seq ${expectedSeq}: prev_hash does not match prior entry_hash.`,
      );
    }

    let expectedEntryHash: string;
    let canonicalDisk: string;
    try {
      expectedEntryHash = await sha256Hex(
        canonicalJsonString({ seq: obj.seq, prev_hash: obj.prev_hash, event: obj.event }),
      );
      canonicalDisk = canonicalJsonString(obj);
    } catch {
      return makeCompromisedReport(
        ledgerName,
        expectedSeq,
        expectedSeq,
        `Entry at seq ${expectedSeq} cannot be put in canonical form.`,
      );
    }
    if (obj.entry_hash !== expectedEntryHash) {
      return makeCompromisedReport(
        ledgerName,
        expectedSeq,
        expectedSeq,
        `Tampered entry content at seq ${expectedSeq}: entry_hash mismatch.`,
      );
    }

    if (line !== canonicalDisk) {
      return makeCompromisedReport(
        ledgerName,
        expectedSeq,
        expectedSeq,
        `Non-canonical encoding / mid-log byte tampering at seq ${expectedSeq}.`,
      );
    }

    expectedPrev = obj.entry_hash;
    lastHash = obj.entry_hash;
    parsedEntries.push({ seq: expectedSeq, event: toPlain(obj.event) as Record<string, unknown> });
  }

  const grouped = new Map<string, Array<{ seq: number; event: Record<string, unknown> }>>();
  for (const item of parsedEntries) {
    const meta = isPlainRecord(item.event.metadata) ? item.event.metadata : {};
    const sid = typeof meta.session_id === "string" && meta.session_id ? meta.session_id : "default";
    const bucket = grouped.get(sid);
    if (bucket) {
      bucket.push(item);
    } else {
      grouped.set(sid, [item]);
    }
  }

  const sessions: SessionTimeline[] = [];
  const allAadTriggers: TerminalTrigger[] = [];
  let sawEnforcedBlock = false;
  let observedAadCount = 0;
  let observedBlockCount = 0;

  for (const [sid, sidEntries] of grouped.entries()) {
    const zonesTraversed: Zone[] = [];
    const zoneTransitions: string[] = [];
    const blockPrecursors: TimelineEvent[] = [];
    const events: TimelineEvent[] = [];
    const aadTriggers: TerminalTrigger[] = [];
    const aadIndexById = new Map<string, number>();
    let prevZone: Zone | null = null;
    let sessionMode: "enforce" | "observe" | null = null;

    for (const entry of sidEntries) {
      const ev = entry.event;
      const meta = isPlainRecord(ev.metadata) ? ev.metadata : {};
      const ruleId = String(ev.rule_id);
      const zone = ev.zone as Zone;
      const severity = ev.severity as Severity;
      const reasonCode = mapReasonCode(ruleId);
      const rpcId =
        typeof ev.request_id === "string" || typeof ev.request_id === "number" ? ev.request_id : null;
      const toolName = typeof ev.tool_name === "string" ? ev.tool_name : null;
      const isObserved = meta.enforcement_mode === "observe";
      if (ruleId === SESSION_STARTED_RULE_ID) {
        if (meta.enforcement_mode === "observe") {
          sessionMode = "observe";
        } else if (meta.enforcement_mode === "enforce") {
          sessionMode = "enforce";
        }
      }

      const tEv: TimelineEvent = {
        seq: entry.seq,
        timestamp_utc: String(ev.timestamp_utc),
        session_id: sid,
        zone,
        action: String(ev.action),
        severity,
        verdict_allow: Boolean(ev.verdict_allow),
        rule_id: ruleId,
        reason_code: reasonCode,
        reason: String(ev.reason),
        tool_name: toolName,
        rpc_id: rpcId,
        artifact_sha256: String(ev.artifact_sha256),
      };
      events.push(tEv);

      if (!zonesTraversed.includes(zone)) {
        zonesTraversed.push(zone);
      }
      if (prevZone !== null && prevZone !== zone) {
        zoneTransitions.push(`${prevZone} -> ${zone}`);
      }
      prevZone = zone;

      if (severity === "BLOCK") {
        if (isObserved) {
          observedBlockCount += 1;
        } else {
          sawEnforcedBlock = true;
        }
        blockPrecursors.push(tEv);
      } else if (severity === "AAD_FIRE") {
        if (isObserved) {
          observedAadCount += 1;
        } else {
          const eventId = String(ev.event_id);
          aadIndexById.set(eventId, aadTriggers.length);
          aadTriggers.push({
            seq: entry.seq,
            timestamp_utc: String(ev.timestamp_utc),
            session_id: sid,
            zone,
            action: String(ev.action),
            rule_id: ruleId,
            reason_code: reasonCode,
            rpc_id: rpcId,
            tool_name: toolName,
            artifact_sha256: String(ev.artifact_sha256),
            redacted_summary: String(ev.reason),
            trigger_event_id: eventId,
            containment_confirmed: false,
            containment_seq: null,
          });
        }
      } else if (ruleId === AAD_CONTAINMENT_CONFIRMED_RULE_ID) {
        const refId = meta.trigger_event_id;
        if (typeof refId === "string") {
          const idx = aadIndexById.get(refId);
          if (idx !== undefined) {
            const existing = aadTriggers[idx];
            if (existing && entry.seq > existing.seq && !existing.containment_confirmed) {
              aadTriggers[idx] = {
                ...existing,
                containment_confirmed: true,
                containment_seq: entry.seq,
              };
            }
          }
        }
      }
    }

    let sessionTerminal: TerminalTrigger | null = null;
    if (aadTriggers.length > 0) {
      const unconfirmed = aadTriggers.filter((t) => !t.containment_confirmed);
      sessionTerminal =
        (unconfirmed.length > 0 ? unconfirmed[unconfirmed.length - 1] : aadTriggers[aadTriggers.length - 1]) ?? null;
      allAadTriggers.push(...aadTriggers);
    }

    sessions.push({
      session_id: sid,
      event_count: events.length,
      zones_traversed: zonesTraversed,
      zone_transitions: zoneTransitions,
      block_precursors: blockPrecursors,
      terminal_event: sessionTerminal,
      events,
      enforcement_mode: sessionMode,
    });
  }

  const unconfirmedTriggers = allAadTriggers.filter((t) => !t.containment_confirmed);
  const unconfirmedCount = unconfirmedTriggers.length;
  const globalTerminal: TerminalTrigger | null =
    (unconfirmedTriggers.length > 0
      ? unconfirmedTriggers[unconfirmedTriggers.length - 1]
      : allAadTriggers[allAadTriggers.length - 1]) ?? null;

  let status: IncidentStatus;
  if (unconfirmedCount > 0) {
    status = "AAD_TRIGGERED_UNCONFIRMED";
  } else if (allAadTriggers.length > 0) {
    status = "AAD_CONTAINED";
  } else if (sawEnforcedBlock) {
    status = "BLOCKED_ACTIVITY";
  } else if (observedAadCount > 0 || observedBlockCount > 0) {
    status = "OBSERVED_VIOLATIONS";
  } else {
    status = "CLEAN";
  }

  return {
    status,
    chain_valid: true,
    provenance: "browser_verified",
    verification: {
      ledger_path: ledgerName,
      valid: true,
      entry_count: parsedEntries.length,
      last_seq: parsedEntries.length - 1,
      last_hash: lastHash,
      first_invalid_seq: null,
      first_invalid_line: null,
      anchored: false,
      reason: null,
    },
    session_count: sessions.length,
    total_events: parsedEntries.length,
    unconfirmed_aad_triggers: unconfirmedCount,
    observed_aad_count: observedAadCount,
    observed_block_count: observedBlockCount,
    sessions,
    terminal_event: globalTerminal,
  };
}

export async function parseAirlockInput(text: string, filename = "audit.jsonl"): Promise<IncidentReport> {
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) {
    try {
      const obj: unknown = JSON.parse(trimmed);
      if (isPlainRecord(obj) && typeof obj.status === "string" && isPlainRecord(obj.verification) && Array.isArray(obj.sessions)) {
        // A pre-built report (for example `mellyn-ir --json` output) carries its own verdict, which this browser
        // cannot check. Mark it so the UI never presents it as verified here.
        return { ...(obj as unknown as IncidentReport), provenance: "imported_unverified" };
      }
    } catch {
      // Fall through to JSONL chain verification.
    }
  }
  return verifyAndReconstructAirlockJsonl(text, filename);
}

function extractGatewayEvent(obj: Record<string, unknown>): GatewayAuditEvent {
  const ev: GatewayAuditEvent = {
    audit_id: String(obj.audit_id),
    timestamp: String(obj.timestamp),
    session_id: String(obj.session_id),
    tool_name: String(obj.tool_name),
    mcp_server: typeof obj.mcp_server === "string" ? obj.mcp_server : null,
    decision: String(obj.decision),
    risk_tier: typeof obj.risk_tier === "string" ? obj.risk_tier : "HIGH",
    tainted: Boolean(obj.tainted),
    taint_sources: Array.isArray(obj.taint_sources) ? obj.taint_sources.map(String) : [],
    args_sha256: typeof obj.args_sha256 === "string" ? obj.args_sha256 : "",
    reasons: Array.isArray(obj.reasons) ? obj.reasons.map(String) : [],
    policy_id: typeof obj.policy_id === "string" ? obj.policy_id : null,
    grant_id: typeof obj.grant_id === "string" ? obj.grant_id : null,
    event_type: typeof obj.event_type === "string" ? obj.event_type : "authorization",
    taint_count:
      obj.taint_count instanceof RawNumber
        ? obj.taint_count.value
        : typeof obj.taint_count === "number"
          ? obj.taint_count
          : 0,
  };
  if (obj.seq instanceof RawNumber && obj.seq.isInteger) {
    ev.seq = obj.seq.value;
  } else if (typeof obj.seq === "number" && Number.isInteger(obj.seq)) {
    ev.seq = obj.seq;
  }
  if (typeof obj.prev_hash === "string") {
    ev.prev_hash = obj.prev_hash;
  }
  if (typeof obj.entry_hash === "string") {
    ev.entry_hash = obj.entry_hash;
  }
  if (typeof obj.enforcement_mode === "string") {
    ev.enforcement_mode = obj.enforcement_mode;
  }
  return ev;
}

interface ParsedGatewayLine {
  lineNo: number;
  rawObj: Record<string, unknown> | null;
  parseError: string | null;
}

function scanGatewayAuditLines(text: string): {
  events: GatewayAuditEvent[];
  rows: ParsedGatewayLine[];
  totalLines: number;
  malformedLines: number;
} {
  const events: GatewayAuditEvent[] = [];
  const rows: ParsedGatewayLine[] = [];
  let totalLines = 0;
  let malformedLines = 0;

  const rawLines = text.split(/\r?\n/);
  for (let i = 0; i < rawLines.length; i += 1) {
    const lineNo = i + 1;
    const trimmed = (rawLines[i] ?? "").trim();
    if (!trimmed) {
      continue;
    }
    totalLines += 1;
    try {
      const obj = parseJsonPreservingNumbers(trimmed);
      if (
        isPlainRecord(obj) &&
        typeof obj.audit_id === "string" &&
        typeof obj.timestamp === "string" &&
        typeof obj.session_id === "string" &&
        typeof obj.tool_name === "string" &&
        typeof obj.decision === "string"
      ) {
        events.push(extractGatewayEvent(obj));
        rows.push({ lineNo, rawObj: obj, parseError: null });
      } else {
        malformedLines += 1;
        rows.push({ lineNo, rawObj: null, parseError: `Audit entry on line ${lineNo} is missing required fields.` });
      }
    } catch (err) {
      malformedLines += 1;
      const msg = err instanceof Error ? err.message : String(err);
      rows.push({ lineNo, rawObj: null, parseError: `Malformed JSON or duplicate key on line ${lineNo}: ${msg}` });
    }
  }

  return { events, rows, totalLines, malformedLines };
}

export function parseGatewayAuditJsonl(text: string): GatewayAuditPayload {
  const { events, totalLines, malformedLines } = scanGatewayAuditLines(text);
  return {
    events,
    total_lines: totalLines,
    returned_count: events.length,
    malformed_lines: malformedLines,
  };
}

export async function verifyGatewayAuditJsonl(text: string): Promise<GatewayAuditPayload> {
  const { events, rows, totalLines, malformedLines } = scanGatewayAuditLines(text);
  const hasChain = rows.some((row) => row.rawObj !== null && Object.prototype.hasOwnProperty.call(row.rawObj, "entry_hash"));
  if (!hasChain) {
    const firstErr = rows.find((row) => row.parseError !== null)?.parseError ?? null;
    if (firstErr !== null && text.includes('"entry_hash"')) {
      return {
        events,
        total_lines: totalLines,
        returned_count: events.length,
        malformed_lines: malformedLines,
        chain_valid: false,
        chain_reason: firstErr,
      };
    }
    return {
      events,
      total_lines: totalLines,
      returned_count: events.length,
      malformed_lines: malformedLines,
      chain_valid: null,
      chain_reason: null,
    };
  }

  let expectedSeq = 0;
  let expectedPrev = GENESIS_PREV_HASH;
  let chainValid = true;
  let chainReason: string | null = null;

  for (const row of rows) {
    if (row.parseError !== null || row.rawObj === null) {
      chainValid = false;
      chainReason = row.parseError ?? `Malformed JSON entry on line ${row.lineNo}.`;
      break;
    }
    const obj = row.rawObj;
    const seqVal = obj.seq;
    if (!(seqVal instanceof RawNumber) || !seqVal.isInteger || seqVal.value !== expectedSeq) {
      chainValid = false;
      chainReason = `Sequence mismatch on line ${row.lineNo}: expected seq=${expectedSeq}.`;
      break;
    }
    const prevHash = obj.prev_hash;
    if (typeof prevHash !== "string" || prevHash !== expectedPrev) {
      chainValid = false;
      chainReason = `Chain link mismatch on line ${row.lineNo}: prev_hash does not match previous entry_hash.`;
      break;
    }
    const entryHash = obj.entry_hash;
    if (typeof entryHash !== "string" || !SHA256_HEX_RE.test(entryHash)) {
      chainValid = false;
      chainReason = `Missing or malformed entry_hash on line ${row.lineNo}.`;
      break;
    }

    const bodyWithoutHash = Object.create(null) as Record<string, unknown>;
    for (const [k, v] of Object.entries(obj)) {
      if (k !== "entry_hash") {
        defineOwn(bodyWithoutHash, k, v);
      }
    }
    const expectedHash = await sha256Hex(serializeExactSorted(bodyWithoutHash));
    if (entryHash !== expectedHash) {
      chainValid = false;
      chainReason = `Entry digest mismatch on line ${row.lineNo} (tampered record).`;
      break;
    }

    expectedSeq += 1;
    expectedPrev = entryHash;
  }

  return {
    events,
    total_lines: totalLines,
    returned_count: events.length,
    malformed_lines: malformedLines,
    chain_valid: chainValid,
    chain_reason: chainReason,
  };
}

export function parseAssuranceReportJson(text: string): ControlAssuranceReport {
  const raw: unknown = JSON.parse(text);
  if (
    !isPlainRecord(raw) ||
    typeof raw.overall_status !== "string" ||
    !isPlainRecord(raw.summary) ||
    !isPlainRecord(raw.frameworks) ||
    !Array.isArray(raw.cases)
  ) {
    throw new Error("Assurance report JSON is missing required summary, frameworks, or cases fields.");
  }
  return raw as unknown as ControlAssuranceReport;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

export function validateLoopbackBaseUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim().replace(/\/+$/, "");
  if (trimmed === "") {
    return "";
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error("Base URL must be blank (same-origin) or a valid URL.");
  }
  if (parsed.username || parsed.password) {
    throw new Error("URLs with embedded credentials are forbidden.");
  }
  if (parsed.protocol === "https:") {
    return `${parsed.origin}${parsed.pathname === "/" ? "" : parsed.pathname}`;
  }
  if (parsed.protocol === "http:" && LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase())) {
    return `${parsed.origin}${parsed.pathname === "/" ? "" : parsed.pathname}`;
  }
  throw new Error("Plaintext http:// is permitted only for loopback hosts (127.0.0.1, localhost, [::1]).");
}

const APPROVAL_DEEP_LINK_RE = /^\/approvals\/(apr_[A-Za-z0-9_-]{8,64})\/?$/;
const APPROVALS_ROUTE_RE = /^\/approvals\/?$/;

export function parseApprovalDeepLink(pathname: string): string | null {
  const match = APPROVAL_DEEP_LINK_RE.exec(pathname.trim());
  return match?.[1] ?? null;
}

export function isApprovalsRoute(pathname: string): boolean {
  return APPROVALS_ROUTE_RE.test(pathname.trim()) || parseApprovalDeepLink(pathname) !== null;
}
