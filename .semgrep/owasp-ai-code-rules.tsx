// Semgrep rule tests for owasp-ai-code-rules.yaml. Run from inside .semgrep/: semgrep --test .
// Intentionally insecure test input; excluded from repository scans and never built.
import DOMPurify from "dompurify";

declare const llmOutput: string;

export function Unsafe() {
  // ruleid: owasp-ai-ts-no-dynamic-code-eval
  eval(llmOutput);
  // ruleid: owasp-ai-ts-no-dynamic-code-eval
  const fn = new Function("a", llmOutput);
  // ruleid: owasp-ai-ts-no-dynamic-code-eval
  setTimeout("alert(1)", 100);
  // ok: owasp-ai-ts-no-dynamic-code-eval
  setTimeout(() => fn(), 100);

  // ruleid: owasp-ai-ts-insecure-random-for-security
  const token = Math.random().toString(36);
  // ok: owasp-ai-ts-insecure-random-for-security
  const safeToken = crypto.randomUUID();

  // ruleid: owasp-ai-ts-dangerously-set-inner-html
  const raw = <div dangerouslySetInnerHTML={{ __html: llmOutput }} />;
  // ok: owasp-ai-ts-dangerously-set-inner-html
  const sanitized = <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(llmOutput) }} />;
  // ok: owasp-ai-ts-dangerously-set-inner-html
  const text = <p>{llmOutput}</p>;

  return [raw, sanitized, text, token, safeToken];
}
