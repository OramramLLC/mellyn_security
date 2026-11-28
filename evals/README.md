# Mellyn Security — External Evaluation Suite (`evals/`)

This directory contains isolated external security harnesses designed for **Google Colab** (with automatic GPU VRAM model selection across **A100 80GB**, **A100 40GB**, **L4 24GB**, and **T4 16GB**) using open-weight **Qwen3** models served locally via **vLLM** (`--enable-auto-tool-choice --tool-call-parser hermes`). Running against local open-weights avoids third-party API moderation blocks when testing prompt injections, canary exfiltration, guardrail tampering, and SSRF probes.

## Harnesses Included

1. **`evals/fuzzer/` (`mcp-fuzzer` / `mcp-server-fuzzer`)**
   - `target_mcp_server.py`: Stdlib MCP 2025-06-18 stdio target server (`read_note`, `write_note`, `echo_status`).
   - `run_fuzzer.py`: Automatically generates a strict AgBOM-pinned TOML policy and drives either the built-in `--mode smoke` suite or external `--mode mcp-fuzzer` CLI against `mellyn.airlock.proxy`, followed by `verify_chain` / `reconstruct_incident` ledger verification and zero-canary checks.
2. **`evals/promptfoo/` (`Promptfoo`)**
   - `eval_mcp_server.py`: Mock workspace & mock outbound comms/HTTP sink server (zero real external network traffic).
   - `mellyn_mcp_provider.py`: Promptfoo custom Python provider running side-by-side tool-calling loops with **Mellyn OFF (`direct`)** vs. **Mellyn ON (`airlock`)**.
   - `promptfooconfig.yaml`: 12 A/B test cases (benign utility, `.env` read, canary exfiltration plain/Base64, indirect prompt injection, `.gitleaks.toml`/`.env` tampering, cloud metadata SSRF, unauthorized recipients, traversal, invisible Unicode smuggling).
3. **`evals/agentdojo/` (`AgentDojo`)**
   - `mellyn_defense.py`: `MellynToolGate` wrapping `Authorizer`, `ScannerConfig`/`scan_value`, and hash-chained `AuditLogger`, plus `build_mellyn_tools_executor()`.
   - `run_agentdojo.py`: Evaluates **Baseline (OFF)** vs. **`MellynToolGate` (ON)** across `workspace`, `banking`, `slack`, and `travel` suites, outputting `agentdojo_scorecard.json` and `agentdojo_scorecard.md`.
4. **`evals/colab_a100_eval.ipynb`**
   - Ready-to-run Colab A100 notebook orchestrating vLLM, all three harnesses, and `mellyn-ir` verification.

## Quick Start (Colab A100 / Local Eval Venv)

```bash
# 1. Install Mellyn + eval dependencies (intentionally kept outside root lockfiles)
pip install -e . vllm mcp-fuzzer agentdojo==0.1.35

# 2. Start vLLM matching your GPU VRAM:
#    - A100 80GB: Qwen/Qwen3-30B-A3B-Instruct-2507 (BF16 MoE, drop the --reasoning-parser flags)
#    - A100 40GB: Qwen/Qwen3-32B-AWQ (--max-model-len 16384)
#    - L4 24GB:   Qwen/Qwen3-14B-AWQ (--max-model-len 16384 --max-num-seqs 4)
#    - T4 16GB:   Qwen/Qwen3-8B-AWQ  (--max-model-len 8192 --max-num-seqs 4 --dtype half)
python -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen3-32B-AWQ \
  --host 127.0.0.1 --port 8000 \
  --enable-auto-tool-choice --tool-call-parser hermes \
  --reasoning-parser qwen3 --default-chat-template-kwargs '{"enable_thinking": false}' \
  --max-model-len 16384 --gpu-memory-utilization 0.90

export OPENAI_BASE_URL=http://127.0.0.1:8000/v1
export OPENAI_API_KEY=EMPTY
export MELLYN_EVAL_MODEL=Qwen/Qwen3-32B-AWQ

# 3. Run the harnesses
python -m evals.fuzzer.run_fuzzer --mode smoke --output-dir outputs/fuzzer_smoke
python -m evals.fuzzer.run_fuzzer --mode mcp-fuzzer --runs 25 --output-dir outputs/fuzzer_live
PROMPTFOO_PYTHON="$(which python)" npx -y promptfoo@latest eval \
  -c evals/promptfoo/promptfooconfig.yaml -o outputs/promptfoo/results.json --no-cache -j 1
python -m evals.agentdojo.run_agentdojo --suites workspace banking slack travel --output-dir outputs/agentdojo
```
