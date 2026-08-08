# v0.2 Hard Release Gates

Spec section 42 lists twelve conditions that block tagging v0.2. Each is
enforced by an automated test (or an architectural invariant) below. Status is
as of this reference implementation.

| # | Gate (must NOT be true) | Enforced by | Status |
|---|--------------------------|-------------|--------|
| 1 | Retriever can access private network addresses | `tests/security/test_ssrf.py` — scheme/IP/DNS-rebind/redirect-to-private tests; `GuardedBackend` pins connections to validated IPs | ✅ |
| 2 | High-confidence identity precision below target | `tests/benchmark/test_identity_precision.py` — precision ≥ 0.98 on the corpus (currently 1.00) | ✅ |
| 3 | LLM can trigger external actions | `ai/provider.py` has no tools/network beyond one chat endpoint; `tests/security/test_ai_containment.py` rejects any extra output field | ✅ |
| 4 | Sensitive API keys appear in logs | Keys live in the OS keyring / encrypted vault only; `provider_settings` refuses secret-like fields (`tests/unit/test_storage.py`); logs use redaction (`security/redaction.py`) | ✅ |
| 5 | Raw pages retained indefinitely | Scanner discards response bodies after extraction; only URL/title/hash/snippet/observations are stored (spec §9, §21) | ✅ |
| 6 | External scripts execute in the local UI | CSP `default-src 'none'`, no external `script-src`/`connect-src`; self-contained inline UI (`tests/security/test_app_security.py`) | ✅ |
| 7 | Removal links enter the registry without provenance | `RegistryEntry` requires ≥1 source URL and validates URL safety; `tests/security/test_registry.py` | ✅ |
| 8 | App claims deletion where only delisting occurred | Verification reports observed states only; wording "not observed in the tested search" (`remediation/verification.py`, `tests/integration/test_verification.py`) | ✅ |
| 9 | Search-provider failure appears as zero findings | Scanner records `provider_errors` and marks the scan `INCOMPLETE`; never silent zero (`scanner.py`, `tests/integration/test_scan_pipeline.py`) | ✅ |
| 10 | User cannot delete the local workspace completely | `POST /api/v1/danger/delete-all` deletes DB + WAL/SHM + key material + vault (`tests/unit/test_storage.py::test_delete_all_removes_db_file`) | ✅ |
| 11 | An ordinary scan requires an Exposure-operated server | No Exposure server exists; all processing is local. `ManualURLProvider` works with no search API at all | ✅ |
| 12 | AI is required for basic operation | Default `ai_mode = NO_AI`; `NullProvider`; deterministic explanations always available (`tests/security/test_ai_containment.py::test_null_provider_returns_none`) | ✅ |

## How to re-verify

```bash
pip install -e ".[dev,pdf]"
ruff check src tests
mypy
pytest -q
pytest tests/benchmark -q -s      # prints precision/recall
pip-audit
```

All of the above run in CI (`.github/workflows/ci.yml`).
