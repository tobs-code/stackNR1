# stackNR1 — Agent Control Stack (v0.1, prototype)

A fail-closed control layer for agent actions. The agent may propose an action,
but it never executes it itself: a policy gate has to authorize it first, and the
effect is carried out by a separate worker process against PostgreSQL. If
anything is unclear — timeout, error, missing authorization, stale state — there
is **no effect**.

> **Status:** work in progress, reference prototype, not a production system.
> Spec v0.1 is frozen at Rev. 7 (SHA-256 `F2BDE27F…C2B8B3`, see
> `BUILD_MANIFEST.md`). Phases 1 and 2 (F1, F2, F3, F4, F7, F10) are
> implemented; later phases are still open. A green test run is **not** a
> security proof.

## How it works

```
proposal ──► gate ──────────────────► authorization record (hash)
             schema / capability           │
             target binding                ▼
             OPA policy              worker process
                                    reload + verify record
                                           │
                                           ▼
                                    DB function (one transaction)
                                    auth · target · run active
                                    version/CAS · idempotency
                                    lifecycle (status + history)
                                           │
                                           ▼
                                    effect + transitions + outbox
```

The database — not the process — is the security boundary for the protected
operations. Runtime roles cannot modify `records`, `authorization_records`,
`outbox_events`, or `evidence_ledger` directly: protected writes go through
`SECURITY DEFINER` functions owned by `stack_owner` that re-check every
invariant themselves. Gate and recovery keep narrowly scoped writes on
`actions` / `policy_decisions` (create, deny, quarantine).

## Target invariants and current status

| ID | Invariant | Status |
|----|-----------|--------|
| I1 | **No bypass:** no effect without a persisted authorization record. Execution runs in a separate worker process (`python -m control_stack.worker.server`) with its own DB credentials; the DB re-checks record, target, run, and version in one transaction. | enforced |
| I2 | **Deny dominates:** only `allow == true` with no violations continues. OPA timeout (500 ms), unreachable OPA, invalid JSON, non-boolean allow, or any violation ⇒ exception, nothing persisted. | enforced |
| I3 | **Binding:** immutable authorization record over a JCS-canonicalized field set (SHA-256). The gate is INSERT-only, worker and recovery have SELECT only, so runtime roles cannot update or delete it. The worker reloads the record and re-derives the canonical hash; the DB function compares record and action row. | enforced |
| I4 | **Stale reject:** version check and CAS (`UPDATE … WHERE version = expected`) in the *same* transaction. | enforced |
| I5 | **Idempotency:** server-side key `run_id:action_id`, `UNIQUE`; replay of the stored result under a row lock; same key with a different payload is rejected. | partial — the `idempotency_conflict` evidence event is missing (audit F6, phase 3) |
| I6 | **Outcome unknown:** unknown commit outcome becomes `outcome_unknown`; reconcile inspects persisted state instead of trusting client errors. | enforced — recovery writes a legal transition history and never advances status without a matching `action_transitions` row (audit F3/F10) |
| I7 | **Deny fingerprint:** the same run/action/target/args denied within 15 minutes is annotated with `repeat_of`. | enforced (limited by design: no guarantee against semantic rewording) |
| I8 | **Manual approval:** no approval path in v0.1. | deferred |

## What this is not

- No LLM runtime, no agent loop, no HTTP API, no UI. This is the control layer
  an agent runtime would call.
- Only two demo actions exist (`demo_read`, `demo_update_record`); both act on
  PostgreSQL. There are deliberately **no external side effects** yet.
- Manual approval is not implemented; owner/superuser is outside the threat
  model.
- The audit findings F5, F6, F8, F9 are still open (see roadmap). F3 and F10
  were closed in phase 2.

## Tech

Python 3.12+, pydantic 2.10.4, psycopg 3.2.4, PostgreSQL 16, OPA 0.68 (Rego),
pytest 8.3.4, Docker Compose.

## Repository layout

```
src/control_stack/   gate, execution broker, state, evidence, recovery, policy, worker, mig
migrations/          schema and role/boundary migrations 001–010
policies/            Rego policies (authorization + invariants)
tests/               unit, integration, adversarial
config/              action registry, security config
docs/                frozen spec, audit report, ADR, acceptance matrix, campaign
```

## Quickstart

Prerequisites: Docker and Python 3.12+.

```bash
# 1. Postgres 16 on 5433 + OPA 0.68 on 8181
#    PowerShell: Set-Content .env 'POSTGRES_PASSWORD=testpw'
printf 'POSTGRES_PASSWORD=testpw\n' > .env
docker compose up -d

# 2. Python environment
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e .
pip install "pytest==8.3.4"

# 3. Test database (one-time)
python -c "import psycopg; c=psycopg.connect('dbname=postgres user=control_stack password=testpw host=127.0.0.1 port=5433', autocommit=True); c.execute('CREATE DATABASE control_stack_test'); c.close()"

# 4. Migrate both databases (idempotent)
python -m control_stack.mig.runner "dbname=control_stack user=control_stack password=testpw host=127.0.0.1 port=5433"
python -m control_stack.mig.runner "dbname=control_stack_test user=control_stack password=testpw host=127.0.0.1 port=5433"

# 5. Run the suite
pytest -q
```

Reset everything with `docker compose down -v`.

The adversarial tests use the real runtime roles (`stack_gate`, `stack_worker`,
`stack_recovery`) and assert on persisted database state, not just on status
codes or exceptions.

## Roadmap

The internal audit (`docs/audit-nr1-report.md`) lists 10 findings; the phasing
matches the audit recommendation.

| Phase | Content | Status |
|-------|---------|--------|
| 1 | F1 target binding, F2 atomic run status, F4 fake commit, F7 DB as boundary | implemented |
| 2 | F3, F10: lifecycle transitions, pair CHECKs, DB-enforced status history | implemented |
| 3 | F5, F6, F8: evidence sequence, `idempotency_conflict` event, checkpoint anchor | open |
| 4 | F9: read contract + negative matrix | open |

## Documentation

- `docs/spec-v0.1.md` — frozen specification (Rev. 6)
- `docs/audit-nr1-report.md` — frozen audit report (F1–F10)
- `docs/adr-001-f7-db-enforced-boundary.md` — decision: DB-enforced boundary
- `docs/acceptance-phase-1.md` — binding phase-1 acceptance matrix
- `docs/acceptance-phase-2.md` — binding phase-2 acceptance matrix (F3/F10)
- `docs/campaign-report.md` — last documented campaign run (81/81 at `e91b849`)
- `BUILD_MANIFEST.md` — frozen spec hash and change log

There is currently no hosted CI pipeline; run the suite locally as shown above.

## Related

[policy-gate](https://github.com/tobs-code/policy-gate): deterministic,
allowlist-first policy gate for LLM applications.
