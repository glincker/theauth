# Policy engine benchmarks

Measures the unified policy engine across four evaluation paths.

## How to run

```sh
# From repo root
pnpm bench

# Or scoped to the core package
pnpm --filter kavachos bench
```

Requires no extra dependencies. `vitest bench` uses `tinybench` internally, which is already a transitive dependency.

## Scenarios

| Name | What it exercises |
|---|---|
| warm cache hit | LRU hit, no DB touch, pure in-memory path |
| cold path - direct permission | Cache miss, one DB query to fetch agent permissions, no role or graph lookup |
| cold path - rbac role expansion | Cache miss, org membership + role join to derive permissions |
| cold path - rebac graph lookup | Cache miss, ReBAC relationship tuple check against the graph |

Each scenario runs for 1 second. The throughput check (1,000 warm-cache evaluations) runs once after the suite in `afterAll` and warns on stderr if it misses the target.

## Targets (M-series, single-threaded)

| Path | p99 target |
|---|---|
| Warm cache hit | < 1 ms |
| Cold direct permission | < 5 ms |
| Cold RBAC expansion | < 5 ms |
| Cold ReBAC walk | < 5 ms |
| Throughput (warm cache) | ≥ 50,000 evals/sec |

Targets are soft-enforced for v1: misses write a warning to stderr but exit 0. A hard CI gate (fail on 20% regression from the previous main run baseline) is tracked as a follow-up.

## Data setup

Each run creates a fresh in-memory SQLite database with:
- 1 user
- 1 agent (owned by the user)
- 5 direct permissions (mix of plain, wildcard, and relation-scoped)
- 1 org, 1 role, 1 org membership (for the RBAC path)
- 1 ReBAC resource + 1 relationship tuple (for the ReBAC path)
