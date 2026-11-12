# Contributing

Thanks for helping. Two rules carry more weight than style here.

**1. Nothing may widen the scope gate.** Every adapter, redirect following,
webhook delivery, DNS lookup and crawler step must go through the validated
destination, not the hostname the caller typed. A pull request that adds a new
outbound path without a scope test will be asked for one.

**2. Do not claim detection you have not measured.** The lab in `strix.lab`
exists so precision/recall are numbers, not adjectives. A new detector needs an
oracle case; a finding must not claim a verification level the evidence does not
support (see `DETECTION_BENCHMARK.md`).

## Local setup

```bash
pip install -c constraints.txt -e ".[dev]"
ruff check src tests scripts
mypy
python scripts/check_secrets.py .
pytest
python -m strix.lab --no-nuclei --workflow web,network --report lab.json
```

CI runs exactly these on Python 3.12 and 3.13, plus a live-server smoke test and
a Docker build. If you cannot run one of them locally, say so in the pull
request rather than leaving it implied.

## Tests

`tests/` mirrors `src/strix/`. Two autouse fixtures shape every test: DNS is
deterministic and sockets may only reach loopback, so a test that would touch the
real network fails loudly instead of flaking. Use the `local_target` fixture for
HTTP behaviour rather than mocking the scope gate — the gate is usually what the
test is about.

## Boundaries worth knowing before you change things

- `strix/core/store.py` (synchronous, used by the worker, monitor, retention and
  CLI) and `strix/core/store_async.py` (async, used by the request path) are two
  implementations of one persistence API. They are known to have drifted; if you
  change a query in one, check the other. Consolidating them is the single most
  valuable refactor in the repository.
- Job state lives in SQLite; the queue lives in memory. One process, enforced by
  a lock file, until a shared queue exists.
- `STRIX_API_KEY` is a bootstrap administrator key, adopted at startup. Keys are
  stored as SHA-256 hashes and shown once.

## Commits

Small, focused commits with a message that explains why. Add a test for anything
that is not a one-liner. Do not add a dependency without discussing it first in
an issue — the runtime dependency list is deliberately short.
