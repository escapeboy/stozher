# Gateway integration constraints — Harbormaster v27.1.3

Empirical reconnaissance of `~/htdocs/harbormaster` @ `4f07955`, `__version__ = "27.1.3"`
(`src/harbormaster/__init__.py:6`). Findings were **observed** (commands run, files read), not
inferred. Binding input to S2 — read this before writing gateway code.

Config-surface decision derived from finding #1 is recorded separately in
**ADR-0005**; the "must be authored, not extended" finding is **ADR-0004**.

---

## 1. Config: `extra="forbid"` everywhere → resolved by ADR-0005

`_FORBID_EXTRA = ConfigDict(extra="forbid")` (`config.py:21`) is applied to every model including
`HarbormasterConfig` (`config.py:449`). An undeclared TOML section is a **hard boot failure**
(verified empirically). Loader: `load_config()` (`config.py:495-507`); search path
`./.harbormaster.toml` then `${XDG_CONFIG_HOME:-~/.config}/harbormaster/config.toml`, first match
wins, not merged (`config.py:487-492`).

**Per ADR-0005: the gateway reads its own `stozher-gateway.toml` and `STOZHER_*` env vars only.
Do not add a field to `HarbormasterConfig`. Do not modify anything under `src/harbormaster/`.**
Activation uses the already-shipped `[plugins] enabled/allow` keys (`config.py:258-266`).

Conventions to imitate in our own config models: `enabled: bool = False` gating; `*_env` field
naming the env var holding a secret, never the secret (`config.py:141`); `Field(..., gt=0)` bounds;
`Literal[...]` enums; `@field_validator` for cross-field rules (`config.py:291-300`).

## 2. The codebase is threads + blocking I/O, NOT asyncio

`async def` appears in only 7 files, all UI/transport. **Zero MCP tools are async** — every tool is
a sync `def` inside `register()` (e.g. `tools/ask.py:11-75`). Tool I/O bottoms out in
`subprocess.run`/`Popen` (`backends/claude.py:146,266,429`; `ssh.py:80`). `httpx` appears only
under the `[fleetq]` extra and only as the **sync** `httpx.Client` (`fleetq/bridge.py:73`),
driven from daemon threads.

**Two sync dispatch sites would silently break on an `async def` tool** — they call
`tool.fn(**arguments)` directly and never await:

- `src/harbormaster/fleetq/dispatcher.py:626`
- `src/harbormaster/ui/routes.py:2752`

An async handler returns an un-awaited coroutine there → garbage envelope +
`RuntimeWarning: coroutine was never awaited`.

**Therefore (binding): register SYNC tool handlers.** Own a persistent background event loop in a
daemon thread and bridge via `asyncio.run_coroutine_threadsafe` for the async MCP client.
`asyncio.run()` inside a tool raises on the stdio/HTTP path (already inside a running loop), and a
long-lived downstream session cannot be owned by a per-call loop anyway.

Thread lifecycle precedent to copy, including `finally`-block teardown: `JobWorker`
(`jobs/worker.py:115-129` — `threading.Event` + daemon thread + `.stop(timeout=5.0)`),
`HeartbeatLoop` (`fleetq/heartbeat.py:125-137`), teardown at `__main__.py:149-154, 345-347`.

**Note:** FastMCP calls sync tools directly on the event loop (verified in installed `mcp 1.27.0`;
no `anyio.to_thread` in `mcp/server/` outside `fastmcp/resources/types.py`). Every existing tool
already blocks the loop — `await_delegated_task(timeout_seconds=900)` stalls it up to 15 min. So a
sync handler is conventional here, but our kernel HTTP call **must** carry a hard short timeout,
and **the park-pending-approval path must never be a sync blocking wait inside a sync tool.**

## 3. stdio spawns a fresh process per connection

`__main__.py:306-308`: `run_background_subsystems = (args.transport != "stdio" or
config.fleetq.bridge_in_stdio)`. Rationale documented at `__main__.py:296-305` / `config.py:155-165`
— Claude Code/Desktop spawn one stdio process **per connection**, so long-lived subsystems would
duplicate per session, spam stderr, and leak daemon threads. Guarded by
`tests/unit/test_main_background_subsystems.py`.

A gateway holding long-lived downstream MCP connections plus a kernel HTTP session hits this
exact failure mode. **Follow the `bridge_in_stdio`-style opt-in gate, or make downstream
connections lazy/per-call on stdio.**

Related: `SAFE_FOR_PARALLEL` is a hardcoded allowlist (`fleetq/dispatcher.py:493-504`) so our
dynamically-named tools take the safe single-worker path automatically. The docstring at
`dispatcher.py:490-492` states the rule: any tool holding process-global state belongs on the
operator's unsafe list until proven otherwise — a gateway holding downstream sessions qualifies.

## 4. Plugin contract

```python
# entry point group: "harbormaster.tools"   (plugins.py:49)
def register(mcp: FastMCP, config: HarbormasterConfig) -> None: ...   # plugins.py:51
```

Built-ins register first, `load_plugins(mcp, config)` strictly last (`tools/__init__.py:25-45`),
called once from `build_server` (`server.py:35-39`). Working in-tree skeleton to copy verbatim:
`examples/plugins/harbormaster-plugin-hello/`.

Three gates (`plugins.py:81-163`): `plugins.enabled` false → returns before `entry_points()` is
even called (`:95-97`); empty `allow` → everything rejected (`:99-106`), matched against the
**distribution** name (`:62-78`); `try/except` around both `ep.load()` and `register_fn()`
(`:121-145`) so a raising plugin never breaks startup.

**Runtime-computed tool names work** — `FastMCP.add_tool(fn, name=..., description=...)` and
`remove_tool` both exist in installed `mcp 1.27.0`. **Unverified assumption:** that they exist at
the declared floor `mcp>=1.2.0` (`pyproject.toml:52`). Either raise the floor in our extra or
feature-guard with `hasattr`. Do not treat as observed.

Consequence: gateway calls won't be recordable in the UI network log without a change — its
`NetworkTool` Literal accepts only four names (`ui/network_log.py:27-32`).

## 5. Auth and transports (reuse, don't reimplement)

Transports (`__main__.py:46-51`): `stdio` (default), `sse`, `streamable-http`. Ports in use:
**7531** (UI), **7532** (MCP HTTP) — `config.py:109-110`. Pick a distinct one.

- stdio → **no auth at all** (`transport.py:24-28`).
- HTTP → bearer token from env, **required, no opt-out**; empty → `SystemExit(2)` with a
  `secrets.token_urlsafe(32)` recipe (`transport.py:31-50`).
- Middleware `build_bearer_middleware()` accepts `Authorization: Bearer <t>` via
  `hmac.compare_digest` (`transport.py:84`) **or** an `hm-auth` cookie (`transport.py:53, 92-98`).

**Reuse `require_auth_token_or_exit` + `build_bearer_middleware` from `transport.py`** rather than
writing new auth. Use a distinct env var — `HARBORMASTER_MCP_TOKEN` / `HARBORMASTER_UI_TOKEN` are
taken; use `STOZHER_GATEWAY_TOKEN`.

Entry-point shape: `main(argv: list[str] | None = None) -> int` + `if __name__ == "__main__":
raise SystemExit(main())` (`__main__.py:350-351`, `ui/cli.py:149-150`). Guard optional imports with
`except ImportError` + an install hint returning 2 (`ui/cli.py:103-116`).

## 6. Dependencies

Base deps are deliberately two: `mcp>=1.2.0`, `pydantic>=2.5` (`pyproject.toml:51-54`).
`requires-python = ">=3.11"`; CI covers **3.11, 3.12, 3.13**.

**No crypto dependency exists anywhere** — grep for `cryptography|nacl|ed25519|pynacl` in `src/`
returns zero hits; the only crypto-adjacent stdlib use is `hmac.compare_digest`. Ed25519 is
genuinely new and **must be optional** — an unconditional import breaks "disabled loses nothing"
for bare installs.

`httpx` is **not** a base dependency. Either require our own extra, or use `urllib.request`
(precedent: `dispatcher_cli.py:154-167`). Any extra we add must **also** be appended to `[dev]`
(`pyproject.toml:93-123`) or CI won't have the deps. Pins carry an inline comment explaining why.

## 7. Import-time side effects — do NOT add more

These fire on plain `import`, before config loads, and create files on disk:
`ui/network_log.py:71` (`network_log = NetworkStore()` → `~/.harbormaster/network_log.db`),
`ui/memory_revisions.py:232`, `fleetq/dispatcher.py:477`, `tools/graph.py:23`,
`ui/markdown.py:102-103`.

**Follow the lazy singleton pattern instead:** `dispatcher_metrics_store.py:157-170`
(`_STORE` + `get_metrics_store()`/`set_metrics_store()`). That store is SQLite-backed, WAL,
**short-lived connection per call**, `timeout=5.0`, `0o700`/`0o600` perms (`:52-67`) — it holds no
long-lived handle, so outbound HTTP cannot deadlock against it.

`jobs/subsystem.py:65-145` `get_subsystem(config)` has **real first-call side effects** (DB writes
+ spawns N daemon threads). Never call it from a gateway path that should be inert when
enforcement is off.

`_configure_logging` **removes all pre-existing root handlers** (`__main__.py:132-133`) — logging
configured at import time by a gateway module gets wiped.

Any on-disk store we add must take a `STOZHER_*` env override resolved in a
`default_db_path()`-style function (`dispatcher_metrics_store.py:31-41`) **and** be redirected in
`tests/conftest.py` at module top level — the singletons are built at *import* time, so a fixture
runs too late (`conftest.py:12-16`).

## 8. Tests and gates

```
uv sync --extra dev
uv run ruff check src/ tests/
uv run mypy --strict src/harbormaster/
uv run pytest tests/ -v
```

- Suite: **2196 passed, 1 skipped in ~234s (3m54s)** on Python 3.11.14. Budget ~4 min per run.
- `mypy --strict` (`pyproject.toml:163-166`) → **`Success: no issues found in 80 source files`**.
  **No suppression baseline exists**; only 5 inline `# type: ignore` in all of `src/`. Keep it at
  zero. A stubless crypto lib gets a `[[tool.mypy.overrides]]` block, not inline ignores.
- ruff (`pyproject.toml:155-161`): line-length 100, py311, `select = [E,F,W,I,N,UP,B,C4,SIM]`,
  `ignore = ["E501"]`. **No `per-file-ignores` block exists at all.** `# noqa: BLE001` is the
  in-tree idiom for intentional broad `except Exception`.
- No pytest markers; unit/ui/integration separated by directory only, so the whole suite always
  runs. `pytest-httpserver>=1.1` is in `[dev]` — use it to test kernel HTTP calls without a live
  kernel.
- No shared config/server fixture. Tests do `build_server(HarbormasterConfig())` plus a per-file
  local `_tools_by_name(mcp)` helper, then call `tools[name].fn(...)`
  (`tests/unit/test_tools.py:8-9, 48-52`). Plugin-loader tests hand-roll `_FakeDist`/
  `_FakeEntryPoint` + monkeypatch `harbormaster.plugins.entry_points`
  (`tests/unit/test_plugins.py:14-46`) — reuse this to test registration without installing a dist.

**Pre-existing lint failure on `main`, not ours:** `uv run ruff check src/ tests/` reports 3 errors
in `tests/unit/test_delegate_subprocess_timeout.py` (`I001` unsorted imports L8; `F401` unused
`pytest` L13; `F401` unused `BackendError` L16). `ruff>=0.4` is unpinned, so CI likely passed on an
older ruff — version drift. **Know this so our diff isn't blamed for it. Do not fix it in a Stozher
commit** (ADR-0005: Harbormaster core is read-only to us); report it upstream separately.

## 9. Required S2 regression test

ADR-0005 makes "Harbormaster loses nothing" structurally true; S2 must prove it:

1. A `harbormaster.toml` that enables the gateway (`[plugins] enabled/allow` only) still validates
   under `HarbormasterConfig.model_validate` — i.e. vanilla Harbormaster boots on it.
2. With the gateway distribution absent, `load_plugins` emits a WARNING and skips — no exception,
   server still builds (`plugins.py:153-161`).
3. With enforcement config present but kernel unreachable, gateway tools fail closed per spec 06
   (block or degrade, never silently proceed) and Harbormaster's own tools are unaffected.

---

## Unverified — treat as assumptions, not facts

- `FastMCP.add_tool(name=...)` / `remove_tool` at the declared floor `mcp>=1.2.0`. Confirmed at
  installed 1.27.0 only.
- Whether CI on Harbormaster `main` is green overall (GitHub Actions not queried). Only the local
  ruff failure and local mypy/pytest passes were observed.
