# Legion Qt Sunset Plan (Web + Headless CLI + MCP)

## Goal
Remove desktop Qt mode and eliminate PyQt/Qt requirements from the runtime paths we keep:
- Web mode
- Headless CLI mode
- MCP mode

## Verified Current Qt/PyQt Footprint
Qt/PyQt imports currently exist in 25 files:
- `app/ModelHelpers.py`
- `app/Screenshooter.py`
- `app/auxiliary.py`
- `app/importers/NmapImporter.py`
- `app/importers/PythonImporter.py`
- `app/settings.py`
- `ui/*` (19 files)

Direct Qt-linked dependencies in web/CLI/MCP paths:
- `app/settings.py` uses `QtCore.QSettings` and is used by:
  - `app/web/runtime.py`
  - `app/web/routes.py`
  - `app/logic.py`
- `app/importers/NmapImporter.py` subclasses `QtCore.QThread` and is used by:
  - `app/web/runtime.py`
  - `legion.py` headless mode
  - `app/mcpServer.py`

## Phase 0 (Done/In Progress): Remove Easy Shared Qt Coupling
Scope:
- Move shared non-UI helpers out of `app.auxiliary` into Qt-free core module.
- Remove unnecessary UI imports from shared runtime paths.
- Replace `QSemaphore` in DB adapters with `threading.Semaphore`.

Status:
- Implemented in current working tree:
  - `app/core/common.py` added and used by `Project`, `ProjectManager`, repositories, MCP.
  - `app/logic.py` no longer imports `ui.ancillaryDialog`.
  - DB adapters no longer require Qt semaphore.

Acceptance:
- Modified Python files compile.
- Web JS scheduler settings behavior still valid.

## Phase 1: Replace `QSettings` Backend With Qt-Free Config Layer
Scope:
- Replace `QtCore.QSettings` in `app/settings.py` with a pure-Python backend.
- Keep existing `AppSettings`/`Settings` public behavior stable for web/CLI/MCP callers.
- Preserve config file compatibility (`legion.conf`) and migration behavior.

Deliverables:
- New config adapter module (pure Python).
- `app/settings.py` updated to remove `PyQt6` import.
- Regression tests for settings defaults/migrations plus read/write round trip.

Acceptance:
- `app/web/runtime.py`, `app/web/routes.py`, `app/logic.py` work without PyQt installed.
- `tests/app/test_SettingsDefaults.py` and `tests/app/test_SettingsMigrations.py` pass.

## Phase 2: Split Nmap Import Core From Qt Threading
Scope:
- Extract importer logic from `NmapImporter` into a Qt-free service class/function.
- Keep a thin Qt adapter only for legacy desktop UI path (temporary, until desktop removal).
- Update web/CLI/MCP to call the Qt-free importer service directly.

Deliverables:
- New `nmap import service` module with callback hooks for progress/log events.
- `app/web/runtime.py`, `legion.py` headless mode, and `app/mcpServer.py` switched to service usage.
- Preserve all current Nmap import behavior (host/service/script/CVE updates, progress semantics).

Acceptance:
- Importing the same XML yields the same DB outcomes as before.
- Web import job and headless/MCP scan-import paths keep working.
- New/updated tests cover Nmap import parity on fixture XMLs.

## Phase 3: Consolidate Web/CLI/MCP Orchestration
Scope:
- Remove duplicated scan/import orchestration logic between `app/web/runtime.py`, `legion.py`, and `app/mcpServer.py`.
- Create shared runtime service for:
  - target ingestion
  - nmap execution
  - nmap import
  - optional scheduler/action follow-up

Deliverables:
- New shared service module consumed by web, CLI, and MCP.
- MCP handlers use same execution path as web/CLI (parity by construction).

Acceptance:
- Same command path and data updates for equivalent operations across web/CLI/MCP.
- Reduced duplicated code in `app/mcpServer.py` and `legion.py`.

## Phase 4: Remove Desktop Qt Runtime
Scope:
- Remove GUI startup branch from `legion.py`.
- Remove `ui/` package and Qt-only app modules that are no longer needed.
- Remove Qt-only tests.

Deliverables:
- CLI/web/MCP-only entrypoints.
- No imports from `ui.*` in retained runtime code.

Acceptance:
- Running web, headless CLI, and MCP succeeds in environment without PyQt/qasync.
- Desktop mode removed from docs/CLI help.

## Phase 5: Dependency and Packaging Cleanup
Scope:
- Remove `PyQt6` and `qasync` from runtime dependency set.
- Update packaging/docs/CI for web+headless+MCP-only product.

Deliverables:
- Updated `requirements.txt` and packaging artifacts.
- CI matrix runs without Qt libs.

Acceptance:
- Fresh install without Qt packages supports web, CLI, MCP workflows.

## Risks and Mitigations
- Risk: Nmap import regressions.
  - Mitigation: parity fixtures + DB outcome tests before removing old path.
- Risk: settings migration regressions.
  - Mitigation: explicit migration tests and backup/round-trip tests.
- Risk: MCP drift from web/CLI behavior.
  - Mitigation: shared orchestration service and no duplicate pipeline code.

## Clarifications Needed Before Phase 1/2 Implementation
1. Entry default after desktop removal:
   - Should `python legion.py` default to `--web`, or require explicit mode flag?
2. Backward compatibility:
   - Must we keep full backward compatibility for existing `legion.conf` keys and layout, or can we normalize formatting if values stay equivalent?
3. Nmap parity gate:
   - Which flows are mandatory for sign-off: `import XML only`, `scan+import`, `scan+import+run_actions`, and `MCP run_discovery`?
4. Cutover strategy:
   - Remove Qt desktop in one pass after parity, or keep a short deprecation window behind a feature flag?

## Confirmed Decisions (2026-02-21)
- Default mode after desktop removal: web mode.
- Config compatibility requirement: key/value compatibility only (formatting normalization allowed).
- Nmap parity gate: required for `import XML only`, `scan+import`, `scan+import+run_actions`, and `MCP run_discovery`.
- Cutover strategy: one-step desktop Qt removal after parity.

## Progress Snapshot (2026-02-21)
- Phase 1 (partially complete):
  - `app/settings.py` no longer depends on `QtCore.QSettings`.
  - New Qt-free config backend: `app/core/config_store.py`.
- Phase 2/3 groundwork:
  - `NmapImporter` now has a non-Qt fallback path for headless environments.
  - New shared import entrypoint: `app/importers/nmap_runner.py`.
  - Web, headless CLI, and MCP now use the shared Nmap import runner.
- Additional reliability coverage:
  - Added tests in `tests/app/test_NmapImportRunner.py` for valid fixture parsing, malformed XML handling, and relocated XML file discovery.
