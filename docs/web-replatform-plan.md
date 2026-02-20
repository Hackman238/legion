# Legion Web Replatform Plan

## Agreed Decisions
- Target parity: full feature parity with current Qt interface.
- Project format: keep `.legion` SQLite compatibility.
- Transition strategy: parallel runtime first (Qt + Web), then cutover after parity and migration validation.
- Target platforms: Linux + macOS first, Windows best-effort where tooling exists.
- Web bind: localhost only.
- Transport: websocket-first realtime updates.
- Distribution: keep Kali packaging compatibility; preserve Docker support.
- Theme: purple/indigo/gray (Teams-inspired), Jinja templates first.
- Scheduler modes: deterministic and AI, user-selectable.
- AI providers: local model endpoint (LM Studio) and cloud providers (OpenAI/Claude).
- Cloud notice: explicit warning when cloud AI mode is enabled.
- Safety model: autonomous by default, approvals for dangerous actions, per-command "don't ask again" capability.
- Decision trail: store rationale, risk score, selected/rejected actions.
- Initial goal profiles: `Internal Asset Discovery`, `External Pentest`.

## Recommended Transition (Parallel)
1. Stabilize shared backend services and data model first.
2. Stand up Flask + Jinja + websocket shell running against the same project/database.
3. Port features module-by-module behind compatibility checks.
4. Run dual-mode validation (same scans/projects in Qt and web).
5. Cut over default entrypoint to web once parity and regression criteria pass.
6. Keep Qt as fallback for one release window, then remove.

## Phased Delivery

### Phase 0 - Foundation and Safety
- Fix core data path defects that impact scheduler/process reliability.
- Add regression tests for process output persistence and headless scheduler action resolution.
- Add web runtime scaffold (Flask app factory, websocket feed, Jinja shell, localhost mode).

### Phase 1 - Project and Scan Core
- Web flows for create/open/save `.legion` projects.
- Add hosts / staged scan / import Nmap XML.
- Process queue and live output panels.
- Preserve current staged scan and output folder semantics.

### Phase 2 - Main Workspaces
- Hosts/Services/Tools tabs parity.
- Notes, screenshots, scripts, CVEs, and process management parity.
- Responder/Relay and brute-force workflows parity.

### Phase 3 - Scheduler Modes
- Deterministic scheduler parity in web settings and runtime.
- AI scheduler planner with goal-profile context and risk policy.
- Approval workflow for dangerous actions and per-command trust cache.
- Decision/audit log persisted to SQLite.

### Phase 4 - Packaging and Cutover
- Debian/Kali packaging updates for Flask runtime dependencies.
- Docker image update and runtime defaults.
- Web as default entrypoint, Qt fallback toggle retained temporarily.

## Current Implementation Snapshot
- Completed:
  - Web bootstrap/runtime with localhost Flask mode and websocket snapshot feed.
  - Scheduler deterministic/AI toggle, provider config, danger categories, approval-family cache.
  - Scheduler decision audit persistence + web visibility.
  - Web project lifecycle actions (new temp/open/save-as).
  - Web-triggered scan pipeline (targets file import, Nmap XML import, Nmap scan + import) with async job tracking.
  - Workspace APIs/UI for hosts, services, tools, host details, process output, screenshots, and host notes/scripts/CVEs.
  - Web dangerous-action approval queue with approve/reject + optional family pre-approval and execution jobs.
  - Web process controls for kill/retry/hide/clear and incremental process output polling.
- Next parity priorities:
  - Deeper process control parity (kill/retry/clear) and richer output streaming semantics.
  - Feature coverage for responder/relay/brute-force dedicated workflows.
  - Process detail/output streaming controls and cancellation parity.

## Locked-In Policy Choices
- Pre-approval scope is by command family (template-level), not exact one-off command lines.
- Initial dangerous categories:
  - `exploit_execution`
  - `credential_bruteforce`
  - `network_flooding`
  - `destructive_write_actions`
- Provider credentials are stored in plaintext config for now and hardened later.
