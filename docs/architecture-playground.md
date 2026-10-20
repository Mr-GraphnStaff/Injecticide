# AI architecture playground

The architecture page accepts a user-declared system map. It does not discover
infrastructure, inspect effective policies, contact mapped services, run a vendor
scanner or certify a system safe. All generated suggestions start as `not_run`.

## Use

Open **Explore architecture** from the overview. Start from the sample or choose
**New map**. Add components from the palette, select cards to edit properties,
and connect them using **From** and **To**. Connections are directed. Mark
untrusted-content and write capabilities explicitly.

**LLM client / app** is a separate component from a person, model, agent or
gateway. Use it for a chat interface, desktop/CLI client or SDK application and
connect it according to the actual request path; no hosting topology is assumed.

Move a card with the pointer or focus it and use arrow keys. Scroll the map to
pan, zoom or use **Fit map**. Undo and redo retain up to 30 map edits.

**Generate test plan** sends the map to the existing application backend. Each
suggestion names its reason, component/connection IDs, evidence requirements,
suggested execution method and a source reference. **Highlight on map** shows
the associated topology. A declared gateway or approval does not suppress a
test or count as proof of protection. Editing the map invalidates its plan.

Use **Save locally** for explicit browser storage or export JSON for portable
storage. Nothing is automatically saved to the server. Labels and control notes
should not contain credentials. Imported maps are validated by the backend
before replacing the current map. Existing built-in scenarios remain available
through **Open built-in scenario explorer**.

## Contract and limits

Schema version 1 contains `name`, `nodes` and `edges`; see `architecture_map.py`
for its strict schema. Limits: 256 KiB request, 100 components, 200 connections,
500 suggestions and 20 rendered suggestions per page. Additional suggestions
are counted explicitly. A map hash and planner version accompany exports.

Planning is deterministic. A bounded breadth-first traversal finds one shortest
directed path per external/retrieval source and action/memory destination.
This is not exhaustive path analysis, attack execution or vulnerability detection.
Disconnected paths are not invented; cycles terminate. Control declarations,
model/agent components, skill/plugin packages and marked connections also
produce specific verification suggestions. Data sensitivity is descriptive
metadata in this version, not a severity score or a policy decision.

References remain separate: OWASP LLM application guidance, OWASP Agentic
Applications guidance and the OWASP Agentic Skills Incubator Project. Reference
links provide planning context, not a certification or complete standards mapping.
NIST governance assessment and external scanner/runtime integrations are not
implemented by this canvas release.

## Validation

- `python -m pytest -q`
- `node tests/browser/architecture_canvas.cjs` with Playwright on `NODE_PATH`,
  installed Edge and cached React/Babel libraries in `tmp/scan-resource-regression`.
  Set `INJECTICIDE_TEST_URL` to a running candidate (default localhost:8237).

The browser test uses real planning and scenario APIs with synthetic maps. It
checks branding, escaped labels, import/export, movement, connections, undo/redo,
plan invalidation, navigation and narrow layouts. It does not establish vendor
control effectiveness or external scanner interoperability.
