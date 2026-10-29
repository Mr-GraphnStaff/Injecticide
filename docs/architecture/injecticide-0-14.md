# Injecticide architecture — 0.14.0

Implementation architecture. Deployment and live acceptance are recorded
separately in `docs/validation/`; a diagram is not deployment evidence.

```mermaid
flowchart TB
    subgraph runtime[Scan and test runtime]
        User[User / MCP client] --> Proxy[HTTPS / Nginx]
        Proxy --> Web[Web application and API]
        Web --> Sandbox[Isolated static skill scanner]
        Sandbox --> Reports[Findings, coverage, citations and skill maps]
        Web -->|explicit user-selected tests| Models[Optional LLM endpoints]
    end
    subgraph research[Background research — existing isolated research MCP]
        Sources[Approved skills, plugins, standards and threat sources]
        Sources --> Collector[Bounded daily public HTTPS / API collection]
        Collector --> Catalog[SQLite snapshots, hashes, revisions and failures]
        Catalog --> Obsession[Obsession MCP — durable daily policy gate]
        Obsession --> High[High: eligible evidence / approved literal recipe]
        Obsession --> Review[Medium / low / baseline: review queue]
        Review --> Decisions[Implement / Investigate / Reject + audit reason]
    end
    Catalog -->|read-only research tools| Web
    subgraph delivery[Delivery — existing Pi agent and Azure pipeline]
        High --> Bridge[Trusted host bridge — fixed JSON-only scope]
        Bridge --> Tests[Fixed regression suite]
        Tests --> PR[Candidate branch and pull request]
        PR --> CI[Exact-head Azure tests and three container builds]
        CI --> Protection[Strict branch protection and pinned CI identity]
        Protection --> Merge[Eligible automatic merge]
        Merge --> Qualify[Post-merge exact-payload qualification]
        Qualify --> Deploy[Existing Pi deployment wrapper]
        Deploy --> Health[Health checks and rollback]
        Decisions -->|supported Implement proposal| HumanPR[Review-required PR]
        HumanPR --> CI
        CI -->|reviewed broader update and master validation| Human[Human acceptance and production environment gate]
        Human --> Deploy
    end
    Health -->|versioned release for subsequent scans| Sandbox
```

- Scans do not initiate research. A running process retains its cached release
  catalog; publication changes subsequent processes rather than in-flight rules.
- Internet content is untrusted evidence. It cannot supply approval, code, regex,
  file paths, shell commands or release credentials. The collector has no Git or
  deployment credentials, host checkout write mount or Docker socket.
- The automatic lane permits only `research_mcp/obsession_updates.json` and
  `skill_sandbox/rules/obsession_signatures.json`. Novel literal indicators request
  contextual review; they do not prove malicious intent. Shipped recipes are
  empty; adding a recipe requires local policy review.
- Initial baselines and community submissions require review. Unsupported new
  code changes require engineering work and human acceptance.
- Branch protection, exact CI identity, current evidence and post-merge
  qualification must all pass. Missing prerequisites block automatic release.
- Source search, runtime correctness, compliance, vulnerability applicability and
  operational deployment are separate outcomes. New external cost requires
  advance approval. See the source assessment for collection and access limits.
