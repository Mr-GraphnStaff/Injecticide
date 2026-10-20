function newsLink(url) {
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'https:' && !parsed.username && !parsed.password &&
            (!parsed.port || parsed.port === '443') &&
            ['github.com', 'genai.owasp.org', 'owasp.github.io', 'www.nist.gov'].includes(parsed.hostname) ? parsed.href : null;
    } catch { return null; }
}

function NewsTime({ value }) {
    const date = new Date(value);
    return value && !Number.isNaN(date.valueOf()) ?
        <time dateTime={value}>{date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</time> :
        <span>Not yet recorded</span>;
}

function ResearchUpdates() {
    const [feed, setFeed] = React.useState(null);
    const [failed, setFailed] = React.useState(false);
    React.useEffect(() => {
        let disposed = false;
        let controller = null;
        async function refresh() {
            if (document.hidden || controller) return;
            controller = new AbortController();
            const timeout = setTimeout(() => controller && controller.abort(), 8000);
            try {
                const response = await fetch('/api/research/news', { signal: controller.signal, cache: 'no-store' });
                if (!response.ok) throw new Error('Unavailable');
                const data = await response.json();
                if (!data || !Array.isArray(data.items) || !data.collection) throw new Error('Invalid feed');
                if (!disposed) { setFeed(data); setFailed(false); }
            } catch {
                if (!disposed) setFailed(true);
            } finally {
                clearTimeout(timeout);
                controller = null;
            }
        }
        refresh();
        const timer = setInterval(refresh, 60000);
        document.addEventListener('visibilitychange', refresh);
        return () => {
            disposed = true;
            clearInterval(timer);
            document.removeEventListener('visibilitychange', refresh);
            if (controller) controller.abort();
        };
    }, []);
    const collection = feed?.collection || {};
    const stale = failed || feed?.feed_stale;
    const unavailable = feed?.available === false || (!feed && failed);
    const status = unavailable ? 'Research feed unavailable' : stale ? 'Showing saved updates — connection interrupted' :
        !feed ? 'Loading research updates…' : !collection.worker_alive ? 'Collector stopped' :
        collection.collecting ? 'Collector running' : collection.last_cycle ? 'Collector active · hourly watch' : 'Waiting for first collection';
    const items = (feed?.items || []).slice(0, 8).filter(item => newsLink(item.url));
    return (
        <section id="research-updates" className="home-panel" aria-labelledby="research-title">
            <div className="home-section-head">
                <div><p className="home-eyebrow">From the research MCP</p><h2 id="research-title">Latest source updates</h2></div>
                <p role="status" className={`home-status ${stale || unavailable || (feed && !collection.worker_alive) ? 'home-status-warning' : ''}`}>{status}</p>
            </div>
            <p className="home-muted">Dated vendor releases and observed reference changes, collected from approved public sources. Preview releases are labeled.</p>
            {feed?.available && <dl className="home-metrics">
                <div><dt>Last collection completed</dt><dd><NewsTime value={collection.last_cycle} /></dd></div>
                <div><dt>Configured sources</dt><dd>{collection.source_count ?? 'Unknown'}</dd></div>
                <div><dt>Retained snapshots</dt><dd>{collection.retained_snapshots ?? 'Unknown'}</dd></div>
                <div><dt>Sources with fetch errors</dt><dd>{collection.sources_with_errors ?? 'Unknown'}</dd></div>
            </dl>}
            {!!collection.last_error && <p className="home-warning">The collector reported an error. Collection coverage is incomplete.</p>}
            {!!collection.sources_with_errors && <p className="home-warning">Some sources could not be collected. Retained updates may still be shown.</p>}
            {items.length > 0 ? <ul className="home-news-list">{items.map(item => <li key={item.id}>
                <div className="home-news-meta"><span>{item.kind === 'source_change' ? 'Reference change' : 'Vendor release'}</span>{item.preview && <span className="home-preview">Preview release</span>}</div>
                <a href={newsLink(item.url)} target="_blank" rel="noopener noreferrer">{item.title}<span className="sr-only"> (opens in a new tab)</span><span aria-hidden="true"> ↗</span></a>
                <p className="home-muted">{item.source} · {item.date_label} <NewsTime value={item.date} /></p>
            </li>)}</ul> : feed && !unavailable && <p className="home-empty">No recent releases or changed reference pages in the retained catalog yet.</p>}
            {unavailable && <p className="home-empty">The research service cannot be reached. Testing and scanning remain available.</p>}
            <p className="home-footnote">Source watch · past 30 days · up to 8 items. A page change is not a verified new standard or vulnerability. Research informs review; scanner rules and payloads change through reviewed releases.</p>
        </section>
    );
}

function Home({ onLaunchConsole, onLaunchArchitecture, buildInfo, onNavigate }) {
    const capabilities = [
        ['01', 'Prompt testing', 'Run curated payloads against configured LLM endpoints. Review deterministic response signals and export results.'],
        ['02', 'Skill & plugin scanning', 'Inspect uploaded instructions, code, manifests and dependencies. Review findings alongside explicit coverage gaps.'],
        ['03', 'Architecture playground', 'Map models, agents, edge controls, gateways, MCP, tools and data. Generate a test plan with reasons and evidence requirements.'],
        ['04', 'Research watch', 'Follow vendor tools, skills, project configuration and security references through an hourly, bounded source collector.'],
    ];
    return (
        <div className="injecticide-home">
            <a className="home-skip" href="#home-main">Skip to main content</a>
            <ProductHeader section="overview" buildInfo={buildInfo} onNavigate={onNavigate} />
            <main id="home-main" className="home-shell home-main" tabIndex="-1">
                <section className="home-hero" aria-labelledby="home-title">
                    <div>
                        <p className="home-eyebrow">AI security testing & research</p>
                        <h1 id="home-title">Test the prompt.<br />Inspect the package.<br /><span>Understand the risk.</span></h1>
                        <p className="home-lead">Bring evidence to your AI security review. Test model responses, inspect agent skills and plugins, and trace risks across your workflow.</p>
                        <div className="home-actions">
                            <button onClick={onLaunchConsole} className="home-button home-button-primary">Open testing & scanning <span aria-hidden="true">→</span></button>
                            <button onClick={onLaunchArchitecture} className="home-button">Explore architecture</button>
                        </div>
                    </div>
                    <aside className="home-evidence-card" aria-labelledby="evidence-title">
                        <img src="/static/images/daf-tech-sphere.png" alt="" width="160" height="160" />
                        <p className="home-eyebrow">Evidence before assurance</p>
                        <h2 id="evidence-title">Know what was checked.<br />See what remains unknown.</h2>
                        <p className="home-muted">Review measurable signals, source attribution and coverage limits. A clean result does not certify a safe system.</p>
                    </aside>
                </section>
                <section aria-labelledby="capabilities-title">
                    <div className="home-section-head"><h2 id="capabilities-title">One toolkit. Four ways to investigate.</h2></div>
                    <div className="home-capabilities">{capabilities.map(([number, title, text]) => <article className="home-panel" key={number}>
                        <span className="home-number">{number}</span><h3>{title}</h3><p className="home-muted">{text}</p>
                    </article>)}</div>
                </section>
                <ResearchUpdates />
                <section className="home-references" aria-labelledby="references-title">
                    <h2 id="references-title">Distinct references. Different jobs.</h2>
                    <p className="home-muted">LLM application risks, autonomous workflows, skill risks and governance each need their own lens.</p>
                    <ul>
                        <li><a href="https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/" target="_blank" rel="noopener noreferrer">OWASP LLM Top 10 2026 ↗</a><span>LLM application risks</span></li>
                        <li><a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" rel="noopener noreferrer">OWASP Agentic Applications Top 10 2026 ↗</a><span>Autonomous workflows</span></li>
                        <li><a href="https://owasp.org/projects/agentic-skills-top-10" target="_blank" rel="noopener noreferrer">OWASP Agentic Skills Top 10 ↗</a><span>Skill-specific risks · Incubator Project</span></li>
                        <li><a href="https://www.nist.gov/itl/ai-risk-management-framework" target="_blank" rel="noopener noreferrer">NIST AI RMF & Generative AI Profile ↗</a><span>Risk management and governance</span></li>
                    </ul>
                </section>
            </main>
            <ProductFooter />
        </div>
    );
}
