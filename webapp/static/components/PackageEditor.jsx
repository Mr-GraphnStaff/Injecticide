
const EDITOR_DESTINATIONS = [
    ['generic-agent-skills', 'Generic Agent Skills', 'skill', 'Choose the format expected by your receiving tool.'],
    ['claude-ai', 'Claude.ai', 'zip', 'Claude.ai documents packaged ZIP uploads.'],
    ['claude-code', 'Claude Code', 'zip', 'Claude Code discovers skill directories; extract this archive before installation.'],
    ['claude-api', 'Claude API', 'zip', 'Claude API documents packaged ZIP uploads.'],
    ['openai-codex', 'OpenAI Codex', 'zip', 'Codex discovers skill directories; extract this archive before installation.'],
    ['openai-api', 'OpenAI API', 'zip', 'Use the documented ZIP upload flow for the receiving API.'],
    ['gemini-cli', 'Gemini CLI', 'skill', 'Gemini CLI documents .skill packages and local installation.'],
];

function EditorValidation({ validation }) {
    if (!validation) return <p>Destination validation was not reported.</p>;
    const describe = value => {
        if (typeof value === 'string') return value;
        let source;
        try { const candidate = new URL(value?.source); if (candidate.protocol === 'https:') source = candidate.href; } catch (_) {}
        return <span>{value?.path ? value.path + ': ' : ''}{value?.message || JSON.stringify(value)}{source && <> <a href={source} target="_blank" rel="noopener noreferrer" className="underline">Source</a></>}</span>;
    };
    return <div>
        <p>{validation.status === 'not_checked' ? 'Archive structure inspected. Destination validation has not run.' : (validation.errors || []).length ? 'Destination validation reported errors.' : 'Destination validation reported no errors.'}</p>
        <ul>{(validation.errors || []).map((item, i) => <li key={'error-' + i} className="text-red-300">{describe(item)}</li>)}
            {(validation.warnings || []).map((item, i) => <li key={'warning-' + i} className="text-yellow-300">{describe(item)}</li>)}</ul>
    </div>;
}


function OriginalEditorFindings({ file }) {
    const text = (value, limit = 1000) => {
        const raw = typeof value === 'string' ? value : value == null ? '' : JSON.stringify(value);
        return raw.length > limit ? raw.slice(0, limit) + '…' : raw;
    };
    const findings = Array.isArray(file?.findings) ? file.findings : [];
    return <section aria-label="Original scan findings for selected file" className="p-3 border border-gray-700 rounded space-y-2">
        <h4>Original scan findings for selected file</h4>
        <p className="text-sm">Evidence from the original upload. The edited copy receives a separate fresh scan after building.</p>
        {!file ? <p>No original scan evidence was supplied for this file.</p> : <>
            {file.skipped && <p>Original scan skipped this file. {text(file.reason)}</p>}
            {!findings.length && <p>No findings were reported for this file. This does not establish package safety.</p>}
            {findings.length > 100 && <p>Showing the first 100 of {findings.length} findings; review the complete original scan report for the rest.</p>}
            <ul>{findings.slice(0, 100).map((finding, index) => {
                const evidence = [finding.observations, finding.matches, finding.policy_evaluation?.observations, finding.samples].filter(Array.isArray).flatMap(items => items.slice(0, 3)).slice(0, 3);
                return <li key={index} className="my-2" data-editor-original-finding="true">
                    <h5>{text(finding.title || finding.id || 'Finding', 200)}{finding.title && finding.id ? ' · ' + text(finding.id, 120) : ''} · {text(finding.severity || 'Severity not reported', 80)}</h5>
                    <p>{text(finding.description)}</p>
                    <ul>{evidence.map((item, i) => {
                        const line = item?.line ?? item?.line_number;
                        const sample = typeof item === 'string' ? item : item?.text ?? item?.match ?? item?.matched_text ?? item?.preview ?? item?.reason ?? item;
                        return <li key={i}>{Number.isInteger(line) ? 'Line ' + line + ': ' : ''}<span className="whitespace-pre-wrap break-words">{text(sample, 500)}</span></li>;
                    })}</ul>
                </li>;
            })}</ul>
        </>}
    </section>;
}

function PackageEditor({ file, targetRuntime, scanResult }) {
    const [token] = React.useState(() => Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join(''));
    const [manifest, setManifest] = React.useState(null);
    const [drafts, setDrafts] = React.useState({});
    const [changes, setChanges] = React.useState({});
    const [path, setPath] = React.useState('');
    const [destination, setDestination] = React.useState('generic-agent-skills');
    const [format, setFormat] = React.useState(file?.name?.toLowerCase().endsWith('.zip') ? 'zip' : 'skill');
    const [phase, setPhase] = React.useState('idle');
    const [error, setError] = React.useState('');
    const [result, setResult] = React.useState(null);
    const [failedValidation, setFailedValidation] = React.useState(null);
    const [acknowledged, setAcknowledged] = React.useState(false);
    const [revision, setRevision] = React.useState(0);
    const [progress, setProgress] = React.useState(null);
    const [elapsedSeconds, setElapsedSeconds] = React.useState(0);
    const operation = React.useRef({ sequence: 0, controller: null, waitTimer: null, startedAt: null });
    const downloadUrls = React.useRef(new Set());
    const draftControl = React.useRef(null);
    const fileControl = React.useRef(null);
    const busy = ['inspecting', 'building', 'downloading'].includes(phase);
    const selected = manifest?.files?.find(item => item.path === path);
    const originalScanFile = (scanResult?.files || []).find(item => item.path === path);
    const original = selected?.content || '';
    const draft = Object.prototype.hasOwnProperty.call(drafts, path) ? drafts[path] : original;
    const accepted = changes[path];
    const pendingDrafts = (manifest?.files || []).filter(item => item.editable && changes[item.path]?.action !== 'remove' &&
        Object.prototype.hasOwnProperty.call(drafts, item.path) && drafts[item.path] !== (changes[item.path]?.content ?? item.content ?? ''));
    const profile = EDITOR_DESTINATIONS.find(item => item[0] === destination);

    const stageLabels = {
        inspecting: 'Requesting archive inspection', inspection_complete: 'Archive inspection complete',
        submitting: 'Sending package and accepted edits', queued: 'Queued',
        validating_and_building: 'Validating and rebuilding', rescanning: 'Rescanning rebuilt copy',
        checking_coverage: 'Checking scan coverage', ready: 'Complete', failed: 'Failed',
        downloading: 'Receiving the ready copy', waiting: 'Waiting for server status'
    };
    function stopOperation() {
        clearTimeout(operation.current.waitTimer);
        operation.current.waitTimer = null;
        operation.current.sequence += 1;
        operation.current.controller?.abort();
        operation.current.controller = null;
    }
    function beginOperation(stage, message, waitMs) {
        stopOperation();
        const controller = new AbortController();
        const task = { sequence: operation.current.sequence, controller, startedAt: performance.now() };
        operation.current = { ...task, waitTimer: null };
        setElapsedSeconds(0); setProgress({ stage, message });
        operation.current.waitTimer = setTimeout(() => {
            if (operation.current.sequence !== task.sequence) return;
            setElapsedSeconds(Math.floor((performance.now() - task.startedAt) / 1000));
            stopOperation(); setPhase('stopped');
            setError('Stopped waiting after ' + Math.round(waitMs / 1000) + ' seconds. This does not confirm a server failure; processing may continue. The original upload and any accepted edits are preserved.');
        }, waitMs);
        return task;
    }
    const isCurrent = task => operation.current.sequence === task.sequence && !task.controller.signal.aborted;
    function finishOperation(task) {
        if (operation.current.sequence !== task.sequence) return;
        clearTimeout(operation.current.waitTimer); operation.current.waitTimer = null;
        setElapsedSeconds(Math.floor((performance.now() - task.startedAt) / 1000));
    }
    function showServerProgress(value) {
        setProgress({
            stage: typeof value?.stage === 'string' && Object.prototype.hasOwnProperty.call(stageLabels, value.stage) ? value.stage : 'waiting',
            message: typeof value?.message === 'string' ? value.message.slice(0, 500) : 'Exact server stage is unavailable. Waiting for the next status response.',
            serverElapsedSeconds: Number.isFinite(value?.elapsed_seconds) && value.elapsed_seconds >= 0 ? Math.floor(value.elapsed_seconds) : null
        });
    }
    function stopWaiting() {
        if (operation.current.startedAt != null) setElapsedSeconds(Math.floor((performance.now() - operation.current.startedAt) / 1000));
        stopOperation(); setError(''); setPhase('stopped');
    }
    React.useEffect(() => {
        if (!busy) return;
        const timer = setInterval(() => {
            if (operation.current.startedAt != null) setElapsedSeconds(Math.floor((performance.now() - operation.current.startedAt) / 1000));
        }, 1000);
        return () => clearInterval(timer);
    }, [busy]);
    function editorUrl(value) {
        const url = new URL(value, window.location.origin);
        if (url.origin !== window.location.origin || !url.pathname.startsWith('/api/skills/editor/')) throw new Error('The editor returned an invalid job URL.');
        return url.href;
    }
    async function editorFetch(url, task, options = {}) {
        const response = await fetch(editorUrl(url), { ...options, headers: { 'X-Editor-Token': token }, signal: task.controller.signal });
        if (!response.ok) {
            let message = 'Editor request failed (' + response.status + ').';
            let bodyValidation = null;
            try {
                const body = await response.json();
                const detail = body.error || body.detail;
                bodyValidation = detail?.validation || body.validation;
                if (typeof detail === 'string') message = detail;
                else if (detail?.message) message = detail.message + (detail.stage ? ' Stage: ' + detail.stage + '.' : '') + (detail.request_id ? ' Reference: ' + detail.request_id : '');
            } catch (_) {}
            const problem = new Error(message); problem.validation = bodyValidation;
            throw problem;
        }
        return response;
    }
    function fail(task, problem) {
        if (isCurrent(task)) { setFailedValidation(problem.validation || null); setError(problem.message || 'Editor request failed.'); setPhase('failed'); }
    }
    React.useEffect(() => {
        stopOperation();
        setManifest(null); setDrafts({}); setChanges({}); setPath(''); setResult(null); setFailedValidation(null); setDestination('generic-agent-skills'); setError(''); setPhase('idle'); setRevision(0); setAcknowledged(false);
        setFormat(file?.name?.toLowerCase().endsWith('.zip') ? 'zip' : 'skill');
        setProgress(null); setElapsedSeconds(0);
        return () => {
            stopOperation();
            downloadUrls.current.forEach(url => URL.revokeObjectURL(url));
            downloadUrls.current.clear();
        };
    }, [file]);
    React.useEffect(() => {
        stopOperation(); setResult(null); setFailedValidation(null); setAcknowledged(false);
        setProgress(null); setElapsedSeconds(0);
        setPhase(current => current === 'inspecting' ? 'idle' : current === 'building' || current === 'downloading' || current === 'ready' ? 'reviewing' : current);
    }, [targetRuntime]);

    async function inspect() {
        const task = beginOperation('inspecting', 'Sending the file and waiting for its archive manifest.', 60000);
        setError(''); setFailedValidation(null); setResult(null); setPhase('inspecting');
        try {
            const form = new FormData(); form.append('file', file);
            const response = await editorFetch('/api/skills/editor/inspect', task, { method: 'POST', body: form });
            const data = await response.json();
            if (!isCurrent(task)) return;
            if (!Array.isArray(data.files)) throw new Error('The package manifest was incomplete.');
            data.files = data.files.map(item => ({ ...item, editable: item.editable && typeof item.content === 'string' }));
            setManifest(data); setDrafts({}); setChanges({}); setRevision(0);
            setPath(data.files[0]?.path || ''); setPhase('reviewing');
            setProgress({ stage: 'inspection_complete', message: 'Archive inspected. Destination metadata validation runs during rebuilding.' });
        } catch (problem) { fail(task, problem); } finally { finishOperation(task); }
    }
    function invalidateBuild() { setAcknowledged(false); setResult(null); setFailedValidation(null); setError(''); setPhase('reviewing'); setProgress(null); }

    function openGuidanceFile(item) {
        setPath(item.path);
        requestAnimationFrame(() => (draftControl.current || fileControl.current)?.focus());
    }
    function suggestionDraft(item) {
        const target = manifest?.files?.find(entry => entry.path === item.path);
        if (!target?.editable || typeof target.content !== 'string' || changes[item.path]?.action === 'remove' ||
            typeof item.before !== 'string' || !item.before.length || typeof item.after !== 'string') return null;
        const current = Object.prototype.hasOwnProperty.call(drafts, item.path) ? drafts[item.path] : target.content;
        const index = current.indexOf(item.before);
        if (index < 0 || index !== current.lastIndexOf(item.before)) return null;
        return current.slice(0, index) + item.after + current.slice(index + item.before.length);
    }
    function stageSuggestion(item) {
        const next = suggestionDraft(item);
        if (next === null) return;
        setDrafts(current => ({ ...current, [item.path]: next }));
        invalidateBuild(); openGuidanceFile(item);
    }

    function acceptEdit() {
        if (!selected?.editable || draft === original) return;
        setChanges(current => ({ ...current, [path]: { path, original_sha256: selected.sha256, action: 'replace', content: draft, revision: revision + 1 } }));
        setRevision(value => value + 1); invalidateBuild();
    }
    function removeFile() {
        if (!selected) return;
        setChanges(current => ({ ...current, [path]: { path, original_sha256: selected.sha256, action: 'remove', revision: revision + 1 } }));
        setRevision(value => value + 1); invalidateBuild();
    }
    function restoreFile() {
        setChanges(current => { const next = { ...current }; delete next[path]; return next; });
        setDrafts(current => { const next = { ...current }; delete next[path]; return next; });
        setRevision(value => value + 1); invalidateBuild();
    }
    async function buildPackage() {
        const task = beginOperation('submitting', 'Sending the original package and your accepted changes.', 180000);
        setResult(null); setAcknowledged(false); setFailedValidation(null); setError(''); setPhase('building');
        try {
            const form = new FormData(); form.append('file', file);
            const batch = Object.values(changes).map(({ revision: ignored, ...change }) => change);
            form.append('changes', JSON.stringify(batch)); form.append('target_profile', destination);
            form.append('output_format', format); form.append('target_runtime', targetRuntime || 'generic');
            const response = await editorFetch('/api/skills/editor/export', task, { method: 'POST', body: form });
            const job = await response.json();
            if (!isCurrent(task)) return;
            if (!job.status_url) throw new Error('The build did not return a status URL.');
            showServerProgress(job.progress);
            while (isCurrent(task)) {
                const statusResponse = await editorFetch(job.status_url, task);
                const status = await statusResponse.json();
                if (!isCurrent(task)) return;
                showServerProgress(status.progress);
                if (status.status === 'failed') {
                    setProgress({ stage: 'failed', message: typeof status.error?.message === 'string' ? status.error.message.slice(0, 500) : 'The server reported that this build failed.' });
                    const problem = new Error((status.error?.message || 'Package build failed.') + (status.error?.stage ? ' Stage: ' + status.error.stage + '.' : '') + (status.error?.request_id ? ' Reference: ' + status.error.request_id : ''));
                    problem.validation = status.error?.validation; throw problem;
                }
                if (status.status === 'ready') {
                    if (!status.result?.download_url) throw new Error('The build did not return a download URL.');
                    setResult(status.result); setPhase('ready');
                    setProgress({ stage: 'ready', message: 'Edited copy is ready. Review destination validation and the fresh scan before downloading.' }); return;
                }
                await new Promise((resolve, reject) => {
                    const abort = () => { clearTimeout(timer); reject(new DOMException('Cancelled', 'AbortError')); };
                    const timer = setTimeout(() => { task.controller.signal.removeEventListener('abort', abort); resolve(); }, 1000);
                    task.controller.signal.addEventListener('abort', abort, { once: true });
                    if (task.controller.signal.aborted) abort();
                });
            }
        } catch (problem) { fail(task, problem); } finally { finishOperation(task); }
    }
    async function downloadPackage() {
        const task = beginOperation('downloading', 'Receiving the already built copy. Your browser will handle saving it.', 60000); setPhase('downloading'); setError('');
        try {
            const downloadAddress = new URL(result.download_url, window.location.origin);
            if (result.requires_acknowledgement && acknowledged) downloadAddress.searchParams.set('acknowledge_limitations', 'true');
            const response = await editorFetch(downloadAddress.href, task);
            const blob = await response.blob();
            if (!isCurrent(task)) return;
            const url = URL.createObjectURL(blob); downloadUrls.current.add(url);
            const anchor = document.createElement('a'); anchor.href = url; anchor.download = result.filename || ('edited-package.' + format);
            document.body.appendChild(anchor); anchor.click(); anchor.remove();
            setTimeout(() => { URL.revokeObjectURL(url); downloadUrls.current.delete(url); }, 1000);
            setPhase('ready'); setProgress({ stage: 'ready', message: 'Copy received and download handed to your browser.' });
        } catch (problem) { fail(task, problem); } finally { finishOperation(task); }
    }
    return <section className="mt-6 p-4 rounded-lg border border-gray-600 bg-gray-900/50 space-y-3" aria-labelledby="package-editor-title" data-package-editor="true">
        <h3 id="package-editor-title" className="text-lg font-semibold">Review and edit a package copy</h3>
        <p>The original upload stays unchanged. Review text, accept each edit or removal, then build and rescan a downloadable copy.</p>
        <p className="text-sm text-gray-400">Package content is processed by this workspace's editor and scanner. It is not sent to an LLM. Guidance is reviewed in advance; it is not live content-aware AI.</p>
        {progress && <section aria-label="Package operation status" className="p-3 rounded border border-gray-600 space-y-2" data-editor-progress="true">
            <p role="status" aria-live="polite" aria-atomic="true">
                <strong>{busy ? 'Running' : phase === 'failed' ? (progress.stage === 'failed' ? 'Build failed' : 'Request failed') : phase === 'stopped' ? 'Stopped waiting' : phase === 'ready' ? 'Ready' : 'Ready to review'}</strong>
                {' · '}{busy ? 'Stage: ' : 'Last observed stage: '}{stageLabels[progress.stage] || 'Stage not reported'}
            </p>
            {busy && <progress aria-label="Package operation in progress" className="w-full" />}
            <p>Elapsed: {elapsedSeconds} seconds in this browser.</p>
            {progress.serverElapsedSeconds != null && <p>Server time at last update: {progress.serverElapsedSeconds} seconds.</p>}
            <p>{progress.message}</p>
            {phase === 'stopped' && <p>Only this browser stopped waiting. Server processing may continue. Retry after it finishes; your accepted edits and original findings remain available.</p>}
            {phase === 'failed' && <p>The request did not complete successfully. Your accepted edits and original scan findings remain available below.</p>}
        </section>}
        {error && <p role="alert" className="text-red-300">{error}</p>}
        {failedValidation && <div role="region" aria-label="Failed destination validation"><h4>Destination validation issues</h4><EditorValidation validation={failedValidation} /></div>}
        {!manifest && <button type="button" className="px-3 py-2 rounded bg-blue-700" disabled={!file || busy} onClick={inspect}>Review package files</button>}
        {busy && <button type="button" className="px-3 py-2 rounded border" onClick={stopWaiting}>Stop waiting</button>}
        {manifest && <>
            <p className="text-xs break-all">Original SHA-256: {manifest.archive_sha256}</p>
            <details><summary>Archive inspection</summary><EditorValidation validation={manifest.validation} /></details>
            <details><summary>Review guidance ({(manifest.recommendations || []).length})</summary>
                <p>Recommendations are suggestions. Make and accept your own edits below; nothing is applied automatically.</p>
                {(manifest.recommendations || []).map((item, index) => <article key={index} className="my-3 p-3 border border-gray-700 rounded">
                    <h4>{item.title}</h4><p>{item.path}{item.line ? ': ' + item.line : ''}</p><p>{item.explanation}</p>
                    {item.before != null && <><h5>Before</h5><pre className="whitespace-pre-wrap break-words">{item.before}</pre></>}
                    {item.after != null && <><h5>Suggested text</h5><pre className="whitespace-pre-wrap break-words">{item.after}</pre></>}
                    {item.manual && <p>Manual review required.</p>}
                    {manifest.files.some(entry => entry.path === item.path) && <button type="button" disabled={busy} className="px-3 py-2 rounded border" onClick={() => openGuidanceFile(item)}>Open this file</button>}
                    <button type="button" disabled={busy || suggestionDraft(item) === null} className="px-3 py-2 rounded border" onClick={() => stageSuggestion(item)}>Stage suggested change</button>
                    <p className="text-sm">Staging only updates the draft. Review the before/after text and accept the edit separately. Staging requires one exact literal match in an editable preview.</p>
                </article>)}
            </details>
            <label className="block" htmlFor="editor-file">Package file</label>
            <select id="editor-file" ref={fileControl} className="w-full p-2 bg-gray-800 border border-gray-600 rounded" value={path} disabled={busy} onChange={event => setPath(event.target.value)}>
                {manifest.files.map(item => <option key={item.path} value={item.path}>{item.path} · {item.editable ? 'text' : 'binary / read only'}{changes[item.path] ? ' · ' + changes[item.path].action + ' accepted' : ''}</option>)}
            </select>
            {selected && <div className="space-y-3">
                <OriginalEditorFindings file={originalScanFile} />
                <p className="text-xs break-all">Original file SHA-256: {selected.sha256} · {selected.size} bytes</p>
                {accepted?.action === 'remove' ? <p className="text-yellow-300">Removal accepted for this copy.</p> : selected.editable ? <div className="grid md:grid-cols-2 gap-3">
                    <div><h4>Before · original</h4><pre className="p-2 bg-gray-950 rounded whitespace-pre-wrap break-words overflow-auto" style={{ maxHeight: '24rem' }}>{original}</pre></div>
                    <div><label htmlFor="editor-draft">After · editable draft</label><textarea id="editor-draft" ref={draftControl} className="w-full p-2 bg-gray-800 border border-gray-600 rounded font-mono text-sm" rows={14} value={draft} disabled={busy} spellCheck={false} onChange={event => { const value = event.target.value; setDrafts(current => ({ ...current, [path]: value })); invalidateBuild(); }} />
                        <button type="button" className="px-3 py-2 rounded bg-blue-700" onClick={acceptEdit} disabled={busy || draft === original || (accepted?.action === 'replace' && accepted.content === draft)}>Accept this text edit</button>
                    </div>
                </div> : <p>Binary, oversized or preview-limited files are read only and preserved byte for byte unless you explicitly accept removal. {selected.editable_reason === 'preview_budget_exceeded' && 'The combined text preview limit was reached.'}</p>}
                <p className="text-sm text-yellow-300">Removing a file can break references, scripts or required entrypoints. Review references before accepting removal.</p>
                <div className="flex flex-wrap gap-2">
                    <button type="button" className="px-3 py-2 rounded border border-red-700" disabled={busy || accepted?.action === 'remove'} onClick={removeFile}>Accept removal of this file</button>
                    <button type="button" className="px-3 py-2 rounded border" disabled={busy || (!accepted && !Object.prototype.hasOwnProperty.call(drafts, path))} onClick={restoreFile}>Restore original file</button>
                </div>
            </div>}
            <h4>Accepted changes · revision {revision}</h4>
            <ul>{Object.values(changes).map(change => <li key={change.path} className="break-all">{change.action === 'remove' ? 'Remove' : 'Replace'} {change.path} · accepted revision {change.revision} · original hash {change.original_sha256}</li>)}</ul>
            {!Object.keys(changes).length && <p>No file changes accepted. You may still build a format-converted copy.</p>}
            {!!pendingDrafts.length && <p role="status" className="text-yellow-300">{pendingDrafts.length} draft(s) need acceptance or restoration before building.</p>}
            <div className="grid md:grid-cols-2 gap-3">
                <div><label htmlFor="editor-destination">Destination</label><select id="editor-destination" className="block w-full p-2 bg-gray-800 border rounded" disabled={busy} value={destination} onChange={event => { setDestination(event.target.value); invalidateBuild(); }}>{EDITOR_DESTINATIONS.map(item => <option key={item[0]} value={item[0]}>{item[1]}</option>)}</select></div>
                <div><label htmlFor="editor-format">Download format</label><select id="editor-format" className="block w-full p-2 bg-gray-800 border rounded" disabled={busy} value={format} onChange={event => { setFormat(event.target.value); invalidateBuild(); }}><option value="skill">.skill</option><option value="zip">.zip</option></select></div>
            </div>
            <p className="text-sm">{profile[3]} Recommended download: .{profile[2]}. Your chosen format is .{format}; both use a ZIP container.</p>
            <button type="button" className="px-3 py-2 rounded bg-blue-700" disabled={busy || !!pendingDrafts.length} onClick={buildPackage}>{phase === 'failed' ? 'Retry build and rescan' : 'Build and rescan accepted copy'}</button>
            {result && <div className="p-3 border border-gray-600 rounded space-y-3">
                <h4>Edited copy: {result.filename}</h4><p className="text-xs break-all">SHA-256: {result.sha256}</p>
                <h5>Destination and format validation</h5><EditorValidation validation={result.validation} />
                <h5>Fresh scan findings</h5><p>A completed scan describes measured findings. Installation and runtime behavior have not been tested.</p>
                {result.scan_result ? <details><summary>View fresh scan report</summary><pre className="whitespace-pre-wrap break-words overflow-auto" style={{ maxHeight: '24rem' }}>{JSON.stringify(result.scan_result, null, 2)}</pre></details> : <p>No scan report was returned.</p>}
                <details><summary>Build change summary</summary><pre className="whitespace-pre-wrap break-words">{JSON.stringify(result.change_summary, null, 2)}</pre></details>
                {(result.verification?.analysis_limitations?.length > 0 || result.verification?.limited_assets?.length > 0) && <section aria-label="Inspection limitations" className="p-3 border border-yellow-700 rounded space-y-2">
                    <h5>Completed with analysis limitations</h5>
                    <p>The supported scan finished. The limitations below remain; this copy is not certified safe to execute or install.</p>
                    {(result.verification?.limited_assets || []).length > 0 && <><p>These assets received supported structure or XML checks. Binary runtime behavior, rendering and OCR were not verified:</p><ul>{result.verification.limited_assets.map(item => <li key={item} className="break-all">{item}</li>)}</ul></>}
                    <ul>{(result.verification?.analysis_limitations || []).map((item, index) => <li key={index} className="break-words">{item.path} · {item.stage}: {item.reason}{item.scope ? ' Scope: ' + item.scope : ''}</li>)}</ul>
                </section>}
                {result.requires_acknowledgement && <div className="space-y-2"><p className="text-yellow-300">Remaining findings or inspection limitations require your review. Partial inspection does not establish package safety.</p><label className="block"><input type="checkbox" checked={acknowledged} disabled={busy} onChange={event => setAcknowledged(event.target.checked)} /> I reviewed the remaining findings and inspection limitations.</label></div>}
                <button type="button" className="px-3 py-2 rounded bg-green-800" disabled={busy || (result.requires_acknowledgement && !acknowledged)} onClick={downloadPackage}>Download edited .{format}</button>
            </div>}
        </>}
    </section>;
}
