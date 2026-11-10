const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), http = require('node:http');
const root = path.resolve(__dirname, '../..'), run = process.env.AGENT_WORKING_DIR;
assert.ok(run, 'Use the managed launcher');
let owner = root;
while (!fs.existsSync(path.join(owner, 'working/.agent-control/policy.json'))) {
    const parent = path.dirname(owner); assert.notEqual(parent, owner); owner = parent;
}
assert.ok(path.resolve(run).startsWith(path.join(owner, 'working/runs') + path.sep));
const output = path.join(run, 'reports/browser/package-editor');
fs.mkdirSync(output, { recursive: true });
const assets = path.join(owner, 'working/cache/browser/scan-resource-regression');
const source = fs.readFileSync(path.join(root, 'webapp/static/components/PackageEditor.jsx'), 'utf8');
// Intentionally invalid frontmatter: archive inspection must not imply destination approval.
const original = '# Example without YAML frontmatter\nOriginal text';
const manifest = { archive_sha256: 'archive-hash', detected_format: 'skill', validation: { status: 'not_checked', errors: [], warnings: ['Only archive structure was inspected; metadata and destination validation run during rebuild.'] }, recommendations: [{ path: 'SKILL.md', title: 'Review wording', explanation: 'Manual review', before: '<script>bad()</script>', after: 'Safer wording', manual: true }, {path:'SKILL.md',title:'Literal guidance',explanation:'Fixture guidance',before:'Original text',after:'Reviewed text'}], files: [{ path: 'SKILL.md', sha256: 'text-hash', size: original.length, editable: true, content: original }, { path: 'asset.bin', sha256: 'binary-hash', size: 4, editable: false }, { path:'preview.txt',sha256:'preview-hash',size:120000,editable:true,editable_reason:'preview_budget_exceeded' }] };
const tokens = [], exportBodies = [];
let statuses = 0, failureMode = false, controlledStage = null, forceRescanFailure = false;
let holdInspect = false, holdJobs = false, holdDownload = false, failNextDownload = false, readyDelayMs = 0;
const held = { inspect: new Set(), jobs: new Set(), download: new Set() };
const closedHeld = { inspect: 0, jobs: 0, download: 0 };
function holdResponse(res, kind) {
    held[kind].add(res);
    res.once('close', () => { held[kind].delete(res); closedHeld[kind] += 1; });
}
async function until(check, label) {
    const deadline = Date.now() + 3000;
    while (!check() && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20));
    assert.ok(check(), label);
}
const server = http.createServer((req, res) => {
    if (req.url === '/') {
        res.setHeader('Content-Type', 'text/html');
        return res.end('<!doctype html><html lang="en"><meta charset="UTF-8"><body><div id="root"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script src="/babel.js"></script><script src="/fixture.js"></script></body></html>');
    }
    if (['/react.js', '/react-dom.js', '/babel.js'].includes(req.url)) {
        res.setHeader('Content-Type', 'text/javascript');
        return res.end(fs.readFileSync(path.join(assets, req.url.slice(1))));
    }
    if (req.url === '/fixture.js') {
        res.setHeader('Content-Type', 'text/javascript');
        const fixture = source + '\nfunction Fixture(){const [file,setFile]=React.useState(new File(["original bytes"],"source.skill"));window.selectNewFile=()=>setFile(new File(["new original"],"next.zip"));return <PackageEditor file={file} targetRuntime="generic" scanResult={{files:[{path:"SKILL.md",findings:[{id:"original-id",title:"Original matching finding",severity:"medium",description:"Review the observed phrase.",observations:[{line:8,text:"<em>Original text</em>"},{line:9,text:"Second observation"},{line:10,text:"Third observation"},{line:11,text:"Fourth observation hidden"}]}]}]}}/>;} ReactDOM.render(<Fixture/>,document.getElementById("root"));';
        return res.end('eval(Babel.transform(' + JSON.stringify(fixture) + ',{presets:["react"]}).code)');
    }
    if (req.url.startsWith('/api/skills/editor/')) {
        tokens.push(req.headers['x-editor-token']);
        assert.ok(!req.url.includes('token'));
        res.setHeader('Content-Type', 'application/json');
        if (req.url.endsWith('/inspect')) { if (holdInspect) return holdResponse(res, 'inspect'); return res.end(JSON.stringify(manifest)); }
        if (req.url.endsWith('/export')) {
            let body = ''; req.on('data', value => body += value); req.on('end', () => { exportBodies.push(body); failureMode = body.includes('claude-ai'); res.statusCode = 202; res.end(JSON.stringify({ job_id: 'job', status_url: '/api/skills/editor/jobs/job', progress: {stage:'queued',message:'Accepted by the fixture server.',elapsed_seconds:0} })); }); return;
        }
        if (req.url.endsWith('/jobs/job')) {
            statuses += 1;
            if (holdJobs) return holdResponse(res, 'jobs');
            if (forceRescanFailure) return res.end(JSON.stringify({status:'failed',progress:{stage:'failed',message:'Fixture rescan failed.',elapsed_seconds:9},error:{stage:'checking_coverage',message:'Synthetic inspection failure: example/assets/template.pptx'}}));
            if (controlledStage) return res.end(JSON.stringify({status:'running',progress:{stage:controlledStage,message:'Server declared '+controlledStage,elapsed_seconds:7}}));
            if (failureMode) return res.end(JSON.stringify({status:'failed',error:{message:'Package validation failed.',stage:'validation',validation:{errors:[{path:'example/SKILL.md',message:'Name must match the folder.',source:'https://agentskills.io/specification'}],warnings:[]}}}));
            const readyBody = JSON.stringify(statuses === 1 ? { status: 'running' } : { status: 'ready', result: { filename: 'edited.skill', requires_acknowledgement: true, sha256: 'output-hash', validation: { errors: [], warnings: ['Installation untested'] }, change_summary: ['replace SKILL.md', 'remove asset.bin'], scan_result: { files: [], findings: 0 }, download_url: '/api/skills/editor/jobs/job/download' } });
            const reply = () => res.end(readyBody);
            if (readyDelayMs) { const delay = readyDelayMs; readyDelayMs = 0; setTimeout(reply, delay); return; }
            return reply();
        }
        if (req.url.startsWith('/api/skills/editor/jobs/job/download')) { assert.ok(req.url.includes('acknowledge_limitations=true')); if (holdDownload) return holdResponse(res, 'download'); if (failNextDownload) { failNextDownload=false; res.statusCode=503; return res.end(JSON.stringify({detail:{message:'Synthetic download request failure.'}})); } res.setHeader('Content-Type', 'application/zip'); return res.end(Buffer.from('PK edited copy')); }
    }
    res.statusCode = 404; res.end();
});
(async () => {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { chromium } = require('C:/Python312/Lib/site-packages/playwright/driver/package');
    console.error('BROWSER_STEP launch');
    const browser = await chromium.launchPersistentContext(path.join(output, 'profile'), { timeout: 30000, acceptDownloads: true, executablePath: path.join(process.env.LOCALAPPDATA, 'BraveSoftware/Brave-Browser/Application/brave.exe'), headless: true, downloadsPath: path.join(output, 'downloads'), tracesDir: path.join(output, 'traces') });
    try {
        console.error('BROWSER_STEP page');
        const page = await browser.newPage();
        for (const blank of browser.pages()) { if (blank !== page && blank.url() === 'about:blank') await blank.close(); }
        page.setDefaultTimeout(10000);
        const errors = []; page.on('pageerror', error => errors.push(error.message));
        await page.goto('http://127.0.0.1:' + server.address().port);
        await page.getByRole('button', { name: 'Review package files', exact: true }).click();
        await page.getByText('Archive inspection', {exact:true}).click();
        assert.ok((await page.locator('[data-package-editor]').textContent()).includes('Archive structure inspected. Destination validation has not run.'));
        assert.ok(!(await page.locator('[data-package-editor]').textContent()).includes('Destination validation reported no errors.'));
        const evidence = page.getByRole('region', {name:'Original scan findings for selected file',exact:true});
        assert.ok((await evidence.textContent()).includes('Original matching finding · original-id · medium'));
        assert.ok((await evidence.textContent()).includes('Line 8: <em>Original text</em>'));
        assert.equal(await evidence.locator('em').count(),0);
        assert.ok(!(await evidence.textContent()).includes('Fourth observation hidden'));
        await page.getByText('Review guidance (2)', {exact:true}).click();
        const stages = page.getByRole('button', {name:'Stage suggested change',exact:true});
        assert.equal(await stages.nth(0).isDisabled(),true,'Unmatched suggestion cannot stage');
        await stages.nth(1).focus(); await stages.nth(1).press('Enter');
        assert.equal(await page.getByLabel('After · editable draft').inputValue(),original.replace('Original text','Reviewed text'));
        assert.equal(await page.getByRole('button',{name:'Build and rescan accepted copy',exact:true}).isDisabled(),true,'Staging is not acceptance');
        const acceptStaged = page.getByRole('button',{name:'Accept this text edit',exact:true});
        await acceptStaged.focus(); await acceptStaged.press('Enter');
        assert.equal(await page.getByRole('button',{name:'Build and rescan accepted copy',exact:true}).isDisabled(),false);
        await page.getByLabel('Package file', { exact: true }).selectOption('preview.txt');
        assert.equal(await page.getByLabel('After · editable draft').count(), 0);
        assert.ok((await page.locator('[data-package-editor]').textContent()).includes('combined text preview limit'));
        await page.getByLabel('Package file', { exact: true }).selectOption('SKILL.md');
        await page.getByLabel('After · editable draft').fill(original + '\nAccepted change');
        assert.equal(await page.getByRole('button', { name: 'Build and rescan accepted copy', exact: true }).isDisabled(), true);
        await page.getByRole('button', { name: 'Accept this text edit', exact: true }).click();
        await page.getByLabel('Package file', { exact: true }).selectOption('asset.bin');
        await page.getByRole('button', { name: 'Accept removal of this file', exact: true }).click();
        await page.getByLabel('Package file', { exact: true }).selectOption('SKILL.md');
        assert.equal(await page.getByRole('heading', { name: 'Before · original', exact: true }).locator('..').locator('pre').textContent(), original);
        await page.getByLabel('Destination', { exact: true }).selectOption('gemini-cli');
        assert.equal(await page.getByLabel('Download format', { exact: true }).inputValue(), 'skill');
        console.error('BROWSER_STEP server-stages');
        controlledStage = 'validating_and_building';
        await page.getByRole('button', { name: 'Build and rescan accepted copy', exact: true }).click();
        const activity = page.getByRole('region', {name:'Package operation status',exact:true});
        await activity.getByText('Server declared validating_and_building', {exact:true}).waitFor();
        assert.ok((await activity.textContent()).includes('Running'));
        assert.equal(await activity.getByRole('progressbar').getAttribute('value'), null, 'Progress is indeterminate');
        assert.ok((await activity.textContent()).includes('Server time at last update: 7 seconds.'));
        await page.waitForFunction(() => /Elapsed: [1-9][0-9]* seconds/.test(document.querySelector('[data-editor-progress]').textContent));
        assert.ok(!(await activity.locator('[aria-live]').textContent()).includes('Elapsed:'), 'Timer does not announce each second');
        for (const stage of ['rescanning','checking_coverage']) {
            controlledStage = stage;
            await activity.getByText('Server declared '+stage, {exact:true}).waitFor();
        }
        controlledStage = null;
        await page.getByRole('button', { name: 'Download edited .skill', exact: true }).waitFor({ timeout: 10000 });
        assert.equal(await page.getByRole('button', { name: 'Download edited .skill', exact: true }).isDisabled(), true);
        await page.getByLabel('I reviewed the remaining findings and inspection limitations.', { exact: true }).check();
        console.error('BROWSER_STEP download-retry');
        failNextDownload = true;
        await page.getByRole('button', { name: 'Download edited .skill', exact: true }).click();
        await page.getByRole('alert').filter({hasText:'Synthetic download request failure.'}).waitFor();
        assert.ok((await activity.textContent()).includes('Request failed'));
        assert.equal(await page.getByRole('button', {name:'Download edited .skill',exact:true}).isEnabled(), true);
        assert.equal(exportBodies.length, 1, 'Retrying a ready download does not rebuild');
        const waiting = page.waitForEvent('download');
        await page.getByRole('button', { name: 'Download edited .skill', exact: true }).click();
        const downloaded = await waiting;
        assert.equal(downloaded.suggestedFilename(), 'edited.skill');
        assert.equal(fs.readFileSync(await downloaded.path(), 'utf8'), 'PK edited copy');
        assert.equal(exportBodies.length, 1); assert.ok(exportBodies[0].includes('"original_sha256":"text-hash"')); assert.ok(exportBodies[0].includes('"action":"remove"')); assert.ok(exportBodies[0].includes('Accepted change'));
        assert.ok(tokens.length >= 5); assert.match(tokens[0], /^[a-f0-9]{64}$/); assert.ok(tokens.every(token => token === tokens[0]));
        await page.evaluate(() => window.selectNewFile());
        await page.getByRole('button', { name: 'Review package files', exact: true }).waitFor();
        assert.equal(await page.getByLabel('Download format', { exact: true }).count(), 0);
        assert.equal(await page.getByRole('button', { name: 'Download edited .skill', exact: true }).count(), 0);
        await page.getByRole('button', { name: 'Review package files', exact: true }).click();
        assert.equal(await page.getByLabel('Download format', { exact: true }).inputValue(), 'zip');
        assert.equal(await page.getByLabel('After · editable draft').inputValue(), original);
        await page.getByLabel('Destination', { exact: true }).selectOption('claude-ai');
        await page.getByRole('button', { name: 'Build and rescan accepted copy', exact: true }).click();
        const failed = page.getByRole('region', { name:'Failed destination validation',exact:true });
        await failed.waitFor();
        assert.ok((await failed.textContent()).includes('example/SKILL.md: Name must match the folder.'));
        assert.equal(await failed.getByRole('link', {name:'Source',exact:true}).getAttribute('href'),'https://agentskills.io/specification');
        assert.equal(await page.getByRole('button', {name:'Download edited .zip',exact:true}).count(),0);
        console.error('BROWSER_STEP failure-preservation');
        // A terminal server failure keeps review work and original evidence usable.
        await page.getByLabel('Destination', {exact:true}).selectOption('generic-agent-skills');
        await page.getByLabel('After · editable draft').fill(original+'\nRetained revision');
        await page.getByRole('button', {name:'Accept this text edit',exact:true}).click();
        forceRescanFailure = true;
        await page.getByRole('button', {name:'Build and rescan accepted copy',exact:true}).click();
        await activity.getByText('Build failed', {exact:true}).waitFor();
        assert.ok((await page.getByRole('alert').textContent()).includes('example/assets/template.pptx'));
        assert.equal(await page.getByLabel('After · editable draft').inputValue(), original+'\nRetained revision');
        assert.ok((await page.locator('[data-package-editor]').textContent()).includes('Replace SKILL.md · accepted revision'));
        assert.ok((await evidence.textContent()).includes('original-id'));
        assert.equal(await page.getByRole('button', {name:'Retry build and rescan',exact:true}).isEnabled(), true);
        assert.equal(await page.getByRole('button', {name:'Download edited .zip',exact:true}).count(), 0);
        await page.screenshot({path:path.join(output,'rescan-failure.png'),fullPage:true});

        console.error('BROWSER_STEP stop-waiting');
        // Stop waiting aborts this browser request, not the server job.
        forceRescanFailure = false; controlledStage = 'rescanning';
        await page.getByRole('button', {name:'Retry build and rescan',exact:true}).click();
        await activity.getByText('Server declared rescanning', {exact:true}).waitFor();
        holdJobs = true;
        await until(() => held.jobs.size > 0, 'Status request reached the server');
        const closedBeforeStop = closedHeld.jobs;
        const stop = page.getByRole('button', {name:'Stop waiting',exact:true});
        await stop.focus(); await stop.press('Enter');
        await activity.getByText('Stopped waiting', {exact:true}).waitFor();
        assert.ok((await activity.textContent()).includes('Server processing may continue.'));
        assert.ok(!(await activity.textContent()).includes('Build failed'));
        assert.equal(await page.getByLabel('After · editable draft').inputValue(),original+'\nRetained revision');
        await until(() => closedHeld.jobs > closedBeforeStop, 'Stopped browser request was closed');
        const requestsAfterStop = statuses;
        await new Promise(resolve => setTimeout(resolve, 1200));
        assert.equal(statuses,requestsAfterStop,'Polling stops after the user stops waiting');
        holdJobs = false; controlledStage = null;

        console.error('BROWSER_STEP waiting-timeouts');
        // Accelerate only long waiting deadlines on this separate page.
        const timeoutPage = await browser.newPage();
        timeoutPage.on('pageerror',error=>errors.push(error.message));
        await timeoutPage.addInitScript(() => {
            const nativeTimeout = window.setTimeout.bind(window);
            window.accelerateEditorWaits = true;
            window.setTimeout = (callback, delay, ...args) => nativeTimeout(callback, window.accelerateEditorWaits && delay >= 60000 ? 1000 : delay, ...args);
        });
        holdInspect = true;
        await timeoutPage.goto('http://127.0.0.1:'+server.address().port);
        await timeoutPage.getByRole('button',{name:'Review package files',exact:true}).click();
        await timeoutPage.getByRole('alert').filter({hasText:'Stopped waiting after 60 seconds.'}).waitFor();
        assert.ok((await timeoutPage.locator('[data-editor-progress]').textContent()).includes('Stopped waiting'));
        assert.ok((await timeoutPage.getByRole('alert').textContent()).includes('does not confirm a server failure'));
        holdInspect = false;
        await timeoutPage.evaluate(() => window.accelerateEditorWaits = false);
        await timeoutPage.getByRole('button',{name:'Review package files',exact:true}).click();
        await timeoutPage.getByLabel('After · editable draft').waitFor();
        holdJobs = true;
        await timeoutPage.evaluate(() => window.accelerateEditorWaits = true);
        await timeoutPage.getByRole('button',{name:'Build and rescan accepted copy',exact:true}).click();
        await timeoutPage.getByRole('alert').filter({hasText:'Stopped waiting after 180 seconds.'}).waitFor();
        assert.equal(await timeoutPage.getByLabel('After · editable draft').inputValue(),original);
        holdJobs = false;
        // A valid slow status response must not inherit the preceding timeout clock.
        await timeoutPage.evaluate(() => window.accelerateEditorWaits = false);
        readyDelayMs = 1500;
        console.error('BROWSER_STEP recovery-ready-delay',readyDelayMs);
        await timeoutPage.getByRole('button',{name:'Build and rescan accepted copy',exact:true}).click();
        const timedDownload = timeoutPage.getByRole('button',{name:'Download edited .skill',exact:true});
        try { await timedDownload.waitFor({timeout:5000}); }
        catch (problem) {
            console.error('RECOVERY_DIAGNOSTIC',JSON.stringify({status:await timeoutPage.locator('[data-editor-progress]').textContent(),alerts:await timeoutPage.getByRole('alert').allTextContents(),statuses,failureMode,forceRescanFailure,controlledStage,holdJobs,exports:exportBodies.length}));
            await timeoutPage.screenshot({path:path.join(output,'timeout-recovery-diagnostic.png'),fullPage:true});
            throw problem;
        }
        assert.equal(await timeoutPage.getByRole('alert').count(),0,'Normal recovery completes without a shortened waiting deadline');
        await timeoutPage.getByLabel('I reviewed the remaining findings and inspection limitations.',{exact:true}).check();
        holdDownload = true;
        await timeoutPage.evaluate(() => window.accelerateEditorWaits = true);
        const exportsBeforeDownloadTimeout = exportBodies.length;
        await timedDownload.click();
        await timeoutPage.getByRole('alert').filter({hasText:'Stopped waiting after 60 seconds.'}).waitFor();
        assert.equal(await timedDownload.isEnabled(),true,'Ready artifact can be retried after a download timeout');
        assert.equal(exportBodies.length,exportsBeforeDownloadTimeout);
        holdDownload = false;
        await timeoutPage.close();

        console.error('BROWSER_STEP resource-cleanup');
        // Track timer resources, then deliver an old status despite an ignored abort.
        const resourcePage = await browser.newPage();
        resourcePage.on('pageerror',error=>errors.push(error.message));
        await resourcePage.addInitScript(() => {
            const timeouts=new Set(), intervals=new Set();
            const nativeTimeout=window.setTimeout.bind(window), nativeClearTimeout=window.clearTimeout.bind(window);
            const nativeInterval=window.setInterval.bind(window), nativeClearInterval=window.clearInterval.bind(window);
            window.setTimeout=(callback,delay,...args)=>{
                if(typeof callback!=='function')return nativeTimeout(callback,delay,...args);
                let id; id=nativeTimeout((...values)=>{timeouts.delete(id);callback(...values);},delay,...args);
                timeouts.add(id); return id;
            };
            window.clearTimeout=id=>{timeouts.delete(id);nativeClearTimeout(id);};
            window.setInterval=(callback,delay,...args)=>{const id=nativeInterval(callback,delay,...args);intervals.add(id);return id;};
            window.clearInterval=id=>{intervals.delete(id);nativeClearInterval(id);};
            window.editorTimerCounts=()=>({timeouts:timeouts.size,intervals:intervals.size});
            const nativeFetch=window.fetch.bind(window);
            window.fetch=(url,options={})=>{
                if(window.ignoreEditorJobAbort && String(url).includes('/api/skills/editor/jobs/')){
                    const {signal,...rest}=options; return nativeFetch(url,rest);
                }
                return nativeFetch(url,options);
            };
        });
        await resourcePage.goto('http://127.0.0.1:'+server.address().port);
        await resourcePage.getByRole('button',{name:'Review package files',exact:true}).click();
        await resourcePage.getByLabel('After · editable draft').waitFor();
        await resourcePage.evaluate(()=>window.ignoreEditorJobAbort=true);
        holdJobs = true;
        await resourcePage.getByRole('button',{name:'Build and rescan accepted copy',exact:true}).click();
        await until(()=>held.jobs.size>0,'Old job status is pending');
        await resourcePage.evaluate(()=>window.selectNewFile());
        await resourcePage.waitForFunction(()=>{const counts=window.editorTimerCounts();return counts.timeouts===0&&counts.intervals===0;},undefined,{timeout:3000});
        const staleResponse=resourcePage.waitForResponse(response=>response.url().endsWith('/api/skills/editor/jobs/job'));
        for(const response of held.jobs)response.end(JSON.stringify({status:'failed',progress:{stage:'failed',message:'Stale failure'},error:{stage:'rescan',message:'Stale failure must stay hidden.'}}));
        await staleResponse;
        await resourcePage.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
        assert.equal(await resourcePage.locator('[data-editor-progress]').count(),0,'Late previous-file status stays hidden');
        assert.equal(await resourcePage.getByRole('alert').count(),0);
        await until(()=>held.jobs.size===0,'Old held response was released');
        await resourcePage.evaluate(()=>window.ignoreEditorJobAbort=false);
        await resourcePage.getByRole('button',{name:'Review package files',exact:true}).click();
        await resourcePage.getByLabel('After · editable draft').waitFor();
        await resourcePage.getByRole('button',{name:'Build and rescan accepted copy',exact:true}).click();
        await until(()=>held.jobs.size>0,'Unmount has an active operation to clean up');
        await resourcePage.evaluate(()=>ReactDOM.unmountComponentAtNode(document.getElementById('root')));
        await resourcePage.waitForFunction(()=>{const counts=window.editorTimerCounts();return counts.timeouts===0&&counts.intervals===0;},undefined,{timeout:3000});
        await until(()=>held.jobs.size===0,'Unmount closed the status request');
        assert.equal(await resourcePage.locator('#root').innerHTML(),'');
        holdJobs = false;
        await resourcePage.close();
        assert.deepEqual(errors, []);
        await page.screenshot({ path: path.join(output, 'editor.png'), fullPage: true });
        console.log(JSON.stringify({ pass: true, assertions: ['explicit text acceptance', 'binary removal', 'original preserved', 'same token headers on every request', 'poll then authenticated download', 'destination format choice', 'new selection resets editor', 'acknowledgement required for download', 'preview-limited text remains read only', 'failed validation shows path and source', 'invalid frontmatter archive inspection does not claim destination validation', 'original selected-file evidence and bounded escaped observations', 'keyboard stage then explicit acceptance', 'declared server phases and elapsed', 'rescan failure preserves review work', 'stopped waiting is not server cancellation', 'ready download retry without rebuild', 'bounded inspect/build/download waiting', 'selection/unmount timer cleanup and stale response rejection'], output }));
    } finally {
        let closeTimer;
        try { await Promise.race([browser.close(), new Promise((_, reject) => { closeTimer = setTimeout(() => reject(new Error('Browser close exceeded ten seconds')), 10000); })]); }
        finally { clearTimeout(closeTimer); server.closeAllConnections(); server.close(); }
    }
})().catch(error => { console.error(error); server.close(); process.exitCode = 1; });
