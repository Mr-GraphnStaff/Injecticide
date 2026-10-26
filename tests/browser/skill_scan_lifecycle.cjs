// Run with Node and Playwright available via NODE_PATH. Uses only synthetic scans.
// Pinned browser libraries: tmp/scan-resource-regression/{react,react-dom,babel}.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { execFileSync } = require('node:child_process');
const { chromium } = require('playwright');
// Contact labels cannot infer internal provenance from a reference path/domain.
const appForClassification = fs.readFileSync(path.resolve(__dirname, '../../webapp/static/app.js'), 'utf8');
const classificationSource = appForClassification.slice(appForClassification.indexOf('const SECURITY_CATEGORIES'), appForClassification.indexOf('function classifyFindingLabel'));
const classifyContact = new Function(classificationSource + ';return classifyReviewClass;')();
for (const role of ['active', 'reference', 'reference_template']) {
    for (const id of ['pii_email_address', 'pii_phone_number']) {
        assert.equal(classifyContact({id, tier:'review', category:'data', severity:'medium', samples:['security@company.test'], is_actionable:true}, role), 'sensitive_data');
    }
}

const root = path.resolve(__dirname, '../..');
const packageReport = JSON.parse(execFileSync('python', ['-c',
    "import io,json,zipfile; from skill_sandbox.app import scan_upload; b=io.BytesIO(); z=zipfile.ZipFile(b,'w'); z.writestr('demo/SKILL.md','---\\nname: demo\\ndescription: Fixture\\n---\\nSummarize text.'); z.writestr('demo/logo.png',bytes([137,80,78,71,13,10,26,10,0])); z.close(); print(json.dumps(scan_upload(b.getvalue(),'package-fixture.zip')))"
], {cwd: root, encoding:'utf8'}));
const policyReport = JSON.parse(execFileSync('python', ['-c',
    "import io,json,zipfile; from pathlib import Path; from skill_sandbox.app import scan_upload; b=io.BytesIO(); z=zipfile.ZipFile(b,'w'); z.writestr('demo/SKILL.md','---\\nname: demo\\ndescription: Fixture\\n---\\nSummarize text.'); z.writestr('demo/scripts/apply_notes.py.md',Path('tests/fixtures/package_snippets/apply_notes.py.md').read_text()); z.close(); print(json.dumps(scan_upload(b.getvalue(),'policy-fixture.zip')))"
], {cwd: root, encoding:'utf8'}));
const assetRoot = path.join(root, 'tmp/scan-resource-regression');
const source = fs.readFileSync(process.env.INJECTICIDE_APP_SOURCE || path.join(root, 'webapp/static/app.js'), 'utf8');
const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', req.url === '/' ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8');
    if (req.url === '/') return res.end('<div id="root"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script src="/babel.js"></script><script src="/fixture.js"></script>');
    if (req.url === '/fixture.js') return res.end('eval(Babel.transform(' + JSON.stringify(source.replace('ReactDOM.render(<Root />,', 'ReactDOM.render(<App />,')) + ', {presets:["react"]}).code)');
    if (['/react.js', '/react-dom.js', '/babel.js'].includes(req.url)) return res.end(fs.readFileSync(path.join(assetRoot, req.url.slice(1))));
    res.statusCode = 404;
    res.end();
});

(async () => {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const browser = await chromium.launch({ channel: process.env.INJECTICIDE_TEST_BROWSER || 'msedge', headless: true });
    try {
        const page = await browser.newPage({ acceptDownloads: true });
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        await page.addInitScript(() => {
            // Mock endpoint data; keep no uploaded File or completed report in this harness.
            window.pendingScans = [];
            const originalSetTimeout = window.setTimeout;
            window.setTimeout = (fn, ms, ...args) => originalSetTimeout(fn, ms === 60000 ? 1200 : ms, ...args);
            window.fetch = async (url, options) => {
                if (url === '/api/skills/scan') {
                    window.lastScanRuntime = options.body.get('target_runtime');
                    return new Promise((resolve, reject) => {
                        const ignoreAbort = window.ignoreScanAbort;
                        options.signal.addEventListener('abort', () => {
                            if (!ignoreAbort) reject(new DOMException('Aborted', 'AbortError'));
                        }, {once:true});
                        window.pendingScans.push({ signal: options.signal, resolve });
                    });
                }
                return new Response(JSON.stringify({ categories: [], endpoints: [], payload_presets: [] }), { status: 200 });
            };
        });
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        const input = page.locator('input[type=file]');
        const scan = page.getByRole('button', { name: 'Scan Skill File/Bundle', exact: true });
        const select = name => input.setInputFiles({ name, mimeType: 'text/markdown', buffer: Buffer.from('Synthetic skill fixture') });
        const respond = async (filename, large = false) => page.evaluate(({filename, large}) => {
            const files = Array.from({length: large ? 200 : 1}, (_, i) => ({
                path: `${filename}/file-${i}.md`, artifact_role: 'active', skipped: false,
                findings: Array.from({length: large ? 40 : 1}, (_, j) => ({
                    id: `fixture-${j}`, tier: 'block', severity: 'high', category: 'prompt',
                    description: 'Synthetic finding for resource regression', is_actionable: true,
                    finding_category: 'policy_override', subject: 'fixture', action_state: 'present', disposition: 'review',
                    samples: [`sample-${j}`],
                })),
            }));
            window.pendingScans.shift().resolve(new Response(JSON.stringify({
                filename, files, warnings: [], summary: { total_files: files.length, flagged_files: files.length, total_findings: large ? 8000 : 1 },
            }), { status: 200 }));
        }, {filename, large});
        const waitReport = filename => page.getByText(filename, {exact:true}).waitFor();

        await page.getByLabel('Target runtime', {exact:true}).selectOption('claude-code');
        await select('package-fixture.zip');
        await scan.click();
        assert.equal(await page.evaluate(() => window.lastScanRuntime), 'claude-code');
        await page.evaluate(report => window.pendingScans.shift().resolve(new Response(JSON.stringify(report), {status:200})), packageReport);
        await waitReport('package-fixture.zip');
        assert.equal(await page.getByText('Package review incomplete', {exact:true}).count(), 1);
        assert.equal(await page.locator('[data-package-overview]').count(), 1);
        assert.equal(await page.getByRole('region', {name:'Vendor requirement verification'}).count(), 1);
        assert.match(await page.getByRole('region', {name:'Vendor requirement verification'}).innerText(), /UNKNOWN/);
        if (process.env.INJECTICIDE_TEST_SCREENSHOT) {
            await page.getByRole('region', {name:'Vendor requirement verification'}).screenshot({path: process.env.INJECTICIDE_TEST_SCREENSHOT});
        }
        await page.getByLabel('Package report section', {exact:true}).selectOption('checks');
        assert.equal(await page.locator('[data-package-evidence]').count(), 10);
        await page.getByRole('navigation', {name:'Package evidence pages', exact:true}).getByRole('button', {name:'Next', exact:true}).click();
        assert.equal(await page.locator('[data-package-evidence]').count(), 10);
        await page.getByRole('button', {name:'detailed', exact:true}).click();
        const packageDownload = page.waitForEvent('download');
        await page.getByRole('button', {name:'Export Detailed', exact:true}).click();
        const packageExport = fs.readFileSync(await (await packageDownload).path(), 'utf8');
        assert.match(packageExport, /binary_asset_inventory_only/);
        assert.match(packageExport, /UPD-01/);
        assert.match(packageExport, /artifact_sha256/);
        assert.match(packageExport, /vendor_verification/);

        await select('vendor-fixture.zip');
        await scan.click();
        const vendorReport = {...packageReport, filename:'vendor-fixture.zip', vendor_verification:{
            status:'current_documented_requirements', product:'Claude custom skill uploads', live_check:true,
            compatibility:'fails_documented_requirement', statement:'Harmless metadata fixture.',
            documents:[], requirements:[], checks:[{path:'demo/SKILL.md', field:'description_max_characters',
                observed:201, maximum:200, status:'fail'}]}};
        await page.evaluate(report => window.pendingScans.shift().resolve(new Response(JSON.stringify(report), {status:200})), vendorReport);
        await waitReport('vendor-fixture.zip');
        assert.equal(await page.getByText('Documented vendor requirement not met', {exact:true}).count(), 1);
        const vendorPanel = page.getByRole('region', {name:'Vendor requirement verification'});
        await vendorPanel.getByText('Sources, limits and checks', {exact:true}).click();
        assert.match(await vendorPanel.innerText(), /observed 201, maximum 200/);
        if (process.env.INJECTICIDE_TEST_SCREENSHOT) await vendorPanel.screenshot({path:process.env.INJECTICIDE_TEST_SCREENSHOT});

        await select('policy-fixture.zip');
        await scan.click();
        await page.evaluate(report => window.pendingScans.shift().resolve(new Response(JSON.stringify(report), {status:200})), policyReport);
        await waitReport('policy-fixture.zip');
        assert.equal(await page.getByText('Executable code packaged as a document', {exact:true}).count(), 1);
        assert.equal(await page.getByText('Potential upload-control bypass: executable source behind a document extension. Malware is not established.', {exact:true}).count(), 1);

        await select('first.skill');
        await scan.click();
        assert.equal(await input.evaluate(el => el.files.length), 0, 'upload must release file picker reference');
        await respond('first.skill', true);
        await waitReport('first.skill');
        assert.equal(await page.locator('[data-skill-file]').count(), 10);
        assert.equal(await page.locator('[data-skill-finding]').count(), 100);
        await page.getByRole('navigation', {name:'File pages', exact:true}).getByRole('button', {name:'Next', exact:true}).click();
        assert.match(await page.locator('[data-skill-file]').first().innerText(), /file-10.md/);
        await page.getByRole('navigation', {name:'Finding pages', exact:true}).first().getByRole('button', {name:'Next', exact:true}).click();
        assert.match(await page.locator('[data-skill-finding]').first().innerText(), /fixture-10/);
        await page.getByRole('button', {name:'detailed', exact:true}).click();
        const downloadEvent = page.waitForEvent('download');
        await page.getByRole('button', {name:'Export Detailed', exact:true}).click();
        const exported = fs.readFileSync(await (await downloadEvent).path(), 'utf8');
        assert.match(exported, /file-199.md/);
        assert.match(exported, /fixture-39/);

        // A new selection removes the previous report immediately, before scanning.
        await select('second.skill');
        assert.equal(await page.locator('[data-skill-file]').count(), 0);
        await page.evaluate(() => { window.ignoreScanAbort = true; });
        await scan.click();
        await select('third.skill');
        await page.evaluate(() => { window.ignoreScanAbort = false; });
        assert.equal(await page.evaluate(() => window.pendingScans[0].signal.aborted), true);
        await scan.click();
        // Simulate a transport that delivers an old response despite cancellation.
        await respond('second.skill');
        assert.equal(await page.getByText('second.skill', {exact:true}).count(), 0);
        await respond('third.skill');
        await waitReport('third.skill');

        const cdp = await page.context().newCDPSession(page);
        const measurements = [];
        for (let i = 0; i < 12; i++) {
            await select(`repeat-${i}.skill`);
            await scan.click();
            await respond(`repeat-${i}.skill`, true);
            await waitReport(`repeat-${i}.skill`);
            assert.equal(await input.evaluate(el => el.files.length), 0);
            assert.equal(await page.locator('[data-skill-file]').count(), 10);
            assert.equal(await page.locator('[data-skill-finding]').count(), 100);
            await cdp.send('HeapProfiler.collectGarbage');
            measurements.push({ ...(await cdp.send('Memory.getDOMCounters')), ...(await cdp.send('Runtime.getHeapUsage')) });
        }
        assert.ok(measurements.at(-1).nodes <= measurements[2].nodes + 100, 'DOM nodes must not accumulate between scans');
        assert.ok(measurements.at(-1).usedSize <= measurements[2].usedSize + 5 * 1024 * 1024, 'heap must not grow with scan history');
        await page.getByRole('button', {name:'Clear scan', exact:true}).click();
        assert.equal(await page.locator('[data-skill-file]').count(), 0);
        assert.equal(await input.evaluate(el => el.files.length), 0);

        await select('timeout.skill');
        await scan.click();
        await page.getByText('Scan timed out. Select the file again to retry.', {exact:true}).waitFor();
        assert.equal(await page.evaluate(() => window.pendingScans[0].signal.aborted), true);
        await respond('timeout.skill');
        assert.equal(await page.getByText('timeout.skill', {exact:true}).count(), 0);

        await select('leaving.skill');
        await scan.click();
        await page.evaluate(() => ReactDOM.unmountComponentAtNode(document.getElementById('root')));
        await page.waitForFunction(() => window.pendingScans[0].signal.aborted);
        assert.equal(await page.evaluate(() => window.pendingScans[0].signal.aborted), true);
        await respond('leaving.skill');
        assert.equal(await page.locator('#root').innerHTML(), '');
        assert.deepEqual(errors, []);
        console.log(JSON.stringify({status:'PASS', repeatedScans:12, filesPerReport:200, findingsPerReport:8000,
            maxVisibleFiles:10, maxVisibleFindings:100,
            postGCHeapMiB:measurements.map(m => +(m.usedSize / 1024 / 1024).toFixed(2)),
            postGCNodes:measurements.map(m => m.nodes),
            checked:['real package report','partial coverage headline','policy bypass distinct from malware','package evidence pagination','fingerprint and checks export','file release','replacement','stale response','pagination','complete export','clear','timeout','unmount']}, null, 2));
    } finally {
        await browser.close();
    }
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => server.close());
