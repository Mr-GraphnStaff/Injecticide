// Run with Node and Playwright available via NODE_PATH. Uses only synthetic scans.
// Pinned browser libraries: tmp/scan-resource-regression/{react,react-dom,babel}.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '../..');
const assetRoot = path.join(root, 'tmp/scan-resource-regression');
const source = fs.readFileSync(process.env.INJECTICIDE_APP_SOURCE || path.join(root, 'webapp/static/app.js'), 'utf8');
const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', req.url === '/' ? 'text/html' : 'text/javascript');
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
            checked:['file release','replacement','stale response','pagination','complete export','clear','timeout','unmount']}, null, 2));
    } finally {
        await browser.close();
    }
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => server.close());
