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
let statuses = 0, failureMode = false;
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
        if (req.url.endsWith('/inspect')) return res.end(JSON.stringify(manifest));
        if (req.url.endsWith('/export')) {
            let body = ''; req.on('data', value => body += value); req.on('end', () => { exportBodies.push(body); failureMode = body.includes('claude-ai'); res.statusCode = 202; res.end(JSON.stringify({ job_id: 'job', status_url: '/api/skills/editor/jobs/job' })); }); return;
        }
        if (req.url.endsWith('/jobs/job')) {
            statuses += 1;
            if (failureMode) return res.end(JSON.stringify({status:'failed',error:{message:'Package validation failed.',stage:'validation',validation:{errors:[{path:'example/SKILL.md',message:'Name must match the folder.',source:'https://agentskills.io/specification'}],warnings:[]}}}));
            return res.end(JSON.stringify(statuses === 1 ? { status: 'running' } : { status: 'ready', result: { filename: 'edited.skill', requires_acknowledgement: true, sha256: 'output-hash', validation: { errors: [], warnings: ['Installation untested'] }, change_summary: ['replace SKILL.md', 'remove asset.bin'], scan_result: { files: [], findings: 0 }, download_url: '/api/skills/editor/jobs/job/download' } }));
        }
        if (req.url.startsWith('/api/skills/editor/jobs/job/download')) { assert.ok(req.url.includes('acknowledge_limitations=true')); res.setHeader('Content-Type', 'application/zip'); return res.end(Buffer.from('PK edited copy')); }
    }
    res.statusCode = 404; res.end();
});
(async () => {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { chromium } = require('C:/Python312/Lib/site-packages/playwright/driver/package');
    const browser = await chromium.launch({ executablePath: path.join(process.env.LOCALAPPDATA, 'BraveSoftware/Brave-Browser/Application/brave.exe'), headless: true, downloadsPath: path.join(output, 'downloads'), tracesDir: path.join(output, 'traces') });
    try {
        const page = await browser.newPage({ acceptDownloads: true });
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
        await page.getByRole('button', { name: 'Build and rescan accepted copy', exact: true }).click();
        await page.getByRole('button', { name: 'Download edited .skill', exact: true }).waitFor({ timeout: 10000 });
        assert.equal(await page.getByRole('button', { name: 'Download edited .skill', exact: true }).isDisabled(), true);
        await page.getByLabel('I reviewed the remaining findings and inspection limitations.', { exact: true }).check();
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
        assert.deepEqual(errors, []);
        await page.screenshot({ path: path.join(output, 'editor.png'), fullPage: true });
        console.log(JSON.stringify({ pass: true, assertions: ['explicit text acceptance', 'binary removal', 'original preserved', 'same token headers on every request', 'poll then authenticated download', 'destination format choice', 'new selection resets editor', 'acknowledgement required for download', 'preview-limited text remains read only', 'failed validation shows path and source', 'invalid frontmatter archive inspection does not claim destination validation', 'original selected-file evidence and bounded escaped observations', 'keyboard stage then explicit acceptance'], output }));
    } finally { await browser.close(); server.close(); }
})().catch(error => { console.error(error); server.close(); process.exitCode = 1; });
