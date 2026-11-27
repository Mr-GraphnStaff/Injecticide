// Managed, isolated browser UI against the real local policy and scan API.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {execFileSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const run = process.env.AGENT_WORKING_DIR;
if (!run || !path.resolve(run).startsWith(path.join(root, 'working', 'runs') + path.sep)) throw Error('Use the managed launcher.');
const output = path.join(run, 'reports', 'browser', 'plugin-anatomy');
fs.mkdirSync(output, {recursive:true});
const cache = path.join(root, 'working', 'cache', 'browser');
const assets = path.join(cache, 'scan-resource-regression');
const {chromium} = require(path.join(cache, 'node_modules', 'playwright'));
const source = fs.readFileSync(path.join(root, 'webapp/static/components/PackageEditor.jsx'), 'utf8') + '\n' + fs.readFileSync(path.join(root, 'webapp', 'static', 'app.js'), 'utf8');
const template = fs.readFileSync(path.join(root, 'webapp', 'static', 'org-policy-template.json'), 'utf8');
const fixture = Buffer.from(execFileSync('python', ['-c', "import base64,io,json,zipfile; from pathlib import Path; files=json.loads(Path('tests/fixtures/plugin_anatomy.json').read_text()); b=io.BytesIO(); z=zipfile.ZipFile(b,'w'); [z.writestr(p,v if isinstance(v,str) else json.dumps(v)) for p,v in files.items()]; z.close(); print(base64.b64encode(b.getvalue()).decode())"], {cwd:root,encoding:'utf8'}).trim(), 'base64');
let scans = 0, validations = 0, mode = 'normal', releaseHeld;
const deadline = setTimeout(() => { console.error('Policy browser acceptance exceeded its 120 second bound.'); process.exit(1); }, 120000);
const server = http.createServer(async (req, res) => {
    if (req.url === '/') {
        res.setHeader('Content-Type','text/html;charset=utf-8');
        return res.end('<html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/static/home.css"></head><body><div id="root"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script src="/babel.js"></script><script src="/fixture.js"></script></body></html>');
    }
    if (['/react.js','/react-dom.js','/babel.js'].includes(req.url)) return res.end(fs.readFileSync(path.join(assets, req.url.slice(1))));
    if (req.url === '/fixture.js') return res.end('eval(Babel.transform(' + JSON.stringify(source.replace('ReactDOM.render(<Root />,', 'ReactDOM.render(<App />,')) + ',{presets:["react"]}).code)');
    if (req.url === '/static/org-policy-template.json') return res.end(template);
    if (req.url === '/static/home.css') { res.setHeader('Content-Type','text/css'); return res.end(fs.readFileSync(path.join(root,'webapp/static/home.css'))); }
    if (req.url === '/static/finding-labels.json') return res.end(fs.readFileSync(path.join(root,'webapp/static/finding-labels.json')));
    if (req.url.startsWith('/api/skills/policy/validate') || req.url.startsWith('/api/skills/scan')) {
        const chunks = []; for await (const chunk of req) chunks.push(chunk);
        if (req.url === '/api/skills/scan') scans++;
        if (req.url === '/api/skills/policy/validate') {
            validations++;
            if (mode === 'offline') { res.writeHead(503, {'Content-Type':'application/json'}); return res.end('{}'); }
            if (mode === 'hold') { mode = 'normal'; await new Promise(resolve => { releaseHeld = resolve; }); }
        }
        try {
            const upstream = await fetch((process.env.INJECTICIDE_TEST_URL || 'http://127.0.0.1:8247') + req.url,
                {method:req.method, headers:req.headers['content-type'] ? {'Content-Type':req.headers['content-type']} : {},
                 ...(req.method === 'POST' ? {body:Buffer.concat(chunks)} : {})});
            res.writeHead(upstream.status, {'Content-Type':'application/json'}); res.end(await upstream.text());
        } catch (error) { res.writeHead(502); res.end('{}'); }
        return;
    }
    res.setHeader('Content-Type','application/json'); res.end('[]');
});

(async () => {
    await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
    const browser = await chromium.launch({headless:true, downloadsPath:path.join(output,'downloads'), channel:'msedge'});
    try {
        const page = await browser.newPage({acceptDownloads:true});
        page.setDefaultTimeout(25000);
        const errors = []; page.on('pageerror', error => {errors.push(error.message);console.error(error.message);});
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        await page.getByLabel('Skill file',{exact:true}).setInputFiles({name:'anatomy-demo.plugin',mimeType:'application/zip',buffer:fixture});
        await page.getByRole('button',{name:'Scan Skill File/Bundle',exact:true}).click();
        const anatomy = page.getByRole('region',{name:'Plugin anatomy',exact:true});
        await anatomy.waitFor();
        assert.match(await anatomy.innerText(),/anatomy-demo/);
        assert.match(await anatomy.innerText(),/Subagents: 2/);
        assert.match(await anatomy.innerText(),/Inactive|ignored default/i);
        assert.match(await anatomy.innerText(),/Nothing was installed, started or invoked/);
        assert.doesNotMatch(await anatomy.innerText(),/PLACEHOLDER_PRIVATE_CONFIG_VALUE/);
        assert.equal(await anatomy.locator('[data-plugin-component]').count(),10);
        await anatomy.getByRole('navigation',{name:'Plugin component pages',exact:true}).getByRole('button',{name:'Next',exact:true}).click();
        assert.match(await anatomy.innerText(),/Message channels/);
        assert.match(await anatomy.innerText(),/<img src=x onerror=alert\(1\)>/);
        assert.equal(await page.locator('img[src=x]').count(),0);
        await page.getByRole('button',{name:'detailed',exact:true}).click();
        const markdownDownload = page.waitForEvent('download');
        await page.getByRole('button',{name:'Export Detailed',exact:true}).click();
        const markdown = fs.readFileSync(await (await markdownDownload).path(),'utf8');
        assert.match(markdown,/## Plugin anatomy/);
        assert.match(markdown,/Background monitors/);
        assert.match(markdown,/Message channels/);
        assert.match(markdown,/ignored\\_default/);
        const anatomyExport = markdown.split('## Plugin anatomy')[1].split('## Policy results')[0];
        assert.doesNotMatch(anatomyExport,/PLACEHOLDER_PRIVATE_CONFIG_VALUE/);
        assert.doesNotMatch(anatomyExport,/<img src=x/);
        assert.match(anatomyExport,/&lt;img/);
        const jsonDownload = page.waitForEvent('download');
        await page.getByRole('button',{name:'Download full data (JSON)',exact:true}).click();
        const exported = JSON.parse(fs.readFileSync(await (await jsonDownload).path(),'utf8'));
        const model = exported.result.package_analysis.plugin_anatomy;
        assert.equal(model.profile,'claude-code');
        assert.ok(model.plugins[0].components.length > 10);
        assert.doesNotMatch(JSON.stringify(model),/PLACEHOLDER_PRIVATE_CONFIG_VALUE/);
        // Follow a source with keyboard activation and verify the selected file.
        const sourceLink = anatomy.getByRole('button',{name:'.claude-plugin/plugin.json',exact:true}).first();
        await sourceLink.focus(); await sourceLink.press('Enter');
        await page.waitForFunction(()=>document.activeElement?.id === 'file-reader-detail-heading');
        assert.match(await page.locator('[data-reader-file][aria-current=true]').innerText(),/\.claude-plugin\/plugin.json/);
        await page.getByRole('tab',{name:'Overview',exact:true}).click();
        await page.setViewportSize({width:390,height:844});
        await anatomy.scrollIntoViewIfNeeded();
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth + 1),true);
        await page.screenshot({path:path.join(output,'anatomy-mobile.png')});
        assert.equal(errors.length,0,errors.join('\n'));
        fs.writeFileSync(path.join(output,'result.json'),JSON.stringify({result:'passed',scans,components:model.component_count,
            checks:['real scan','component families','precedence','pagination','literal labels','source keyboard focus','detailed and JSON exports','390px layout'],errors},null,2));
        console.log(JSON.stringify({result:'passed',scans,components:model.component_count,output}));
    } finally {await browser.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));clearTimeout(deadline);}
})().catch(error=>{console.error(error);server.closeAllConnections();server.close();clearTimeout(deadline);process.exitCode=1;});

