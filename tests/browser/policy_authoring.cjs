// Managed, isolated browser UI against the real local policy and scan API.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {execFileSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const run = process.env.AGENT_WORKING_DIR;
if (!run || !path.resolve(run).startsWith(path.join(root, 'working', 'runs') + path.sep)) throw Error('Use the managed launcher.');
const output = path.join(run, 'reports', 'browser', 'policy-authoring');
fs.mkdirSync(output, {recursive:true});
const cache = path.join(root, 'working', 'cache', 'browser');
const assets = path.join(cache, 'scan-resource-regression');
const {chromium} = require(path.join(cache, 'node_modules', 'playwright'));
const source = fs.readFileSync(path.join(root, 'webapp/static/components/PackageEditor.jsx'), 'utf8') + '\n' + fs.readFileSync(path.join(root, 'webapp', 'static', 'app.js'), 'utf8');
const template = fs.readFileSync(path.join(root, 'webapp', 'static', 'org-policy-template.json'), 'utf8');
const fixture = Buffer.from(execFileSync('python', ['-c', "import base64,io,zipfile; b=io.BytesIO(); z=zipfile.ZipFile(b,'w'); z.writestr('SKILL.md','---\\nname: demo\\ndescription: Public text\\n---\\nSummarize text.'); z.writestr('references/quiet.py',\"print('public synthetic text')\\n\"); z.close(); print(base64.b64encode(b.getvalue()).decode())"], {cwd:root,encoding:'utf8'}).trim(), 'base64');
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
    const browser = await chromium.launch({headless:true, downloadsPath:path.join(output,'downloads'),
        ...(process.env.INJECTICIDE_TEST_BROWSER_PATH ? {executablePath:process.env.INJECTICIDE_TEST_BROWSER_PATH} : {channel:'msedge'})});
    try {
        const page = await browser.newPage();
        page.setDefaultTimeout(20000);
        const errors = []; page.on('pageerror', error => { errors.push(error.message); console.error('pageerror:',error.message); });
        await page.addInitScript(() => {
            const original = window.fetch;
            window.fetch = (input, options) => original(input,
                window.ignorePolicyAbort && String(input).includes('/policy/validate') ? {...options,signal:undefined} : options);
        });
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        await page.getByText('Organization AI policy (optional)',{exact:false}).click();
        const editor = page.getByLabel('Policy JSON',{exact:true});
        const validate = page.getByRole('button',{name:'Validate policy',exact:true});
        const scan = page.getByRole('button',{name:'Scan Skill File/Bundle',exact:true});
        const status = page.locator('#org-policy-status');
        await page.getByRole('button',{name:'Add: No packaged scripts',exact:true}).click();
        await status.filter({hasText:'Policy validated by the server'}).waitFor();
        const noScripts = await editor.inputValue();
        assert.equal(JSON.parse(noScripts).rules[0].when.packaged_script,true);
        console.log('preset validated');
        await page.getByLabel('Skill file',{exact:true}).setInputFiles({name:'uninvoked.plugin',mimeType:'application/zip',buffer:fixture});
        const bad = JSON.parse(noScripts); bad.rules = [];
        const invalidNames = ['instruction_override_phrase','unicode_concealment','file_length_exceeded','unpinned_dependency','runtime_install','unbounded_construct','bare_script_file','m365_connector','mcp_server'];
        invalidNames.forEach((name,index) => bad.rules.push({...JSON.parse(noScripts).rules[0],id:`R${index}`,
            when:{[index < 7 ? 'finding' : 'capability']:name}}));
        await editor.fill(JSON.stringify(bad)); await validate.click();
        await status.filter({hasText:'9 problems'}).waitFor();
        assert.equal(await page.locator('#org-policy-problems li').count(),9);
        assert.equal(await editor.getAttribute('aria-invalid'),'true');
        assert.doesNotMatch(await page.locator('#org-policy-problems').innerText(),/database_profile/);
        // Closed details must open and focus the editable policy after rejected submit.
        await page.locator('.org-policy-input > summary').click();
        await scan.click(); await editor.waitFor({state:'visible'});
        await page.waitForFunction(() => document.activeElement?.id === 'org-policy');
        assert.equal(scans,0,'invalid policy never uploads package');
        console.log('nine-error policy blocked before upload; focus recovered');
        assert.equal(await page.getByLabel('Skill file',{exact:true}).evaluate(el=>el.files.length),1);
        await editor.fill(noScripts); mode = 'offline'; await validate.click();
        await status.filter({hasText:'unavailable'}).waitFor();
        await scan.click(); await page.locator('#skill-scan-error').filter({hasText:'unavailable'}).waitFor();
        assert.equal(scans,0,'validation outage cannot upload package');
        console.log('validation outage blocked before upload');
        mode = 'hold'; await page.evaluate(()=>{window.ignorePolicyAbort=true;});
        await editor.fill(noScripts); await validate.click();
        await page.waitForFunction(()=>document.querySelector('#org-policy-status').textContent.includes('Checking'));
        while (!releaseHeld) await new Promise(resolve=>setTimeout(resolve,10));
        await editor.fill(JSON.stringify(bad)); await validate.click();
        await status.filter({hasText:'9 problems'}).waitFor(); releaseHeld();
        await page.waitForTimeout(150);
        assert.match(await status.innerText(),/9 problems/,'old valid response cannot overwrite newer invalid policy');
        console.log('late validation response ignored');
        await page.evaluate(()=>{window.ignorePolicyAbort=false;});
        await editor.fill(noScripts); await validate.click();
        await status.filter({hasText:'Policy validated by the server'}).waitFor();
        await scan.click();
        await page.locator('[data-policy-results] [data-organization-disposition="block"]').waitFor();
        assert.equal(scans,1);
        assert.match(await page.locator('body').innerText(),/No packaged scripts/);
        assert.match(await page.locator('body').innerText(),/quiet.py/);
        assert.equal(errors.length,0,errors.join('\n'));
        await page.setViewportSize({width:390,height:844});
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth <= window.innerWidth + 1),true,'mobile has no horizontal overflow');
        await page.locator('.org-policy-input').screenshot({path:path.join(output,'policy-mobile.png')});
        fs.writeFileSync(path.join(output,'result.json'),JSON.stringify({scans,validations,checks:['preset','nine errors','no upload invalid/outage','late response','focus','real script scan'],pageErrors:errors},null,2));
        console.log(JSON.stringify({scans,validations,result:'passed',output}));
    } finally { await browser.close(); server.closeAllConnections(); await new Promise(resolve=>server.close(resolve)); clearTimeout(deadline); }
})().catch(error=>{console.error(error);server.close();process.exitCode=1;});
