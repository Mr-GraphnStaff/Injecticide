// Isolated browser acceptance checks for scanner evidence and manual retry recovery.
// Synthetic uploads/responses only; no production or customer content is contacted.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '../..');
const assets = path.join(root, 'tmp/scan-resource-regression');
const source = fs.readFileSync(path.join(root, 'webapp/static/app.js'), 'utf8');
const script = source.replace('ReactDOM.render(<Root />,', 'ReactDOM.render(<App />,');
const server = http.createServer((req, res) => {
    if (req.url === '/') {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.end('<!doctype html><html lang="en"><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/home.css"><style>body{margin:0}*{box-sizing:border-box}[hidden]{display:none!important}</style><div id="root"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script src="/babel.js"></script><script src="/fixture.js"></script></html>');
    }
    if (req.url === '/fixture.js') {
        res.setHeader('Content-Type', 'text/javascript');
        return res.end('eval(Babel.transform(' + JSON.stringify(script) + ',{presets:["react"]}).code)');
    }
    if (req.url === '/home.css') {
        res.setHeader('Content-Type', 'text/css');
        return res.end(fs.readFileSync(path.join(root, 'webapp/static/home.css')));
    }
    if (['/react.js', '/react-dom.js', '/babel.js'].includes(req.url)) {
        res.setHeader('Content-Type', 'text/javascript');
        return res.end(fs.readFileSync(path.join(assets, req.url.slice(1))));
    }
    res.statusCode = 404; res.end();
});
const report = {
    filename: 'synthetic-evidence.skill', file_type: '.skill', scan_request_id: 'body-request', warnings: [],
    summary: {total_files: 1, flagged_files: 1, total_findings: 1, info_findings: 0},
    coverage: {status: 'partial', analyzed_files: 1, total_files: 1, total_bytes: 1500, statement: 'A detector did not inspect the complete text.'},
    readiness: {status: 'needs_review', tenant_policy_verified: false, runtime_evaluation: 'not_assessed'},
    governance_evidence: {artifact_sha256: 'a'.repeat(64), controls: [], signature_verification: {status:'not_present'}, evaluation: {status:'not_assessed'}},
    scanner_metadata: {scanner_version:'0.7.0', adapter_version:'fixture', catalogs:[]},
    package_analysis: {artifact_kind:'skill', target_runtime:'claude-code', runtime_targets:[], format_findings:[], components:[], execution_references:[], dependencies:[]},
    check_results: [],
    vendor_verification: {status:'unknown', runtime:'claude-code', live_check:false, compatibility:'unknown', reason:'Source changed; awaiting review.', documents:[],requirements:[],checks:[]},
    official_validator_results: [{id:'fixture-validator', runtime:'claude-code', status:'fail', revision:'fixture-revision-123', source_url:'https://example.org/official-validator', scope:'format_validation_only', diagnostics:['Required metadata was absent.']}],
    files:[{path:'example/SKILL.md', size:1500, skipped:false, assessment_state:'text_analyzed', artifact_role:'active',
        creator_mitigation:{status:'verified',convention:'B',eof_verified:true,satisfies_tagging_convention:true,policy_scope:'large_file_tagging_only'},
        large_file_tagged_chunked_reference:true,
        analysis_coverage:{pattern_detector:{status:'complete',inspected_characters:1500,total_characters:1500}, component_inventory:{status:'partial',inspected_characters:1000,total_characters:1500,reason:'Synthetic detector budget exceeded.'}},
        findings:[{id:'pii_email_address',severity:'medium',tier:'review',category:'data',is_actionable:true,description:'Synthetic contact signal',samples:['person@example.test']}]}],
};
(async () => {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const browser = await chromium.launch({channel:process.env.INJECTICIDE_TEST_BROWSER || 'msedge',headless:true});
    try {
        const page = await browser.newPage({viewport:{width:1440,height:1100},acceptDownloads:true});
        const errors=[]; page.on('pageerror', e=>errors.push(e.message));
        await page.addInitScript(() => {
            window.scanCalls=0; window.pending=[]; window.nextMode='pending';
            const originalTimer=window.setTimeout;
            window.setTimeout=(fn,ms,...args)=>originalTimer(fn,ms===60000?1400:ms,...args);
            window.fetch=async(url,options)=>{
                if(url!=='/api/skills/scan') return new Response(JSON.stringify({categories:[],endpoints:[],payload_presets:[]}));
                window.scanCalls++;
                if(window.nextMode==='transport') throw new TypeError('Failed to fetch');
                return new Promise((resolve,reject)=>{
                    const item={resolve,reject,signal:options.signal,ignoreAbort:window.ignoreAbort};
                    options.signal.addEventListener('abort',()=>{if(!item.ignoreAbort)reject(new DOMException('Aborted','AbortError'));},{once:true});
                    window.pending.push(item);
                });
            };
        });
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        const file=page.getByLabel('Skill file',{exact:true});
        const scan=page.getByRole('button',{name:'Scan Skill File/Bundle',exact:true});
        const choose=name=>file.setInputFiles({name,mimeType:'text/markdown',buffer:Buffer.from('UNEXPORTED_SYNTHETIC_CONTENT')});
        const reply=(data,status=200,headers={})=>page.evaluate(({data,status,headers})=>window.pending.shift().resolve(new Response(JSON.stringify(data),{status,headers})),{data,status,headers});
        await choose('retry.skill');
        await page.evaluate(()=>{window.nextMode='transport'});
        await scan.click();
        await page.getByRole('alert').filter({hasText:'cause is not confirmed'}).waitFor();
        assert.equal(await file.evaluate(el=>el.files.length),1,'transport failure preserves local selection');
        assert.equal(await page.evaluate(()=>window.scanCalls),1);
        await page.waitForTimeout(80);
        assert.equal(await page.evaluate(()=>window.scanCalls),1,'no automatic retries');
        await page.evaluate(()=>{window.nextMode='pending'});
        await scan.focus(); await page.keyboard.press('Enter');
        await page.waitForFunction(()=>window.scanCalls===2);
        assert.equal(await file.evaluate(el=>el.files.length),1,'active upload keeps selection for recovery');
        assert.equal(await page.getByRole('button',{name:'Scanning…',exact:true}).isDisabled(),true);
        await reply(report,200,{'X-Scan-Request-ID':'header-request-123'});
        await page.getByRole('region',{name:'Independent scan evidence'}).waitFor();
        assert.equal(await file.evaluate(el=>el.files.length),0,'success releases local file');
        const overview=page.getByRole('region',{name:'Independent scan evidence'});
        const overviewText=await overview.innerText();
        for(const label of ['Analysis coverage','Static observations','Vendor applicability','Creator mitigation','Policy and runtime evaluation']) assert.ok(overviewText.includes(label));
        assert.match(overviewText,/partial/i);assert.match(overviewText,/1 verified/);assert.match(overviewText,/header-request-123/);
        const validators=page.getByRole('region',{name:'Official format validator results'});
        assert.match(await validators.innerText(),/claude-code.*fail/);
        assert.match(await validators.innerText(),/not a universal security verdict/);
        assert.equal(await validators.getByRole('link').getAttribute('href'),'https://example.org/official-validator');
        const detail=page.getByText('Detector coverage for example/SKILL.md',{exact:true});
        await detail.focus(); await page.keyboard.press('Enter');
        await page.getByText('Synthetic detector budget exceeded.',{exact:true}).waitFor();
        assert.match(await page.locator('[data-skill-file]').innerText(),/Creator mitigation: verified.*EOF marker verified/);
        await page.getByRole('button',{name:'detailed',exact:true}).click();
        const download=page.waitForEvent('download');
        await page.getByRole('button',{name:'Export Detailed',exact:true}).click();
        const markdown=fs.readFileSync(await (await download).path(),'utf8');
        for(const token of ['official_validator_results','fixture-revision-123','analysis_coverage','creator_mitigation','header-request-123']) assert.ok(markdown.includes(token));
        assert.ok(!markdown.includes('UNEXPORTED_SYNTHETIC_CONTENT'));
        for(const width of [390,1440]) {
            await page.setViewportSize({width,height:1100});
            assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),`no horizontal overflow at ${width}px`);
        }
        await page.screenshot({path:path.join(root,'tmp/scanner-evidence-0-7-desktop.png'),fullPage:true});
        await page.setViewportSize({width:390,height:844});
        await page.screenshot({path:path.join(root,'tmp/scanner-evidence-0-7-mobile.png'),fullPage:true});
        await choose('structured-failure.skill'); await scan.click();
        await reply({detail:{message:'Sandbox unavailable',stage:'sandbox_analysis',request_id:'failed-request-456'}},502,{'X-Scan-Request-ID':'failed-request-456'});
        const error=page.getByRole('alert'); await error.filter({hasText:'failed-request-456'}).waitFor();
        assert.match(await error.innerText(),/sandbox_analysis/);
        assert.equal(await file.evaluate(el=>el.files.length),1);
        await scan.click();
        await reply({detail:'Legacy error detail'},400);
        await error.filter({hasText:'Legacy error detail'}).waitFor();
        assert.equal(await file.evaluate(el=>el.files.length),1);
        await scan.click();
        await page.evaluate(()=>window.pending.shift().resolve(new Response('not-json',{status:200})));
        await error.filter({hasText:'reading scan response'}).waitFor();
        assert.equal(await file.evaluate(el=>el.files.length),1);
        await scan.click();
        await error.filter({hasText:'Scan timed out.'}).waitFor();
        assert.equal(await file.evaluate(el=>el.files.length),1,'timeout remains manually retryable');
        assert.equal(await page.evaluate(()=>window.pending[0].signal.aborted),true);
        await page.evaluate(()=>window.pending.shift());
        await page.getByRole('button',{name:'Clear scan',exact:true}).click();
        assert.equal(await file.evaluate(el=>el.files.length),0);
        assert.equal(await page.getByRole('alert').count(),0);
        await choose('old.skill'); await page.evaluate(()=>{window.ignoreAbort=true}); await scan.click();
        await choose('new.skill'); await page.evaluate(()=>{window.ignoreAbort=false});
        await scan.click();
        await reply({...report,filename:'old-result.skill'});
        assert.equal(await page.getByText('old-result.skill',{exact:true}).count(),0);
        await reply({...report,filename:'new-result.skill'});
        await page.getByText('new-result.skill',{exact:true}).waitFor();
        assert.equal(await file.evaluate(el=>el.files.length),0);
        // Old reports without new fields remain readable.
        await choose('legacy.skill'); await scan.click();
        const legacy={...report,filename:'legacy-report.skill'}; delete legacy.official_validator_results;
        legacy.files=legacy.files.map(({analysis_coverage,creator_mitigation,...entry})=>entry);
        await reply(legacy);await page.getByText('legacy-report.skill',{exact:true}).waitFor();
        assert.match(await overview.innerText(),/Tag recognition not reported/);
        // A static format mismatch must not masquerade as incomplete coverage.
        await choose('format.skill'); await scan.click();
        const formatReport={...report,filename:'format-report.skill',coverage:{...report.coverage,status:'complete_supported_content'},
            files:[],package_analysis:{...report.package_analysis,format_findings:[{id:'skill_frontmatter',severity:'error',detail:'Synthetic selected-profile mismatch'}]}};
        await reply(formatReport); await page.getByText('Format observations need review',{exact:true}).waitFor();
        assert.equal(await page.getByText('Package review incomplete',{exact:true}).count(),0);
        assert.deepEqual(errors,[]);
        console.log(JSON.stringify({status:'PASS',checked:['manual retry without reselect','no automatic retry','keyboard submit','double-submit guard','success release','independent evidence axes','verified tag with partial detector coverage','scoped official format failure','source link','correlation export','no upload content in export','390px and 1440px overflow','keyboard disclosure','structured and legacy errors','invalid response','timeout recovery','clear','replacement and stale-response isolation','legacy report compatibility','format mismatch distinct from incomplete coverage'],screenshots:['tmp/scanner-evidence-0-7-desktop.png','tmp/scanner-evidence-0-7-mobile.png']}));
    } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1}).finally(()=>server.close());
