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
// Milestone fixture: synthetic API evidence, not a scan of these local bytes.
const untrustedLabel = '<img src=x onerror="window.untrustedExecuted=true">';
report.summary.total_files = 3;
report.coverage.total_files = 3;
report.coverage.inspection_summary = {
    text_or_structured_files_analyzed: 1, assets_with_structural_inspection: 1,
    files_without_supported_inspection: 0, image_visual_analysis: 'not_performed', font_program_analysis: 'not_performed',
};
report.package_analysis.relationship_graph = {
    status: 'partial', scope: 'Static declared relationships; execution not verified.',
    edges: Array.from({length: 13}, (_, i) => ({source: 'example/SKILL.md',
        target: i === 12 ? untrustedLabel : `references/brief-${i}.md`, line: i + 1, status: 'resolved'})),
    reachable_paths: ['example/SKILL.md'], unreferenced_paths: ['assets/logo.png'],
    limits: [{kind: 'synthetic_source_limit'}],
    action_chains: [{path: ['example/SKILL.md', 'scripts/collect.py'], capability: 'file_read', execution_verified: false}],
    capability_observations: [{source: 'scripts/collect.py', capability: 'network_access', execution_verified: false}],
    external_references: [{source: 'scripts/collect.py', url: 'https://destination.invalid', verification: 'not_contacted'}],
};
report.files.push({path: 'assets/logo.png', size: 1234, skipped: false, assessment_state: 'asset_structure_inspected',
    artifact_role: 'reference', findings: [], asset_inspection: {format: 'png', status: 'inspected', checks: ['signature', 'chunk_crc'],
        binary_security_analysis: 'not_performed', limitations: ['Pixels and OCR not assessed.']},
    analysis_coverage: {asset_structure: {status: 'complete_supported_checks'}}});
report.files.push({path: 'bundle.zip!/SKILL.md', size: 100, skipped: false, assessment_state: 'text_analyzed',
    artifact_role: 'active', findings: [], archive_container: 'bundle.zip', archive_depth: 1,
    archive_inspection: {format: 'zip', status: 'inspected', checks: ['member_crc']}});
report.inventory = report.files.map(({path, size, assessment_state, archive_container, archive_depth}) =>
    ({path, size, assessment_state, archive_container, archive_depth}));
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
        assert.match(await page.locator('[data-skill-file]').first().innerText(),/Creator mitigation: verified.*EOF marker verified/);
        const packageOverview=page.locator('[data-package-overview]');
        assert.match(await packageOverview.locator('[data-inspection-summary]').innerText(),/1 text\/structured files; 1 assets structurally inspected; 0 files without supported inspection/);
        const relationships=packageOverview.locator('[data-package-relationships]');
        const relationshipSummary=relationships.locator('summary');
        await relationshipSummary.focus(); await page.keyboard.press('Enter');
        assert.equal(await relationships.evaluate(el=>el.open),true,'native relationship disclosure responds to keyboard');
        assert.match(await relationships.innerText(),/static declarations, not observed execution/);
        const sections=page.getByLabel('Package report section',{exact:true});
        await sections.selectOption('package_relationships');
        assert.equal(await packageOverview.locator('[data-package-evidence]').count(),10);
        const pages=page.getByRole('navigation',{name:'Package evidence pages',exact:true});
        assert.match(await pages.innerText(),/1–10 of 13/);
        await pages.getByRole('button',{name:'Next',exact:true}).focus(); await page.keyboard.press('Enter');
        assert.equal(await packageOverview.locator('[data-package-evidence]').count(),3);
        assert.ok((await packageOverview.innerText()).includes(JSON.stringify(untrustedLabel).slice(1,-1)),'uploaded label is visible as literal JSON text');
        assert.equal(await packageOverview.locator('img, svg, script').count(),0,'uploaded label never becomes markup');
        assert.equal(await page.evaluate(()=>window.untrustedExecuted),undefined);
        await sections.selectOption('action_chains');
        assert.equal(await pages.count(),0,'changing sections resets paging');
        assert.match(await packageOverview.locator('[data-package-evidence]').innerText(),/execution_verified.*false/s);
        await sections.selectOption('asset_inspection');
        assert.equal(await packageOverview.locator('[data-package-evidence]').count(),2);
        assert.match(await packageOverview.innerText(),/chunk_crc/);
        assert.match(await packageOverview.innerText(),/member_crc/);
        await page.getByRole('button',{name:'detailed',exact:true}).click();
        const download=page.waitForEvent('download');
        await page.getByRole('button',{name:'Export Detailed',exact:true}).click();
        const markdown=fs.readFileSync(await (await download).path(),'utf8');
        for(const token of ['official_validator_results','fixture-revision-123','analysis_coverage','creator_mitigation','header-request-123',
            'relationship_graph','inspection_summary','asset_inspection','chunk_crc','archive_container','archive_depth','bundle.zip!/SKILL.md']) assert.ok(markdown.includes(token));
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
        const legacy=structuredClone({...report,filename:'legacy-report.skill'}); delete legacy.official_validator_results;
        delete legacy.coverage.inspection_summary; delete legacy.package_analysis.relationship_graph;
        legacy.files=legacy.files.map(({analysis_coverage,creator_mitigation,asset_inspection,archive_inspection,archive_container,archive_depth,...entry})=>entry);
        await reply(legacy);await page.getByText('legacy-report.skill',{exact:true}).waitFor();
        assert.match(await overview.innerText(),/Tag recognition not reported/);
        assert.equal(await packageOverview.locator('[data-inspection-summary], [data-package-relationships]').count(),0,'legacy reports omit unavailable new evidence');
        // A static format mismatch must not masquerade as incomplete coverage.
        await choose('format.skill'); await scan.click();
        const formatReport={...report,filename:'format-report.skill',coverage:{...report.coverage,status:'complete_supported_content'},
            files:[],package_analysis:{...report.package_analysis,format_findings:[{id:'skill_frontmatter',severity:'error',detail:'Synthetic selected-profile mismatch'}]}};
        await reply(formatReport); await page.getByText('Format observations need review',{exact:true}).waitFor();
        assert.equal(await page.getByText('Package review incomplete',{exact:true}).count(),0);
        assert.deepEqual(errors,[]);
        console.log(JSON.stringify({status:'PASS',checked:['manual retry without reselect','no automatic retry','keyboard submit','double-submit guard','success release','independent evidence axes','verified tag with partial detector coverage','scoped official format failure','source link','correlation export','no upload content in export','390px and 1440px overflow','keyboard disclosure','relationship keyboard disclosure','relationship pagination and section reset','untrusted relationship labels remain literal text','asset inspection and nested provenance export','legacy reports without new fields','structured and legacy errors','invalid response','timeout recovery','clear','replacement and stale-response isolation','legacy report compatibility','format mismatch distinct from incomplete coverage'],screenshots:['tmp/scanner-evidence-0-7-desktop.png','tmp/scanner-evidence-0-7-mobile.png']}));
    } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1}).finally(()=>server.close());
