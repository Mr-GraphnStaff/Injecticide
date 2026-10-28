// Synthetic scanner contract rendered through the actual React report UI.
// This checks presentation and export fidelity, not specification conformance.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '../..');
const assets = path.join(root, 'tmp/scan-resource-regression');
const source = fs.readFileSync(path.join(root, 'webapp/static/app.js'), 'utf8').replace('ReactDOM.render(<Root />,', 'ReactDOM.render(<App />,');
const hostile = '<img src=x onerror="window.standardLabelExecuted=true">';
const standards = {
    schema_version:1,standard:'agent-skills',source:{url:'https://agentskills.io/specification',revision:'fixture-pinned-revision',source_sha256:'b'.repeat(64),verification:'reviewed_pinned_primary_source'},
    profile_scope:'Synthetic portable format requirements only; no runtime or vendor acceptance is asserted.',overall_status:'fail',overall_status_scope:'applicable_mandatory_portable_format_checks_only',
    summary:{mandatory_pass:9,mandatory_fail:1,mandatory_not_assessed:1,recommendations_attention:1,omitted_skills:1,omitted_rows:2},
    requirements:Array.from({length:11},(_,index)=>({id:index===0?hostile:`format_requirement_${index}`,category:'format',requirement_level:'mandatory',applicability:'portable skill format',status:index===9?'fail':index===10?'not_assessed':'pass',path:'example/SKILL.md',line:index+1,message:index===0?'Synthetic metadata check; not an execution verdict.':`Synthetic measured requirement ${index}.`,implementation_status:index===10?'not_implemented':'implemented',test_refs:['tests/test_standards_assessment.py::synthetic_case'],evidence:[{path:'example/SKILL.md',line:index+1,text:hostile}],sources:[{url:index===0?'javascript:alert(1)':'https://agentskills.io/specification',title:'Agent Skills specification',section:'Required fields',revision:'fixture-pinned-revision',source_sha256:'b'.repeat(64)}]})),
    limitations:['Fixture omits two additional requirements; no omitted requirement is counted as passed.'],limits:[{kind:'standards_requirement_rows',omitted_rows:2}],
    security_guidance:{name:'OWASP Agentic Skills Top 10',project_status:'incubator',source_url:'https://owasp.github.io/www-project-agentic-skills-top-10/',mapping_authority:'Injecticide reviewer-authored relevance mapping; not an OWASP certification or coverage score',risks:[{id:'AST01',title:'Malicious Skills',observed_detector_ids:['prompt_override'],validation:'risk_exploitability_and_runtime_enforcement_not_assessed'}]}
};
standards.requirements.push(
    {id:'vendor_custom_extension',category:'vendor_compatibility',requirement_level:'vendor_extension',applicability:'a named vendor only',status:'fail',path:'example/SKILL.md',message:'Extension warning; portable assessment is independent.',evidence:[],sources:[]},
    {id:'description_guidance',category:'authoring_guidance',requirement_level:'recommendation',status:'fail',message:'Improve the description for authoring quality; recommendation only.',evidence:[],sources:[]},
    {id:'owasp_scoped_mapping',category:'security',requirement_level:'status',status:'not_assessed',message:'Mapped detector IDs are not proof of complete OWASP coverage.',evidence:[],sources:[{url:'https://owasp.org/www-project-agentic-skills/',title:'OWASP Agentic Skills Incubator'}]},
    {id:'runtime_evaluation',category:'runtime_evaluation',requirement_level:'status',status:'not_assessed',message:'No runtime execution was performed.',evidence:[],sources:[]}
);
const report = {
    filename:'standards-fixture.skill',file_type:'.skill',scan_request_id:'standards-fixture',warnings:[],summary:{total_files:1,flagged_files:0,total_findings:0,info_findings:0},
    coverage:{status:'complete',analyzed_files:1,total_files:1,total_bytes:100,statement:'Fixture text only.'},
    readiness:{status:'needs_review',tenant_policy_verified:false,runtime_evaluation:'not_assessed'},
    governance_evidence:{artifact_sha256:'a'.repeat(64),controls:[],signature_verification:{status:'not_present'},evaluation:{status:'not_assessed'}},
    scanner_metadata:{scanner_version:'0.10.0 fixture',adapter_version:'fixture',catalogs:[]},
    package_analysis:{artifact_kind:'skill',target_runtime:'auto',runtime_targets:[],format_findings:[],components:[],execution_references:[],dependencies:[]},
    vendor_verification:{status:'unknown',runtime:'auto',compatibility:'unknown',reason:'Target unverified.',documents:[],requirements:[],checks:[]},check_results:[],official_validator_results:[],
    files:[{path:'example/SKILL.md',size:100,skipped:false,assessment_state:'text_analyzed',artifact_role:'active',findings:[]}],standards_assessment:standards
};
let mode = 'current';
const server = http.createServer((req,res)=>{
    if(req.url==='/') {res.setHeader('Content-Type','text/html;charset=utf-8');return res.end('<!doctype html><html lang="en"><head><title>Standards test</title><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/home.css"><style>body{margin:0}*{box-sizing:border-box}[hidden]{display:none!important}</style></head><body><div id="root"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script src="/babel.js"></script><script src="/fixture.js"></script></body></html>');}
    if(req.url==='/fixture.js'){res.setHeader('Content-Type','text/javascript');return res.end('eval(Babel.transform('+JSON.stringify(source)+',{presets:["react"]}).code)');}
    if(req.url==='/home.css'){res.setHeader('Content-Type','text/css');return res.end(fs.readFileSync(path.join(root,'webapp/static/home.css')));}
    if(['/react.js','/react-dom.js','/babel.js'].includes(req.url)){res.setHeader('Content-Type','text/javascript');return res.end(fs.readFileSync(path.join(assets,req.url.slice(1))));}
    if(req.url.startsWith('/api/')){
        res.setHeader('Content-Type','application/json');
        if(req.url==='/api/skills/scan'){
            const value=JSON.parse(JSON.stringify(report));
            if(mode==='legacy') delete value.standards_assessment;
            if(mode==='portable-pass') {value.standards_assessment.overall_status='pass';value.standards_assessment.summary={mandatory_pass:10,mandatory_fail:0,mandatory_not_assessed:0,recommendations_attention:1};value.standards_assessment.requirements=value.standards_assessment.requirements.filter(row=>row.id!=='format_requirement_10').map(row=>row.id==='format_requirement_9'?{...row,status:'pass'}:row);}
            return res.end(JSON.stringify(value));
        }
        return res.end(JSON.stringify({categories:[],endpoints:[],payload_presets:[]}));
    }
    res.statusCode=404;res.end();
});
(async()=>{
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    const browser=await chromium.launch({channel:process.env.INJECTICIDE_TEST_BROWSER||'msedge',headless:true});
    try{
        const page=await browser.newPage({viewport:{width:1440,height:1100},acceptDownloads:true});
        const errors=[];page.on('pageerror',error=>{errors.push(error.message);console.error('Browser error:',error.message);});
        page.on('console',message=>{if(message.type()==='error' && !message.text().startsWith('Failed to load resource:'))errors.push(message.text());});
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        async function scan(){await page.getByLabel('Skill file',{exact:true}).setInputFiles({name:'standards-fixture.skill',mimeType:'text/markdown',buffer:Buffer.from('SYNTHETIC_ONLY')});await page.getByRole('button',{name:'Scan Skill File/Bundle',exact:true}).click();try{await page.getByRole('heading',{name:'Standards assessment',exact:true}).waitFor();}catch(error){console.error((await page.locator('body').innerText()).slice(-5000));throw error;}}
        await scan();
        const panel=page.locator('[data-standards-assessment]');
        assert.match(await panel.innerText(),/Portable mandatory checks: Fail/);
        assert.deepEqual(await panel.locator('.standards-counts dd').allTextContents(),['10','1','1','1']);
        assert.match(await panel.innerText(),/omitted 1 skills and 2 requirement rows/);
        assert.equal(await panel.locator('[data-standards-requirement]').count(),10);
        assert.match(await panel.innerText(),/not a certificate of full compliance/);
        assert.equal(await panel.locator('img,script,svg,iframe').count(),0);
        assert.equal(await page.evaluate(()=>window.standardLabelExecuted),undefined);
        assert.equal(await panel.locator('a[href^="javascript:"]').count(),0);
        assert.match(await panel.innerText(),/Source link unavailable/);
        const disclosure=panel.locator('[data-standards-requirement]').first().getByText('Source file evidence (1)',{exact:true});
        await disclosure.focus();await page.keyboard.press('Enter');
        assert.equal(await disclosure.evaluate(element=>element.parentElement.open),true);
        assert.match(await panel.locator('[data-standards-requirement]').first().innerText(),/example\/SKILL.md:1/);
        const pager=panel.getByRole('navigation',{name:'Standards requirement pages'});
        await pager.getByRole('button',{name:'Next',exact:true}).click();
        assert.equal(await panel.locator('[data-standards-requirement]').count(),1);
        assert.match(await panel.innerText(),/Not assessed.*Mandatory.*not implemented/s);
        for(const [name,text] of [['Vendor compatibility',/Vendor extension.*does not independently fail/s],['Authoring recommendations',/Recommendation/],['Security review',/not proof of complete OWASP coverage/],['Runtime evaluation',/No runtime execution was performed/]]){
            const button=panel.getByRole('button',{name:new RegExp(`^${name}`)});await button.focus();await page.keyboard.press('Enter');
            assert.equal(await button.getAttribute('aria-pressed'),'true');assert.match(await panel.locator('.standards-selected-category').innerText(),text);
        }
        await panel.getByRole('button',{name:/^Security review/}).click();
        await panel.getByText('OWASP Agentic Skills Top 10 · incubator',{exact:true}).click();
        assert.match(await panel.locator('.standards-security-guidance').innerText(),/not an OWASP certification or coverage score/);
        assert.match(await panel.locator('.standards-security-guidance').innerText(),/prompt_override/);
        await panel.getByText('Specification source and assessment limits',{exact:true}).click();
        assert.match(await panel.innerText(),/fixture-pinned-revision/);assert.match(await panel.innerText(),/omits two additional requirements/);
        const sourceLink=panel.locator('.standards-reference a');assert.equal(await sourceLink.getAttribute('href'),'https://agentskills.io/specification');assert.equal(await sourceLink.getAttribute('rel'),'noopener noreferrer');
        for(const depth of ['summary','detailed']){
            await page.getByRole('button',{name:depth,exact:true}).click();
            const event=page.waitForEvent('download');await page.getByRole('button',{name:depth==='summary'?'Export Summary':'Export Detailed',exact:true}).click();
            const markdown=fs.readFileSync(await (await event).path(),'utf8');
            const match=markdown.match(/## Standards assessment[\s\S]*?```json\n([\s\S]*?)\n```/);
            assert.ok(match);assert.deepEqual(JSON.parse(match[1]).standards_assessment,standards);
            assert.ok(!markdown.includes('SYNTHETIC_ONLY'));
        }
        for(const width of [390,1440]){await page.setViewportSize({width,height:1100});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`standards page reflows at ${width}`);}
        await panel.screenshot({path:path.join(root,'tmp/skill-standards-desktop.png')});
        mode='portable-pass';await scan();
        assert.match(await panel.innerText(),/Portable mandatory checks: Pass/);
        await panel.getByRole('button',{name:/^Vendor compatibility/}).click();assert.match(await panel.locator('.standards-selected-category').innerText(),/Vendor extension/);
        await panel.getByRole('button',{name:/^Runtime evaluation/}).click();assert.match(await panel.locator('.standards-selected-category').innerText(),/Not assessed/);
        mode='legacy';await scan();
        assert.equal(await page.locator('[data-standards-assessment]').count(),0);
        assert.match(await page.locator('.skill-standards').innerText(),/Not assessed — this report does not include/);
        assert.deepEqual(errors,[]);
        console.log('PASS: separate standards axes, mandatory counts, unknowns, vendor extension scope, citations, keyboard, pagination, hostile labels, exports, 390px reflow and legacy reports.');
    }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
