// Independent QA for the coordinator's scoped report/token/effect presentation.
// Synthetic API evidence only; this does not validate scanner or tokenizer accuracy.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const http=require('node:http');
const path=require('node:path');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'../..');
const assets=path.join(root,'tmp/scan-resource-regression');
const source=fs.readFileSync(path.join(root,'webapp/static/app.js'),'utf8').replace('ReactDOM.render(<Root />,','ReactDOM.render(<App />,');
const hostile='<img src=x onerror="window.scopeLabelExecuted=true">';
const metric={characters:1200,utf8_bytes:1250,estimated_tokens:300};
const footprint={skills:[{path:'fixture/SKILL.md',metadata_discovery:{characters:120,utf8_bytes:120,estimated_tokens:30},main_instructions:metric,directly_referenced_text:{characters:2400,utf8_bytes:5000,estimated_tokens:null},packaged_supporting_text:metric,scenario_scope:'OPTIONAL_REFERENCE_SCENARIO_ONLY',guidance:['ACTUAL_RUN_TOKEN_USAGE_UNKNOWN']}],extracted_text_total:{characters:4800,utf8_bytes:6500,estimated_tokens:null},largest_text_files:[{path:'fixture/references/note.md',characters:2400,utf8_bytes:5000}],limitations:['NON_ASCII_PROXY_NOT_AVAILABLE','Repeated model/tool calls are unmeasured.'],limits:[]};
const effects={observations:[{status:'static_witness',source:{path:'fixture/source.py',line:3},sink:{path:'fixture/send.py',line:9},trace:[{kind:'source',path:'fixture/source.py',line:3,operation:'source_read'},{kind:'sink',path:'fixture/send.py',line:9,operation:'network_payload'}]},{status:'unknown',path:hostile,line:12,reason:'unsupported_dynamic_boundary'}],coverage:{scope:'STATIC_EFFECT_SCOPE_NOT_RUNTIME'},limits:[{kind:'bounded_effect_fixture'}]};
const assessment={schema_version:1,standard:'agent-skills',source:{url:'https://agentskills.io/specification',revision:'fixture-revision',source_sha256:'b'.repeat(64),verification:'reviewed_pinned_primary_source'},profile_scope:'PORTABLE_FORMAT_SCOPE_ONLY',overall_status:'pass',summary:{mandatory_pass:1,mandatory_fail:0,mandatory_not_assessed:0,recommendations_attention:0},requirements:[{id:'portable_name',category:'format',requirement_level:'mandatory',status:'pass',path:'fixture/SKILL.md',line:2,message:'MEASURED_PORTABLE_FIELD',evidence:[],sources:[]}],limitations:['NO_FULL_COMPLIANCE_CERTIFICATE']};
const improvementPlan={schema_version:1,artifact_sha256:'a'.repeat(64),scanner_version:'0.11.0-fixture',scope:'STATIC_PLAN_ONLY_NO_RUNTIME_OR_COMPLIANCE_CERTIFICATION',priority_policy:'ORDER_OF_WORK_NOT_QUANTIFIED_RISK',limits:[{kind:'fixture_plan_budget',omitted_items:2}],items:[
    {id:'plan_format',rule_id:'name_required',priority:'required',priority_basis:'mandatory format check: fail',category:'mandatory_format',status:'confirmed_failure',path:'fixture/SKILL.md',line:2,reason:'PLAN_CONFIRMED_FAILURE',action:'PLAN_CORRECT_MEASURED_FORMAT',validation:'PLAN_RESCAN_CORRECTION',sources:[{path:'fixture/SKILL.md',line:2},{url:'https://agentskills.io/specification',revision:'fixture-revision'}]},
    {id:'plan_security',rule_id:'dynamic_exec',priority:'normal',priority_basis:'existing tier: review; severity: medium',category:'security_review',status:'review_required',path:hostile,line:8,reason:'PLAN_CONTEXTUAL_REVIEW',action:'PLAN_REVIEW_NOT_PROVEN_MALICIOUS ``` <script>window.scopeLabelExecuted=true</script>',validation:'PLAN_PRESERVE_LEGITIMATE_CONTROLS',sources:[{path:hostile,line:8}]},
    {id:'plan_advisory',rule_id:'body_line_guidance',priority:'normal',category:'recommendation',status:'recommended',path:'fixture/SKILL.md',reason:'PLAN_ADVISORY_ONLY',action:'PLAN_OPTIONAL_LOADING',validation:'PLAN_MEASURE_TASK_QUALITY',sources:[]},
    {id:'plan_unknown',rule_id:'runtime_control_enforcement',priority:'manual',category:'manual_assessment',status:'not_assessed',path:null,line:null,reason:'PLAN_UNKNOWN_RUNTIME',action:'PLAN_OBTAIN_AUTHORIZED_EVIDENCE',validation:'PLAN_RUNTIME_SEPARATE',sources:[]}
]};
const report={filename:'scoped-fixture.skill',file_type:'.skill',scan_request_id:'scoped-fixture',summary:{total_files:1,flagged_files:1,total_findings:1,info_findings:0},warnings:['OVERVIEW_WARNING_AVAILABLE'],coverage:{status:'partial',analyzed_files:1,total_files:1,total_bytes:6500,statement:'EXPLICIT_PARTIAL_SCAN_COVERAGE'},readiness:{status:'needs_review',runtime_evaluation:'not_assessed',tenant_policy_verified:false},governance_evidence:{artifact_sha256:'a'.repeat(64),controls:[],signature_verification:{status:'not_present'},evaluation:{status:'not_assessed'}},scanner_metadata:{scanner_version:'0.11.0-fixture',adapter_version:'fixture',catalogs:[]},package_analysis:{artifact_kind:'skill',target_runtime:'generic',runtime_targets:[],format_findings:[],components:[],execution_references:[],dependencies:[],effect_analysis:effects},files:[{path:'fixture/SKILL.md',size:1250,skipped:false,assessment_state:'text_analyzed',artifact_role:'active',findings:[{id:'pii_email_address',severity:'medium',tier:'review',category:'data',finding_category:'sensitive_data_presence',is_actionable:true,description:'SECURITY_FINDING_RETAINED',samples:['SYNTHETIC_PERSON@example.test']}]}],standards_assessment:assessment,token_footprint:footprint,official_validator_results:[{id:'official-fixture',status:'pass',runtime:'generic',scope:'format_validation_only',revision:'fixture',source_url:'https://example.org/format'}],vendor_verification:{status:'unknown',runtime:'generic',compatibility:'unknown',reason:'SUPPORTING_VENDOR_SOURCE',documents:[],requirements:[],checks:[]},check_results:[]};
let legacy=false;
report.improvement_plan=improvementPlan;
const server=http.createServer((req,res)=>{
    if(req.url==='/'){res.setHeader('Content-Type','text/html;charset=utf-8');return res.end('<!doctype html><html lang="en"><head><title>Report scopes QA</title><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/home.css"><style>body{margin:0}*{box-sizing:border-box}[hidden]{display:none!important}</style></head><body><div id="root"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script src="/babel.js"></script><script src="/fixture.js"></script></body></html>');}
    if(req.url==='/fixture.js'){res.setHeader('Content-Type','text/javascript');return res.end('eval(Babel.transform('+JSON.stringify(source)+',{presets:["react"]}).code)');}
    if(req.url==='/home.css'){res.setHeader('Content-Type','text/css');return res.end(fs.readFileSync(path.join(root,'webapp/static/home.css')));}
    if(['/react.js','/react-dom.js','/babel.js'].includes(req.url)){res.setHeader('Content-Type','text/javascript');return res.end(fs.readFileSync(path.join(assets,req.url.slice(1))));}
    if(req.url.startsWith('/api/')){res.setHeader('Content-Type','application/json');if(req.url==='/api/skills/scan'){const value=structuredClone(report);if(legacy){delete value.token_footprint;delete value.improvement_plan;delete value.standards_assessment;delete value.package_analysis.effect_analysis;value.scan_request_id='legacy-scopes';}return res.end(JSON.stringify(value));}return res.end(JSON.stringify({categories:[],endpoints:[],payload_presets:[]}));}
    res.statusCode=404;res.end();
});
(async()=>{
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    const browser=await chromium.launch({channel:process.env.INJECTICIDE_TEST_BROWSER||'msedge',headless:true});
    try{
        const page=await browser.newPage({viewport:{width:1440,height:1100},acceptDownloads:true});
        const errors=[];page.on('pageerror',error=>errors.push(error.message));
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        async function scan(){await page.getByLabel('Skill file',{exact:true}).setInputFiles({name:'scoped-fixture.skill',mimeType:'text/markdown',buffer:Buffer.from('UNEXPORTED_RAW_UPLOAD')});await page.getByRole('button',{name:'Scan Skill File/Bundle',exact:true}).click();await page.getByRole('tablist',{name:'Scan report scope'}).waitFor();}
        await scan();
        const navigation=page.getByRole('tablist',{name:'Scan report scope'});
        const names=['Overview','Security','Structure & process','Standards','Token usage','Evidence & coverage'];
        assert.deepEqual(await navigation.getByRole('tab').allTextContents(),names);
        assert.equal(await navigation.locator('[tabindex="0"]').count(),1);
        assert.equal(await page.getByRole('tabpanel').count(),1,'only active scope is exposed to accessibility navigation');
        assert.match(await page.getByRole('tabpanel').innerText(),/OVERVIEW_WARNING_AVAILABLE/);
        const first=navigation.getByRole('tab',{name:'Overview',exact:true});await first.focus();
        for(let index=1;index<names.length;index++){
            await page.keyboard.press('ArrowRight');
            const tab=navigation.getByRole('tab',{name:names[index],exact:true});
            assert.equal(await tab.getAttribute('aria-selected'),'true');assert.equal(await tab.evaluate(element=>element===document.activeElement),true);
            assert.equal(await page.getByRole('tabpanel').getAttribute('aria-labelledby'),await tab.getAttribute('id'));
        }
        await page.keyboard.press('ArrowRight');assert.equal(await first.getAttribute('aria-selected'),'true','arrow navigation wraps');
        await page.keyboard.press('End');assert.equal(await navigation.getByRole('tab',{name:'Evidence & coverage',exact:true}).getAttribute('aria-selected'),'true');
        await page.keyboard.press('Home');assert.equal(await first.getAttribute('aria-selected'),'true');
        await navigation.getByRole('tab',{name:'Security',exact:true}).click();
        assert.match(await page.getByRole('tabpanel').innerText(),/SECURITY_FINDING_RETAINED/);
        await navigation.getByRole('tab',{name:'Structure & process',exact:true}).click();
        assert.match(await page.getByRole('tabpanel').innerText(),/fixture\/source.py:3 → fixture\/send.py:9/);
        assert.match(await page.getByRole('tabpanel').innerText(),/unsupported dynamic boundary/);
        assert.equal(await page.getByRole('tabpanel').locator('img,script,iframe').count(),0);
        assert.equal(await page.evaluate(()=>window.scopeLabelExecuted),undefined);
        await navigation.getByRole('tab',{name:'Standards',exact:true}).click();
        assert.match(await page.getByRole('tabpanel').innerText(),/MEASURED_PORTABLE_FIELD/);
        assert.match(await page.getByRole('tabpanel').innerText(),/SUPPORTING_VENDOR_SOURCE/);
        assert.equal(await page.getByRole('region',{name:'Official format validator results'}).count(),1);
        await navigation.getByRole('tab',{name:'Token usage',exact:true}).click();
        const tokens=page.locator('[data-token-footprint]');
        for(const text of ['Discovery metadata','Main SKILL.md','Directly referenced text','Packaged supporting text','Exact tokens: not measured','rough text proxy','Token estimate unavailable','OPTIONAL_REFERENCE_SCENARIO_ONLY','ACTUAL_RUN_TOKEN_USAGE_UNKNOWN','NON_ASCII_PROXY_NOT_AVAILABLE','do not add the rows'])assert.ok((await tokens.innerText()).includes(text));
        assert.match(await tokens.innerText(),/1,200 characters/);assert.match(await tokens.innerText(),/1,250 UTF-8 bytes/);
        await navigation.getByRole('tab',{name:'Evidence & coverage',exact:true}).click();
        assert.match(await page.getByRole('tabpanel').innerText(),/Analysis coverage/);
        assert.match(await page.getByRole('tabpanel').innerText(),/partial/);
        for(const depth of ['summary','detailed']){
            await page.getByRole('button',{name:depth,exact:true}).click();
            const download=page.waitForEvent('download');await page.getByRole('button',{name:depth==='summary'?'Export Summary':'Export Detailed',exact:true}).click();
            const markdown=fs.readFileSync(await(await download).path(),'utf8');
            for(const marker of ['pii_email_address','MEASURED_PORTABLE_FIELD','SUPPORTING_VENDOR_SOURCE','source_read','network_payload','STATIC_EFFECT_SCOPE_NOT_RUNTIME','OPTIONAL_REFERENCE_SCENARIO_ONLY','NON_ASCII_PROXY_NOT_AVAILABLE'])assert.ok(markdown.includes(marker),`${depth} export retains ${marker} from another scope`);
            if(depth==='detailed')assert.ok(markdown.includes('SECURITY_FINDING_RETAINED'),'detailed export retains complete finding description');
            assert.ok(!markdown.includes('UNEXPORTED_RAW_UPLOAD'));
        }
        const planDownload=page.waitForEvent('download');
        await page.getByRole('button',{name:'Export improvement plan (.md)',exact:true}).click();
        const plan=await planDownload;
        assert.equal(plan.suggestedFilename(),'scoped-fixture.skill-improvement-plan.md');
        const planMarkdown=fs.readFileSync(await plan.path(),'utf8');
        for(const marker of ['PLAN_CONFIRMED_FAILURE','PLAN_CORRECT_MEASURED_FORMAT','PLAN_RESCAN_CORRECTION','PLAN_CONTEXTUAL_REVIEW','PLAN_REVIEW_NOT_PROVEN_MALICIOUS','PLAN_PRESERVE_LEGITIMATE_CONTROLS','PLAN_ADVISORY_ONLY','PLAN_OPTIONAL_LOADING','PLAN_UNKNOWN_RUNTIME','PLAN_OBTAIN_AUTHORIZED_EVIDENCE','PLAN_RUNTIME_SEPARATE','fixture/SKILL.md','https://agentskills.io/specification','a'.repeat(64),'STATIC_PLAN_ONLY_NO_RUNTIME_OR_COMPLIANCE_CERTIFICATION','ORDER_OF_WORK_NOT_QUANTIFIED_RISK'])assert.ok(planMarkdown.includes(marker),`plan export retains ${marker}`);
        assert.ok(planMarkdown.indexOf('PLAN_CONFIRMED_FAILURE')<planMarkdown.indexOf('PLAN_UNKNOWN_RUNTIME'),'required correction precedes unknown runtime evidence');
        assert.ok(!planMarkdown.includes('UNEXPORTED_RAW_UPLOAD'),'the plan excludes raw uploaded source content');
        const planBlocks=[...planMarkdown.matchAll(/```json\n([\s\S]*?)\n```/g)].map(match=>JSON.parse(match[1]));
        for(const item of improvementPlan.items)assert.deepEqual(planBlocks.find(block=>block.id===item.id),item,'JSON fences preserve literal source strings without breaking Markdown structure');
        assert.equal(await page.evaluate(()=>window.scopeLabelExecuted),undefined,'export never executes hostile source labels');
        for(const width of [390,1440]){await page.setViewportSize({width,height:1100});for(const name of names){await navigation.getByRole('tab',{name,exact:true}).click();assert.equal(await page.getByRole('button',{name:'Export improvement plan (.md)',exact:true}).isVisible(),true,'plan download remains available in every scope');assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name} reflows at ${width}`);}}
        await navigation.getByRole('tab',{name:'Token usage',exact:true}).click();
        await page.screenshot({path:path.join(root,'tmp/skill-report-scopes-tokens.png'),fullPage:true});
        legacy=true;await scan();
        assert.equal(await first.getAttribute('aria-selected'),'true','a fresh scan resets the active scope');
        await navigation.getByRole('tab',{name:'Token usage',exact:true}).click();assert.match(await page.getByRole('tabpanel').innerText(),/Not assessed in this report/);
        await navigation.getByRole('tab',{name:'Standards',exact:true}).click();assert.match(await page.getByRole('tabpanel').innerText(),/Not assessed — this report does not include/);
        await navigation.getByRole('tab',{name:'Structure & process',exact:true}).click();assert.match(await page.getByRole('tabpanel').innerText(),/Python effect traces.*Not assessed in this report/s);
        const legacyDownload=page.waitForEvent('download');await page.getByRole('button',{name:'Export improvement plan (.md)',exact:true}).click();
        assert.match(fs.readFileSync(await(await legacyDownload).path(),'utf8'),/Not assessed in this report.*fresh scan/s);
        assert.deepEqual(errors,[]);
        console.log('PASS: six report scopes, roving keyboard, retained evidence, complete report and improvement-plan exports, literal hostile strings, 390px reflow, fresh-scan reset and legacy unknowns.');
    }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
