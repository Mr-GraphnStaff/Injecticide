// Independent QA for the coordinator's scoped report/token/effect presentation.
// Synthetic API evidence only; this does not validate scanner or tokenizer accuracy.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const http=require('node:http');
const path=require('node:path');
const root = path.resolve(__dirname, '../..');
// Source can be a nested worktree; scratch belongs to the launcher's owner root.
// The launcher supplies AGENT_WORKING_DIR, not AGENT_WORKING_ROOT.
function findOwnerRoot(start) {
    for (let candidate = start; ; candidate = path.dirname(candidate)) {
        if (fs.existsSync(path.join(candidate, 'working', '.agent-control', 'policy.json'))) return candidate;
        if (path.dirname(candidate) === candidate) throw new Error('No owner working-area marker found.');
    }
}
const ownerRoot = fs.realpathSync(process.env.AGENT_WORKING_ROOT || findOwnerRoot(root));
const working = path.join(ownerRoot, 'working');
const run = process.env.AGENT_WORKING_DIR && path.resolve(process.env.AGENT_WORKING_DIR);
const relativeRun = run && path.relative(fs.realpathSync(path.join(working, 'runs')), fs.realpathSync(run));
if (!run || !relativeRun || relativeRun === '..' || relativeRun.startsWith(`..${path.sep}`) || path.isAbsolute(relativeRun)) {
    throw new Error('Run this harness through working_area.py run --root <checkout> -- node <harness>.');
}
require('node:child_process').execFileSync('python', ['C:/Users/DavidFarris/.codex/tools/working_area.py', 'check', '--root', ownerRoot], {cwd:ownerRoot, stdio:'pipe'});
const output = path.join(run, 'reports', 'browser', path.basename(__filename, '.cjs'));
fs.mkdirSync(output, {recursive:true});
const browserCache = path.join(working, 'cache', 'browser');
const assetCandidates = [path.join(browserCache, 'scan-resource-regression'), path.join(working, 'relocated', '2026-11-02', 'tmp', 'scan-resource-regression')];
const assets = assetCandidates.find(folder => ['react.js','react-dom.js','babel.js'].every(name => fs.existsSync(path.join(folder, name)))) || assetCandidates[0];
// Read existing dependencies only. Never install packages or browsers here.
const playwrightCandidates = [process.env.INJECTICIDE_PLAYWRIGHT_MODULE,
    path.join(browserCache, 'node_modules', 'playwright'),
    process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'npm-cache', '_npx', 'e41f203b7505f1fb', 'node_modules', 'playwright-core'),
    'C:/Python312/Lib/site-packages/playwright/driver/package'].filter(Boolean);
const playwrightModule = playwrightCandidates.find(folder => fs.existsSync(path.join(folder, 'package.json')));
if (!playwrightModule) throw new Error('Set INJECTICIDE_PLAYWRIGHT_MODULE to an existing local Playwright package.');
const {chromium} = require(playwrightModule);
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
// Authored API evidence tests presentation/downloads, not backend policy decisions.
const policyHash='c'.repeat(64);
const policyLabel='Policy '+hostile+' <script>window.scopeLabelExecuted=true</script> [claim](javascript:window.scopeLabelExecuted=true) ```\n# forged';
const exception={rule_id:'directory-exception',path:'fixture/SKILL.md',finding_id:'pii_email_address',
    rationale:'Explicit synthetic exception',approver:'Named Security Approver',expires:'2099-12-31',reason:'Reviewed directory use'};
const coverageException={rule_id:'coverage-exception',path:null,finding_id:null,rationale:'Explicit unread coverage acceptance',
    approver:'Coverage Review Team',expires:'2099-12-31',reason:'Synthetic aggregate gap accepted for this assessment only'};
const policyIdentity={name:policyLabel,organization:'Hostile Company '+hostile,compiled_date:'2026-11-08',sha256:policyHash,
    sources:[{id:'company-standard',title:'Declared policy source',owner:'Policy Owner'}]};
const technicalVerdict={explicit_verdict:'block',baseline_disposition:'block',finding_disposition:'block',
    risk_classification:{overall_risk:'high',recommendation:'block_by_default'},governance_decisions:{},inputs_status:'known'};
const organizationReport={technical_verdict:technicalVerdict,organization_disposition:'allow',policy:policyIdentity,
    authority:'declared_unverified',evaluation_date:'2026-11-08',exceptions_applied:[exception,coverageException],exceptions_not_applied:[],
    residual_findings:[],full_stops:[],coverage_limits:[{path:null,status:'partial',reason:'Coverage remains unread',accepted_by:['coverage-exception']}],
    deciding_rules:[],not_statically_checkable:['Runtime controls remain unverified'],errors:[],limits:['Synthetic report only'],fallback_reason:null};
const policyEvaluation={status:'applied',policy:policyIdentity,organization_disposition:'allow',organization_report:organizationReport,
    rules:[{id:exception.rule_id,title:policyLabel,effect:'allow',enforcement:'mandatory',triggered:true,source:'company-standard',
        section:'4.2',requirement:'Accept only the named synthetic finding',approver:exception.approver,evidence:[]}],
    effect_summary:{block:0,require_approval:0,warn:0,allow:1},errors:[],not_statically_checkable:[]};
let legacy=false, policyMode='applied';
function policyForMode() {
    if (policyMode==='none') return {status:'none',rules:[],errors:[]};
    const evaluation=structuredClone(policyEvaluation);
    if (policyMode==='legacy') { delete evaluation.organization_report; delete evaluation.organization_disposition; evaluation.decision='allow'; }
    if (policyMode==='residual') {
        evaluation.organization_disposition=evaluation.organization_report.organization_disposition='require_approval';
        evaluation.organization_report.residual_findings=[{path:'fixture/residual.md',id:'residual-review',scanner_disposition:'require_approval',protected:false}];
        evaluation.organization_report.deciding_rules=[{id:'residual-review-rule',effect:'require_approval',approver:'Residual Review Team'}];
    }
    if (policyMode==='invalid') {
        evaluation.status='invalid'; evaluation.rules=[]; evaluation.effect_summary={block:0,require_approval:0,warn:0,allow:0};
        evaluation.organization_disposition=evaluation.organization_report.organization_disposition='block';
        evaluation.errors=[{path:'rules[1].effect',message:'Invalid policy effect '+hostile}];
        Object.assign(evaluation.organization_report,{exceptions_applied:[],deciding_rules:[],errors:evaluation.errors,
            coverage_limits:organizationReport.coverage_limits.map(gap=>({...gap,accepted_by:[]})),
            fallback_reason:'Invalid policy rejected in its entirety; scanner baseline retained',
            residual_findings:[{path:exception.path,id:exception.finding_id,scanner_disposition:'block',protected:false}]});
    }
    return evaluation;
}
report.final_verdict='block';
report.risk_classification={overall_risk:'high',recommendation:'block_by_default'};
report.improvement_plan=improvementPlan;
const server=http.createServer((req,res)=>{
    if(req.url==='/'){res.setHeader('Content-Type','text/html;charset=utf-8');return res.end('<!doctype html><html lang="en"><head><title>Report scopes QA</title><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/home.css"><style>body{margin:0}*{box-sizing:border-box}[hidden]{display:none!important}</style></head><body><div id="root"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script src="/babel.js"></script><script src="/fixture.js"></script></body></html>');}
    if(req.url==='/fixture.js'){res.setHeader('Content-Type','text/javascript');return res.end('eval(Babel.transform('+JSON.stringify(source)+',{presets:["react"]}).code)');}
    if(req.url==='/home.css'){res.setHeader('Content-Type','text/css');return res.end(fs.readFileSync(path.join(root,'webapp/static/home.css')));}
    if(['/react.js','/react-dom.js','/babel.js'].includes(req.url)){res.setHeader('Content-Type','text/javascript');return res.end(fs.readFileSync(path.join(assets,req.url.slice(1))));}
    if(req.url.startsWith('/api/')){res.setHeader('Content-Type','application/json');if(req.url==='/api/skills/scan'){const value=structuredClone(report);value.policy_evaluation=policyForMode();if(policyMode==='residual'){value.files.push({path:'fixture/residual.md',assessment_state:'text_analyzed',findings:[{id:'residual-review',tier:'review',severity:'medium',description:'Residual review remains required'}]});value.summary.total_files++;value.summary.flagged_files++;value.summary.total_findings++;}if(legacy){delete value.token_footprint;delete value.improvement_plan;delete value.standards_assessment;delete value.package_analysis.effect_analysis;value.scan_request_id='legacy-scopes';}return res.end(JSON.stringify(value));}return res.end(JSON.stringify({categories:[],endpoints:[],payload_presets:[]}));}
    res.statusCode=404;res.end();
});
(async()=>{
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    const browser=await chromium.launch({downloadsPath:path.join(output,'downloads'),tracesDir:path.join(output,'traces'),channel:process.env.INJECTICIDE_TEST_BROWSER||'msedge',headless:true});
    try{
        const page=await browser.newPage({viewport:{width:1440,height:1100},acceptDownloads:true});
        const errors=[];page.on('pageerror',error=>errors.push(error.message));
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        async function scan(){await page.getByLabel('Skill file',{exact:true}).setInputFiles({name:'scoped-fixture.skill',mimeType:'text/markdown',buffer:Buffer.from('UNEXPORTED_RAW_UPLOAD')});await page.getByRole('button',{name:'Scan Skill File/Bundle',exact:true}).click();await page.getByRole('tablist',{name:'Scan report scope'}).waitFor();}
        await scan();
        const navigation=page.getByRole('tablist',{name:'Scan report scope'});
        const names=['Overview','Files','Security','Structure & process','Standards','Token usage','Evidence & coverage'];
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
            // The readable 0.16 reports summarize standards/governance; they do
            // not reproduce every UI-only requirement, effect or token detail.
            for(const heading of ['Headline','What to fix','Policy results','Database coverage','Findings by file','Summary','Governance','Standards','Warnings'])
                assert.ok(markdown.includes(`## ${heading}\n`),`${depth} report retains its ${heading} section`);
            for(const marker of ['fixture/SKILL.md','pii_email_address','OVERVIEW_WARNING_AVAILABLE',
                'EXPLICIT_PARTIAL_SCAN_COVERAGE','block_by_default','Portable mandatory status: pass',
                'Mandatory passed: 1 · failed: 0 · not assessed: 0',
                'Vendor requirements: unknown · runtime compatibility: unknown','a'.repeat(64)])
                assert.ok(markdown.includes(marker),`${depth} report retains ${marker}`);
            assert.ok(markdown.includes(`- Report: ${depth}`));
            const findingsSection=markdown.split('## Findings by file\n')[1].split('\n## Summary')[0];
            if(depth==='detailed') {
                for(const marker of ['Description: SECURITY_FINDING_RETAINED','Artifact role: active · size 1250 bytes',
                    'Tier: review','SYNTHETIC_PERSON@example.test'])
                    assert.ok(findingsSection.includes(marker),`detailed findings retain ${marker}`);
            } else {
                assert.ok(!findingsSection.includes('Description:'),'summary findings omit detailed descriptions');
                assert.ok(!findingsSection.includes('Samples (as reported'),'summary findings omit sample values');
            }
            assert.ok(!markdown.includes('UNEXPORTED_RAW_UPLOAD'),'readable reports exclude raw uploaded source');
        }
        const planDownload=page.waitForEvent('download');
        await page.getByRole('button',{name:'Export improvement plan (.md)',exact:true}).click();
        const plan=await planDownload;
        assert.match(plan.suggestedFilename(),/^scoped-fixture-injecticide-0\.11\.0-fixture-\d{8}-\d{4}-improvement-plan\.md$/);
        const planMarkdown=fs.readFileSync(await plan.path(),'utf8');
        for(const marker of ['PLAN_CONFIRMED_FAILURE','PLAN_CORRECT_MEASURED_FORMAT','PLAN_RESCAN_CORRECTION','PLAN_CONTEXTUAL_REVIEW','PLAN_REVIEW_NOT_PROVEN_MALICIOUS','PLAN_PRESERVE_LEGITIMATE_CONTROLS','PLAN_ADVISORY_ONLY','PLAN_OPTIONAL_LOADING','PLAN_UNKNOWN_RUNTIME','PLAN_OBTAIN_AUTHORIZED_EVIDENCE','PLAN_RUNTIME_SEPARATE','fixture/SKILL.md','https://agentskills.io/specification','a'.repeat(64),'STATIC_PLAN_ONLY_NO_RUNTIME_OR_COMPLIANCE_CERTIFICATION','ORDER_OF_WORK_NOT_QUANTIFIED_RISK'])assert.ok(planMarkdown.includes(marker),`plan export retains ${marker}`);
        assert.ok(planMarkdown.indexOf('PLAN_CONFIRMED_FAILURE')<planMarkdown.indexOf('PLAN_UNKNOWN_RUNTIME'),'required correction precedes unknown runtime evidence');
        assert.ok(!planMarkdown.includes('UNEXPORTED_RAW_UPLOAD'),'the plan excludes raw uploaded source content');
        const planBlocks=[...planMarkdown.matchAll(/```json\n([\s\S]*?)\n```/g)].map(match=>JSON.parse(match[1]));
        for(const item of improvementPlan.items)assert.deepEqual(planBlocks.find(block=>block.id===item.id),item,'JSON fences preserve literal source strings without breaking Markdown structure');
        assert.equal(await page.evaluate(()=>window.scopeLabelExecuted),undefined,'export never executes hostile source labels');
        const policyButton=page.getByRole('button',{name:'Export organization policy report (.md)',exact:true});
        async function exportPolicy() {
            assert.equal(await policyButton.isEnabled(),true);
            const pending=page.waitForEvent('download');
            await policyButton.click();
            const download=await pending;
            assert.equal(await download.failure(),null);
            assert.match(download.suggestedFilename(),/^scoped-fixture-injecticide-0\.11\.0-fixture-\d{8}-\d{4}-report-organization-policy\.md$/);
            const saved=path.join(output,'downloads',policyMode+'-'+download.suggestedFilename());
            await download.saveAs(saved);
            const raw=fs.readFileSync(saved,'utf8');
            assert.ok(!raw.includes('UNEXPORTED_RAW_UPLOAD'),'policy export excludes uploaded source');
            assert.ok(!/<\/?(?:script|img)\b/i.test(raw),'policy export contains no raw executable HTML');
            assert.equal(await page.evaluate(()=>window.scopeLabelExecuted),undefined);
            // Unescape Markdown punctuation only for semantic assertions below;
            // escaping assertions always inspect the original downloaded bytes.
            return {raw,text:raw.replace(/\\([\\`*_{}\[\]()#!|])/g,'$1')};
        }
        await navigation.getByRole('tab',{name:'Overview',exact:true}).click();
        assert.equal(await page.locator('[data-organization-disposition]').getAttribute('data-organization-disposition'),'allow');
        assert.equal(await page.getByRole('heading',{name:'Company disposition: allow',exact:true}).count(),1);
        assert.equal(await page.locator('[data-policy-results] img, [data-policy-results] script').count(),0);
        const appliedPolicy=await exportPolicy();
        assert.ok(appliedPolicy.raw.includes(policyHash),'exact supplied policy hash is retained');
        assert.ok(appliedPolicy.raw.includes('&lt;script&gt;') && appliedPolicy.raw.includes('&lt;img'),'HTML labels are entity escaped');
        assert.ok(appliedPolicy.raw.includes('\\[claim\\]\\(javascript:') && appliedPolicy.raw.includes('\\`\\`\\`'),'Markdown links and fences remain literal');
        assert.match(appliedPolicy.text,/## Company disposition\s+\*\*allow\*\*/);
        assert.match(appliedPolicy.text,/Original scanner verdict:.*"explicit_verdict":"block"/);
        for(const marker of [policyHash,'directory-exception','Named Security Approver','fixture/SKILL.md','2099-12-31',
            'Residual findings','Coverage remains unread','coverage-exception','partial','declared_unverified',
            'Declared policy source','Runtime controls remain unverified','Synthetic report only'])
            assert.ok(appliedPolicy.text.includes(marker),`policy export retains ${marker}`);
        policyMode='residual'; await scan();
        const residualPolicy=await exportPolicy();
        for(const marker of ['require_approval','fixture/residual.md','residual-review','residual-review-rule','Residual Review Team'])
            assert.ok(residualPolicy.text.includes(marker),`unaccepted residual evidence retains ${marker}`);
        policyMode='invalid'; await scan();
        assert.equal(await page.locator('[data-organization-disposition]').getAttribute('data-organization-disposition'),'block');
        const invalidPolicy=await exportPolicy();
        assert.match(invalidPolicy.text,/## Company disposition\s+\*\*block\*\*/);
        assert.ok(invalidPolicy.text.includes('Invalid policy rejected in its entirety'));
        assert.ok(invalidPolicy.text.includes('Invalid policy effect'));
        assert.match(invalidPolicy.text,/## Exceptions applied\s+None reported\./);
        assert.ok(!invalidPolicy.text.includes('coverage-exception'),'invalid policy cannot accept an unread coverage gap');
        assert.ok(!invalidPolicy.text.includes('## Company disposition\n\n**allow**'),'invalid policy never implies company acceptance');
        policyMode='none'; await scan();
        assert.equal(await policyButton.isDisabled(),true,'no supplied policy cannot be exported as an acceptance report');
        policyMode='applied'; await scan();
        for(const width of [390,1440]){await page.setViewportSize({width,height:1100});for(const name of names){await navigation.getByRole('tab',{name,exact:true}).click();assert.equal(await page.getByRole('button',{name:'Export improvement plan (.md)',exact:true}).isVisible(),true,'plan download remains available in every scope');assert.equal(await policyButton.isVisible(),true,'organization report download remains available in every scope');assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name} reflows at ${width}`);}}
        await navigation.getByRole('tab',{name:'Token usage',exact:true}).click();
        await page.screenshot({path:path.join(output, 'skill-report-scopes-tokens.png'),fullPage:true});
        legacy=true;policyMode='legacy';await scan();
        assert.equal(await first.getAttribute('aria-selected'),'true','a fresh scan resets the active scope');
        await navigation.getByRole('tab',{name:'Token usage',exact:true}).click();assert.match(await page.getByRole('tabpanel').innerText(),/Not assessed in this report/);
        await navigation.getByRole('tab',{name:'Standards',exact:true}).click();assert.match(await page.getByRole('tabpanel').innerText(),/Not assessed — this report does not include/);
        await navigation.getByRole('tab',{name:'Structure & process',exact:true}).click();assert.match(await page.getByRole('tabpanel').innerText(),/Python effect traces.*Not assessed in this report/s);
        const legacyDownload=page.waitForEvent('download');await page.getByRole('button',{name:'Export improvement plan (.md)',exact:true}).click();
        assert.match(fs.readFileSync(await(await legacyDownload).path(),'utf8'),/Not assessed in this report.*fresh scan/s);
        const legacyPolicy=await exportPolicy();
        assert.match(legacyPolicy.text,/disposition unavailable.*Scan again/s);
        assert.ok(legacyPolicy.text.includes('No company acceptance is inferred from legacy allow annotations'));
        assert.ok(!legacyPolicy.text.includes('## Company disposition'),'legacy allow annotations do not fabricate approval');
        assert.deepEqual(errors,[]);
        console.log('PASS: seven report scopes, roving keyboard, retained evidence, complete report/improvement-plan/organization-policy downloads, scanner/company separation, residual/invalid/none/legacy policy states, literal hostile strings, 390px reflow, fresh-scan reset and legacy unknowns.');
    }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
