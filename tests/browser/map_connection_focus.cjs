// Synthetic scan response; actual React interaction and separate playground drafts.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '../..');
const assets = path.join(root, 'tmp/scan-resource-regression');
const script = ['webapp/static/pages/Home.jsx', 'webapp/static/pages/ArchitectureCanvas.jsx', 'webapp/static/pages/MapPng.js', 'webapp/static/app.js'].map(name => fs.readFileSync(path.join(root, name), 'utf8')).join('\n');
const citation = (source, line = null) => ({path:source,line,line_accuracy:line ? 'exact' : 'file_only'});
const hostile = '<img src=x onerror="window.uploadExecuted=true">';
const diagram = {
    schema_version:1,status:'partial',scope:'Documented source relationships and explicit order only. Runtime behavior is unverified.',runtime_verified:false,
    nodes:[
        {id:'n0',kind:'file',label:'example/SKILL.md',path:'example/SKILL.md',entrypoint:true,citations:[citation('example/SKILL.md')],finding_ids:[],knowledge_status:'known'},
        {id:'n1',kind:'step',label:'Read source',text:'Read input and produce a review.',path:'example/SKILL.md',citations:[citation('example/SKILL.md',4)],finding_ids:[],knowledge_status:'known'},
        {id:'n2',kind:'file',label:'scripts/review.py',path:'scripts/review.py',citations:[citation('scripts/review.py')],finding_ids:['dynamic_exec'],knowledge_status:'known'},
        {id:'n3',kind:'capability',label:'file read',path:null,citations:[citation('scripts/review.py',8)],finding_ids:[],knowledge_status:'known'},
        {id:'n4',kind:'external',label:'https://destination.invalid',path:null,citations:[citation('scripts/review.py',10)],finding_ids:[],knowledge_status:'known'},
        {id:'n5',kind:'unresolved',label:hostile,path:null,citations:[citation('example/SKILL.md',9)],finding_ids:[],knowledge_status:'unknown'}
    ],
    edges:[
        {id:'e0',source:'n0',target:'n1',label:'documents step',status:'resolved',citations:[citation('example/SKILL.md',4)],knowledge_status:'known'},
        {id:'e1',source:'n0',target:'n2',label:'declares command reference',status:'resolved',citations:[citation('example/SKILL.md',7)],knowledge_status:'known'},
        {id:'e2',source:'n2',target:'n3',label:'contains capability syntax',status:'resolved',citations:[citation('scripts/review.py',8)],knowledge_status:'known'},
        {id:'e3',source:'n2',target:'n4',label:'names network destination',status:'resolved',citations:[citation('scripts/review.py',10)],knowledge_status:'known'},
        {id:'e4',source:'n0',target:'n5',label:'declares reference',status:'unresolved',citations:[citation('example/SKILL.md',9)],knowledge_status:'unknown'}
    ],
    omitted:{nodes:2,edges:3},unresolved_nodes:1,limits:[{kind:'diagram_node_count'}],mermaid:'flowchart LR\n n0["example/SKILL.md"] --> n2["scripts/review.py"]'
};
for(let i=6;i<40;i++) diagram.nodes.push({id:'n'+i,kind:'file',label:'references/evidence-'+i+'.md',path:'references/evidence-'+i+'.md',citations:[citation('references/evidence-'+i+'.md')],finding_ids:[],knowledge_status:'known'});
for(let i=0;i<100;i++) diagram.edges.push({id:'dense'+i,source:'n'+(i%40),target:'n'+((i*7+3)%40),label:'references source',status:'resolved',citations:[citation('example/SKILL.md',i+10)]});
diagram.architecture_map = {schema_version:1,name:'Scanned skill: documented relationships',nodes:diagram.nodes.map((node,index)=>({id:node.id,kind:node.entrypoint?'skill':'data',label:node.label,x:40+(index%3)*300,y:30+Math.floor(index/3)*180,trust:'unknown',sensitivity:'unknown',controls:'Imported static scan evidence; runtime unverified.'})),edges:diagram.edges.map(edge=>({id:edge.id,source:edge.source,target:edge.target,untrusted:false,write:false}))};
const report = {
    filename:'synthetic-process.skill',file_type:'.skill',scan_request_id:'synthetic-process',warnings:[],
    summary:{total_files:2,flagged_files:1,total_findings:1,info_findings:0},
    coverage:{status:'partial',analyzed_files:2,total_files:2,total_bytes:500,statement:'Synthetic coverage only.'},
    readiness:{status:'needs_review',tenant_policy_verified:false,runtime_evaluation:'not_assessed'},
    governance_evidence:{artifact_sha256:'a'.repeat(64),controls:[],signature_verification:{status:'not_present'},evaluation:{status:'not_assessed'}},
    scanner_metadata:{scanner_version:'0.9.0',adapter_version:'fixture',catalogs:[]},
    package_analysis:{artifact_kind:'skill',target_runtime:'claude-code',runtime_targets:[],format_findings:[],components:[],execution_references:[],dependencies:[]},
    check_results:[],vendor_verification:{status:'unknown',runtime:'claude-code',compatibility:'unknown',reason:'Fixture',documents:[],requirements:[],checks:[]},
    files:[{path:'example/SKILL.md',size:100,skipped:false,assessment_state:'text_analyzed',artifact_role:'active',findings:[]},{path:'scripts/review.py',size:100,skipped:false,assessment_state:'text_analyzed',artifact_role:'active',findings:[{id:'dynamic_exec',severity:'high',tier:'review',is_actionable:true,category:'code',description:'Synthetic measurable capability',samples:['line 8: eval(data)']}]}],
    process_diagram:diagram
};
const server=http.createServer((req,res)=>{
    if(req.url==='/') {res.setHeader('Content-Type','text/html;charset=utf-8');return res.end('<!doctype html><html lang="en"><head><title>Process diagram test</title><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/home.css"><style>body{margin:0}*{box-sizing:border-box}[hidden]{display:none!important}</style></head><body><div id="root"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script src="/babel.js"></script><script src="/fixture.js"></script></body></html>');}
    if(req.url==='/fixture.js'){res.setHeader('Content-Type','text/javascript');return res.end('eval(Babel.transform('+JSON.stringify(script)+',{presets:["react"]}).code)');}
    if(req.url==='/home.css'){res.setHeader('Content-Type','text/css');return res.end(fs.readFileSync(path.join(root,'webapp/static/home.css')));}
    if(['/react.js','/react-dom.js','/babel.js'].includes(req.url)){res.setHeader('Content-Type','text/javascript');return res.end(fs.readFileSync(path.join(assets,req.url.slice(1))));}
    res.statusCode=404;res.end();
});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try {
 const page=await browser.newPage({viewport:{width:1440,height:1000},acceptDownloads:true});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/api/**',route=>{const url=route.request().url();return route.fulfill({contentType:'application/json',body:JSON.stringify(url.endsWith('/skills/scan')?report:url.endsWith('/architecture/plan')?{planner_version:'fixture',map_hash:'fixture',tests:[{id:'test',title:'Synthetic path',reason:'Fixture',node_ids:['n0','n2'],edge_ids:['e1'],expected_evidence:'Fixture',suggested_engine:'manual',reference:'https://owasp.org'}],omitted_tests:0}:{categories:[],endpoints:[],payload_presets:[],items:[],available:false,collection:{}})});});
 await page.goto(`http://127.0.0.1:${server.address().port}`);
 await page.getByRole('button',{name:'Testing & scanning',exact:true}).click();
 await page.getByLabel('Skill file',{exact:true}).setInputFiles({name:'dense.skill',mimeType:'text/plain',buffer:Buffer.from('SYNTHETIC')});
 await page.getByRole('button',{name:'Scan Skill File/Bundle',exact:true}).click();await page.getByRole('tab',{name:'Structure & process',exact:true}).click();
 const process=page.locator('[data-process-diagram]');await process.waitFor();
 assert.equal(await process.locator('.process-node').count(),40);assert.equal(await process.locator('.process-edge').count(),105);
 await process.getByRole('button',{name:'Inspect scripts/review.py',exact:true}).click();
 const count=diagram.edges.filter(e=>e.source==='n2'||e.target==='n2').length;
 assert.equal(await process.locator('.process-edge.active').count(),count);
 assert.equal(await process.locator('.process-edge.dimmed').count(),105-count);
 await process.getByLabel('Only selected connections',{exact:true}).check();
 assert.equal(await process.locator('.connection-hidden').count(),105-count);
 await process.screenshot({path:path.join(root,'tmp/dense-process-selected.png')});
 await process.getByRole('button',{name:'Clear selection',exact:true}).click();assert.equal(await process.locator('.connection-hidden').count(),0);
 await process.getByRole('button',{name:'Inspect scripts/review.py',exact:true}).focus();await page.keyboard.press('Enter');await page.keyboard.press('Escape');
 assert.equal(await process.locator('.process-node.selected').count(),0);
 await process.getByRole('button',{name:'Add process diagram to playground',exact:true}).click();
 await page.locator('.map-node').nth(2).click();assert.equal(await page.locator('.connection-selected').count(),count);
 await page.getByLabel('Only selected connections',{exact:true}).check();
 await page.getByRole('button',{name:'Generate test plan',exact:true}).click();await page.getByRole('button',{name:'Highlight on map',exact:true}).click();
 assert.equal(await page.locator('.map-edge.active').count(),1);assert.equal(await page.locator('.map-edge.active.connection-hidden').count(),0,'test path remains visible');
 const before=await page.locator('.map-node').nth(2).evaluate(n=>n.style.left);
 await page.locator('.map-node').nth(2).focus();await page.keyboard.press('ArrowRight');
 assert.equal(await page.locator('.map-node').nth(2).evaluate(n=>n.style.left),`${parseFloat(before)+20}px`);
 assert.equal(await page.locator('.map-edge.active').count(),0,'editing still invalidates test plan');
 for(const width of [390,1440]) {await page.setViewportSize({width,height:1000});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));}
 await page.locator('.map-workspace').screenshot({path:path.join(root,'tmp/dense-playground-selected.png')});
 const downloadEvent=page.waitForEvent('download');await page.getByRole('button',{name:'Export map',exact:true}).click();
 const exported=JSON.parse(fs.readFileSync(await(await downloadEvent).path(),'utf8'));assert.equal(exported.nodes.length,40);assert.equal(exported.edges.length,105);
 await page.locator('.map-node').nth(2).focus();await page.keyboard.press('Escape');assert.equal(await page.locator('.connection-hidden').count(),0);
 assert.equal(await page.locator('img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.uploadExecuted),undefined);assert.deepEqual(errors,[]);
 console.log('PASS: dense 40-component/105-connection map; mouse/keyboard focus and clear; focused filter; plan path retained; keyboard movement/invalidation; 390/1440 reflow; full JSON export; escaped source labels.');
 } finally {await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(e=>{console.error(e);process.exitCode=1;});
