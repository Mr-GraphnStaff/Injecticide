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
    const browser=await chromium.launch({channel:process.env.INJECTICIDE_TEST_BROWSER||'msedge',headless:true});
    try{
        const page=await browser.newPage({viewport:{width:1600,height:1100},acceptDownloads:true});
        const errors=[];page.on('pageerror',error=>errors.push(error.message));
        await page.route('**/api/**',async route=>{
            const url=route.request().url();
            const value=url.endsWith('/skills/scan')?report:url.endsWith('/app/version')?{display_version:'0.9.0 fixture'}:url.endsWith('/research/news')?{items:[],available:false,collection:{}}:{categories:[],endpoints:[],payload_presets:[]};
            await route.fulfill({contentType:'application/json',body:JSON.stringify(value)});
        });
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        await page.getByRole('button',{name:'Explore architecture',exact:true}).click();
        await page.getByLabel('System name',{exact:true}).fill('Original separate architecture draft');
        await page.getByRole('button',{name:'Save locally',exact:true}).click();
        const saved=await page.evaluate(()=>localStorage.getItem('injecticide-map-v1'));
        await page.getByRole('button',{name:'Testing & scanning',exact:true}).click();
        await page.getByLabel('Skill file',{exact:true}).setInputFiles({name:'synthetic-process.skill',mimeType:'text/markdown',buffer:Buffer.from('SYNTHETIC_NOT_EXECUTED')});
        await page.getByRole('button',{name:'Scan Skill File/Bundle',exact:true}).click();
        await page.getByRole('tab',{name:'Structure & process',exact:true}).click();
        const process=page.locator('[data-process-diagram]');await process.waitFor();
        assert.equal(await process.locator('.process-node').count(),6);
        assert.equal(await process.locator('.process-edge').count(),5);
        assert.match(await process.innerText(),/2 components and 3 relationships/);
        assert.match(await process.innerText(),/Known:.*Inferred:.*Unknown:/s);
        assert.match(await process.innerText(),/Partial view/);
        await process.getByRole('button',{name:'Inspect scripts/review.py',exact:true}).focus();await page.keyboard.press('Enter');
        assert.match(await process.locator('.process-inspector').innerText(),/dynamic_exec/);
        assert.equal(await process.locator('.process-edge.active').count(),3);
        assert.equal(await process.locator('.process-edge.dimmed').count(),2);
        await process.getByLabel('Only selected connections',{exact:true}).check();
        assert.equal(await process.locator('.process-edge:visible').count(),3);
        await page.keyboard.press('Escape');
        assert.equal(await process.locator('.process-edge:visible').count(),5);
        assert.equal(await process.locator('.process-edge.dimmed').count(),0);
        await process.getByRole('button',{name:'Inspect scripts/review.py',exact:true}).focus();await page.keyboard.press('Space');
        await process.locator('.process-inspector').getByRole('button',{name:'scripts/review.py:8',exact:true}).click();
        assert.match(await process.locator('.process-source-evidence').innerText(),/Synthetic measurable capability/);
        await page.waitForFunction(()=>document.activeElement.textContent==='Source file evidence: scripts/review.py');
        await process.getByRole('button',{name:`Inspect ${hostile}`,exact:true}).click();
        assert.match(await process.locator('.process-inspector').innerText(),/UNKNOWN — UNVERIFIED/);
        assert.equal(await process.locator('img,script,iframe').count(),0);
        assert.equal(await page.evaluate(()=>window.uploadExecuted),undefined);
        await process.getByRole('button',{name:'Relationship list',exact:true}).click();
        assert.equal(await process.locator('.process-relationship-list > ul > li').count(),5);
        assert.match(await process.locator('.process-relationship-list').innerText(),/example\/SKILL.md:7/);
        const exported=page.waitForEvent('download');await process.getByRole('button',{name:'Export diagram evidence',exact:true}).click();
        assert.deepEqual(JSON.parse(fs.readFileSync(await (await exported).path(),'utf8')),diagram);
        const mermaid=page.waitForEvent('download');await process.getByRole('button',{name:'Export Mermaid',exact:true}).click();
        assert.equal(fs.readFileSync(await (await mermaid).path(),'utf8'),diagram.mermaid);
        await process.getByRole('button',{name:'Visual diagram',exact:true}).click();
        for(const width of [390,1600]){
            await page.setViewportSize({width,height:1100});
            assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`page reflows at ${width}`);
        }
        await process.screenshot({path:path.join(root,'tmp/skill-process-diagram-desktop.png')});
        await process.getByRole('button',{name:'Add process diagram to playground',exact:true}).focus();await page.keyboard.press('Enter');
        await page.getByRole('heading',{name:'New skill process map',exact:true}).waitFor();
        assert.equal(await page.locator('.map-node').count(),6,'new map does not merge with eight-node starter draft');
        assert.equal(await page.getByLabel('System name',{exact:true}).inputValue(),'Skill process: synthetic-process.skill');
        assert.equal(await page.evaluate(()=>localStorage.getItem('injecticide-map-v1')),saved,'automatic opening preserves saved architecture');
        assert.match(await page.locator('.map-source-evidence').first().innerText(),/example\/SKILL.md/);
        assert.equal(await page.locator('.map-edge.dimmed').count(),0,'no implicit connection focus');
        await page.locator('.map-node').nth(2).click();
        assert.equal(await page.locator('.map-edge.connection-selected').count(),3);
        assert.equal(await page.locator('.map-edge.dimmed').count(),2);
        await page.getByLabel('Only selected connections',{exact:true}).check();
        assert.equal(await page.locator('.map-edge').evaluateAll(edges=>edges.filter(edge=>getComputedStyle(edge).display!=='none').length),3);
        await page.locator('.map-node').nth(2).focus();await page.keyboard.press('Escape');
        assert.equal(await page.locator('.map-edge').evaluateAll(edges=>edges.filter(edge=>getComputedStyle(edge).display!=='none').length),5);
        await page.locator('.map-node').first().focus();await page.keyboard.press('Enter');
        assert.equal(await page.locator('.map-edge.connection-selected').count(),3);
        assert.match(await page.locator('.map-connection').first().innerText(),/documents step.*example\/SKILL.md:4/s);
        await page.getByRole('button',{name:'Save locally',exact:true}).click();
        assert.equal(await page.evaluate(()=>localStorage.getItem('injecticide-map-v1')),saved,'explicit skill map save uses separate storage');
        const skillKeys=await page.evaluate(()=>Object.keys(localStorage).filter(key=>key.startsWith('injecticide-skill-process-map-v1:')));
        assert.equal(skillKeys.length,1);assert.equal(JSON.parse(await page.evaluate(key=>localStorage.getItem(key),skillKeys[0])).nodes.length,6);
        await page.getByRole('button',{name:'Clear selection',exact:true}).click();
        assert.equal(await page.locator('.map-edge').evaluateAll(edges=>edges.filter(edge=>getComputedStyle(edge).display!=='none').length),5);
        const mapDownload=page.waitForEvent('download');await page.getByRole('button',{name:'Export map',exact:true}).click();
        const mapFile=await mapDownload;assert.equal(mapFile.suggestedFilename(),'skill-process-synthetic-process.skill-map.json');
        const map=JSON.parse(fs.readFileSync(await mapFile.path(),'utf8'));assert.equal(map.nodes.length,6);assert.equal(map.name,'Skill process: synthetic-process.skill');
        assert.equal(await page.evaluate(()=>window.uploadExecuted),undefined);
        const replacement={...map,name:'Replacement with reused identity',nodes:[{...map.nodes[0],label:'Replacement node'}],edges:[]};
        await page.locator('input[type=file]').setInputFiles({name:'replacement.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(replacement))});
        await page.getByText('The map was replaced. Original scan citations are no longer attached to this draft.',{exact:true}).waitFor();
        assert.equal(await page.locator('.map-source-evidence').count(),0,'replacement IDs cannot inherit original source citations');
        await page.getByRole('button',{name:'Return to scan report',exact:true}).focus();await page.keyboard.press('Enter');
        await page.locator('[data-process-diagram]').waitFor();
        await page.waitForFunction(()=>document.activeElement.id==='skill-process-add-to-playground');
        await page.getByRole('button',{name:'Architecture analysis',exact:true}).click();
        assert.equal(await page.getByLabel('System name',{exact:true}).inputValue(),'Original separate architecture draft');
        assert.equal(await page.locator('.map-node').count(),8,'original unsaved in-memory draft restored');
        assert.deepEqual(errors,[]);
        console.log('PASS: source-linked graph, literal hostile labels, knowledge legend, keyboard, exports, reflow, separate playground map, report return and existing-draft preservation.');
    } finally {await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
