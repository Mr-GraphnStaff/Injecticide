const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const root = path.resolve(__dirname, '../..');
const run = process.env.AGENT_WORKING_DIR;
assert.ok(run, 'Use the owner working-area launcher');
let owner = root;
while (!fs.existsSync(path.join(owner,'working','.agent-control','policy.json'))) {
    const parent=path.dirname(owner); assert.notEqual(parent,owner); owner=parent;
}
const relative=path.relative(path.join(owner,'working','runs'),run);
assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
const output=path.join(run,'reports','browser','local-model-controls');fs.mkdirSync(output,{recursive:true});
const cache=path.join(owner,'working','cache','browser');
const assets=path.join(cache,'scan-resource-regression');
const candidates=[path.join(cache,'node_modules','playwright'),'C:/Python312/Lib/site-packages/playwright/driver/package'];
const modulePath=candidates.find(p=>fs.existsSync(path.join(p,'package.json')));assert.ok(modulePath);
const {chromium}=require(modulePath);
const brave=path.join(process.env.LOCALAPPDATA,'BraveSoftware','Brave-Browser','Application','brave.exe');assert.ok(fs.existsSync(brave));
const source=fs.readFileSync(path.join(root,'webapp/static/app.js'),'utf8').replace('ReactDOM.render(<Root />,','ReactDOM.render(<App />,');
const hostile='<img src=x onerror="window.localModelInjected=true"> [unsafe](javascript:alert(1))';
let mode='completed';const selections=[];const jobs=new Map();let transientPolls=0;let totalPolls=0;let bodyDropSent=false;
function report(selected) {
    return {filename:'fixture.skill',file_type:'skill',summary:{total_files:1,flagged_files:0,total_findings:0,info_findings:0},warnings:[],
        coverage:{status:'partial',analyzed_files:1,total_files:1},readiness:{status:'needs_review'},
        policy_evaluation:{status:'none',rules:[],errors:[]},
        files:[{path:'SKILL.md',size:20,findings:[],assessment_state:'text_analyzed',artifact_role:'active'}],
        local_analysis:!selected?{status:'skipped',reason:'Not requested for this scan',findings:[]}:
            mode==='error'?{status:'error',reason:'Local model analysis unavailable or invalid',findings:[]}:
            {status:mode,model:'qwen3.5:2b',duration_seconds:19.4,coverage:{selected_files:1,omitted_or_clipped_files:mode==='partial'?2:0},
             findings:[{path:'SKILL.md',category:'data_exfiltration',severity:'medium',detail:hostile,evidence_excerpt:'literal evidence '+hostile}],advisory_only:true}};
}
const server=http.createServer((req,res)=>{
    if(req.url==='/'){res.setHeader('Content-Type','text/html');return res.end('<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/home.css"></head><body><div id="root"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script src="/babel.js"></script><script src="/fixture.js"></script></body></html>');}
    if(req.url==='/fixture.js'){res.setHeader('Content-Type','text/javascript; charset=utf-8');return res.end('eval(Babel.transform('+JSON.stringify(source)+',{presets:["react"]}).code)');}
    if(req.url==='/home.css'){res.setHeader('Content-Type','text/css');return res.end(fs.readFileSync(path.join(root,'webapp/static/home.css')));}
    if(['/react.js','/react-dom.js','/babel.js'].includes(req.url)){res.setHeader('Content-Type','text/javascript; charset=utf-8');return res.end(fs.readFileSync(path.join(assets,req.url.slice(1))));}
    if(req.url==='/api/skills/scan'){
        let raw='';req.on('data',chunk=>raw+=chunk);req.on('end',()=>{
            assert.ok(/name="background"\r\n\r\ntrue/.test(raw));
            const selected=/name="use_local_llm"\r\n\r\ntrue/.test(raw);selections.push(selected);
            const id=require('node:crypto').randomBytes(16).toString('hex');
            jobs.set(id,{result:report(selected),mode,polls:0});
            res.writeHead(202,{'Content-Type':'application/json'});
            res.end(JSON.stringify({job_id:id,status_url:'https://not-allowed.example/receipt',scan_request_id:'fixture-1'}));
        });return;
    }
    if(req.url.startsWith('/api/skills/scan/jobs/')){
        const job=jobs.get(req.url.split('/').at(-1));assert.ok(job);job.polls++;totalPolls++;
        res.setHeader('Content-Type','application/json');
        if(!transientPolls++){res.statusCode=503;return res.end('{}');}
        if(!bodyDropSent){bodyDropSent=true;res.flushHeaders();res.write('{"status":');setTimeout(()=>res.destroy(),20);return;}
        if(job.mode==='server-failed')return res.end(JSON.stringify({status:'failed',http_status:502,detail:{message:'Fixture analysis failed',stage:'sandbox',request_id:'fixture-1'}}));
        if(job.polls<2||job.mode==='slow'){res.statusCode=202;return res.end('{"status":"running"}');}
        return res.end(JSON.stringify({status:'completed',result:job.result}));
    }
    res.setHeader('Content-Type','application/json');res.end(JSON.stringify({categories:[],endpoints:[],payload_presets:[]}));
});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const browser=await chromium.launch({executablePath:brave,headless:true,downloadsPath:path.join(output,'downloads'),tracesDir:path.join(output,'traces')});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1100},acceptDownloads:true});const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('http://127.0.0.1:'+server.address().port);
  const toggle=page.getByRole('checkbox',{name:'Use local LLM',exact:true});await toggle.waitFor();assert.equal(await toggle.isChecked(),true);
  assert.equal(await page.getByRole('button',{name:'Close App',exact:true}).count(),0);
  async function scan(){await page.getByLabel('Skill file',{exact:true}).setInputFiles({name:'fixture.skill',mimeType:'text/markdown',buffer:Buffer.from('inert fixture')});await page.getByRole('button',{name:'Scan Skill File/Bundle',exact:true}).click();assert.equal(await toggle.isDisabled(),true);await page.locator('[data-local-ai-results]').waitFor();}
  await scan();const card=page.locator('[data-local-ai-results]');assert.match(await card.innerText(),/Completed.*limited text review/s);assert.ok((await card.innerText()).includes(hostile));assert.equal(await page.evaluate(()=>Boolean(window.localModelInjected)),false);
  const downloadPromise=page.waitForEvent('download');await page.getByRole('button',{name:'Export Summary',exact:true}).click();const download=await downloadPromise;const markdown=fs.readFileSync(await download.path(),'utf8');
  assert.match(markdown,/## Local AI analysis/);assert.ok(!markdown.includes('<img src=x'));assert.ok(markdown.includes('&lt;img'));
  await page.screenshot({path:path.join(output,'brave-local-ai-results.png'),fullPage:true});
  for(const width of [390,1440]){await page.setViewportSize({width,height:1100});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'No horizontal overflow at '+width);}
  await toggle.uncheck();await scan();assert.match(await card.innerText(),/Not requested for this scan/);assert.equal(selections.at(-1),false);
  await toggle.check();mode='partial';await scan();assert.match(await card.innerText(),/Partially checked/);assert.match(await card.innerText(),/omitted or shortened: 2/);
  mode='error';await scan();assert.match(await card.innerText(),/Analysis unavailable/);assert.ok(!(await card.innerText()).includes('No evidence-backed observations were returned'));
  mode='server-failed';await page.getByLabel('Skill file',{exact:true}).setInputFiles({name:'fixture.skill',mimeType:'text/markdown',buffer:Buffer.from('inert fixture')});
  await page.getByRole('button',{name:'Scan Skill File/Bundle',exact:true}).click();
  await page.getByText(/Fixture analysis failed.*Stage: sandbox/).waitFor();
  mode='slow';await page.getByRole('button',{name:'Scan Skill File/Bundle',exact:true}).click();
  await page.getByRole('button',{name:'Stop waiting and clear',exact:true}).waitFor();
  await page.getByRole('button',{name:'Stop waiting and clear',exact:true}).click();
  await page.waitForTimeout(1700);const stoppedPolls=totalPolls;
  await page.waitForTimeout(1700);assert.equal(totalPolls,stoppedPolls,'Clearing must stop polling');
  assert.deepEqual(errors,[]);assert.deepEqual(selections,[true,false,true,true,true,true]);
  assert.ok(transientPolls>0);assert.equal(bodyDropSent,true);
  console.log(JSON.stringify({pass:true,browser:'Brave',executable:brave,version:browser.version(),selections,screenshot:path.join(output,'brave-local-ai-results.png')}));
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;server.close();});
