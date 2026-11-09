const assert=require('node:assert/strict');
const fs=require('node:fs');const path=require('node:path');const crypto=require('node:crypto');
const root=path.resolve(__dirname,'../..');const run=process.env.AGENT_WORKING_DIR;assert.ok(run);
let owner=root;while(!fs.existsSync(path.join(owner,'working','.agent-control','policy.json'))){const p=path.dirname(owner);assert.notEqual(p,owner);owner=p;}
const rel=path.relative(path.join(owner,'working','runs'),run);assert.ok(rel&&!rel.startsWith('..')&&!path.isAbsolute(rel));
const output=path.join(run,'reports','browser','real-package-uat');fs.mkdirSync(output,{recursive:true});
const args=process.argv.slice(2);const option=name=>args[args.indexOf(name)+1];
const archive=option('--archive'),entry=option('--entry');assert.ok(archive&&entry&&fs.existsSync(archive)&&fs.existsSync(entry));
const hash=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const before={[archive]:hash(archive),[entry]:hash(entry)};
const cache=path.join(owner,'working','cache','browser');const candidates=[path.join(cache,'node_modules','playwright'),'C:/Python312/Lib/site-packages/playwright/driver/package'];
const {chromium}=require(candidates.find(p=>fs.existsSync(path.join(p,'package.json'))));
const executable=path.join(process.env.LOCALAPPDATA,'BraveSoftware','Brave-Browser','Application','brave.exe');
(async()=>{
 const browser=await chromium.launch({executablePath:executable,headless:true,downloadsPath:path.join(output,'downloads'),tracesDir:path.join(output,'traces')});
 const cases=[],errors=[];let publicAccess;
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1100},acceptDownloads:true});page.on('pageerror',e=>errors.push(e.message));
  await page.route('https://unpkg.com/**',route=>{
   const url=route.request().url();const name=url.includes('react-dom@')?'react-dom.js':url.includes('/react@')?'react.js':url.includes('@babel/standalone@')?'babel.js':null;
   if(name)return route.fulfill({path:path.join(cache,'scan-resource-regression',name),contentType:'application/javascript; charset=utf-8'});
   return route.continue();
  });
  if(!args.includes('--skip-public')) try {
   const response=await page.goto('https://injecticide.daf-tech.com',{waitUntil:'domcontentloaded',timeout:25000});
   publicAccess={status:response?.status(),url:page.url()};
   if(response?.ok()) {
    await page.getByRole('button',{name:'Testing & scanning',exact:true}).first().click({timeout:15000});
    await page.getByRole('checkbox',{name:'Use local LLM',exact:true}).waitFor({timeout:15000});
    publicAccess.newControlVisible=true;
   }
  } catch(e){publicAccess={...publicAccess,error:e.message.split('\n')[0],newControlVisible:false};}
  if(args.includes('--skip-public')) publicAccess={previousReadOnlyCheck:'timed_out_in_fresh_profile'};
  const base='http://192.168.50.193:8000';
  await page.route('**/api/skills/scan',route=>new URL(route.request().url()).hostname==='192.168.50.193'?route.continue():route.abort());
  await page.goto(base,{waitUntil:'domcontentloaded',timeout:30000});await page.getByRole('button',{name:'Testing & scanning',exact:true}).first().click();
  const toggle=page.getByRole('checkbox',{name:'Use local LLM',exact:true});await toggle.waitFor();
  assert.equal(await page.getByRole('button',{name:'Close App',exact:true}).count(),0);
  console.log('LIVE_BROWSER_TARGET',JSON.stringify({base,publicAccess,browser:'Brave',version:browser.version()}));
  async function scan(id,file,enabled,alias=false){
   if(args.includes('--only')&&option('--only')!==id)return;
   await toggle.setChecked(enabled);
   if(alias)await page.getByLabel('Skill file',{exact:true}).setInputFiles({name:'original.skill',mimeType:'application/zip',buffer:fs.readFileSync(file)});
   else await page.getByLabel('Skill file',{exact:true}).setInputFiles(file);
   const start=Date.now();const pending=page.waitForResponse(r=>(r.url().endsWith('/api/skills/scan')&&r.request().method()==='POST'&&r.status()!==202)||(r.url().includes('/api/skills/scan/jobs/')&&r.request().method()==='GET'&&r.status()===200),{timeout:270000}).then(response=>({response}),error=>({error}));
   const submission=page.waitForResponse(r=>r.url().endsWith('/api/skills/scan')&&r.request().method()==='POST',{timeout:30000});
   console.log('REAL_SCAN_START',JSON.stringify({id,enabled,buttonEnabled:await page.locator('#skill-scan').getByRole('button',{name:/Scan Skill File\/Bundle/}).isEnabled()}));
   await page.locator('#skill-scan').getByRole('button',{name:/Scan Skill File\/Bundle/}).click({timeout:20000});const accepted=await submission;const submissionSeconds=(Date.now()-start)/1000;assert.equal(accepted.status(),202);console.log('REAL_JOB_ACCEPTED',JSON.stringify({id,submissionSeconds}));const received=await pending;if(received.error)throw received.error;const response=received.response;
   const receivedBody=await response.json();const report=receivedBody.status==='completed'?receivedBody.result:receivedBody;const completedSeconds=(Date.now()-start)/1000;fs.writeFileSync(path.join(output,id+'.json'),JSON.stringify(report,null,2));
   const local=report.local_analysis;const result={id,file:path.basename(file),filenameAlias:alias?'original.skill':null,enabled,status:response.status(),elapsedSeconds:completedSeconds,submissionSeconds,localStatus:local?.status,observations:local?.findings?.length,selectedFiles:local?.coverage?.selected_files,omittedFiles:local?.coverage?.omitted_or_clipped_files};
   cases.push(result);console.log('REAL_PACKAGE_SCAN',JSON.stringify(result));assert.equal(response.status(),200,JSON.stringify(report.detail));
   await page.locator('[data-local-ai-results]').waitFor({timeout:15000});
   if(!enabled)assert.equal(local.status,'skipped');else assert.ok(['completed','partial'].includes(local?.status),'Local analysis failed: '+JSON.stringify({status:local?.status,errorType:local?.error_type}));
   const jsonPending=page.waitForEvent('download');await page.getByRole('button',{name:'Download full data (JSON)',exact:true}).click();const downloaded=JSON.parse(fs.readFileSync(await(await jsonPending).path(),'utf8'));assert.equal(downloaded.result.local_analysis.status,local.status);
   const mdPending=page.waitForEvent('download');await page.getByRole('button',{name:/Export Summary$/}).click();const markdown=fs.readFileSync(await(await mdPending).path(),'utf8');assert.match(markdown,/## Local AI analysis/);
   await page.screenshot({path:path.join(output,id+'.png'),fullPage:true});
  }
  await scan('entry-static',entry,false);
  await scan('entry-local-ai',entry,true);
  await scan('zip-static',archive,false);
  await scan('zip-local-ai',archive,true);
  await scan('skill-format-local-ai',archive,true,true);
  for(const [file,digest]of Object.entries(before))assert.equal(hash(file),digest,'Original input changed');
  assert.deepEqual(errors,[]);
  fs.writeFileSync(path.join(output,'receipt.json'),JSON.stringify({pass:true,base,publicAccess,browser:'Brave',cases,originalHashes:before,originalsUnchanged:true},null,2));
  console.log('PASS_REAL_PACKAGE_UAT',output);
 }finally{
  for(const [file,digest]of Object.entries(before))assert.equal(hash(file),digest,'Original input changed');
  fs.writeFileSync(path.join(output,'progress.json'),JSON.stringify({publicAccess,cases,errors,originalHashes:before},null,2));
  await browser.close();
 }
})().catch(e=>{console.error(e);process.exitCode=1;});
