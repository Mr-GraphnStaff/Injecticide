const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),http=require('node:http');
const root=path.resolve(__dirname,'../..'),run=process.env.AGENT_WORKING_DIR;
assert.ok(run,'Use the managed launcher');
let owner=root;while(!fs.existsSync(path.join(owner,'working/.agent-control/policy.json'))){const parent=path.dirname(owner);assert.notEqual(parent,owner);owner=parent;}
assert.ok(path.resolve(run).startsWith(path.join(owner,'working/runs')+path.sep));
const output=path.join(run,'reports/browser/export-filenames');fs.mkdirSync(output,{recursive:true});
const assets=path.join(owner,'working/cache/browser/scan-resource-regression');
const source=fs.readFileSync(path.join(root,'webapp/static/app.js'),'utf8');
const ctx={Date};vm.createContext(ctx);
vm.runInContext(source.slice(source.indexOf('function slugifyFilename('),source.indexOf('\n}',source.indexOf('function slugifyFilename('))+2)+
 source.slice(source.indexOf('function filenameTimestamp('),source.indexOf('/* ---- Shared helpers for fix items')),ctx);
const long='Enterprise Customer Architecture With A Very Long Shared Prefix '.repeat(20);
const options={name:long,kind:'diagram',ext:'png',buildInfo:{package_version:'0.17.0'}};
const first=ctx.injecticideFilename(options),second=ctx.injecticideFilename({...options,name:long+'different'});
assert.notEqual(first,second,'Different truncated names retain a distinguishing hint');
for(const name of [long,'../CON.secret: /invalid?name','é'.repeat(1000),'a'.repeat(10000)]){
 for(const ext of ['png','json','md','mmd','csv']){
  const value=ctx.injecticideFilename({...options,name,ext,kind:'report-organization-policy'.repeat(5),buildInfo:{package_version:'1'.repeat(200)}});
  assert.ok(value.length<=80,value);assert.match(value,/^[a-z0-9._-]+$/);assert.ok(value.endsWith('.'+ext));assert.ok(!value.startsWith('.'));
 }
}
assert.ok(ctx.scanDownloadName({filename:long+'.skill'}, {}, 'improvement-plan','md').length<=80);
const combined=['webapp/static/pages/Home.jsx','webapp/static/pages/ArchitectureCanvas.jsx','webapp/static/pages/MapPng.js','webapp/static/app.js'].map(name=>fs.readFileSync(path.join(root,name),'utf8')).join('\n');
const server=http.createServer((req,res)=>{
 if(req.url==='/'){res.setHeader('Content-Type','text/html');return res.end('<!doctype html><html lang="en"><meta charset="UTF-8"><body><div id="root"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script src="/babel.js"></script><script src="/fixture.js"></script></body></html>');}
 if(req.url==='/fixture.js'){res.setHeader('Content-Type','text/javascript');return res.end('eval(Babel.transform('+JSON.stringify(combined)+',{presets:["react"]}).code)');}
 if(['/react.js','/react-dom.js','/babel.js'].includes(req.url)){res.setHeader('Content-Type','text/javascript');return res.end(fs.readFileSync(path.join(assets,req.url.slice(1))));}
 if(req.url==='/static/images/daf-tech-sphere.png'){res.setHeader('Content-Type','image/png');return res.end(fs.readFileSync(path.join(root,'webapp',req.url)));}
 res.setHeader('Content-Type','application/json');res.end(JSON.stringify({categories:[],endpoints:[],payload_presets:[],items:[],collection:{},package_version:'0.17.0',app_version:'0.17.0'}));
});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const {chromium}=require('C:/Python312/Lib/site-packages/playwright/driver/package');
 const brave=path.join(process.env.LOCALAPPDATA,'BraveSoftware/Brave-Browser/Application/brave.exe');
 const browser=await chromium.launch({executablePath:brave,headless:true,downloadsPath:path.join(output,'downloads'),tracesDir:path.join(output,'traces')});
 try{
  const page=await browser.newPage({acceptDownloads:true});const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('http://127.0.0.1:'+server.address().port);
  await page.getByRole('button',{name:'Explore architecture',exact:true}).click();
  const title=long.slice(0,160);await page.getByLabel('System name',{exact:true}).fill(title);
  const names=[];
  for(const [button,ext] of [['Export PNG','png'],['Export map','json'],['Export AI diagram prompt (.md)','md']]){
   const pending=page.waitForEvent('download');await page.getByRole('button',{name:button,exact:true}).click();const download=await pending;
   const name=download.suggestedFilename();names.push(name);assert.ok(name.length<=80);assert.ok(name.endsWith('.'+ext));
   const bytes=fs.readFileSync(await download.path());
   if(ext==='png')assert.equal(bytes.subarray(0,8).toString('hex'),'89504e470d0a1a0a');
   if(ext==='json')assert.equal(JSON.parse(bytes.toString()).name,title,'Only the filename is shortened');
   if(ext==='md')assert.ok(bytes.toString().includes(title));
  }
  assert.equal(await page.getByLabel('System name',{exact:true}).inputValue(),title);assert.deepEqual(errors,[]);
  console.log(JSON.stringify({pass:true,filenameLimit:80,downloads:names,actualPng:true,contentsPreserved:true}));
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(e=>{console.error(e);process.exitCode=1;server.close();});
