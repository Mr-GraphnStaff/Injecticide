// Synthetic source data only. Run with Playwright on NODE_PATH and installed Edge.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {chromium} = require('playwright');
const root = path.resolve(__dirname, '../..');
const assets = path.join(root, 'tmp/scan-resource-regression');
const source = fs.readFileSync(path.join(root, 'webapp/static/pages/Home.jsx'), 'utf8');
const fixture = `function Fixture(){const [page,setPage]=React.useState('home');return page==='home'?<Home buildInfo={{display_version:'0.3.1'}} onLaunchConsole={()=>setPage('Testing console')} onLaunchArchitecture={()=>setPage('Architecture analysis')}/>:<h1>{page}</h1>} ReactDOM.render(<Fixture/>,document.getElementById('root'));`;
const server = http.createServer((req,res)=>{
    if(req.url==='/') {res.setHeader('Content-Type','text/html');return res.end('<meta charset="UTF-8"><link rel="stylesheet" href="/home.css"><style>body{margin:0}p,h1,h2,h3,dd{margin:0}.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}</style><div id="root"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script src="/babel.js"></script><script src="/fixture.js"></script>');}
    if(req.url==='/fixture.js') {res.setHeader('Content-Type','text/javascript');return res.end('eval(Babel.transform('+JSON.stringify(source+fixture)+',{presets:["react"]}).code)');}
    if(['/react.js','/react-dom.js','/babel.js'].includes(req.url)) {res.setHeader('Content-Type','text/javascript');return res.end(fs.readFileSync(path.join(assets,req.url.slice(1))));}
    if(req.url==='/home.css') {res.setHeader('Content-Type','text/css');return res.end(fs.readFileSync(path.join(root,'webapp/static/home.css')));}
    if(req.url==='/static/images/daf-tech-sphere.png') {res.setHeader('Content-Type','image/png');return res.end(fs.readFileSync(path.join(root,'webapp/static/images/daf-tech-sphere.png')));}
    res.statusCode=404;res.end();
});
(async()=>{
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    const browser = await chromium.launch({channel:'msedge',headless:true});
    try {
        const page=await browser.newPage({viewport:{width:1440,height:1100}});
        const errors=[];page.on('pageerror',error=>errors.push(error.message));
        await page.addInitScript(()=>{
            window.mode='good';window.fetches=0;
            const originalInterval=window.setInterval;
            window.setInterval=(fn,ms)=>originalInterval(fn,ms===60000?300:ms);
            window.fetch=async()=>{
                window.fetches++;
                if(window.mode==='failure')throw new Error('offline');
                if(window.mode==='unavailable')return new Response(JSON.stringify({available:false,feed_stale:true,items:[],collection:{}}));
                const data={available:true,feed_stale:false,items:[
                    {id:'release',kind:'release',title:'OpenAI Codex v1.2 · synthetic preview',source:'OpenAI Codex',url:'https://github.com/openai/codex/releases/tag/v1.2',date:'2026-10-20T10:00:00Z',date_label:'Published',preview:true},
                    {id:'change',kind:'source_change',title:'NIST AI RMF reference page changed',source:'NIST AI RMF',url:'https://www.nist.gov/itl/ai-risk-management-framework',date:'2026-10-20T09:00:00Z',date_label:'Observed'},
                    {id:'escape',kind:'release',title:'<img src=x onerror="window.injected=true">',source:'Synthetic escaping check',url:'https://github.com/openai/codex/releases/tag/test'},
                    {id:'unsafe',title:'UNSAFE LINK',url:'javascript:alert(1)'}
                ],collection:{worker_alive:true,collecting:false,last_cycle:'2026-10-20T10:00:00Z',source_count:24,retained_snapshots:37,sources_with_errors:1}};
                if(window.mode==='empty')data.items=[];
                return new Response(JSON.stringify(data));
            };
        });
        const url=`http://127.0.0.1:${server.address().port}`;
        await page.goto(url);
        await page.getByRole('status').filter({hasText:'Collector active'}).waitFor();
        assert.equal(await page.getByText('Another DAF-TECH Product',{exact:true}).count(),1);
        assert.equal(await page.getByText('Preview release',{exact:true}).count(),1);
        assert.equal(await page.getByText('UNSAFE LINK',{exact:true}).count(),0);
        assert.equal(await page.locator('.home-news-list img').count(),0);
        assert.equal(await page.evaluate(()=>window.injected),undefined);
        assert.equal(await page.getByText('Some sources could not be collected. Retained updates may still be shown.',{exact:true}).count(),1);
        await page.keyboard.press('Tab');
        assert.equal(await page.evaluate(()=>document.activeElement.textContent),'Skip to main content');
        await page.keyboard.press('Enter');
        assert.equal(await page.evaluate(()=>document.activeElement.id),'home-main');
        await page.locator('.home-brand').focus();
        await page.screenshot({path:path.join(root,'tmp/research-mcp-validation-20261020/home-desktop.png'),fullPage:true});
        await page.setViewportSize({width:375,height:850});
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
        await page.screenshot({path:path.join(root,'tmp/research-mcp-validation-20261020/home-mobile.png'),fullPage:true});
        await page.evaluate(()=>{window.mode='failure'});
        await page.getByRole('status').filter({hasText:'Showing saved updates'}).waitFor();
        assert.equal(await page.locator('.home-news-list li').count(),3);
        await page.evaluate(()=>{window.mode='empty'});
        await page.getByText('No recent releases or changed reference pages in the retained catalog yet.',{exact:true}).waitFor();
        await page.evaluate(()=>{window.mode='unavailable'});
        await page.getByRole('status').filter({hasText:'Research feed unavailable'}).waitFor();
        await page.getByRole('button',{name:'Open testing & scanning'}).click();
        await page.getByRole('heading',{name:'Testing console',exact:true}).waitFor();
        const fetches=await page.evaluate(()=>window.fetches);
        await page.waitForTimeout(700);
        assert.equal(await page.evaluate(()=>window.fetches),fetches);
        await page.goto(url);
        await page.getByRole('button',{name:'Explore architecture'}).click();
        await page.getByRole('heading',{name:'Architecture analysis',exact:true}).waitFor();
        assert.deepEqual(errors,[]);
        console.log('Home browser checks passed: branding, escaping, links, coverage, stale/empty/unavailable, mobile, focus, navigation and cleanup.');
    }finally{await browser.close();server.close();}
})().catch(error=>{console.error(error);server.close();process.exitCode=1;});
