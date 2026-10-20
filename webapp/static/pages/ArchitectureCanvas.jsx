/* User-declared maps only. No mapped address or vendor is contacted. */
const MAP_KINDS = {
    user:'Person / client', edge:'Edge / WAF', gateway:'AI gateway', model:'Model',
    agent:'Agent / orchestrator', mcp:'MCP server', tool:'Tool / API', skill:'Skill / plugin',
    retrieval:'Retrieval / RAG', memory:'Memory / vector store', code:'Code runner',
    data:'Data store', approval:'Human approval', security:'Security control', output:'Output / destination'
};
function mapNode(id,kind,label,x,y,trust='internal') {
    return {id,kind,label,x,y,trust,sensitivity:'unknown',controls:''};
}
function starterMap() {
    return {schema_version:1,name:'AI application with edge, model gateway and MCP',nodes:[
        mapNode('client','user','User',40,100,'external'),
        mapNode('edge','edge','Cloudflare edge',320,100),
        mapNode('agent','agent','Application / agent',600,100),
        mapNode('gateway','gateway','AI Gateway',880,100),
        mapNode('model','model','Model provider',1160,100),
        mapNode('mcp','mcp','MCP server',600,370,'privileged'),
        mapNode('business','tool','Business API',880,370,'privileged'),
        mapNode('rag','retrieval','Retrieved documents',320,370,'external')
    ],edges:[['client','edge'],['edge','agent'],['agent','gateway'],['gateway','model'],['agent','mcp'],['mcp','business'],['rag','agent']].map(([source,target],i)=>({id:'e'+i,source,target,untrusted:source==='client'||source==='rag',write:target==='business'}))};
}
function ArchitectureCanvas({onBack,onNavigate,buildInfo}) {
    const [map,setMap] = React.useState(starterMap);
    const [selected,setSelected] = React.useState('agent');
    const [source,setSource] = React.useState('agent');
    const [target,setTarget] = React.useState('mcp');
    const [zoom,setZoom] = React.useState(0.8);
    const [history,setHistory] = React.useState([]);
    const [future,setFuture] = React.useState([]);
    const [plan,setPlan] = React.useState(null);
    const [highlight,setHighlight] = React.useState(null);
    const [message,setMessage] = React.useState('');
    const [busy,setBusy] = React.useState(false);
    const [testPage,setTestPage] = React.useState(0);
    const file = React.useRef(null);
    const viewport = React.useRef(null);
    const drag = React.useRef(null);
    const request = React.useRef(null);
    const revision = React.useRef(0);
    React.useEffect(()=>()=>{revision.current++;if(request.current) request.current.abort();},[]);
    function commit(next) {
        revision.current++;
        if(request.current) request.current.abort();
        setBusy(false);setHistory(h=>[...h.slice(-29),map]);setFuture([]);setMap(next);setPlan(null);setHighlight(null);setTestPage(0);
    }
    function patchNode(patch) {commit({...map,nodes:map.nodes.map(n=>n.id===selected?{...n,...patch}:n)});}
    function move(id,x,y) {
        setMap(m=>({...m,nodes:m.nodes.map(n=>n.id===id?{...n,x:Math.max(0,Math.min(3000,x)),y:Math.max(0,Math.min(1800,y))}:n)}));
    }
    function invalidate() {revision.current++;if(request.current)request.current.abort();setBusy(false);setPlan(null);setHighlight(null);}
    function undo(redo=false) {
        const list=redo?future:history;if(!list.length)return;
        invalidate();setMap(list[list.length-1]);
        if(redo){setFuture(list.slice(0,-1));setHistory(h=>[...h,map]);}
        else{setHistory(list.slice(0,-1));setFuture(f=>[...f,map]);}
    }
    function add(kind) {
        if(map.nodes.length>=100){setMessage('Map limit: 100 components.');return;}
        const id='n'+crypto.randomUUID().replaceAll('-','');
        commit({...map,nodes:[...map.nodes,mapNode(id,kind,MAP_KINDS[kind],80+(map.nodes.length%5)*260,650)]});setSelected(id);
    }
    async function analyze() {
        if(request.current)request.current.abort();
        const controller=new AbortController();request.current=controller;
        const current=revision.current;setBusy(true);setMessage('');
        const timeout=setTimeout(()=>controller.abort(),15000);
        try {
            const response=await fetch('/api/architecture/plan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(map),signal:controller.signal});
            const data=await response.json();if(!response.ok)throw Error(typeof data.detail==='string'?data.detail:'Map rejected');
            if(current===revision.current){setPlan(data);setTestPage(0);setMessage('Test plan ready. No live tests have run.');}
        } catch(error) {if(current===revision.current)setMessage(error.name==='AbortError'?'Planning cancelled or timed out.':error.message);}
        finally {clearTimeout(timeout);if(request.current===controller){request.current=null;setBusy(false);}}
    }
    function download(value,name) {
        const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:'application/json'}));
        const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    }
    async function validateAndLoad(value) {
        const serialized=JSON.stringify(value);
        if(new Blob([serialized]).size>262144)throw Error('Map exceeds 256 KiB');
        if(request.current)request.current.abort();
        const controller=new AbortController();request.current=controller;
        const current=revision.current;const timeout=setTimeout(()=>controller.abort(),15000);
        try {
            const response=await fetch('/api/architecture/plan',{method:'POST',headers:{'Content-Type':'application/json'},body:serialized,signal:controller.signal});
            const result=await response.json();if(!response.ok)throw Error(typeof result.detail==='string'?result.detail:'Invalid map');
            if(request.current!==controller||current!==revision.current)return;
            commit(value);setSelected(value.nodes[0]?.id||'');setMessage('Map loaded. Generate a fresh plan after editing.');
        } finally {clearTimeout(timeout);if(request.current===controller)request.current=null;}
    }
    async function importFile(event) {
        try {const f=event.target.files[0];if(!f)return;if(f.size>262144)throw Error('Map exceeds 256 KiB');await validateAndLoad(JSON.parse(await f.text()));}
        catch(error){setMessage(error.message);}finally{event.target.value='';}
    }
    const node=map.nodes.find(n=>n.id===selected);
    const connected = map.edges.filter(e=>e.source===selected||e.target===selected);
    return <div className="injecticide-home injecticide-workbench">
        <ProductHeader section="architecture" buildInfo={buildInfo} onBack={onBack} onNavigate={onNavigate}/>
        <main className="home-shell map-main">
            <div className="map-heading"><div><p className="home-eyebrow">MAP → TEST → EVIDENCE</p><h1>AI architecture playground</h1><p>Map the system. Find what to test and why.</p></div><span className="map-tag">Modeled · controls unverified</span></div>
            <div className="map-toolbar" aria-label="Map actions">
                <button onClick={()=>{commit(starterMap());setSelected('agent');}}>Starter map</button>
                <button onClick={()=>commit({schema_version:1,name:'Untitled system',nodes:[],edges:[]})}>New map</button>
                <button disabled={!history.length} onClick={()=>undo()}>Undo</button><button disabled={!future.length} onClick={()=>undo(true)}>Redo</button>
                <button onClick={()=>{try{localStorage.setItem('injecticide-map-v1',JSON.stringify(map));setMessage('Saved in this browser.');}catch(e){setMessage('Browser storage unavailable. Export the map instead.');}}}>Save locally</button>
                <button onClick={async()=>{try{const text=localStorage.getItem('injecticide-map-v1');if(!text)throw Error('No saved map in this browser.');await validateAndLoad(JSON.parse(text));}catch(e){setMessage(e.message);}}}>Load saved</button>
                <button onClick={()=>download(map,'injecticide-map.json')}>Export map</button><button onClick={()=>file.current.click()}>Import map</button>
                <input type="file" accept=".json,application/json" ref={file} onChange={importFile} hidden/>
                <button className="home-button-primary" disabled={busy} onClick={analyze}>{busy?'Planning…':'Generate test plan'}</button>
            </div>
            <p role="status" className="map-status">{message||'Maps contain architecture details. Save locally or export deliberately; keep credentials out of labels and control notes.'}</p>
            <label className="map-name">System name<input maxLength="160" value={map.name} onChange={e=>commit({...map,name:e.target.value})}/></label>
            <div className="map-layout">
                <aside className="map-panel map-palette"><h2>Add component</h2><p>Choose a component, then move it on the map.</p>{Object.entries(MAP_KINDS).map(([kind,label])=><button key={kind} onClick={()=>add(kind)}>＋ {label}</button>)}</aside>
                <section className="map-panel map-workspace" aria-label="Architecture canvas">
                    <div className="map-toolbar"><button aria-label="Zoom out" onClick={()=>setZoom(z=>Math.max(.3,z-.1))}>−</button><span>{Math.round(zoom*100)}%</span><button aria-label="Zoom in" onClick={()=>setZoom(z=>Math.min(1.5,z+.1))}>＋</button><button onClick={()=>{const width=Math.max(500,...map.nodes.map(n=>n.x+250));setZoom(Math.max(.15,Math.min(1,viewport.current.clientWidth/width)));viewport.current.scrollTo(0,0);}}>Fit map</button><span>Scroll to pan · select a card to edit · arrow keys move cards</span></div>
                    <div className="map-scroll" ref={viewport} tabIndex="0" aria-label="Scrollable system map"><div style={{width:3260*zoom,height:2040*zoom}}><div className="map-surface" style={{transform:`scale(${zoom})`}}>
                        <svg width="3260" height="2040" aria-hidden="true"><defs><marker id="map-arrow" markerWidth="10" markerHeight="8" refX="9" refY="4" orient="auto"><path d="M0 0 L10 4 L0 8" fill="#86cfc2"/></marker></defs>{map.edges.map(e=>{const a=map.nodes.find(n=>n.id===e.source),b=map.nodes.find(n=>n.id===e.target);if(!a||!b)return null;return <path key={e.id} className={highlight?.edge_ids.includes(e.id)?'map-edge active':'map-edge'} d={`M${a.x+220} ${a.y+50} C${a.x+275} ${a.y+50},${b.x-55} ${b.y+50},${b.x} ${b.y+50}`} markerEnd="url(#map-arrow)"/>;})}</svg>
                        {map.nodes.map(n=><button key={n.id} className={`map-node ${n.id===selected?'selected':''} ${highlight?.node_ids.includes(n.id)?'highlighted':''}`} style={{left:n.x,top:n.y}} aria-label={`${n.label}, ${MAP_KINDS[n.kind]}. Arrow keys to move.`}
                            onClick={()=>setSelected(n.id)}
                            onKeyDown={e=>{const delta={ArrowLeft:[-20,0],ArrowRight:[20,0],ArrowUp:[0,-20],ArrowDown:[0,20]}[e.key];if(delta){e.preventDefault();commit({...map,nodes:map.nodes.map(v=>v.id===n.id?{...v,x:Math.max(0,Math.min(3000,v.x+delta[0])),y:Math.max(0,Math.min(1800,v.y+delta[1]))}:v)});}}}
                            onPointerDown={e=>{if(e.button!==0)return;setSelected(n.id);e.currentTarget.setPointerCapture(e.pointerId);drag.current={id:n.id,x:n.x,y:n.y,cx:e.clientX,cy:e.clientY,before:map,moved:false};}}
                            onPointerMove={e=>{const d=drag.current;if(!d||d.id!==n.id)return;if(!d.moved&&Math.hypot(e.clientX-d.cx,e.clientY-d.cy)<4)return;if(!d.moved){invalidate();d.moved=true;}move(n.id,d.x+(e.clientX-d.cx)/zoom,d.y+(e.clientY-d.cy)/zoom);}}
                            onLostPointerCapture={()=>{const d=drag.current;if(d?.moved){setHistory(h=>[...h.slice(-29),d.before]);setFuture([]);}drag.current=null;}}
                            onPointerUp={e=>{if(e.currentTarget.hasPointerCapture(e.pointerId))e.currentTarget.releasePointerCapture(e.pointerId);}}>
                            <span>{MAP_KINDS[n.kind]}</span><strong>{n.label||'Unnamed component'}</strong><small>{n.trust} · {n.sensitivity}</small>
                        </button>)}
                    </div></div></div>
                </section>
                <aside className="map-panel map-inspector"><h2>Component details</h2>{node?<>
                    <label>Name<input maxLength="160" value={node.label} onChange={e=>patchNode({label:e.target.value})}/></label>
                    <label>Trust<select value={node.trust} onChange={e=>patchNode({trust:e.target.value})}>{['external','internal','privileged','unknown'].map(v=><option key={v}>{v}</option>)}</select></label>
                    <label>Data sensitivity<select value={node.sensitivity} onChange={e=>patchNode({sensitivity:e.target.value})}>{['public','internal','sensitive','unknown'].map(v=><option key={v}>{v}</option>)}</select></label>
                    <label>Declared controls<textarea maxLength="1000" value={node.controls} onChange={e=>patchNode({controls:e.target.value})}/></label><p>Notes describe intended controls. Enforcement needs test evidence.</p>
                    <button onClick={()=>{commit({...map,nodes:map.nodes.filter(n=>n.id!==selected),edges:map.edges.filter(e=>e.source!==selected&&e.target!==selected)});setSelected('');}}>Remove component</button>
                </>:<p>Select a component to edit it.</p>}
                <h2>Connect components</h2><label htmlFor="map-from">From</label><select id="map-from" value={source} onChange={e=>setSource(e.target.value)}><option value="">Choose…</option>{map.nodes.map(n=><option key={n.id} value={n.id}>{n.label}</option>)}</select>
                <label htmlFor="map-to">To</label><select id="map-to" value={target} onChange={e=>setTarget(e.target.value)}><option value="">Choose…</option>{map.nodes.map(n=><option key={n.id} value={n.id}>{n.label}</option>)}</select>
                <button onClick={()=>{if(!map.nodes.some(n=>n.id===source)||!map.nodes.some(n=>n.id===target)){setMessage('Choose two existing components.');return;}if(map.edges.length>=200){setMessage('Map limit: 200 connections.');return;}commit({...map,edges:[...map.edges,{id:'e'+crypto.randomUUID().replaceAll('-',''),source,target,untrusted:false,write:false}]});}}>Add directed connection</button>
                <h3>Selected component connections</h3>{connected.map(e=><div className="map-connection" key={e.id}><p>{map.nodes.find(n=>n.id===e.source)?.label} → {map.nodes.find(n=>n.id===e.target)?.label}</p>{[['untrusted','Untrusted content'],['write','Allows writes']].map(([key,label])=><label key={key}><input type="checkbox" checked={e[key]} onChange={event=>commit({...map,edges:map.edges.map(v=>v.id===e.id?{...v,[key]:event.target.checked}:v)})}/>{label}</label>)}<button onClick={()=>commit({...map,edges:map.edges.filter(v=>v.id!==e.id)})}>Remove connection</button></div>)}
                </aside>
            </div>
            <section className="map-results map-panel"><div className="map-heading"><div><p className="home-eyebrow">YOUR MAP → YOUR TEST PLAN</p><h2>{plan?`${plan.tests.length} suggested tests`:'Ready to find what needs testing?'}</h2></div>{plan&&<button onClick={()=>download({map,plan},'injecticide-test-plan.json')}>Export test plan</button>}</div>
                <p>{plan?plan.limitations:'Generate a plan to identify applicable tests, their exact component paths and the evidence to collect. Drawing a map does not execute requests.'}</p>
                {plan&&<><p className="map-hash">Planner {plan.planner_version} · Map SHA-256: {plan.map_hash}</p><div className="map-test-list">{plan.tests.slice(testPage*20,(testPage+1)*20).map(test=><article key={test.id} className="map-test"><span className="map-tag">Not run</span><h3>{test.title}</h3><p>{test.reason}</p><p><strong>Path:</strong> {test.node_ids.map(id=>map.nodes.find(n=>n.id===id)?.label||id).join(' → ')}</p><p><strong>Collect:</strong> {test.expected_evidence}</p><p><strong>Suggested method:</strong> {test.suggested_engine}</p><div className="map-toolbar"><button onClick={()=>setHighlight(test)}>Highlight on map</button><a href={test.reference} target="_blank" rel="noopener noreferrer">Reference ↗</a></div></article>)}</div><p>{plan.omitted_tests>0?`${plan.omitted_tests} additional suggestions omitted by the 500-test budget. Narrow the map for fuller coverage.`:''}</p><div className="map-toolbar"><button disabled={testPage===0} onClick={()=>setTestPage(p=>p-1)}>Previous tests</button><span>Page {testPage+1} of {Math.max(1,Math.ceil(plan.tests.length/20))}</span><button disabled={(testPage+1)*20>=plan.tests.length} onClick={()=>setTestPage(p=>p+1)}>Next tests</button></div>{!plan.tests.length&&<p>No planning rules matched this map. This does not establish safety or coverage.</p>}</>}
            </section>
            <section className="map-panel map-examples"><button onClick={()=>onNavigate('scenarios')}>Open built-in scenario explorer</button></section>
        </main><ProductFooter/>
    </div>;
}
