// Real local FastAPI upload -> static scan -> diagram -> new playground map.
// Run a candidate API with external research/sandbox origins unset; synthetic input only.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {chromium} = require('playwright');
const root = path.resolve(__dirname, '../..');
const base = process.env.INJECTICIDE_TEST_URL || 'http://127.0.0.1:8241';
const fixture = execFileSync('python', ['-c', [
    'import io,sys,zipfile',
    'b=io.BytesIO()',
    "z=zipfile.ZipFile(b,'w')",
    "z.writestr('review/SKILL.md', '---\\nname: review\\ndescription: Read a local input and prepare a report\\n---\\n# Process\\n1. Read [input](references/input.md).\\n2. Run `python scripts/review.py` to prepare the local report.\\n3. Ask for approval before sharing the report.\\n'.replace('\\n',chr(10)))",
    "z.writestr('review/references/input.md','Synthetic sample input. No customer content.')",
    "z.writestr('review/scripts/review.py', 'from pathlib import Path\\ntext = Path(\"references/input.md\").read_text()\\nPath(\"report.txt\").write_text(text)\\n'.replace('\\n',chr(10)))",
    'z.close()', 'sys.stdout.buffer.write(b.getvalue())'
].join(';')], {cwd:root});
(async()=>{
    const browser=await chromium.launch({channel:'msedge',headless:true});
    try {
        const page=await browser.newPage({viewport:{width:1600,height:1100},acceptDownloads:true});
        const errors=[];page.on('pageerror',error=>errors.push(error.message));
        await page.route('https://unpkg.com/**',route=>route.fulfill({
            path:path.join(root,'tmp/scan-resource-regression',route.request().url().includes('react-dom')?'react-dom.js':route.request().url().includes('@babel')?'babel.js':'react.js'),contentType:'text/javascript'}));
        // Keep this acceptance test local; optional presentation CDNs are unnecessary.
        await page.route('https://cdn.tailwindcss.com/**',route=>route.fulfill({contentType:'text/javascript',body:''}));
        await page.route('https://cdnjs.cloudflare.com/**',route=>route.fulfill({contentType:'text/css',body:''}));
        await page.goto(base);
        await page.getByRole('button',{name:'Open testing & scanning',exact:false}).click();
        await page.getByLabel('Skill file',{exact:true}).setInputFiles({name:'local-review.skill',mimeType:'application/zip',buffer:fixture});
        const scanResponse=page.waitForResponse(response=>response.url().endsWith('/api/skills/scan'));
        await page.getByRole('button',{name:'Scan Skill File/Bundle',exact:true}).click();
        const response=await scanResponse;assert.equal(response.status(),200);
        const report=await response.json();
        assert.equal(report.scanner_metadata.scanner_version,'0.14.0');
        assert.ok(report.documented_process.steps.length>=3);
        const diagram=report.process_diagram;
        assert.ok(diagram.nodes.some(node=>node.kind==='step'&&node.step_type==='approval_mention'));
        assert.equal(diagram.runtime_verified,false);
        assert.ok(diagram.edges.some(edge=>edge.kind==='documented_order'));
        assert.equal(report.improvement_plan.schema_version,1);
        assert.ok(report.improvement_plan.items.some(item=>item.status==='not_assessed'));
        assert.equal(report.token_footprint.skills[0].path,'review/SKILL.md');
        await page.getByRole('tab',{name:'Token usage',exact:true}).click();
        assert.match(await page.getByRole('tabpanel').innerText(),/Exact tokens: not measured/);
        const improvementDownload=page.waitForEvent('download');
        await page.getByRole('button',{name:'Export improvement plan (.md)',exact:true}).click();
        const improvementMarkdown=fs.readFileSync(await(await improvementDownload).path(),'utf8');
        const improvementItems=[...improvementMarkdown.matchAll(/```json\n([\s\S]*?)\n```/g)].map(match=>JSON.parse(match[1]));
        for(const item of report.improvement_plan.items)assert.deepEqual(improvementItems.find(value=>value.id===item.id),item,'download preserves actual API plan item');
        assert.ok(improvementMarkdown.includes(report.improvement_plan.artifact_sha256));
        assert.ok(improvementMarkdown.includes(report.improvement_plan.priority_policy));
        await page.getByRole('tab',{name:'Structure & process',exact:true}).click();
        const panel=page.locator('[data-process-diagram]');await panel.waitFor();
        assert.equal(await panel.locator('.process-node').count(),diagram.nodes.length);
        await panel.getByRole('button',{name:'Add process diagram to playground',exact:true}).click();
        await page.getByRole('heading',{name:'New skill process map',exact:true}).waitFor();
        assert.equal(await page.locator('.map-node').count(),diagram.nodes.length);
        const planResponse=page.waitForResponse(response=>response.url().endsWith('/api/architecture/plan'));
        await page.getByRole('button',{name:'Generate test plan',exact:true}).click();
        assert.equal((await planResponse).status(),200);
        await page.getByText('Test plan ready. No live tests have run.',{exact:true}).waitFor();
        await page.screenshot({path:path.join(root,'tmp/skill-process-api-playground.png'),fullPage:true});
        await page.getByRole('button',{name:'Return to scan report',exact:true}).click();
        await page.locator('[data-process-diagram]').waitFor();
        assert.equal(await page.getByRole('tab',{name:'Structure & process',exact:true}).getAttribute('aria-selected'),'true');
        assert.equal(await panel.getByRole('button',{name:'Add process diagram to playground',exact:true}).evaluate(element=>element===document.activeElement),true);
        assert.deepEqual(errors,[]);
        fs.writeFileSync(path.join(root,'tmp/skill-process-api-evidence.json'),JSON.stringify({
            status:'PASS',scope:'Local actual API, synthetic bytes; not production acceptance or uploaded-code execution',
            files:report.summary.total_files,steps:report.documented_process.steps.length,nodes:diagram.nodes.length,edges:diagram.edges.length,
            artifact_sha256:diagram.artifact_sha256,scanner:report.scanner_metadata,
            improvement_items:report.improvement_plan.items.length,improvement_download_matches_api:true,token_footprint_available:true
        },null,2));
        console.log('PASS: actual local multipart upload, scan diagram, separate map, real planning API and return to report.');
    } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
