const {chromium}=require(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES ? process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES+'/playwright' : 'playwright');
const fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
const root=path.resolve(__dirname,'..');
const server=http.createServer((req,res)=>{const name=decodeURIComponent(new URL(req.url,'http://localhost').pathname);const file=path.resolve(root,'.'+name);if(!file.startsWith(root+'/')){res.writeHead(403).end();return;}fs.readFile(file,(err,data)=>{if(err){res.writeHead(404).end();return;}res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.png')?'image/png':'text/html');res.end(data);});});
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;
 const browser=await chromium.launch({executablePath:process.env.VULNWATCH_CHROMIUM_EXECUTABLE || undefined,headless:true,args:['--no-sandbox','--disable-gpu','--disable-dev-shm-usage']});
 const context=await browser.newContext({viewport:{width:430,height:950},acceptDownloads:true});
 await context.route('https://api.osv.dev/**',async route=>{
   if(route.request().method()==='OPTIONS'){await route.fulfill({status:204,headers:{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*'}});return;}
   const body=route.request().postDataJSON();assert.deepEqual(Object.keys(body).sort(),['package','version']);
   await route.fulfill({json:{vulns:[{id:'GHSA-example-test-case',aliases:['CVE-2020-11022'],summary:'Example advisory for UI verification',database_specific:{severity:'HIGH'},affected:[{package:{name:'jquery',ecosystem:'npm'},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'3.5.0'}]}]}]}]},headers:{'Access-Control-Allow-Origin':'*'}});
 });
 await context.route('https://wpscan.com/api/v3/status',route=>route.fulfill({json:{requests_remaining:20},headers:{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*'}}));
 let pdCalls=0;
 await context.route('https://api.projectdiscovery.io/**',async route=>{
   const req=route.request(),url=new URL(req.url()),headers={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*'};
   if(req.method()==='OPTIONS'){await route.fulfill({status:204,headers});return;}
   pdCalls++;assert.equal(req.method(),'GET');assert.equal(req.headers()['x-api-key'],'dummy-pd-ui-key');assert.equal(req.headers()['x-team-id'],'test_workspace');
   const json=url.pathname.includes('/scans/results')?{data:[{vuln_id:'fixture-finding',target:base+'/private?token=SECRET',vuln_status:'fixed',created_at:'2026-09-01T00:00:00Z',updated_at:'2026-09-20T00:00:00Z',event:[{'matched-at':base+'/private',request:'PRIVATE_REQUEST',response:'PRIVATE_RESPONSE',info:{name:'Example previous cloud finding',severity:'high',classification:{'cve-id':['CVE-2020-11022'],'cvss-score':6.1,'epss-score':0.01}}}]},{vuln_id:'unrelated',target:'https://other.test',vuln_status:'open'}],total_results:2,total_pages:1,current_page:1}:{results:[{id:'example-metadata',name:'Example CVE context',description:'Synthetic metadata for UI verification only.',severity:'high',classification:{'cve-id':['CVE-2020-11022'],'cvss-score':6.1,'epss-score':0.01,'cwe-id':['CWE-79']},references:['https://example.com/advisory'],raw:'PRIVATE_TEMPLATE'}],total:1};
   if(url.pathname.includes('/scans/results'))assert.equal(url.searchParams.get('domain'),'127.0.0.1');
   await route.fulfill({json,headers});
 });
 await context.addInitScript(({base})=>{
   if(window.top!==window||location.origin!==base)return;
   const event=()=>({listeners:[],addListener(fn){this.listeners.push(fn);},emit(...args){for(const fn of this.listeners)fn(...args);}});
   const changed=event();
   const area=name=>{const store={};return {store,async setAccessLevel(){},async get(keys){if(keys===null)return structuredClone(store);if(typeof keys==='string')keys=[keys];return Object.fromEntries((keys||[]).map(k=>[k,structuredClone(store[k])]));},async set(data){const delta={};for(const [k,v]of Object.entries(data)){delta[k]={oldValue:store[k],newValue:v};store[k]=structuredClone(v);}changed.emit(delta,name);},async remove(keys){const delta={};for(const k of Array.isArray(keys)?keys:[keys]){delta[k]={oldValue:store[k]};delete store[k];}changed.emit(delta,name);}};};
   const grants=new Set(['https://api.osv.dev/*']),alarms=new Map();
   let fixturePromise=new Promise(resolve=>window.addEventListener('DOMContentLoaded',()=>{const f=document.createElement('iframe');f.style.display='none';f.src=base+'/examples/demo.html';f.onload=()=>resolve(f);document.body.append(f);},{once:true}));
   const runtime={id:'fixture-extension',getURL:p=>'chrome-extension://fixture-extension/'+p,onMessage:event(),async sendMessage(msg){await window.__worker;return new Promise(resolve=>runtime.onMessage.listeners[0](msg,{id:runtime.id,url:runtime.getURL('ui/index.html')},resolve));}};
   const tabs={onActivated:event(),onUpdated:event(),onRemoved:event(),async get(){return {id:1,url:base+'/examples/demo.html',status:'complete'};},async query(){return [await this.get()];}};
   window.chrome={runtime,tabs,storage:{local:area('local'),session:area('session'),onChanged:changed},windows:{async getCurrent(){return {id:1};}},permissions:{onRemoved:event(),async getAll(){return {origins:[...grants]};},async contains({origins=[],permissions=[]}){return [...origins,...permissions].every(p=>grants.has(p));},async request({origins=[],permissions=[]}){[...origins,...permissions].forEach(p=>grants.add(p));return true;},async remove({origins=[]}){origins.forEach(p=>grants.delete(p));this.onRemoved.emit();return true;}},
   action:{async setPopup(){},async setBadgeText(v){window.__badge=v;},async setBadgeBackgroundColor(){},async setTitle(){}},sidePanel:{async setPanelBehavior(){},async open(){}},alarms:{onAlarm:event(),async get(k){return alarms.get(k);},async create(k,v){alarms.set(k,v);},async clear(k){alarms.delete(k);}},webRequest:{onHeadersReceived:event()},notifications:{async create(){}},scripting:{async executeScript({func}){const f=await fixturePromise;return [{documentId:'fixture-doc',result:f.contentWindow.eval('('+func.toString()+')()')}];}}};
   window.__worker=import(base+'/extension/background.js');
 },{base});
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base+'/extension/ui/index.html?view=panel');
 await page.waitForFunction(()=>document.querySelector('#overview').textContent.includes('1 / 3 checked'));
 await page.waitForFunction(()=>!document.querySelector('#scan').disabled);
 assert.equal(await page.evaluate(()=>window.__badge.text),'1');
 await page.locator('[data-tab="advisories"]').click();await page.getByText('Evidence & advisory context').click();
 assert(await page.getByText('Example advisory for UI verification').isVisible());
 await page.getByRole('button',{name:'Mute on this site',exact:true}).click();await page.waitForFunction(()=>window.__badge.text==='');
 await page.getByRole('button',{name:'Unmute on this site',exact:true}).click();await page.waitForFunction(()=>window.__badge.text==='1');
 await page.locator('[data-tab="settings"]').click();await page.locator('[data-theme="dark"]').click();await page.waitForFunction(()=>document.documentElement.style.colorScheme==='dark');
 await page.locator('[data-theme="light"]').click();await page.waitForFunction(()=>document.documentElement.style.colorScheme==='light');
 await page.locator('[data-theme="auto"]').click();await page.waitForFunction(()=>document.documentElement.style.colorScheme==='light dark');
 await page.getByText('API keys · optional',{exact:true}).click();await page.locator('#api-key').fill('dummy-key-ui-check');await page.locator('#save-key').click();await page.waitForFunction(()=>document.querySelector('#key-status').textContent.includes('Key saved'));
 assert.equal(await page.locator('#api-key').inputValue(),'');
 assert.equal(await page.evaluate(()=>JSON.stringify(chrome.storage.local.store).includes('dummy-key-ui-check')),false);
 await page.locator('#test-key').click();await page.getByText('WPScan accepted the key.',{exact:false}).waitFor();
 await page.locator('#remove-key').click();await page.waitForFunction(()=>document.querySelector('#key-status').textContent==='No key configured');
 await page.locator('#provider').selectOption('projectdiscovery');
 assert.equal(await page.locator('#provider-key-link a').getAttribute('href'),'https://cloud.projectdiscovery.io/settings/api-key');
 await page.locator('#pd-team').fill('test_workspace');await page.locator('#save-pd-team').click();await page.getByText('Settings saved.',{exact:true}).waitFor();
 await page.locator('#api-key').fill('dummy-pd-ui-key');await page.locator('#save-key').click();await page.waitForFunction(()=>document.querySelector('#key-status').textContent.includes('Key saved'));
 await page.locator('#test-key').click();await page.getByText('ProjectDiscovery template access succeeded.',{exact:false}).waitFor();
 await page.locator('[data-tab="advisories"]').click();await page.getByRole('button',{name:'ProjectDiscovery context',exact:true}).click();await page.getByText('Example CVE context',{exact:true}).waitFor();
 await page.getByText('ProjectDiscovery · existing cloud findings',{exact:true}).click();await page.getByRole('button',{name:'Load existing cloud findings',exact:true}).click();await page.getByText('Example previous cloud finding',{exact:true}).waitFor();
 assert.equal(await page.evaluate(()=>window.__badge.text),'1');assert.equal(await page.getByText('other.test',{exact:true}).count(),0);
 assert(!await page.locator('body').textContent().then(t=>t.includes('PRIVATE_')));
 assert.equal(await page.evaluate(()=>JSON.stringify(chrome.storage.local.store).includes('dummy-pd-ui-key')),false);
 const oldCalls=pdCalls;await page.getByRole('button',{name:'Load existing cloud findings',exact:true}).click();await page.getByText('ProjectDiscovery lookup complete.',{exact:true}).waitFor();assert.equal(pdCalls,oldCalls);
 for(const width of [320,430,700]){await page.setViewportSize({width,height:950});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'PD overflow at '+width);}
 await page.setViewportSize({width:430,height:950});
 fs.mkdirSync(path.join(root,'screenshots'),{recursive:true});await page.screenshot({path:path.join(root,'screenshots/projectdiscovery.png'),fullPage:true});
 await page.locator('[data-tab="settings"]').click();
 await page.locator('#allow-site').click();await page.waitForFunction(()=>document.querySelector('#watch').checked);
 await page.getByText('Automatic updates',{exact:true}).click();await page.locator('#auto-update').uncheck();await page.waitForFunction(()=>document.querySelector('#frequency').disabled);await page.locator('#auto-update').check();
 await page.locator('[data-tab="overview"]').click();
 const downloadPromise=page.waitForEvent('download');await page.getByRole('button',{name:'Export JSON',exact:true}).click();const download=await downloadPromise;const file=await download.path();const exported=fs.readFileSync(file,'utf8');assert(!exported.includes('dummy-key'));assert(exported.includes('Exploitability unverified'));assert(!exported.includes('fixture-finding'));assert(!exported.includes('Example CVE context'));assert.equal(JSON.parse(exported).version,'0.2.0');
 await page.locator('[data-tab="settings"]').click();await page.locator('#remove-key').click();await page.waitForFunction(()=>document.querySelector('#key-status').textContent==='No key configured');await page.locator('[data-tab="advisories"]').click();await page.waitForFunction(()=>!document.querySelector('#advisories').textContent.includes('Example previous cloud finding'));
 const shotdir=path.join(root,'screenshots');fs.mkdirSync(shotdir,{recursive:true});
 await page.locator('[data-tab="settings"]').click();await page.locator('[data-theme="dark"]').click();await page.locator('[data-tab="overview"]').click();await page.screenshot({path:path.join(shotdir,'overview-dark.png'),fullPage:true});
 await page.locator('[data-tab="settings"]').click();await page.locator('[data-theme="light"]').click();await page.locator('[data-tab="overview"]').click();await page.screenshot({path:path.join(shotdir,'overview-light.png'),fullPage:true});
 for(const width of [320,430,700]){await page.setViewportSize({width,height:950});for(const tab of ['overview','stack','advisories','settings']){await page.locator('[data-tab="'+tab+'"]').click();assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),`Overflow at ${width}px on ${tab}`);}}
 assert.deepEqual(errors,[]);
 console.log('Browser UI checks passed: real capture/detection and background with Chrome API adapters; 3 themes; advisory evidence and mute; key save/test/remove; ProjectDiscovery workspace, metadata, existing findings, cache reuse, exact-host filtering and secret-free exports; website permissions; update settings; JSON export; 320/430/700px layout. No runtime errors. Provider responses mocked.');
 await browser.close();server.close();
})().catch(e=>{console.error(e);server.close();process.exit(1);});
