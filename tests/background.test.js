import test from 'node:test';
import assert from 'node:assert/strict';
const event=()=>({listeners:[],addListener(fn){this.listeners.push(fn);},fire(...args){for(const fn of this.listeners)fn(...args);}});
function area(){const values={};return {values,async setAccessLevel(){},async get(keys){if(keys===null)return structuredClone(values);if(typeof keys==='string')keys=[keys];return Object.fromEntries((keys||[]).map(k=>[k,structuredClone(values[k])]));},async set(data){Object.assign(values,structuredClone(data));},async remove(keys){for(const k of Array.isArray(keys)?keys:[keys])delete values[k];}};}
const local=area(),session=area(),tabs=new Map([[1,{id:1,url:'https://fixture.test/one',status:'complete'}]]),badges=new Map(),grants=new Set(['https://api.osv.dev/*']),alarms=new Map();
let documentId='doc-1',runtimeVersion='3.4.1',fetchHandler;
globalThis.fetch=(...args)=>fetchHandler(...args);
globalThis.chrome={
 storage:{local,session},runtime:{id:'test-extension',getURL:p=>'chrome-extension://test-extension/'+p,onMessage:event()},
 permissions:{async contains({origins=[],permissions=[]}){return [...origins,...permissions].every(x=>grants.has(x));},async getAll(){return {origins:[...grants]};},onRemoved:event()},
 action:{async setPopup(){},async setBadgeText({tabId,text}){badges.set(tabId,text);},async setBadgeBackgroundColor(){},async setTitle(){}},sidePanel:{async setPanelBehavior(){}},
 alarms:{async get(k){return alarms.get(k);},async create(k,v){alarms.set(k,v);},async clear(k){alarms.delete(k);},onAlarm:event()},
 tabs:{async get(id){if(!tabs.has(id))throw new Error('Tab closed');return {...tabs.get(id)};},async query(){return [...tabs.values()];},onRemoved:event(),onUpdated:event()},
 scripting:{async executeScript({target,func}){if(target.documentIds&&target.documentIds[0]!==documentId)throw new Error('Document no longer exists');if(func.name==='capturePage')return [{documentId,result:{href:tabs.get(1).url,resources:[],generators:[],markers:{}}}];if(func.name==='captureRuntime')return [{documentId,result:[{id:'jquery',version:runtimeVersion,signal:'jQuery.fn.jquery'}]}];return [{documentId,result:true}];}},
 webRequest:{onHeadersReceived:event()},notifications:{async create(){}}
};
session.values['page:2']={status:'checking',components:[],token:'interrupted'};
await import('../extension/background.js');
const sender={id:'test-extension',url:'chrome-extension://test-extension/ui/index.html'};
const message=(data,from=sender)=>new Promise(resolve=>chrome.runtime.onMessage.listeners[0](data,from,resolve));
const data=()=>({vulns:[{id:'GHSA-fixture',summary:'Test advisory',database_specific:{severity:'HIGH'},affected:[{package:{name:'jquery',ecosystem:'npm'},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'3.5.0'}]}]}]}]});
const respond=()=>new Response(JSON.stringify(data()),{status:200});
const tick=()=>new Promise(r=>setTimeout(r,0));
test('service worker integration: scan, trust boundary, key lifetime, navigation, and exclusions',async t=>{
 await t.test('a worker restart releases interrupted scans for retry',async()=>{const r=await message({type:'state',tabId:2});assert.equal(r.data.page.status,'error');assert.match(r.data.page.message,/interrupted/);});
 await t.test('a scan produces evidence and a badge',async()=>{fetchHandler=async()=>respond();const r=await message({type:'scan',tabId:1});assert.equal(r.ok,true);assert.equal(r.data.status,'done');assert.equal(badges.get(1),'1');assert.equal(r.data.components[0].strong,true);});
 await t.test('page messages cannot access keys or configuration',async()=>{const r=await message({type:'state',tabId:1},{id:'test-extension',url:'https://fixture.test/one'});assert.equal(r.ok,false);assert.match(r.error,/Untrusted/);});
 await t.test('session key does not appear in state or local storage',async()=>{grants.add('https://wpscan.com/*');const r=await message({type:'saveKey',provider:'wpscan',value:'test-secret-session',storage:'session'});assert.equal(r.ok,true);const state=await message({type:'state',tabId:1});assert.equal(state.data.keys.wpscan.configured,true);assert(!JSON.stringify(state).includes('test-secret-session'));assert(!JSON.stringify(local.values).includes('test-secret-session'));});
 await t.test('changing key lifetime removes the previous copy',async()=>{await message({type:'saveKey',provider:'wpscan',value:'new-local-secret',storage:'local'});assert(!session.values['key:wpscan']);assert.equal(local.values['key:wpscan'].value,'new-local-secret');await message({type:'saveKey',provider:'wpscan',value:'new-session-secret',storage:'session'});assert(!local.values['key:wpscan']);});
 await t.test('clearing observations preserves keys',async()=>{const r=await message({type:'clear'});assert.equal(r.ok,true);assert(session.values['key:wpscan']);assert(!session.values['page:1']);assert(![...Object.keys(local.values)].some(k=>k.startsWith('osv:')));});
 await t.test('old scan cannot overwrite a newer document',async()=>{
   let release;fetchHandler=()=>new Promise(resolve=>{release=()=>resolve(respond());});
   const first=message({type:'scan',tabId:1,force:true});
   for(let i=0;i<30&&!release;i++)await tick();assert(release);
   documentId='doc-2';runtimeVersion='3.4.2';tabs.set(1,{id:1,url:'https://fixture.test/two',status:'loading'});
   chrome.tabs.onUpdated.fire(1,{status:'loading',url:'https://fixture.test/two'},tabs.get(1));await tick();
   fetchHandler=async()=>respond();const second=await message({type:'scan',tabId:1,force:true});assert.equal(second.ok,true);release();await first;
   const current=(await message({type:'state',tabId:1})).data.page;assert.equal(current.path,'https://fixture.test/two');assert.equal(current.components[0].version,'3.4.2');assert.equal(current.status,'done');
 });
 await t.test('excluded origins lose their prior result and badge',async()=>{await message({type:'settings',settings:{exclusions:['https://fixture.test']}});const state=await message({type:'state',tabId:1});assert.equal(state.data.page,null);assert.equal(badges.get(1),'');assert.equal((await message({type:'scan',tabId:1})).ok,false);});
 await t.test('removing an API key clears both storage areas',async()=>{await message({type:'removeKey',provider:'wpscan'});assert(!session.values['key:wpscan']);assert(!local.values['key:wpscan']);});
});
