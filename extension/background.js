import {capturePage,captureRuntime} from './core/capture.js';
import {detect,exactPackageVersion} from './core/detect.js';
import {DEFAULTS,validateSettings,alertCount} from './core/settings.js';
import {PROVIDERS,fetchOSV,fetchGitHub,fetchWPScan,fetchNVD,testProvider} from './core/intel.js';

const jobs=new Map(),lookups=new Map(),epochs=new Map();
const CACHE_TTL=24*60*60*1000;
const pageKey=id=>'page:'+id;
const headerKey=id=>'headers:'+id;
const cacheKey=c=>'osv:'+c.ecosystem+':'+c.package+'@'+c.version;
const originOf=value=>{try{const u=new URL(value);return ['http:','https:'].includes(u.protocol)?u.origin:null;}catch{return null;}};
async function settings(){return {...DEFAULTS,...(await chrome.storage.local.get('settings')).settings};}
async function getPage(id){return (await chrome.storage.session.get(pageKey(id)))[pageKey(id)]||null;}
async function getKey(provider){const k='key:'+provider;return (await chrome.storage.session.get(k))[k]||(await chrome.storage.local.get(k))[k]||null;}
async function providerPermission(provider){if(!PROVIDERS[provider])throw new Error('Unknown provider.');if(!await chrome.permissions.contains({origins:[PROVIDERS[provider].origin]}))throw new Error('Allow this provider in API settings first.');}
async function keyStatuses(){const result={};for(const p of Object.keys(PROVIDERS)){const k=await getKey(p);result[p]={configured:Boolean(k),storage:k?.storage||'session',permission:await chrome.permissions.contains({origins:[PROVIDERS[p].origin]})};}return result;}
async function applySettings(s){
  await chrome.action.setPopup({popup:s.interfaceMode==='sidepanel'?'':'ui/index.html?view=popup'});
  await chrome.sidePanel.setPanelBehavior({openPanelOnActionClick:s.interfaceMode==='sidepanel'});
  const minutes=s.updateFrequency==='weekly'?10080:1440;
  const alarm=await chrome.alarms.get('refresh-advisories');
  if(s.autoUpdate&&s.osvEnabled){if(!alarm||alarm.periodInMinutes!==minutes)await chrome.alarms.create('refresh-advisories',{periodInMinutes:minutes});}
  else await chrome.alarms.clear('refresh-advisories');
}
const ready=(async()=>{
  await chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
  await chrome.storage.session.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
  const prior=await chrome.storage.session.get(null);
  for(const [k,p] of Object.entries(prior))if(k.startsWith('page:')&&['scanning','checking'].includes(p?.status)){
    await chrome.storage.session.set({[k]:{...p,status:'error',components:[],message:'Inspection was interrupted. Click Re-inspect to try again.'}});
    try{await chrome.action.setBadgeText({tabId:Number(k.slice(5)),text:''});}catch{}
  }
  await applySettings(await settings());
})();

async function lookup(component,force=false){
  const k=cacheKey(component);
  if(lookups.has(k))return lookups.get(k);
  const job=(async()=>{
    const old=(await chrome.storage.local.get(k))[k];
    if(!force&&old&&Date.now()-old.at<CACHE_TTL)return {...old,cache:true};
    const result=await fetchOSV(component);
    const entry={...result,at:Date.now(),component:{package:component.package,ecosystem:component.ecosystem,version:component.version}};
    await chrome.storage.local.set({[k]:entry});return {...entry,cache:false};
  })();
  lookups.set(k,job);try{return await job;}finally{lookups.delete(k);}
}
async function trimCache(){
  const all=await chrome.storage.local.get(null),entries=Object.entries(all).filter(([k])=>k.startsWith('osv:')).sort((a,b)=>b[1].at-a[1].at);
  const remove=entries.filter(([,v],i)=>i>=150||Date.now()-v.at>30*CACHE_TTL).map(([k])=>k);if(remove.length)await chrome.storage.local.remove(remove);
}
async function parallelMap(items,fn,workers=2){let i=0;await Promise.all(Array.from({length:Math.min(workers,items.length)},async()=>{while(i<items.length){const n=i++;await fn(items[n],n);}}));}
async function muteList(origin){return (await chrome.storage.local.get('mutes')).mutes?.[origin]||[];}
async function badge(id,page){
  const s=await settings(),mutes=await muteList(page?.origin),count=alertCount(page?.components||[],s.alertThreshold,mutes);
  try{await chrome.action.setBadgeText({tabId:id,text:count?String(count):''});await chrome.action.setBadgeBackgroundColor({tabId:id,color:'#b83f55'});await chrome.action.setTitle({tabId:id,title:count?`${count} components with affected-version matches — VulnWatch`:'VulnWatch — inspect this page'});}catch{}
  return count;
}
async function commit(id,token,patch,epoch){
  if(epochs.get(id)!==epoch)return false;
  const p=await getPage(id);if(!p||p.token!==token||epochs.get(id)!==epoch)return false;
  await chrome.storage.session.set({[pageKey(id)]:{...p,...patch}});return true;
}
async function scan(id,force=false){
  if(jobs.has(id))return jobs.get(id);
  const epoch=epochs.get(id);
  const job=(async()=>{
    const tab=await chrome.tabs.get(id),origin=originOf(tab.url);if(!origin)throw new Error('Open an ordinary HTTP or HTTPS page, then click the extension icon.');
    const s=await settings();if(s.exclusions.includes(origin))throw new Error('This website is excluded. Remove it in Settings to inspect it.');
    if(epochs.get(id)!==epoch)return null;
    const token=crypto.randomUUID();
    await chrome.storage.session.set({[pageKey(id)]:{token,origin,status:'scanning',components:[],started:Date.now(),message:'Reading visible technology signals…'}});await badge(id,null);
    try{
      const dom=await chrome.scripting.executeScript({target:{tabId:id},func:capturePage});
      const documentId=dom[0]?.documentId,snapshot=dom[0]?.result;
      if(!snapshot||!documentId)throw new Error('The page could not be inspected.');
      let runtime=[],runtimeAvailable=true;
      try{const r=await chrome.scripting.executeScript({target:{tabId:id,documentIds:[documentId]},world:'MAIN',func:captureRuntime});runtime=r[0]?.result||[];}catch{runtimeAvailable=false;}
      const h=(await chrome.storage.session.get(headerKey(id)))[headerKey(id)];
      const headers=h&&h.page===snapshot.href&&Date.now()-h.at<60000?h.headers:[];
      const components=detect(snapshot,runtime,headers).map(c=>({...c,status:c.package&&exactPackageVersion(c.version)?s.osvEnabled?'pending':'disabled':c.version?'unsupported':'unknown',advisories:[]}));
      if(!await commit(id,token,{components,status:'checking',documentId,path:snapshot.href,message:'Checking package versions…',runtimeAvailable,headersAvailable:headers.length>0,limited:snapshot.limits?.resources},epoch))return null;
      await parallelMap(components.filter(c=>c.status==='pending'),async c=>{
        if(!(await getPage(id))|| (await getPage(id))?.token!==token)return;
        try{const r=await lookup(c,force);c.advisories=r.advisories;c.status=r.complete?'checked':'partial';c.checkedAt=r.at;c.cached=r.cache;}catch(e){c.status='unavailable';c.error=e.message;}
      });
      // Confirm the same document is still present before displaying results.
      await chrome.scripting.executeScript({target:{tabId:id,documentIds:[documentId]},func:()=>true});
      const ok=await commit(id,token,{components,status:'done',finished:Date.now(),message:''},epoch);
      if(!ok)return null;
      const page=await getPage(id),count=await badge(id,page);
      if(count&&s.notifications&&await chrome.permissions.contains({permissions:['notifications']})){
        const signature=JSON.stringify(components.filter(c=>c.strong&&c.status==='checked').map(c=>[c.key,c.advisories.map(a=>a.id)]));
        const noticeKey='notice:'+origin;
        if((await chrome.storage.session.get(noticeKey))[noticeKey]!==signature){
          await chrome.notifications.create('vw-'+id,{type:'basic',iconUrl:'icons/icon128.png',title:'VulnWatch: affected-version matches',message:`${count} component${count===1?'':'s'} on ${new URL(origin).hostname}. Open VulnWatch to review evidence.`});
          await chrome.storage.session.set({[noticeKey]:signature});
        }
      }
      await trimCache();return page;
    }catch(e){
      const message=/Cannot access|Missing host permission|cannot be scripted/i.test(e.message)?'Page access is unavailable. Click the toolbar icon on this page or grant website access in Settings.':e.message;
      await commit(id,token,{status:'error',message,components:[]},epoch);throw new Error(message);
    }
  })();jobs.set(id,job);try{return await job;}finally{if(jobs.get(id)===job)jobs.delete(id);}
}
async function refreshCache(){
  const s=await settings();if(!s.osvEnabled)throw new Error('Enable OSV lookups first.');
  const all=await chrome.storage.local.get(null),entries=Object.entries(all).filter(([k])=>k.startsWith('osv:')).sort((a,b)=>a[1].at-b[1].at).slice(0,20);
  let updated=0,failed=0;
  await parallelMap(entries,async([,v])=>{try{await lookup(v.component,true);updated++;}catch{failed++;}});
  const result={at:Date.now(),updated,failed,remaining:Math.max(0,Object.keys(all).filter(k=>k.startsWith('osv:')).length-entries.length)};
  await chrome.storage.local.set({lastRefresh:result});await trimCache();return result;
}
async function validateComponent(id,key){const page=await getPage(id);const c=page?.components.find(c=>c.key===key);if(!c)throw new Error('Scan this page again before checking this component.');return c;}
async function handle(msg,sender){
  await ready;
  // Only our extension UI may access configuration, keys, or provider requests.
  if(sender.id!==chrome.runtime.id||!sender.url?.startsWith(chrome.runtime.getURL('ui/')))throw new Error('Untrusted message source.');
  switch(msg?.type){
    case 'state':return {settings:await settings(),page:Number.isInteger(msg.tabId)?await getPage(msg.tabId):null,keys:await keyStatuses(),lastRefresh:(await chrome.storage.local.get('lastRefresh')).lastRefresh||null,mutes:await muteList((await getPage(msg.tabId))?.origin),permissions:(await chrome.permissions.getAll()).origins};
    case 'scan':if(!Number.isInteger(msg.tabId))throw new Error('No page selected.');return await scan(msg.tabId,Boolean(msg.force));
    case 'settings':{
      const next=validateSettings(msg.settings||{},await settings());
      if(next.notifications&&!await chrome.permissions.contains({permissions:['notifications']}))next.notifications=false;
      await chrome.storage.local.set({settings:next});await applySettings(next);
      for(const tab of await chrome.tabs.query({}))if(tab.id){let page=await getPage(tab.id);if(page&&next.exclusions.includes(page.origin)){epochs.set(tab.id,(epochs.get(tab.id)||0)+1);jobs.delete(tab.id);await chrome.storage.session.remove(pageKey(tab.id));page=null;}await badge(tab.id,page);}
      return next;
    }
    case 'saveKey':{
      if(!PROVIDERS[msg.provider])throw new Error('Unknown provider.');await providerPermission(msg.provider);
      const value=typeof msg.value==='string'?msg.value.trim():'';if(!value||value.length>2048||/[\s\x00-\x1f]/.test(value))throw new Error('Enter a valid API token without whitespace.');
      const k='key:'+msg.provider,storage=msg.storage==='local'?'local':'session';
      await chrome.storage[storage].set({[k]:{value,storage}});await chrome.storage[storage==='local'?'session':'local'].remove(k);return {saved:true};
    }
    case 'removeKey':if(!PROVIDERS[msg.provider])throw new Error('Unknown provider.');await chrome.storage.local.remove('key:'+msg.provider);await chrome.storage.session.remove('key:'+msg.provider);return {removed:true};
    case 'testKey':await providerPermission(msg.provider);return testProvider(msg.provider,(await getKey(msg.provider))?.value);
    case 'github':{
      await providerPermission('github');const c=await validateComponent(msg.tabId,msg.key);if(!c.package||!exactPackageVersion(c.version))throw new Error('An exact package version is needed.');return fetchGitHub(c,(await getKey('github'))?.value);
    }
    case 'wpscan':await providerPermission('wpscan');return fetchWPScan(await validateComponent(msg.tabId,msg.key),(await getKey('wpscan'))?.value);
    case 'nvd':await providerPermission('nvd');return fetchNVD(msg.cve,(await getKey('nvd'))?.value);
    case 'refresh':return refreshCache();
    case 'mute':{
      const page=await getPage(msg.tabId),c=page?.components.find(c=>c.key===msg.key);if(!c?.advisories.some(a=>a.id===msg.id))throw new Error('This advisory is no longer in the current results.');
      const mutes=(await chrome.storage.local.get('mutes')).mutes||{};const token=msg.key+'|'+msg.id,list=mutes[page.origin]||[];
      mutes[page.origin]=list.includes(token)?list.filter(k=>k!==token):[...list,token].slice(-200);
      await chrome.storage.local.set({mutes:Object.fromEntries(Object.entries(mutes).slice(-100))});await badge(msg.tabId,page);return {muted:mutes[page.origin].includes(token)};
    }
    case 'clear':{
      for(const id of jobs.keys())epochs.set(id,(epochs.get(id)||0)+1);jobs.clear();
      const all=await chrome.storage.local.get(null);await chrome.storage.local.remove(Object.keys(all).filter(k=>k.startsWith('osv:')||['lastRefresh','mutes'].includes(k)));
      await chrome.storage.session.remove(Object.keys(await chrome.storage.session.get(null)).filter(k=>!k.startsWith('key:')));
      for(const tab of await chrome.tabs.query({}))if(tab.id)await badge(tab.id,null);return {cleared:true};
    }
    default:throw new Error('Unknown action.');
  }
}
chrome.runtime.onMessage.addListener((msg,sender,reply)=>{handle(msg,sender).then(data=>reply({ok:true,data})).catch(e=>reply({ok:false,error:e.message||'Request failed.'}));return true;});
chrome.alarms.onAlarm.addListener(alarm=>{if(alarm.name==='refresh-advisories')ready.then(refreshCache).catch(()=>{});});
chrome.tabs.onRemoved.addListener(id=>{epochs.set(id,(epochs.get(id)||0)+1);jobs.delete(id);ready.then(()=>chrome.storage.session.remove([pageKey(id),headerKey(id)])).catch(()=>{});});
chrome.tabs.onUpdated.addListener((id,change,tab)=>{
  if(change.status==='loading'||change.url){epochs.set(id,(epochs.get(id)||0)+1);jobs.delete(id);}
  (async()=>{
    await ready;
    if(change.status==='loading'||change.url){await chrome.storage.session.remove(pageKey(id));await badge(id,null);}
    if(change.status==='complete'||(change.url&&tab.status==='complete')){
      const s=await settings(),origin=originOf(tab.url);if(!s.watchEnabled||!origin||s.exclusions.includes(origin))return;
      if(await chrome.permissions.contains({origins:[new URL(origin).protocol+'//'+new URL(origin).hostname+'/*']}))await scan(id);
    }
  })().catch(()=>{});
});
chrome.webRequest.onHeadersReceived.addListener(details=>{
  if(details.tabId<0)return;
  (async()=>{
    await ready;
    const allowed=new Set(['server','x-powered-by','x-generator','x-drupal-cache','x-aspnet-version']);
    const u=new URL(details.url),s=await settings();if(s.exclusions.includes(u.origin))return;
    const headers=(details.responseHeaders||[]).filter(h=>allowed.has(h.name.toLowerCase())).map(h=>({name:h.name,value:String(h.value||'').slice(0,250)}));
    await chrome.storage.session.set({[headerKey(details.tabId)]:{page:u.origin+u.pathname,at:Date.now(),headers}});
  })().catch(()=>{});
},{urls:['http://*/*','https://*/*'],types:['main_frame']},['responseHeaders']);
chrome.permissions.onRemoved.addListener(()=>{ready.then(async()=>{for(const tab of await chrome.tabs.query({}))if(tab.id)await badge(tab.id,await getPage(tab.id));}).catch(()=>{});});
