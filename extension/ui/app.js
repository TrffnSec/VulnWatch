import {DEFAULTS,alertCount} from '../core/settings.js';
import {PROVIDERS,safeLink,deduplicate} from '../core/intel.js';
const $=id=>document.getElementById(id);
const view=new URLSearchParams(location.search).get('view')||'popup';
document.body.classList.add(view==='settings'?'settings':view==='panel'?'panel':'popup');
let tabId=null,windowId=null,pinned=false,activeSection=view==='settings'?'settings':'overview';
let state={settings:{...DEFAULTS},page:null,keys:{},mutes:[],permissions:[]},busy=false,lastToken=null,loadTimer,loadSerial=0;
const manualResults=new Map(),pdResults=new Map(),pdPending=new Set();let pdGeneration=0;
function clearPD(){pdGeneration++;pdResults.clear();pdPending.clear();}
function node(tag,text,className){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(className)e.className=className;return e;}
function button(text,handler,className='secondary'){const e=node('button',text,className);e.type='button';e.addEventListener('click',handler);return e;}
function link(text,url){const safe=safeLink(url);if(!safe)return node('span',text);const a=node('a',text);a.href=safe;a.target='_blank';a.rel='noreferrer noopener';return a;}
function feedback(text,error=false){$('feedback').hidden=!text;$('feedback').textContent=text;$('feedback').classList.toggle('error',error);}
async function send(type,payload={}){const r=await chrome.runtime.sendMessage({type,...payload});if(!r?.ok)throw new Error(r?.error||'The extension service worker did not respond.');return r.data;}
function time(value){if(!value)return 'Not available';const date=new Date(value);return Number.isNaN(date.getTime())?'Not available':date.toLocaleString();}
function theme(){document.documentElement.style.colorScheme=state.settings.theme==='auto'?'light dark':state.settings.theme;document.querySelectorAll('[data-theme]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.theme===state.settings.theme)));}
function section(name){activeSection=name;for(const s of ['overview','stack','advisories','settings'])$(s).hidden=s!==name;document.querySelectorAll('[data-tab]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.tab===name)));if(name==='settings')renderSettings();}
async function load(){
  const serial=++loadSerial,selected=tabId;
  const next=await send('state',{tabId:selected});if(serial!==loadSerial||selected!==tabId)return;
  if(next.page?.token!==lastToken){manualResults.clear();clearPD();lastToken=next.page?.token;}
  state=next;render();
}
function scheduleLoad(){clearTimeout(loadTimer);loadTimer=setTimeout(()=>load().catch(e=>feedback(e.message,true)),80);}
function render(){
  theme();const page=state.page,components=page?.components||[];
  $('stack-count').textContent=components.length||'';
  $('advisory-count').textContent=components.reduce((n,c)=>n+c.advisories.length,0)||'';
  $('host').textContent=page?.origin?new URL(page.origin).host:currentTabHost||'No inspectable page';
  $('context-note').textContent=pinned?'Pinned to this tab':page?.finished?'Inspected '+time(page.finished):'Top-level document · passive inspection';
  $('scan').disabled=busy||['scanning','checking'].includes(page?.status)||tabId===null;
  $('scan').textContent=busy||['scanning','checking'].includes(page?.status)?'Inspecting…':page?.status==='done'?'Re-inspect':'Inspect page';
  $('open-panel').hidden=view!=='popup'||state.settings.interfaceMode==='popup';$('pin').hidden=view!=='panel';
  $('context').hidden=view==='settings';$('footer-mode').textContent=state.settings.watchEnabled?'Watching permitted sites':'On-click inspection';
  renderOverview();renderStack();renderAdvisories();if(activeSection==='settings')renderSettings(false);
}
function empty(title,description){const e=node('div',undefined,'empty');e.append(node('div','TRFFN / VULNWATCH','section-label'),node('h2',title),node('p',description));return e;}
function renderOverview(){
  const out=$('overview');out.replaceChildren();const page=state.page;
  if(!page){out.append(empty('Know what is running.','Inspect the current page to see technologies, version evidence, and matching advisories.'));out.append(node('p','OSV receives package names and versions. Optional ProjectDiscovery cloud lookups send the hostname only when you request them.','small muted'));return;}
  if(page.status==='error'){out.append(empty('Inspection unavailable',page.message));return;}
  if(['scanning','checking'].includes(page.status)){out.append(empty('Reading the page…',page.message));return;}
  const cs=page.components,count=alertCount(cs,state.settings.alertThreshold,state.mutes),checked=cs.filter(c=>c.status==='checked').length,totalMatches=cs.reduce((n,c)=>n+c.advisories.length,0);
  const box=node('div',undefined,'summary-box');box.append(node('div','ADVISORY SIGNALS','section-label'),node('div',String(count),'summary-number'),node('h2',count===1?'component with a strong match':'components with strong matches'));
  box.append(node('p',count?'Affected-version matches. Exploitability is unverified.':totalMatches?'Inferred or incomplete matches are available for review.':'No alert-eligible match. This is not a security assessment.','small muted'));
  const stats=node('div',undefined,'summary-bottom');stats.append(node('span',cs.length+' technologies'),node('span',checked+' / '+cs.length+' checked'));box.append(stats);out.append(box);
  if(totalMatches)out.append(button('Review matches & evidence →',()=>section('advisories'),'primary gap'));
  const unavailable=cs.filter(c=>['unavailable','partial'].includes(c.status)).length;if(unavailable)out.append(node('p',`${unavailable} component checks are unavailable or incomplete. See Stack for details.`,'small muted'));
  out.append(node('div','Observed stack','section-label gap'));
  for(const c of cs.slice(0,6)){const row=node('div',undefined,'row');const left=node('div');left.append(node('div',c.name),node('div',c.category,'small muted'));const right=node('div',undefined,'right');right.append(node('div',c.version||'Unknown','mono'),node('div',c.version?c.confidence:'Version unavailable','small muted'));row.append(left,right);out.append(row);}
  if(!cs.length)out.append(node('p','No supported technology signals were found. Hidden or bundled dependencies may still exist.','muted small'));
  out.append(node('p',(page.headersAvailable?'Response headers included.':'Response headers unavailable; permit this site and reload to capture them.')+(page.runtimeAvailable?'':' Runtime signals unavailable.')+(page.limited?' Resource limit reached.':''),'small muted'));
  const actions=node('div',undefined,'button-row gap');actions.append(button('Copy observation',copyObservation),button('Export JSON',exportObservation));out.append(actions);
}
function statusText(c){return {checked:c.advisories.length?'Affected-version match':'No matching OSV advisory',pending:'Checking OSV…',disabled:'OSV disabled',unknown:'Version unknown',unsupported:'No package-version mapping',unavailable:c.error||'Lookup unavailable',partial:'Incomplete provider result'}[c.status]||c.status;}
function fact(label,value){const row=node('div',undefined,'fact');row.append(node('span',label),node('span',String(value)));return row;}
function renderStack(){
  const out=$('stack-list');out.replaceChildren();const query=$('filter').value.toLowerCase();
  const components=(state.page?.components||[]).filter(c=>(c.name+' '+c.category+' '+c.id).toLowerCase().includes(query));
  if(!components.length){out.append(empty(query?'No matching technologies':'No observations yet',query?'Try a different filter.':'Inspect an ordinary web page to populate the stack.'));return;}
  for(const c of components){
    const d=node('details',undefined,'tech');const summary=node('summary',c.name);summary.append(node('span',c.version||'Version unknown','muted mono'));d.append(summary);
    d.append(fact('Category',c.category),fact('Version evidence',c.version?c.confidence:'Unavailable'),fact('Advisory check',statusText(c)));
    if(c.checkedAt)d.append(fact(c.cached?'Cached OSV lookup':'OSV checked',time(c.checkedAt)));
    for(const evidence of c.evidence){const ev=node('div',undefined,'evidence');ev.append(node('code',evidence.signal));if(evidence.origin)ev.append(node('div',evidence.origin,'small muted'));d.append(ev);}
    if(!c.strong&&c.version)d.append(node('p','This version is inferred from an asset name or parameter. Matches do not trigger alerts.','small muted'));
    if(c.package&&c.version)d.append(button('Check GitHub advisories',()=>providerCheck('github',c)));
    if(c.kind.startsWith('wordpress-'))d.append(button('Check WPScan',()=>providerCheck('wpscan',c)));
    const extra=manualResults.get(c.key);if(extra){const result=node('div',undefined,'subresult');result.append(node('div',extra.provider==='wpscan'?'WPScan · temporary results':'GitHub · secondary check','section-label'));
      if(extra.provider==='wpscan'){
        result.append(node('p',extra.data.versionFiltered?'Core version-filtered results.':'Component advisory list — installed-version applicability is not assessed.','small muted'));
        for(const a of extra.data.advisories){result.append(link(a.title,a.url));if(a.fixed)result.append(node('div','Fixed in: '+a.fixed,'mono'));}
      }else for(const a of deduplicate(extra.data.advisories)){result.append(link(a.title,a.references[0]));result.append(node('div',a.id+' · '+a.severity,'mono'));}
      if(!extra.data.advisories.length)result.append(node('p','No records returned by this provider.','small muted'));
      if(extra.data.complete===false)result.append(node('p','Result limit reached; coverage is incomplete.','small muted'));
      d.open=true;d.append(result);
    }
    out.append(d);
  }
}
function renderAdvisories(){
  renderPDCloud();
  const out=$('advisory-list');out.replaceChildren();let count=0;
  for(const c of state.page?.components||[])for(const a of deduplicate(c.advisories)){
    count++;const item=node('article',undefined,'advisory');
    item.append(node('div',a.severity+' · '+(c.strong?'AFFECTED-VERSION MATCH':'INFERRED VERSION'),'severity '+a.severity),node('div',a.title,'advisory-title'),node('div',c.name+' '+c.version+' · '+a.id,'mono'));
    item.append(node('p','Exploitability and use of affected functionality are unverified.','small muted'));
    const details=node('details');details.append(node('summary','Evidence & advisory context'),fact('Version evidence',c.confidence),fact('Sources',a.sources.join(', ')));
    for(const range of a.ranges)details.append(node('p',range,'mono'));if(a.fixed.length)details.append(fact('Fixed boundaries',a.fixed.join(', ')));
    for(const e of c.evidence)details.append(node('div',e.signal,'evidence mono'));
    for(const url of a.references){const ref=node('div');ref.append(link(new URL(url).hostname+' ↗',url));details.append(ref);}
    item.append(details);
    const muted=state.mutes.includes(c.key+'|'+a.id),actions=node('div',undefined,'button-row');
    actions.append(button(muted?'Unmute on this site':'Mute on this site',async()=>{try{await send('mute',{tabId,key:c.key,id:a.id});await load();}catch(e){feedback(e.message,true);}},'quiet small'));
    const cve=[a.id,...a.aliases].find(id=>/^CVE-\d{4}-\d{4,}$/.test(id));
    if(cve)actions.append(button('NVD details',async()=>{const selectedToken=state.page?.token;try{const granted=await chrome.permissions.request({origins:[PROVIDERS.nvd.origin]});if(!granted)return;const r=await send('nvd',{cve});if(state.page?.token!==selectedToken)return;const extra=node('div',undefined,'subresult');extra.append(node('p',r.description,'small'),node('div',`NVD severity: ${r.severity}${r.score!==null?' · CVSS '+r.score:''}`,'small muted'));if(r.url)extra.append(link('NVD record ↗',r.url));item.append(extra);}catch(e){feedback(e.message,true);}},'quiet small'));
    if(cve){actions.append(button(pdPending.has(cve)?'Loading ProjectDiscovery…':'ProjectDiscovery context',()=>pdLookup(cve),'quiet small'));const r=pdResults.get(cve);if(r)item.append(pdTemplateResult(r,cve));}
    item.append(actions);out.append(item);
  }
  if(!count)out.append(empty('No advisory matches to display','Unknown versions, unsupported components, disabled providers, and lookup errors are listed in Stack. An empty result does not mean the site is secure.'));
}
function renderSettings(force=true){
  const s=state.settings;
  $('display').value=s.interfaceMode;$('watch').checked=s.watchEnabled;$('osv').checked=s.osvEnabled;$('auto-update').checked=s.autoUpdate;$('frequency').value=s.updateFrequency;$('frequency').disabled=!s.autoUpdate;$('notifications').checked=s.notifications;$('threshold').value=s.alertThreshold;
  if(force||document.activeElement!==$('excluded'))$('excluded').value=s.exclusions.join('\n');
  const websiteGrants=(state.permissions||[]).filter(p=>!Object.values(PROVIDERS).some(v=>v.origin===p)&&p!=='https://api.osv.dev/*');
  $('permission-status').textContent=websiteGrants.length?'Website access: '+websiteGrants.join(', '):'No persistent website access granted. Toolbar clicks allow temporary inspection.';
  $('allow-site').disabled=!currentTabOrigin;
  const r=state.lastRefresh;$('refresh-status').textContent=r?`${time(r.at)} · ${r.updated} refreshed · ${r.failed} failed${r.remaining?' · '+r.remaining+' entries deferred':''}`:'No refresh yet. Fresh lookups are cached for 24 hours.';
  renderKeyStatus();
}
function renderKeyStatus(){
  const p=$('provider').value,k=state.keys[p];$('key-status').textContent=k?.configured?`Key saved · ${k.storage==='local'?'on this device':'this session'}${k.permission?'':' · provider access revoked'}`:'No key configured';
  $('test-key').disabled=!k?.configured;$('remove-key').disabled=!k?.configured;
  $('provider-key-link').replaceChildren(link('Get '+PROVIDERS[p].name+' API key ↗',PROVIDERS[p].keyUrl));
  $('pd-workspace').hidden=p!=='projectdiscovery';if(document.activeElement!==$('pd-team'))$('pd-team').value=state.settings.projectDiscoveryTeamId||'';
  $('provider-description').textContent={projectdiscovery:'Optional integration; a key is required to use it. Free account signup is available. Endpoint access and quotas depend on your plan. Reads public CVE metadata and existing cloud findings; it does not launch scans.',wpscan:'WordPress core, plugin, and theme intelligence. Provider plan and integration terms apply; results are not cached.',github:'An optional secondary package/version check. Public advisory requests can also work without a token; no repository access is needed.',nvd:'Adds CVE descriptions and CVSS context. NVD details enrich a match; they do not establish applicability.'}[p];
}
function pdMetrics(row){
  const parts=[];if(row.cvss!==null)parts.push('CVSS '+row.cvss);if(row.epss!==null)parts.push('EPSS '+(row.epss*100).toFixed(2)+'%');
  if(row.cwes?.length)parts.push(row.cwes.join(', '));return parts.join(' · ');
}
function pdTemplateResult(r,cve){
  const out=node('div',undefined,'subresult');out.append(node('div','PROJECTDISCOVERY · RELATED TEMPLATE METADATA','section-label'));
  out.append(node('p','Template availability does not establish applicability or change the alert badge.','small muted'));
  for(const t of r.templates){const card=node('div',undefined,'evidence');card.append(node('strong',t.title),node('div',t.id+' · '+t.severity,'mono'));if(t.description)card.append(node('p',t.description,'small'));card.append(node('div',pdMetrics(t),'small muted'));for(const url of t.references){const line=node('div');line.append(link(new URL(url).hostname+' ↗',url));card.append(line);}out.append(card);}
  if(!r.templates.length)out.append(node('p','No exact CVE-linked template metadata returned. This is not a clean security check.','small muted'));
  if(!r.complete)out.append(node('p','Search coverage is incomplete. Only the first 50 candidates are considered.','small muted'));
  out.append(node('p',(r.cached?'Cached · ':'Fetched · ')+time(r.fetchedAt),'small muted'),button('Refresh ProjectDiscovery context',()=>pdLookup(cve,true),'quiet small'));return out;
}
function renderPDCloud(){
  const out=$('pd-cloud');out.replaceChildren();if(state.page?.status!=='done')return;
  const host=new URL(state.page.origin).hostname;
  const box=node('details',undefined,'tech');box.append(node('summary','ProjectDiscovery · existing cloud findings'));
  box.append(node('p','Sends '+host+' to ProjectDiscovery to read existing findings in your account. Results are filtered to this exact hostname. No scan is started.','small muted'));
  const b=button(pdPending.has('findings')?'Loading cloud findings…':'Load existing cloud findings',()=>pdLookup(null));b.disabled=pdPending.has('findings');box.append(b);
  const r=pdResults.get('findings');
  if(r){box.open=true;box.append(node('p','Previous cloud findings · current exploitability is unverified. No badge or export changes.','small muted'));
    for(const f of r.findings){const card=node('article',undefined,'evidence');card.append(node('strong',f.title),fact('Provider severity',f.severity),fact('Provider status',f.status),fact('Hostname',f.host),fact('First recorded',time(f.createdAt)),fact('Last updated',time(f.updatedAt)));if(f.observedAt)card.append(fact('Event time',time(f.observedAt)));if(f.cves.length)card.append(node('div',f.cves.join(', '),'mono'));card.append(node('div',pdMetrics(f),'small muted'));box.append(card);}
    if(!r.findings.length)box.append(node('p','No exact-host findings in the returned records. This does not mean the host is secure.','small muted'));
    if(!r.complete)box.append(node('p','Coverage is incomplete: only the first 50 provider candidates are checked. Review your cloud workspace for the full history.','small muted'));
    box.append(node('p',(r.cached?'Cached · ':'Fetched · ')+time(r.fetchedAt),'small muted'),button('Refresh cloud findings',()=>pdLookup(null,true),'quiet small'));
  }
  if(pdPending.has('findings'))box.open=true;
  box.append(link('Open ProjectDiscovery dashboard ↗','https://cloud.projectdiscovery.io'));out.append(box);
}
async function pdLookup(cve,refresh=false){
  if(!state.keys.projectdiscovery?.configured){$('provider').value='projectdiscovery';section('settings');$('provider').closest('details').open=true;renderKeyStatus();feedback('Add your ProjectDiscovery API key, then return to Advisories.',true);return;}
  const id=tabId,token=state.page?.token,generation=pdGeneration,k=cve||'findings';if(!token||pdPending.has(k))return;
  pdPending.add(k);renderAdvisories();feedback('Loading ProjectDiscovery…');
  try{
    const granted=await chrome.permissions.request({origins:[PROVIDERS.projectdiscovery.origin]});if(!granted){feedback('ProjectDiscovery access was not granted.',true);return;}
    const data=await send(cve?'pdTemplates':'pdFindings',{tabId:id,token,...(cve?{cve}:{}),refresh});
    if(generation!==pdGeneration||id!==tabId||token!==state.page?.token)return;
    pdResults.set(k,data);feedback('ProjectDiscovery lookup complete.');
  }catch(e){if(generation===pdGeneration&&id===tabId&&token===state.page?.token)feedback(e.message,true);}
  finally{if(generation===pdGeneration){pdPending.delete(k);renderAdvisories();}}
}
async function saveSettings(patch){try{state.settings=await send('settings',{settings:patch});render();feedback('Settings saved.');}catch(e){feedback(e.message,true);}}
async function inspect(){if(tabId===null)return;busy=true;render();feedback('');try{await send('scan',{tabId,force:true});}catch(e){feedback(e.message,true);}finally{busy=false;await load();}}
async function providerCheck(provider,c){
  const token=state.page?.token,id=tabId;
  try{
    if(provider==='wpscan'&&!state.keys.wpscan?.configured){feedback('Add your WPScan API key in Settings first.',true);section('settings');return;}
    const granted=await chrome.permissions.request({origins:[PROVIDERS[provider].origin]});if(!granted)return;
    feedback('Checking '+PROVIDERS[provider].name+'…');const data=await send(provider,{tabId:id,key:c.key});if(token!==state.page?.token||id!==tabId)return;
    manualResults.set(c.key,{provider,data});renderStack();feedback('Provider check complete. Results appear under the component.');
  }catch(e){feedback(e.message,true);}
}
function observation(){const p=state.page;return {tool:'TRFFN VulnWatch',version:'0.2.0',notice:'Passive observations and affected-version matches. Exploitability unverified. Top-level document only.',origin:p?.origin,observedAt:p?.finished?new Date(p.finished).toISOString():null,components:p?.components||[],coverage:{headers:p?.headersAvailable,runtime:p?.runtimeAvailable,resourceLimit:p?.limited}};}
async function copyObservation(){try{await navigator.clipboard.writeText(JSON.stringify(observation(),null,2));feedback('Observation copied. Temporary provider results and keys are excluded.');}catch{feedback('Clipboard access unavailable. Use Export JSON instead.',true);}}
function exportObservation(){const blob=new Blob([JSON.stringify(observation(),null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='vulnwatch-observation-'+new Date().toISOString().slice(0,10)+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
let currentTabHost='',currentTabOrigin=null;
async function selectTab(){
  if(pinned)return;
  const tabs=await chrome.tabs.query({active:true,windowId});const tab=tabs[0];
  if(tab&&/^https?:/.test(tab.url||'')){tabId=tab.id;const u=new URL(tab.url);currentTabHost=u.host;currentTabOrigin=u.origin;}
  else {tabId=null;currentTabHost='Open a website to inspect';currentTabOrigin=null;}
  await load();
}
const permissionPattern=origin=>{const u=new URL(origin);return u.protocol+'//'+u.hostname+'/*';};
document.querySelectorAll('[data-tab]').forEach(b=>b.addEventListener('click',()=>section(b.dataset.tab)));
document.querySelectorAll('[data-theme]').forEach(b=>b.addEventListener('click',()=>saveSettings({theme:b.dataset.theme})));
$('save-pd-team').addEventListener('click',()=>saveSettings({projectDiscoveryTeamId:$('pd-team').value}));
$('filter').addEventListener('input',renderStack);$('scan').addEventListener('click',inspect);
$('open-panel').addEventListener('click',()=>{chrome.sidePanel.open({windowId}).then(()=>window.close()).catch(e=>feedback(e.message,true));});
$('pin').addEventListener('click',()=>{pinned=!pinned;$('pin').setAttribute('aria-pressed',String(pinned));$('pin').textContent=pinned?'Unpin tab':'Pin tab';if(!pinned)selectTab().catch(e=>feedback(e.message,true));else render();});
for(const [id,key] of [['display','interfaceMode'],['frequency','updateFrequency'],['threshold','alertThreshold']])$(id).addEventListener('change',e=>saveSettings({[key]:e.target.value}));
for(const [id,key] of [['watch','watchEnabled'],['osv','osvEnabled'],['auto-update','autoUpdate']])$(id).addEventListener('change',e=>saveSettings({[key]:e.target.checked}));
$('notifications').addEventListener('change',async e=>{let on=e.target.checked;try{if(on)on=await chrome.permissions.request({permissions:['notifications']});await saveSettings({notifications:on});}catch(error){feedback(error.message,true);}});
$('save-excluded').addEventListener('click',()=>{const entries=$('excluded').value.split('\n').map(v=>v.trim()).filter(Boolean);try{for(const value of entries){const u=new URL(value);if(!['http:','https:'].includes(u.protocol)||u.username||u.password)throw new Error();}saveSettings({exclusions:entries});}catch{feedback('Use HTTP or HTTPS origins, one per line.',true);}});
for(const [id,all] of [['allow-site',false],['allow-all',true]])$(id).addEventListener('click',async()=>{try{if(!all&&!currentTabOrigin)return;const granted=await chrome.permissions.request({origins:all?['http://*/*','https://*/*']:[permissionPattern(currentTabOrigin)]});if(granted){await saveSettings({watchEnabled:true});feedback('Website access granted. Reload the website for automatic inspection and response headers.');await load();}}catch(e){feedback(e.message,true);}});
$('revoke-sites').addEventListener('click',async()=>{try{const origins=(await chrome.permissions.getAll()).origins.filter(p=>p!=='https://api.osv.dev/*'&&!Object.values(PROVIDERS).some(v=>v.origin===p));if(origins.length)await chrome.permissions.remove({origins});await saveSettings({watchEnabled:false});await load();feedback('Persistent website access revoked.');}catch(e){feedback(e.message,true);}});
$('refresh-data').addEventListener('click',async()=>{const b=$('refresh-data');b.disabled=true;try{const r=await send('refresh');await load();feedback(`Advisory refresh finished: ${r.updated} updated, ${r.failed} failed.`);}catch(e){feedback(e.message,true);}finally{b.disabled=false;}});
$('provider').addEventListener('change',()=>{$('api-key').value='';$('api-key').type='password';$('show-key').textContent='Show';$('show-key').setAttribute('aria-pressed','false');renderKeyStatus();});
$('show-key').addEventListener('click',()=>{const show=$('api-key').type==='password';$('api-key').type=show?'text':'password';$('show-key').textContent=show?'Hide':'Show';$('show-key').setAttribute('aria-pressed',String(show));});
$('save-key').addEventListener('click',async()=>{const provider=$('provider').value,value=$('api-key').value,storage=$('key-storage').value;try{if(!value.trim())throw new Error('Paste an API key first.');const granted=await chrome.permissions.request({origins:[PROVIDERS[provider].origin]});if(!granted)return;await send('saveKey',{provider,value,storage});$('api-key').value='';$('api-key').type='password';$('show-key').textContent='Show';await load();feedback('API key saved.');}catch(e){feedback(e.message,true);}});
$('test-key').addEventListener('click',async()=>{const b=$('test-key');b.disabled=true;try{const r=await send('testKey',{provider:$('provider').value});feedback(r.message+(r.remaining!==null&&r.remaining!==undefined?' Remaining requests: '+r.remaining:''));}catch(e){feedback(e.message,true);}finally{renderKeyStatus();}});
$('remove-key').addEventListener('click',async()=>{try{await send('removeKey',{provider:$('provider').value});$('api-key').value='';await load();feedback('API key removed.');}catch(e){feedback(e.message,true);}});
$('allow-provider').addEventListener('click',async()=>{try{await chrome.permissions.request({origins:[PROVIDERS[$('provider').value].origin]});await load();}catch(e){feedback(e.message,true);}});
$('revoke-provider').addEventListener('click',async()=>{try{await chrome.permissions.remove({origins:[PROVIDERS[$('provider').value].origin]});await load();feedback('Provider permission removed where separately granted. Broad website access may still cover this host.');}catch(e){feedback(e.message,true);}});
$('clear-data').addEventListener('click',async()=>{try{await send('clear');manualResults.clear();clearPD();await load();feedback('Observations, provider caches, and mutes cleared.');}catch(e){feedback(e.message,true);}});
chrome.storage.onChanged.addListener((changes)=>{if(changes['key:projectdiscovery']||changes.settings?.oldValue?.projectDiscoveryTeamId!==changes.settings?.newValue?.projectDiscoveryTeamId)clearPD();scheduleLoad();});
chrome.permissions.onRemoved.addListener(()=>{clearPD();scheduleLoad();});
chrome.tabs.onActivated.addListener(info=>{if(info.windowId===windowId&&!pinned&&view!=='settings')selectTab().catch(e=>feedback(e.message,true));});
chrome.tabs.onUpdated.addListener((id,change)=>{if(id===tabId&&(change.url||change.status==='complete')){if(pinned)load().catch(()=>{});else selectTab().catch(()=>{});}});
chrome.tabs.onRemoved.addListener(id=>{if(id===tabId){pinned=false;$('pin').setAttribute('aria-pressed','false');$('pin').textContent='Pin tab';selectTab().catch(()=>{});}});
(async()=>{windowId=(await chrome.windows.getCurrent()).id;section(activeSection);await selectTab();if(view!=='settings'&&tabId&&!state.page){busy=true;render();try{await send('scan',{tabId});}catch(e){feedback(e.message,true);}finally{busy=false;await load();}}})().catch(e=>feedback(e.message,true));
