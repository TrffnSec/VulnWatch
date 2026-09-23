import {requestJSON,safeLink} from './intel.js';

const API='https://api.projectdiscovery.io';
const LIMIT=50;
const text=(value,max=500)=>typeof value==='string'?value.slice(0,max):'';
const list=value=>Array.isArray(value)?value:[];
const record=value=>value&&typeof value==='object'&&!Array.isArray(value);
const cvePattern=/^CVE-\d{4}-\d{4,}$/;
const number=(value,max)=>typeof value==='number'&&Number.isFinite(value)&&value>=0&&value<=max?value:null;
const severity=value=>['info','low','medium','high','critical'].includes(value)?value.toUpperCase():'UNKNOWN';
let blockedUntil=0;

export function classification(value){
  const c=record(value)?value:{};
  return {cves:list(c['cve-id']).filter(v=>typeof v==='string'&&cvePattern.test(v)).slice(0,10),cwes:list(c['cwe-id']).filter(v=>typeof v==='string'&&/^CWE-\d+$/.test(v)).slice(0,10),cvss:number(c['cvss-score'],10),epss:number(c['epss-score'],1)};
}
function headers(key,teamId){
  if(!key)throw new Error('Add a ProjectDiscovery API key in Settings first.');
  if(teamId&&!/^[a-zA-Z0-9_-]{1,128}$/.test(teamId))throw new Error('Invalid ProjectDiscovery workspace ID.');
  return {'X-API-Key':key,Accept:'application/json',...(teamId?{'X-Team-Id':teamId}:{})};
}
async function request(path,params,key,teamId){
  if(Date.now()<blockedUntil)throw new Error('ProjectDiscovery rate limit reached. Wait '+Math.ceil((blockedUntil-Date.now())/1000)+' seconds before retrying.');
  try{return await requestJSON(API+path+'?'+new URLSearchParams(params),{headers:headers(key,teamId)});}
  catch(e){if(e.status===429)blockedUntil=Date.now()+e.retryAfterMs;throw e;}
}
export function normalizeTemplates(data,cve){
  if(!record(data)||!Array.isArray(data.results))throw new Error('Invalid ProjectDiscovery template response.');
  const seen=new Set(),templates=[];
  for(const row of data.results.slice(0,LIMIT)){
    if(!record(row)||row.is_draft===true||row.template_type==='private')continue;
    const info=classification(row.classification),id=text(row.template_id||row.id,150);
    if(!id||seen.has(id)||(!info.cves.includes(cve)&&id!==cve))continue;
    seen.add(id);
    templates.push({id,title:text(row.name)||id,description:text(row.description,800),severity:severity(row.severity),...info,references:list(row.references).map(safeLink).filter(Boolean).slice(0,5)});
  }
  return {templates,complete:Number.isInteger(data.total)&&data.total>=0&&data.total<=data.results.length&&data.results.length<=LIMIT};
}
export async function fetchProjectDiscoveryTemplates(cve,key,teamId=''){
  if(typeof cve!=='string'||!cvePattern.test(cve))throw new Error('A valid CVE identifier is required.');
  // Request descriptive metadata only, never template bodies or executable content.
  const data=await request('/v2/template/search',{q:cve,scope:'public',limit:String(LIMIT),offset:'0',fields:'id,template_id,name,description,severity,classification,references,template_type,is_draft'},key,teamId);
  return normalizeTemplates(data,cve);
}
export async function testProjectDiscovery(key,teamId=''){
  const data=await request('/v2/template/search',{q:'CVE-2020-11022',scope:'public',limit:'1',fields:'id'},key,teamId);
  if(!record(data)||!Array.isArray(data.results))throw new Error('Invalid ProjectDiscovery template response.');
  return {message:'ProjectDiscovery template access succeeded. Cloud findings access depends on your account and workspace.'};
}
export function hostname(value){
  if(typeof value!=='string'||!value||value.length>4096||/[\s\\]/.test(value))return null;
  try{const u=new URL(value.includes('://')?value:'https://'+value);return ['http:','https:'].includes(u.protocol)&&!u.username&&!u.password?u.hostname.toLowerCase().replace(/\.$/,''):null;}catch{return null;}
}
export function normalizeFindings(data,host){
  if(!record(data)||!Array.isArray(data.data))throw new Error('Invalid ProjectDiscovery findings response.');
  const wanted=hostname(host);if(!wanted)throw new Error('Invalid hostname.');
  const findings=[],seen=new Set();
  for(const row of data.data.slice(0,LIMIT)){
    if(!record(row))continue;
    const events=list(row.event).filter(record);
    // Prefer the event's actual match location. Never match domain suffixes or sibling hosts.
    const matched=events.filter(e=>hostname(e['matched-at']||e.host||row.target)===wanted);
    if(events.length&&!matched.length)continue;
    if(!events.length&&hostname(row.target)!==wanted)continue;
    const event=matched[0]||{},info=record(event.info)?event.info:{};
    const id=text(row.vuln_id,150);if(!id||seen.has(id))continue;seen.add(id);
    findings.push({id,title:text(info.name)||text(row.template_id,150)||'Cloud finding',host:wanted,templateId:text(row.template_id||event['template-id'],150),severity:severity(info.severity),status:text(row.vuln_status,60)||'Unspecified',createdAt:text(row.created_at,50),updatedAt:text(row.updated_at,50),observedAt:text(event.timestamp,50),...classification(info.classification)});
  }
  return {findings,complete:Number.isInteger(data.total_results)&&data.total_results>=0&&data.total_results<=data.data.length&&data.data.length<=LIMIT&&!(data.total_pages>data.current_page),host:wanted};
}
export async function fetchProjectDiscoveryFindings(origin,key,teamId=''){
  const u=new URL(origin);if(!['http:','https:'].includes(u.protocol)||u.username||u.password)throw new Error('An HTTP or HTTPS page is required.');
  const host=hostname(u.origin);
  // domain is a provider-side candidate filter; exact hostname filtering is mandatory locally.
  const data=await request('/v1/scans/results',{domain:host,limit:String(LIMIT),offset:'0',sort_desc:'created_at',severity:'info,unknown,low,medium,high,critical',asset_metadata:'false'},key,teamId);
  return normalizeFindings(data,host);
}
