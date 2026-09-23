export const PROVIDERS={
  wpscan:{name:'WPScan',origin:'https://wpscan.com/*'},
  github:{name:'GitHub',origin:'https://api.github.com/*'},
  nvd:{name:'NVD',origin:'https://services.nvd.nist.gov/*'}
};
const text=(s,max=1000)=>typeof s==='string'?s.slice(0,max):'';
export function safeLink(value){try{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password?u.href:null;}catch{return null;}}
export async function requestJSON(url, options={}){
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),10000);
  try{
    const response=await fetch(url,{...options,signal:controller.signal,credentials:'omit',referrerPolicy:'no-referrer',redirect:'error',cache:'no-store'});
    if(!response.ok){if([401,403].includes(response.status))throw new Error('Access denied. Check the API key, plan, and permissions.');if(response.status===429)throw new Error('Provider rate limit reached. Try again later.');throw new Error(`Provider returned HTTP ${response.status}.`);}
    const reader=response.body.getReader();let size=0;const parts=[];
    while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>2*1024*1024){await reader.cancel();throw new Error('Provider response exceeded the size limit.');}parts.push(value);}
    const buffer=new Uint8Array(size);let offset=0;for(const p of parts){buffer.set(p,offset);offset+=p.length;}return JSON.parse(new TextDecoder().decode(buffer));
  }catch(e){if(e.name==='AbortError')throw new Error('Provider request timed out.');if(e instanceof TypeError)throw new Error('Provider is unreachable. Check connectivity and site permissions.');if(e instanceof SyntaxError)throw new Error('Provider returned an invalid response.');throw e;}finally{clearTimeout(timer);}
}
function severity(v){const s=String(v||'').toUpperCase();return ['LOW','MODERATE','MEDIUM','HIGH','CRITICAL'].includes(s)?s==='MODERATE'?'MEDIUM':s:'UNKNOWN';}
export function normalizeOSV(data,component){
  if(!data||typeof data!=='object'||Array.isArray(data))throw new Error('Invalid OSV response.');
  if(data.vulns!==undefined&&!Array.isArray(data.vulns))throw new Error('Invalid OSV advisory list.');
  return (data.vulns||[]).filter(v=>!v.withdrawn&&v.affected?.some(a=>a.package?.name===component.package&&a.package?.ecosystem===component.ecosystem)).slice(0,100).map(v=>{
    const affected=v.affected.filter(a=>a.package?.name===component.package&&a.package?.ecosystem===component.ecosystem);
    const ranges=affected.flatMap(a=>(a.ranges||[]).map(r=>(r.events||[]).map(e=>e.introduced!==undefined?'introduced '+(e.introduced==='0'?'before first recorded release':e.introduced):e.fixed?'fixed '+e.fixed:e.last_affected?'last affected '+e.last_affected:e.limit?'limit '+e.limit:'').join('; ')));
    return {id:text(v.id,100),aliases:(v.aliases||[]).filter(a=>typeof a==='string').slice(0,20),title:text(v.summary||v.details||v.id,500),severity:severity(v.database_specific?.severity),ranges:ranges.slice(0,12),fixed:[...new Set(affected.flatMap(a=>(a.ranges||[]).flatMap(r=>(r.events||[]).filter(e=>e.fixed).map(e=>text(e.fixed,60)))))],references:(v.references||[]).map(r=>safeLink(r.url)).filter(Boolean).slice(0,8),sources:['OSV'],modified:text(v.modified,50)};
  });
}
export function normalizeGitHub(data,component){
  if(!Array.isArray(data))throw new Error('Invalid GitHub response.');
  return data.filter(v=>!v.withdrawn_at&&v.vulnerabilities?.some(a=>a.package?.name===component.package&&a.package?.ecosystem==='npm')).map(v=>({id:text(v.ghsa_id,100),aliases:[v.cve_id].filter(Boolean),title:text(v.summary,500),severity:severity(v.severity),ranges:v.vulnerabilities.filter(a=>a.package?.name===component.package&&a.package?.ecosystem==='npm').map(a=>text(a.vulnerable_version_range,300)),fixed:v.vulnerabilities.filter(a=>a.package?.name===component.package&&a.package?.ecosystem==='npm').map(a=>a.first_patched_version).filter(Boolean),references:[safeLink(v.html_url)].filter(Boolean),sources:['GitHub'],modified:text(v.updated_at,50)}));
}
export function deduplicate(advisories){
  const groups=[];
  for(const original of advisories){
    const row={...original,aliases:[...(original.aliases||[])],sources:[...(original.sources||[])],references:[...(original.references||[])],ranges:[...(original.ranges||[])],fixed:[...(original.fixed||[])]};
    const ids=new Set([row.id,...row.aliases]);
    for(let i=groups.length-1;i>=0;i--){const g=groups[i];if([g.id,...g.aliases].some(id=>ids.has(id))){ids.add(g.id);g.aliases.forEach(id=>ids.add(id));for(const k of ['sources','references','ranges','fixed'])row[k]=[...new Set([...row[k],...g[k]])];if(row.severity==='UNKNOWN')row.severity=g.severity;groups.splice(i,1);}}
    row.aliases=[...ids].filter(id=>id!==row.id);groups.push(row);
  }
  return groups;
}
export async function fetchOSV(component){
  const data=await requestJSON('https://api.osv.dev/v1/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package:{ecosystem:component.ecosystem,name:component.package},version:component.version})});
  return {advisories:normalizeOSV(data,component),complete:!data.next_page_token&&(data.vulns?.length||0)<=100};
}
export async function fetchGitHub(component,key){
  const q=new URLSearchParams({ecosystem:'npm',affects:component.package+'@'+component.version,per_page:'100',type:'reviewed'});
  const data=await requestJSON('https://api.github.com/advisories?'+q,{headers:{Accept:'application/vnd.github+json',...(key?{Authorization:'Bearer '+key}:{})}});
  return {advisories:normalizeGitHub(data,component),complete:data.length<100};
}
export async function fetchWPScan(component,key){
  if(!key)throw new Error('Add a WPScan key in Settings first.');
  let path;
  if(component.kind==='wordpress-core'){
    if(!component.version)throw new Error('WordPress core version is unknown.');
    path='wordpresses/'+component.version.replace(/\./g,'');
  }else if(['wordpress-plugin','wordpress-theme'].includes(component.kind)&&/^[a-z0-9_-]+$/.test(component.id))path=(component.kind==='wordpress-plugin'?'plugins/':'themes/')+component.id;
  else throw new Error('This component is not supported by WPScan.');
  const data=await requestJSON('https://wpscan.com/api/v3/'+path,{headers:{Authorization:'Token token='+key}});
  const entries=Object.values(data||{}).filter(v=>v&&typeof v==='object');
  return {versionFiltered:component.kind==='wordpress-core',advisories:entries.flatMap(e=>e.vulnerabilities||[]).slice(0,100).map(v=>({id:text(v.id,100),title:text(v.title,500),fixed:text(v.fixed_in,60),url:safeLink('https://wpscan.com/vulnerability/'+encodeURIComponent(v.id)),cves:(v.references?.cve||[]).slice(0,5)}))};
}
export async function fetchNVD(cve,key){
  if(!/^CVE-\d{4}-\d{4,}$/.test(cve))throw new Error('A valid CVE identifier is required.');
  const data=await requestJSON('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='+encodeURIComponent(cve),{headers:key?{apiKey:key}:{}});
  const c=data.vulnerabilities?.[0]?.cve;if(!c)return {description:'No NVD record returned.',severity:'UNKNOWN',score:null};
  const cvss=c.metrics?.cvssMetricV31?.[0]?.cvssData||c.metrics?.cvssMetricV30?.[0]?.cvssData||c.metrics?.cvssMetricV40?.[0]?.cvssData;
  return {description:text(c.descriptions?.find(d=>d.lang==='en')?.value,1400),severity:severity(cvss?.baseSeverity),score:cvss?.baseScore??null,url:'https://nvd.nist.gov/vuln/detail/'+cve};
}
export async function testProvider(provider,key){
  if(!key)throw new Error('Save a key first.');
  if(provider==='wpscan'){const data=await requestJSON('https://wpscan.com/api/v3/status',{headers:{Authorization:'Token token='+key}});return {message:'WPScan accepted the key.',remaining:data.requests_remaining??null};}
  if(provider==='github'){await requestJSON('https://api.github.com/rate_limit',{headers:{Authorization:'Bearer '+key,Accept:'application/vnd.github+json'}});return {message:'GitHub accepted the key.'};}
  if(provider==='nvd'){await requestJSON('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1',{headers:{apiKey:key}});return {message:'NVD request succeeded with this key.'};}
  throw new Error('Unknown provider.');
}
