export const LIBRARIES = Object.assign(Object.create(null), {
  jquery:['jQuery','jquery'], lodash:['Lodash','lodash'], underscore:['Underscore','underscore'],
  bootstrap:['Bootstrap','bootstrap'], moment:['Moment.js','moment'], angular:['AngularJS','angular'],
  vue:['Vue','vue'], react:['React','react'], 'react-dom':['React DOM','react-dom'], axios:['Axios','axios'],
  d3:['D3','d3'], handlebars:['Handlebars','handlebars'], dompurify:['DOMPurify','dompurify'],
  'chart.js':['Chart.js','chart.js'], 'highlight.js':['Highlight.js','highlight.js'], backbone:['Backbone','backbone'],
  sweetalert2:['SweetAlert2','sweetalert2'], marked:['Marked','marked'], '@angular/core':['Angular','@angular/core']
});
export function versionOf(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim().replace(/^v/, '');
  return /^\d{1,5}\.\d{1,5}(?:\.\d{1,5})?(?:-[0-9A-Za-z.-]{1,30})?(?:\+[0-9A-Za-z.-]{1,30})?$/.test(s) ? s : null;
}
export function exactPackageVersion(v) { return typeof v === 'string' && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(v); }
export function safeResource(raw, base) {
  try { const u = new URL(raw, base); if (!['http:', 'https:'].includes(u.protocol)) return null; return {url:u.origin+u.pathname, origin:u.origin, path:u.pathname, version:versionOf(u.searchParams.get('ver') || u.searchParams.get('version'))}; } catch { return null; }
}
const titleSlug = s => s.split('-').map(p=>p ? p[0].toUpperCase()+p.slice(1) : '').join(' ');
export function detect(snapshot = {}, runtime = [], headers = []) {
  const output = new Map();
  function add(id, name, category, version, signal, strong=false, origin='', kind='technology') {
    version=versionOf(version);
    const key=`${kind}:${id}@${version || '?'}`;
    if (!output.has(key)) output.set(key,{key,id,name,category,kind,version,package:LIBRARIES[id]?.[1] || null,ecosystem:LIBRARIES[id]?'npm':null,evidence:[],confidence:'inferred',strong:false});
    const c=output.get(key);
    if (!c.evidence.some(e=>e.signal===signal)) c.evidence.push({signal:String(signal).slice(0,600),origin,strong});
    c.evidence=c.evidence.slice(0,8);c.strong ||= Boolean(strong && version);
    c.confidence=c.strong?(c.evidence.filter(e=>e.strong).length>1?'corroborated':'reported'):'inferred';
  }
  for (const row of Array.isArray(runtime)?runtime.slice(0,30):[]) {
    if (!LIBRARIES[row?.id] || !versionOf(row.version)) continue;
    add(row.id,LIBRARIES[row.id][0],'JavaScript',row.version,`${String(row.signal).slice(0,100)} = ${row.version}`,true);
  }
  for (const g of snapshot.generators || []) {
    const rules=[['wordpress','WordPress',/^WordPress\b(?:\s+([^\s;,]+))?/i],['drupal','Drupal',/^Drupal\b(?:\s+([^\s;,]+))?/i],['joomla','Joomla',/^Joomla!?\b(?:\s+([^\s;,]+))?/i],['ghost','Ghost',/^Ghost\b(?:\s+([^\s;,]+))?/i],['hugo','Hugo',/^Hugo\b(?:\s+([^\s;,]+))?/i],['wix','Wix',/^Wix/i],['squarespace','Squarespace',/^Squarespace/i]];
    for (const [id,name,re] of rules) { const m=String(g).match(re); if(m)add(id,name,'CMS',m[1],`Generator: ${g}`,true,'',id==='wordpress'?'wordpress-core':'technology'); }
  }
  for (const raw of snapshot.resources || []) {
    const r=safeResource(raw,snapshot.href);if(!r)continue;
    const path=r.path.toLowerCase();
    const wp=r.path.match(/\/wp-content\/(plugins|themes)\/([a-z0-9][a-z0-9_-]{0,80})\//i);
    if(wp){add('wordpress','WordPress','CMS',null,'WordPress asset path',false,r.origin,'wordpress-core');add(wp[2].toLowerCase(),titleSlug(wp[2]),wp[1]==='plugins'?'WordPress plugins':'WordPress themes',r.version,`${r.url}${r.version?' (asset version '+r.version+')':''}`,false,r.origin,wp[1]==='plugins'?'wordpress-plugin':'wordpress-theme');}
    if(path.includes('/wp-includes/'))add('wordpress','WordPress','CMS',null,'/wp-includes/ resource',false,r.origin,'wordpress-core');
    if(r.origin==='https://cdn.shopify.com'||r.origin.endsWith('.myshopify.com'))add('shopify','Shopify','Commerce',null,r.url,false,r.origin);
    if(path.includes('/_next/static/'))add('nextjs','Next.js','Framework',null,'/_next/static/ resource',false,r.origin);
    if(path.includes('/_nuxt/'))add('nuxt','Nuxt','Framework',null,'/_nuxt/ resource',false,r.origin);
    // Known package CDNs: use their package namespace, not a fuzzy substring.
    const host=new URL(r.url).hostname;
    let cdn=null;
    if(host==='cdn.jsdelivr.net')cdn=r.path.match(/^\/npm\/(@[^/]+\/[^/@]+|[^/@]+)@([^/]+)\//);
    if(host==='unpkg.com')cdn=r.path.match(/^\/(@[^/]+\/[^/@]+|[^/@]+)@([^/]+)(?:\/|$)/);
    if(cdn&&LIBRARIES[cdn[1]])add(cdn[1],LIBRARIES[cdn[1]][0],'JavaScript',cdn[2],r.url,true,r.origin);
    if(host==='cdnjs.cloudflare.com'){
      const m=r.path.match(/^\/ajax\/libs\/([^/]+)\/([^/]+)\//);const alias={'purify':'dompurify','Chart.js':'chart.js','angular.js':'angular'};const id=m&&(alias[m[1]]||m[1]);
      if(id&&LIBRARIES[id])add(id,LIBRARIES[id][0],'JavaScript',m[2],r.url,true,r.origin);
    }
    const file=path.split('/').pop() || '';
    for(const [id,[name]] of Object.entries(LIBRARIES)){
      const stem=id==='dompurify'?'purify':id==='chart.js'?'chart':id==='highlight.js'?'highlight':id;
      if(stem.includes('/'))continue;
      const escaped=stem.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
      const m=file.match(new RegExp('^'+escaped+'(?:[-.]v?(\\d+\\.\\d+(?:\\.\\d+)?))?(?:\\.min|\\.slim|\\.bundle|\\.production|\\.development|\\.umd)*(?:\\.js|\\.css)$','i'));
      if(m)add(id,name,'JavaScript',m[1]||r.version,r.url+(r.version?' (asset version '+r.version+')':''),false,r.origin);
    }
  }
  const markers=snapshot.markers||{};
  if(markers.next)add('nextjs','Next.js','Framework',null,'__NEXT_DATA__ / Next.js resource marker');
  if(markers.nuxt)add('nuxt','Nuxt','Framework',null,'Nuxt root / resource marker');
  if(markers.webflow)add('webflow','Webflow','CMS',null,'data-wf-site attribute');
  if(markers.drupal)add('drupal','Drupal','CMS',null,'data-drupal-selector attribute');
  if(markers.angular)add('@angular/core','Angular','Framework',markers.angular,'ng-version = '+markers.angular,true);
  for(const h of headers){
    const n=String(h.name).toLowerCase(),v=String(h.value||'').slice(0,250);
    if(n==='server'){
      for(const [id,name,re] of [['nginx','nginx',/\bnginx(?:\/([\d.]+))?/i],['apache','Apache',/\bApache(?:\/([\d.]+))?/i],['iis','Microsoft IIS',/\bMicrosoft-IIS(?:\/([\d.]+))?/i],['cloudflare','Cloudflare',/\bcloudflare\b/i]]){const m=v.match(re);if(m)add(id,name,'Server / edge',m[1],`Server: ${v}`,true);}
    }
    if(n==='x-powered-by'){
      const php=v.match(/\bPHP(?:\/([\d.]+))?/i);if(php)add('php','PHP','Language',php[1],`X-Powered-By: ${v}`,true);
      if(/\bExpress\b/i.test(v))add('express','Express','Framework',null,`X-Powered-By: ${v}`);
      if(/\bASP.NET\b/i.test(v))add('aspnet','ASP.NET','Framework',null,`X-Powered-By: ${v}`);
    }
  }
  if([...output.values()].some(c=>['wordpress','drupal','joomla'].includes(c.id)))add('php','PHP','Language',null,'Inferred from a PHP-based CMS');
  // Fold versionless clues into the only known version, but preserve distinct versions.
  for(const [key,c] of [...output])if(!c.version){const versions=[...output.values()].filter(v=>v.id===c.id&&v.kind===c.kind&&v.version);if(versions.length===1){versions[0].evidence.push(...c.evidence);versions[0].evidence=versions[0].evidence.slice(0,8);output.delete(key);}}
  return [...output.values()].sort((a,b)=>a.category.localeCompare(b.category)||a.name.localeCompare(b.name)).slice(0,80);
}
