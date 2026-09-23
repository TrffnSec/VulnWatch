export const DEFAULTS={theme:'auto',interfaceMode:'hybrid',watchEnabled:false,osvEnabled:true,autoUpdate:true,updateFrequency:'daily',notifications:false,alertThreshold:'all',exclusions:[]};
export function validateSettings(input,current=DEFAULTS){
  const next={...DEFAULTS,...current};
  for(const [key,allowed] of Object.entries({theme:['light','dark','auto'],interfaceMode:['popup','sidepanel','hybrid'],updateFrequency:['daily','weekly'],alertThreshold:['all','high']}))if(allowed.includes(input[key]))next[key]=input[key];
  for(const key of ['watchEnabled','osvEnabled','autoUpdate','notifications'])if(typeof input[key]==='boolean')next[key]=input[key];
  if(Array.isArray(input.exclusions))next.exclusions=[...new Set(input.exclusions.filter(x=>typeof x==='string').map(x=>{try{const u=new URL(x);return ['http:','https:'].includes(u.protocol)?u.origin:null;}catch{return null;}}).filter(Boolean))].slice(0,100);
  return next;
}
export function alertCount(components,threshold='all',muted=[]){
  return components.filter(c=>c.strong&&c.status==='checked'&&(c.advisories||[]).some(a=>!muted.includes(c.key+'|'+a.id)&&(threshold!=='high'||['HIGH','CRITICAL'].includes(a.severity)))).length;
}
