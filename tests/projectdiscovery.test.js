import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeTemplates,normalizeFindings,fetchProjectDiscoveryTemplates,fetchProjectDiscoveryFindings,testProjectDiscovery,classification,hostname} from '../extension/core/projectdiscovery.js';
import {validateSettings} from '../extension/core/settings.js';
const CVE='CVE-2020-11022';
const template={id:'jquery-example',name:'Example metadata',severity:'high',classification:{'cve-id':[CVE],'cwe-id':['CWE-79'],'cvss-score':6.1,'epss-score':0.04},references:['https://example.test/advisory','javascript:alert(1)'],raw:'DO NOT RETAIN TEMPLATE BODY',template_type:'public'};
const finding={vuln_id:'finding-1',target:'https://example.test/path?token=private',created_at:'2026-09-01T00:00:00Z',vuln_status:'fixed',event:[{'matched-at':'https://example.test/private?secret=token',request:'PRIVATE REQUEST',response:'PRIVATE RESPONSE','extracted-results':['PRIVATE DATA'],info:{name:'Example finding',severity:'high',classification:template.classification}}]};
const results=data=>({data,total_results:data.length,total_pages:1,current_page:1});
const reply=data=>new Response(JSON.stringify(data));

test('PD template metadata requires exact CVE association and excludes bodies and private/draft rows',()=>{
 const r=normalizeTemplates({results:[template,{...template},{...template,id:'irrelevant',classification:{'cve-id':[CVE+'0']}},{...template,id:'private',template_type:'private'},{...template,id:'draft',is_draft:true},null],total:6},CVE);
 assert.equal(r.templates.length,1);assert.equal(r.templates[0].cvss,6.1);assert.equal(r.templates[0].epss,0.04);assert.deepEqual(r.templates[0].references,['https://example.test/advisory']);assert(!JSON.stringify(r).includes('DO NOT RETAIN'));assert.equal(r.complete,true);
});
test('PD never turns malformed or truncated responses into complete empty checks',()=>{
 for(const v of [null,{},[],{results:{}},{results:null}])assert.throws(()=>normalizeTemplates(v,CVE));
 assert.equal(normalizeTemplates({results:[],total:100},CVE).complete,false);
 assert.equal(normalizeTemplates({results:[]},CVE).complete,false);
 assert.equal(normalizeFindings({data:[],total_results:60,total_pages:2,current_page:1},'example.test').complete,false);
 assert.throws(()=>normalizeFindings({data:{}},'example.test'));
 const many=Array.from({length:51},(_,i)=>({...template,id:'id-'+i}));assert.equal(normalizeTemplates({results:many,total:51},CVE).templates.length,50);assert.equal(normalizeTemplates({results:many,total:51},CVE).complete,false);
});
test('PD findings retain exact hostname only and discard raw evidence and URLs',()=>{
 const sibling={...finding,vuln_id:'sibling',event:[{'matched-at':'https://sub.example.test',info:{}}]};
 const suffix={...finding,vuln_id:'suffix',event:[{'matched-at':'https://example.test.evil.test',info:{}}]};
 const spoof={...finding,vuln_id:'spoof',event:[{'matched-at':'https://example.test@evil.test',host:'https://example.test',info:{}}]};
 const r=normalizeFindings(results([finding,sibling,suffix,spoof,null,finding]),'EXAMPLE.TEST.');
 assert.equal(r.findings.length,1);assert.equal(r.findings[0].status,'fixed');assert.equal(r.findings[0].host,'example.test');
 for(const secret of ['PRIVATE','secret=','token=','https://example.test/path'])assert(!JSON.stringify(r).includes(secret));
});
test('PD findings allow bare-host records, normalize IPv6, and prefer match location',()=>{
 assert.equal(hostname('[::1]:8080'),'[::1]');assert.equal(hostname('EXAMPLE.TEST.:443'),'example.test');assert.equal(hostname('https://user:password@example.test'),null);
 assert.equal(hostname('javascript://example.test'),null);assert.equal(hostname('example.test\\@evil.test'),null);
 const r=normalizeFindings(results([{vuln_id:'bare',target:'example.test:443'}, {...finding,vuln_id:'redirect',target:'https://elsewhere.test',event:[{'matched-at':'https://example.test/path',host:'https://elsewhere.test'}]}]),'example.test');assert.equal(r.findings.length,2);
});
test('PD score validation preserves zero and rejects invalid ranges and wrong types',()=>{
 assert.equal(classification({'epss-score':0}).epss,0);assert.equal(classification({'epss-score':2}).epss,null);assert.equal(classification({'cvss-score':'9.8'}).cvss,null);assert.equal(classification({'cvss-score':NaN}).cvss,null);
 assert.equal(validateSettings({projectDiscoveryTeamId:' team_123 '}).projectDiscoveryTeamId,'team_123');assert.throws(()=>validateSettings({projectDiscoveryTeamId:'bad\nheader'}));
});
test('PD requests are read-only, send minimal query fields, and test only template access',async()=>{
 const calls=[];globalThis.fetch=async(url,options)=>{calls.push({url:new URL(url),options});return reply(String(url).includes('/scans/results')?results([finding]):{results:[template],total:1});};
 await fetchProjectDiscoveryTemplates(CVE,'dummy-key','team_123');
 await fetchProjectDiscoveryFindings('https://example.test/private?token=SECRET#hash','dummy-key','team_123');
 const r=await testProjectDiscovery('dummy-key');assert.match(r.message,/Cloud findings access depends/);
 assert.equal(calls[0].url.searchParams.get('scope'),'public');assert.equal(calls[0].url.searchParams.get('q'),CVE);assert(!calls[0].url.searchParams.get('fields').split(',').includes('raw'));
 assert.equal(calls[1].url.searchParams.get('domain'),'example.test');assert(!calls[1].url.href.includes('SECRET'));assert(!calls[1].url.href.includes('private'));
 for(const {options} of calls){assert.equal(options.method,undefined);assert.equal(options.headers['X-API-Key'],'dummy-key');assert.equal(options.credentials,'omit');assert.equal(options.redirect,'error');assert.equal(options.referrerPolicy,'no-referrer');assert(!options.body);}
 assert.equal(calls[0].options.headers['X-Team-Id'],'team_123');assert(!calls[2].options.headers['X-Team-Id']);
 await assert.rejects(fetchProjectDiscoveryTemplates('not-a-cve','dummy-key'));await assert.rejects(fetchProjectDiscoveryTemplates(CVE,''));
});
test('PD rate limits use Retry-After and suppress immediate repeated network calls',async()=>{
 let calls=0;globalThis.fetch=async()=>{calls++;return new Response('{}',{status:429,headers:{'Retry-After':'120'}});};
 await assert.rejects(fetchProjectDiscoveryTemplates(CVE,'dummy-key'),/rate limit/);await assert.rejects(fetchProjectDiscoveryFindings('https://example.test','dummy-key'),/Wait 1\d\d seconds/);assert.equal(calls,1);
});
