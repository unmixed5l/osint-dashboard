// Cloudflare Worker: holds API keys, fans out to OSINT sources, returns normalized JSON.
const J=(o,s,h)=>new Response(JSON.stringify(o),{status:s||200,headers:{'content-type':'application/json',...h}});
const detect=q=>/^(\d{1,3}\.){3}\d{1,3}$/.test(q)||/^[a-f0-9:]+:[a-f0-9:]+$/i.test(q)?'ip':
  /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(q)?'hash':/^https?:\/\/\S+$/i.test(q)?'url':
  /^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(q)?'domain':null;
const jget=async(u,o)=>{const r=await fetch(u,o);if(r.status===404)return null;if(!r.ok)throw new Error('HTTP '+r.status);return r.json()};
const need=k=>{if(!k)throw new Error('API key not configured');return k};

export default{async fetch(req,env){
  const cors={'access-control-allow-origin':env.ALLOWED_ORIGIN||'*','access-control-allow-headers':'content-type'};
  if(req.method==='OPTIONS')return new Response(null,{headers:cors});
  const q=(new URL(req.url).searchParams.get('q')||'').trim(),type=detect(q);
  if(!type)return J({error:'Enter a valid IP, domain, URL or hash'},400,cors);
  const host=type==='url'?new URL(q).hostname:q;

  const vt=async()=>{const p={ip:'ip_addresses/'+q,domain:'domains/'+q,hash:'files/'+q,
      url:'urls/'+btoa(q).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_')}[type];
    const d=await jget('https://www.virustotal.com/api/v3/'+p,{headers:{'x-apikey':need(env.VT_KEY)}});
    const link='https://www.virustotal.com/gui/search/'+encodeURIComponent(q);
    if(!d)return{verdict:'unknown',summary:{result:'Not seen by VirusTotal'},link};
    const a=d.data.attributes,s=a.last_analysis_stats||{},m=s.malicious||0,sus=s.suspicious||0;
    return{verdict:m>=3?'malicious':m+sus>0?'suspicious':'clean',link,summary:{
      malicious:m,suspicious:sus,harmless:s.harmless,undetected:s.undetected,reputation:a.reputation,
      owner:a.as_owner,country:a.country,registrar:a.registrar,name:a.meaningful_name,type:a.type_description,
      title:a.title}}};

  const abuse=async()=>{const d=await jget('https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress='+q,
      {headers:{Key:need(env.ABUSEIPDB_KEY),Accept:'application/json'}});const a=d.data,sc=a.abuseConfidenceScore;
    return{verdict:sc>=50?'malicious':sc>=10?'suspicious':'clean',link:'https://www.abuseipdb.com/check/'+q,
      summary:{'abuse score':sc+'%',reports:a.totalReports,'last reported':a.lastReportedAt,country:a.countryCode,
      isp:a.isp,usage:a.usageType,domain:a.domain,tor:a.isTor}}};

  const grey=async()=>{const d=await jget('https://api.greynoise.io/v3/community/'+q,{headers:{key:need(env.GREYNOISE_KEY)}});
    if(!d||d.message==='IP not observed scanning the internet or contained in RIOT data set.')
      return{verdict:'unknown',summary:{result:'Not observed by GreyNoise'},link:'https://viz.greynoise.io/ip/'+q};
    return{verdict:d.classification==='malicious'?'malicious':d.classification==='benign'?'clean':'suspicious',
      link:d.link,summary:{classification:d.classification,noise:d.noise,'common service (RIOT)':d.riot,name:d.name,'last seen':d.last_seen}}};

  const geo=async()=>{const d=await jget('https://ipwho.is/'+q);
    if(!d||!d.success)return{verdict:'unknown',summary:{result:'No geolocation data'}};
    return{verdict:'unknown',summary:{country:d.country,region:d.region,city:d.city,isp:d.connection?.isp,
      org:d.connection?.org,asn:d.connection?.asn,timezone:d.timezone?.id}}};

  const rdap=async()=>{const d=await jget('https://rdap.org/domain/'+host);
    if(!d)return{verdict:'unknown',summary:{result:'No RDAP record'}};
    const ev=Object.fromEntries((d.events||[]).map(e=>[e.eventAction,e.eventDate?.slice(0,10)]));
    const reg=(d.entities||[]).find(e=>(e.roles||[]).includes('registrar'));
    const fn=reg?.vcardArray?.[1]?.find(x=>x[0]==='fn')?.[3];
    const age=ev.registration?Math.floor((Date.now()-new Date(ev.registration))/864e5):null;
    return{verdict:age!==null&&age<30?'suspicious':'unknown',summary:{domain:d.ldhName,registrar:fn,registered:ev.registration,
      'age (days)':age,expires:ev.expiration,updated:ev['last changed'],status:(d.status||[]).join(', '),
      nameservers:(d.nameservers||[]).map(n=>n.ldhName).join(', ')}}};

  const urlhaus=async()=>{const d=await jget('https://urlhaus-api.abuse.ch/v1/url/',{method:'POST',
      headers:{'Auth-Key':need(env.ABUSECH_KEY),'content-type':'application/x-www-form-urlencoded'},body:'url='+encodeURIComponent(q)});
    const link='https://urlhaus.abuse.ch/browse.php?search='+encodeURIComponent(q);
    if(!d||d.query_status!=='ok')return{verdict:'unknown',summary:{result:'Not listed in URLhaus'},link};
    return{verdict:'malicious',link,summary:{status:d.url_status,threat:d.threat,tags:(d.tags||[]).join(', '),'date added':d.date_added}}};

  const bazaar=async()=>{const d=await jget('https://mb-api.abuse.ch/api/v1/',{method:'POST',
      headers:{'Auth-Key':need(env.ABUSECH_KEY),'content-type':'application/x-www-form-urlencoded'},body:'query=get_info&hash='+q});
    const link='https://bazaar.abuse.ch/sample/'+q;
    if(!d||d.query_status!=='ok')return{verdict:'unknown',summary:{result:'Not in MalwareBazaar'},link};
    const x=d.data[0];return{verdict:'malicious',link,summary:{family:x.signature,'file name':x.file_name,type:x.file_type,
      tags:(x.tags||[]).join(', '),'first seen':x.first_seen}}};

  const news=async()=>{const t=type==='url'||type==='domain'?host:q,
      r=await fetch('https://news.google.com/rss/search?hl=en&q='+encodeURIComponent(`"${t}" (malware OR breach OR attack OR phishing)`));
    const x=await r.text(),tag=(s,n)=>(s.match(new RegExp(`<${n}>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?</${n}>`))||[])[1]||'';
    return(x.match(/<item>[\s\S]*?<\/item>/g)||[]).slice(0,6).map(i=>({title:tag(i,'title'),link:tag(i,'link'),date:tag(i,'pubDate')}))};

  const src={ip:{'VirusTotal':vt,'AbuseIPDB':abuse,'GreyNoise':grey,'IP geolocation':geo},
    domain:{'VirusTotal':vt,'RDAP / WHOIS':rdap},url:{'VirusTotal':vt,'URLhaus':urlhaus,'RDAP / WHOIS':rdap},
    hash:{'VirusTotal':vt,'MalwareBazaar':bazaar}}[type];
  const [results,nw]=await Promise.all([
    Promise.all(Object.entries(src).map(async([source,fn])=>{try{return{source,...await fn()}}
      catch(e){return{source,verdict:'error',summary:{error:e.message}}}})),
    news().catch(()=>[])]);
  return J({query:q,type,results,news:nw},200,cors)}};
