let snapshot={certificates:[]}, pending=false, selected=null;
const $=id=>document.getElementById(id);
const date=value=>new Date(value).toLocaleString(undefined,{dateStyle:'medium',timeStyle:'short'});
export function state(c,now=Date.now()){
 const hours=(new Date(c.expires)-now)/3600000;
 if(c.revoked)return {label:'Revoked',color:'red',invalid:true,time:hours<=0?'Expired':`${Math.ceil(hours/24)} days`};
 if(hours<=0)return {label:'Expired',color:'red',invalid:true,time:'Expired'};
 const future=new Date(c.validFrom)>now;
 return {label:future?'Not yet valid':hours>720?'Current':hours>=168?'Expires soon':'Expires within 7 days',color:hours>720?'green':hours>=168?'orange':'red',invalid:false,time:hours<1?'Less than 1 hour':hours<48?`${Math.floor(hours)} hours`:`${Math.floor(hours/24)} days`};
}
const key=c=>JSON.stringify([c.mount,c.serial]);
const title=c=>c.names[0]||c.subject||'Unnamed certificate';
function details(c){
 const s=state(c);
 $('details').hidden=false;
 $('mount').textContent=`${c.mount} / Certificate details`;
 $('subject').textContent=title(c);
 $('status').textContent=s.label;
 $('status').className=s.color;
 $('remaining').textContent=s.time;
 $('remaining').className=s.color;
 $('expires').textContent=`Expires: ${date(c.expires)}`;
 const fields=$('fields');fields.replaceChildren();
 for(const [name,value] of Object.entries({'Subject':c.subject,'Names':c.names.join(', ')||'None','Issuer':c.issuer,'Serial':c.serial,'Valid from':date(c.validFrom),'SHA-256 fingerprint':c.fingerprint})){
  const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=name;dd.textContent=value;fields.append(dt,dd);
 }
}
function render(){
 const query=$('search').value.trim().toLowerCase(),history=$('history').checked;
 const certs=snapshot.certificates.filter(c=>(history||!state(c).invalid)&&[c.subject,c.issuer,c.serial,...c.names].join(' ').toLowerCase().includes(query));
 const current=certs.find(c=>key(c)===selected)||certs[0];selected=current?key(current):null;
 const focused=document.activeElement.closest('#certificates button')?.dataset.key;
 const list=$('certificates'),scroll=list.scrollLeft;list.replaceChildren();
 for(const c of certs){
  const s=state(c),button=document.createElement('button');
  button.className='certificate';button.dataset.key=key(c);button.setAttribute('aria-pressed',String(key(c)===selected));
  const name=document.createElement('strong'),serial=document.createElement('span'),bottom=document.createElement('span'),time=document.createElement('span'),mount=document.createElement('span');
  name.textContent=title(c);serial.textContent=c.serial;serial.className='serial';bottom.className='list-bottom';time.textContent=`${s.label} · ${s.time}`;time.className=s.color;mount.textContent=c.mount;
  bottom.append(time,mount);button.append(name,serial,bottom);button.onclick=()=>{selected=key(c);render()};list.append(button);
  if(button.dataset.key===focused)button.focus({preventScroll:true});
 }
 list.scrollLeft=scroll;
 $('count').textContent=`${certs.length} of ${snapshot.certificates.length} certificates · Nearest expiry first`;
 $('empty').hidden=!!current;$('details').hidden=!current;
 $('empty').textContent=snapshot.lastSuccess?'No certificates match these filters.':'No certificate data is available yet.';
 if(current)details(current);
 $('sync').textContent=(snapshot.lastSuccess?`Last successful refresh: ${date(snapshot.lastSuccess)}`:'Waiting for the first successful refresh.')+(snapshot.refreshing?' Refresh in progress…':'');
 $('error').hidden=!snapshot.error;$('error').textContent=snapshot.error?`Refresh failed: ${snapshot.error}. Check Vault and the renewal Agent. The list keeps the last successful result.`:'';
 $('refresh').disabled=pending||snapshot.refreshing;
}
async function load(){try{const response=await fetch('/api/certificates');if(!response.ok)throw Error();snapshot=await response.json();render();}catch{ $('error').hidden=false;$('error').textContent='Cannot connect to the watcher. Check the container and try again.';}}
$('search').addEventListener('input',render);$('history').addEventListener('change',render);
$('refresh').onclick=async()=>{pending=true;render();try{const response=await fetch('/api/refresh',{method:'POST',headers:{'X-Watcher-Request':'refresh'}});if(!response.ok)throw Error();await load();}catch{$('error').hidden=false;$('error').textContent='Cannot start a refresh. Check the watcher connection.';}finally{pending=false;$('refresh').disabled=!!snapshot.refreshing;}};
load();setInterval(load,5000);
