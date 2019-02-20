#include "MPU9150.h"
#include "Si1132.h"
#include "Si70xx.h"
#include "math.h"
#include "Particle.h"
#include "softap_http.h"
#include "JsonParserGeneratorRK.h"


struct Page
{
    const char* url;
    const char* mime_type;
    const char* data;
};


const char index_html[] = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width, initial-scale=1'><title>Setup your device</title><link rel='stylesheet' type='text/css' href='style.css'></head><body><h1>Connect me to your WiFi!</h1><h3>My device ID:</h3><input type=text id='device-id' size='25' value='' disabled/><button type='button' class='input-helper' id='copy-button'>Copy</button><div id='scan-div'><h3>Scan for visible WiFi networks</h3><button id='scan-button' type='button'>Scan</button></div><div id='networks-div'></div><div id='connect-div' style='display: none'><p>Don't see your network? Move me closer to your router, then re-scan.</p><form id='connect-form'><input type='password' id='password' size='25' placeholder='password'/><button type='button' class='input-helper' id='show-button'>Show</button><button type='submit' id='connect-button'>Connect</button></form></div><script src='rsa-utils/jsbn_1.js'></script><script src='rsa-utils/jsbn_2.js'></script><script src='rsa-utils/prng4.js'></script><script src='rsa-utils/rng.js'></script><script src='rsa-utils/rsa.js'></script><script src='script.js'></script></body></html>";

const char rsa_js[] = "function parseBigInt(a,b){return new BigInteger(a,b);}function linebrk(a,b){var c='';var d=0;while(d+b<a.length){c+=a.substring(d,d+b)+'\\n';d+=b;}return c+a.substring(d,a.length);}function byte2Hex(a){if(a<0x10)return '0'+a.toString(16);else return a.toString(16);}function pkcs1pad2(a,b){if(b<a.length+11){alert('Message too long for RSA');return null;}var c=new Array();var d=a.length-1;while(d>=0&&b>0){var e=a.charCodeAt(d--);if(e<128)c[--b]=e;else if((e>127)&&(e<2048)){c[--b]=(e&63)|128;c[--b]=(e>>6)|192;}else{c[--b]=(e&63)|128;c[--b]=((e>>6)&63)|128;c[--b]=(e>>12)|224;}}c[--b]=0;var f=new SecureRandom();var g=new Array();while(b>2){g[0]=0;while(g[0]==0)f.nextBytes(g);c[--b]=g[0];}c[--b]=2;c[--b]=0;return new BigInteger(c);}function RSAKey(){this.n=null;this.e=0;this.d=null;this.p=null;this.q=null;this.dmp1=null;this.dmq1=null;this.coeff=null;}function RSASetPublic(a,b){if(a!=null&&b!=null&&a.length>0&&b.length>0){this.n=parseBigInt(a,16);this.e=parseInt(b,16);}else alert('Invalid RSA public key');}function RSADoPublic(a){return a.modPowInt(this.e,this.n);}function RSAEncrypt(a){var b=pkcs1pad2(a,(this.n.bitLength()+7)>>3);if(b==null)return null;var c=this.doPublic(b);if(c==null)return null;var d=c.toString(16);if((d.length&1)==0)return d;else return '0'+d;}RSAKey.prototype.doPublic=RSADoPublic;RSAKey.prototype.setPublic=RSASetPublic;RSAKey.prototype.encrypt=RSAEncrypt;";

const char style_css[] = "html{height:100%;margin:auto;background-color:white}body{box-sizing:border-box;min-height:100%;padding:20px;background-color:#1aabe0;font-family:'Lucida Sans Unicode','Lucida Grande',sans-serif;font-weight:normal;color:white;margin-top:0;margin-left:auto;margin-right:auto;margin-bottom:0;max-width:400px;text-align:center;border:1px solid #6e6e70;border-radius:4px}div{margin-top:25px;margin-bottom:25px}h1{margin-top:25px;margin-bottom:25px}button{border-color:#1c75be;background-color:#1c75be;color:white;border-radius:5px;height:30px;font-size:15px;font-weight:bold}button.input-helper{background-color:#bebebe;border-color:#bebebe;color:#6e6e70;margin-left:3px}button:disabled{background-color:#bebebe;border-color:#bebebe;color:white}input[type='text'],input[type='password']{background-color:white;color:#6e6e70;border-color:white;border-radius:5px;height:25px;text-align:center;font-size:15px}input:disabled{background-color:#bebebe;border-color:#bebebe}input[type='radio']{position:relative;bottom:-0.33em;margin:0;border:0;height:1.5em;width:15%}label{padding-top:7px;padding-bottom:7px;padding-left:5%;display:inline-block;width:80%;text-align:left}input[type='radio']:checked+label{font-weight:bold;color:#1c75be}.scanning-error{font-weight:bold;text-align:center}.radio-div{box-sizing:border-box;margin:2px;margin-left:auto;margin-right:auto;background-color:white;color:#6e6e70;border:1px solid #6e6e70;border-radius:3px;width:100%;padding:5px}#networks-div{margin-left:auto;margin-right:auto;text-align:left}#device-id{text-align:center}#scan-button{min-width:100px}#connect-button{display:block;min-width:100px;margin-top:10px;margin-left:auto;margin-right:auto;margin-bottom:20px}#password{margin-top:20px;margin-bottom:10px}";

const char rng_js[] = "var rng_state;var rng_pool;var rng_pptr;function rng_seed_int(a){rng_pool[rng_pptr++]^=a&255;rng_pool[rng_pptr++]^=(a>>8)&255;rng_pool[rng_pptr++]^=(a>>16)&255;rng_pool[rng_pptr++]^=(a>>24)&255;if(rng_pptr>=rng_psize)rng_pptr-=rng_psize;}function rng_seed_time(){rng_seed_int(new Date().getTime());}if(rng_pool==null){rng_pool=new Array();rng_pptr=0;var t;if(window.crypto&&window.crypto.getRandomValues){var ua=new Uint8Array(32);window.crypto.getRandomValues(ua);for(t=0;t<32;++t)rng_pool[rng_pptr++]=ua[t];}if(navigator.appName=='Netscape'&&navigator.appVersion<'5'&&window.crypto){var z=window.crypto.random(32);for(t=0;t<z.length;++t)rng_pool[rng_pptr++]=z.charCodeAt(t)&255;}while(rng_pptr<rng_psize){t=Math.floor(65536*Math.random());rng_pool[rng_pptr++]=t>>>8;rng_pool[rng_pptr++]=t&255;}rng_pptr=0;rng_seed_time();}function rng_get_byte(){if(rng_state==null){rng_seed_time();rng_state=prng_newstate();rng_state.init(rng_pool);for(rng_pptr=0;rng_pptr<rng_pool.length;++rng_pptr)rng_pool[rng_pptr]=0;rng_pptr=0;}return rng_state.next();}function rng_get_bytes(a){var b;for(b=0;b<a.length;++b)a[b]=rng_get_byte();}function SecureRandom(){}SecureRandom.prototype.nextBytes=rng_get_bytes;";

const char jsbn_2_js[] = "function bnpRShiftTo(a,b){b.s=this.s;var c=Math.floor(a/this.DB);if(c>=this.t){b.t=0;return;}var d=a%this.DB;var e=this.DB-d;var f=(1<<d)-1;b[0]=this[c]>>d;for(var g=c+1;g<this.t;++g){b[g-c-1]|=(this[g]&f)<<e;b[g-c]=this[g]>>d;}if(d>0)b[this.t-c-1]|=(this.s&f)<<e;b.t=this.t-c;b.clamp();}function bnpSubTo(a,b){var c=0,d=0,e=Math.min(a.t,this.t);while(c<e){d+=this[c]-a[c];b[c++]=d&this.DM;d>>=this.DB;}if(a.t<this.t){d-=a.s;while(c<this.t){d+=this[c];b[c++]=d&this.DM;d>>=this.DB;}d+=this.s;}else{d+=this.s;while(c<a.t){d-=a[c];b[c++]=d&this.DM;d>>=this.DB;}d-=a.s;}b.s=(d<0)?-1:0;if(d<-1)b[c++]=this.DV+d;else if(d>0)b[c++]=d;b.t=c;b.clamp();}function bnpMultiplyTo(a,b){var c=this.abs(),d=a.abs();var e=c.t;b.t=e+d.t;while(--e>=0)b[e]=0;for(e=0;e<d.t;++e)b[e+c.t]=c.am(0,d[e],b,e,0,c.t);b.s=0;b.clamp();if(this.s!=a.s)BigInteger.ZERO.subTo(b,b);}function bnpSquareTo(a){var b=this.abs();var c=a.t=2*b.t;while(--c>=0)a[c]=0;for(c=0;c<b.t-1;++c){var d=b.am(c,b[c],a,2*c,0,1);if((a[c+b.t]+=b.am(c+1,2*b[c],a,2*c+1,d,b.t-c-1))>=b.DV){a[c+b.t]-=b.DV;a[c+b.t+1]=1;}}if(a.t>0)a[a.t-1]+=b.am(c,b[c],a,2*c,0,1);a.s=0;a.clamp();}function bnpDivRemTo(a,b,c){var d=a.abs();if(d.t<=0)return;var e=this.abs();if(e.t<d.t){if(b!=null)b.fromInt(0);if(c!=null)this.copyTo(c);return;}if(c==null)c=nbi();var f=nbi(),g=this.s,h=a.s;var i=this.DB-nbits(d[d.t-1]);if(i>0){d.lShiftTo(i,f);e.lShiftTo(i,c);}else{d.copyTo(f);e.copyTo(c);}var j=f.t;var k=f[j-1];if(k==0)return;var l=k*(1<<this.F1)+((j>1)?f[j-2]>>this.F2:0);var m=this.FV/l,n=(1<<this.F1)/l,o=1<<this.F2;var p=c.t,q=p-j,r=(b==null)?nbi():b;f.dlShiftTo(q,r);if(c.compareTo(r)>=0){c[c.t++]=1;c.subTo(r,c);}BigInteger.ONE.dlShiftTo(j,r);r.subTo(f,f);while(f.t<j)f[f.t++]=0;while(--q>=0){var s=(c[--p]==k)?this.DM:Math.floor(c[p]*m+(c[p-1]+o)*n);if((c[p]+=f.am(0,s,c,q,0,j))<s){f.dlShiftTo(q,r);c.subTo(r,c);while(c[p]<--s)c.subTo(r,c);}}if(b!=null){c.drShiftTo(j,b);if(g!=h)BigInteger.ZERO.subTo(b,b);}c.t=j;c.clamp();if(i>0)c.rShiftTo(i,c);if(g<0)BigInteger.ZERO.subTo(c,c);}function bnMod(a){var b=nbi();this.abs().divRemTo(a,null,b);if(this.s<0&&b.compareTo(BigInteger.ZERO)>0)a.subTo(b,b);return b;}function Classic(a){this.m=a;}function cConvert(a){if(a.s<0||a.compareTo(this.m)>=0)return a.mod(this.m);else return a;}function cRevert(a){return a;}function cReduce(a){a.divRemTo(this.m,null,a);}function cMulTo(a,b,c){a.multiplyTo(b,c);this.reduce(c);}function cSqrTo(a,b){a.squareTo(b);this.reduce(b);}Classic.prototype.convert=cConvert;Classic.prototype.revert=cRevert;Classic.prototype.reduce=cReduce;Classic.prototype.mulTo=cMulTo;Classic.prototype.sqrTo=cSqrTo;function bnpInvDigit(){if(this.t<1)return 0;var a=this[0];if((a&1)==0)return 0;var b=a&3;b=(b*(2-(a&0xf)*b))&0xf;b=(b*(2-(a&0xff)*b))&0xff;b=(b*(2-(((a&0xffff)*b)&0xffff)))&0xffff;b=(b*(2-a*b%this.DV))%this.DV;return(b>0)?this.DV-b:-b;}function Montgomery(a){this.m=a;this.mp=a.invDigit();this.mpl=this.mp&0x7fff;this.mph=this.mp>>15;this.um=(1<<(a.DB-15))-1;this.mt2=2*a.t;}function montConvert(a){var b=nbi();a.abs().dlShiftTo(this.m.t,b);b.divRemTo(this.m,null,b);if(a.s<0&&b.compareTo(BigInteger.ZERO)>0)this.m.subTo(b,b);return b;}function montRevert(a){var b=nbi();a.copyTo(b);this.reduce(b);return b;}function montReduce(a){while(a.t<=this.mt2)a[a.t++]=0;for(var b=0;b<this.m.t;++b){var c=a[b]&0x7fff;var d=(c*this.mpl+(((c*this.mph+(a[b]>>15)*this.mpl)&this.um)<<15))&a.DM;c=b+this.m.t;a[c]+=this.m.am(0,d,a,b,0,this.m.t);while(a[c]>=a.DV){a[c]-=a.DV;a[++c]++;}}a.clamp();a.drShiftTo(this.m.t,a);if(a.compareTo(this.m)>=0)a.subTo(this.m,a);}function montSqrTo(a,b){a.squareTo(b);this.reduce(b);}function montMulTo(a,b,c){a.multiplyTo(b,c);this.reduce(c);}Montgomery.prototype.convert=montConvert;Montgomery.prototype.revert=montRevert;Montgomery.prototype.reduce=montReduce;Montgomery.prototype.mulTo=montMulTo;Montgomery.prototype.sqrTo=montSqrTo;function bnpIsEven(){return((this.t>0)?(this[0]&1):this.s)==0;}function bnpExp(a,b){if(a>0xffffffff||a<1)return BigInteger.ONE;var c=nbi(),d=nbi(),e=b.convert(this),f=nbits(a)-1;e.copyTo(c);while(--f>=0){b.sqrTo(c,d);if((a&(1<<f))>0)b.mulTo(d,e,c);else{var g=c;c=d;d=g;}}return b.revert(c);}function bnModPowInt(a,b){var c;if(a<256||b.isEven())c=new Classic(b);else c=new Montgomery(b);return this.exp(a,c);}BigInteger.prototype.copyTo=bnpCopyTo;BigInteger.prototype.fromInt=bnpFromInt;BigInteger.prototype.fromString=bnpFromString;BigInteger.prototype.clamp=bnpClamp;BigInteger.prototype.dlShiftTo=bnpDLShiftTo;BigInteger.prototype.drShiftTo=bnpDRShiftTo;BigInteger.prototype.lShiftTo=bnpLShiftTo;BigInteger.prototype.rShiftTo=bnpRShiftTo;BigInteger.prototype.subTo=bnpSubTo;BigInteger.prototype.multiplyTo=bnpMultiplyTo;BigInteger.prototype.squareTo=bnpSquareTo;BigInteger.prototype.divRemTo=bnpDivRemTo;BigInteger.prototype.invDigit=bnpInvDigit;BigInteger.prototype.isEven=bnpIsEven;BigInteger.prototype.exp=bnpExp;BigInteger.prototype.toString=bnToString;BigInteger.prototype.negate=bnNegate;BigInteger.prototype.abs=bnAbs;BigInteger.prototype.compareTo=bnCompareTo;BigInteger.prototype.bitLength=bnBitLength;BigInteger.prototype.mod=bnMod;BigInteger.prototype.modPowInt=bnModPowInt;BigInteger.ZERO=nbv(0);BigInteger.ONE=nbv(1);";

const char jsbn_1_js[] = "var dbits;var canary=0xdeadbeefcafe;var j_lm=((canary&0xffffff)==0xefcafe);function BigInteger(a,b,c){if(a!=null)if('number'==typeof a)this.fromNumber(a,b,c);else if(b==null&&'string'!=typeof a)this.fromString(a,256);else this.fromString(a,b);}function nbi(){return new BigInteger(null);}function am1(a,b,c,d,e,f){while(--f>=0){var g=b*this[a++]+c[d]+e;e=Math.floor(g/0x4000000);c[d++]=g&0x3ffffff;}return e;}function am2(a,b,c,d,e,f){var g=b&0x7fff,h=b>>15;while(--f>=0){var i=this[a]&0x7fff;var j=this[a++]>>15;var k=h*i+j*g;i=g*i+((k&0x7fff)<<15)+c[d]+(e&0x3fffffff);e=(i>>>30)+(k>>>15)+h*j+(e>>>30);c[d++]=i&0x3fffffff;}return e;}function am3(a,b,c,d,e,f){var g=b&0x3fff,h=b>>14;while(--f>=0){var i=this[a]&0x3fff;var j=this[a++]>>14;var k=h*i+j*g;i=g*i+((k&0x3fff)<<14)+c[d]+e;e=(i>>28)+(k>>14)+h*j;c[d++]=i&0xfffffff;}return e;}if(j_lm&&(navigator.appName=='Microsoft Internet Explorer')){BigInteger.prototype.am=am2;dbits=30;}else if(j_lm&&(navigator.appName!='Netscape')){BigInteger.prototype.am=am1;dbits=26;}else{BigInteger.prototype.am=am3;dbits=28;}BigInteger.prototype.DB=dbits;BigInteger.prototype.DM=((1<<dbits)-1);BigInteger.prototype.DV=(1<<dbits);var BI_FP=52;BigInteger.prototype.FV=Math.pow(2,BI_FP);BigInteger.prototype.F1=BI_FP-dbits;BigInteger.prototype.F2=2*dbits-BI_FP;var BI_RM='0123456789abcdefghijklmnopqrstuvwxyz';var BI_RC=new Array();var rr,vv;rr='0'.charCodeAt(0);for(vv=0;vv<=9;++vv)BI_RC[rr++]=vv;rr='a'.charCodeAt(0);for(vv=10;vv<36;++vv)BI_RC[rr++]=vv;rr='A'.charCodeAt(0);for(vv=10;vv<36;++vv)BI_RC[rr++]=vv;function int2char(a){return BI_RM.charAt(a);}function intAt(a,b){var c=BI_RC[a.charCodeAt(b)];return(c==null)?-1:c;}function bnpCopyTo(a){for(var b=this.t-1;b>=0;--b)a[b]=this[b];a.t=this.t;a.s=this.s;}function bnpFromInt(a){this.t=1;this.s=(a<0)?-1:0;if(a>0)this[0]=a;else if(a<-1)this[0]=a+this.DV;else this.t=0;}function nbv(a){var b=nbi();b.fromInt(a);return b;}function bnpFromString(a,b){var c;if(b==16)c=4;else if(b==8)c=3;else if(b==256)c=8;else if(b==2)c=1;else if(b==32)c=5;else if(b==4)c=2;else{this.fromRadix(a,b);return;}this.t=0;this.s=0;var d=a.length,e=false,f=0;while(--d>=0){var g=(c==8)?a[d]&0xff:intAt(a,d);if(g<0){if(a.charAt(d)=='-')e=true;continue;}e=false;if(f==0)this[this.t++]=g;else if(f+c>this.DB){this[this.t-1]|=(g&((1<<(this.DB-f))-1))<<f;this[this.t++]=(g>>(this.DB-f));}else this[this.t-1]|=g<<f;f+=c;if(f>=this.DB)f-=this.DB;}if(c==8&&(a[0]&0x80)!=0){this.s=-1;if(f>0)this[this.t-1]|=((1<<(this.DB-f))-1)<<f;}this.clamp();if(e)BigInteger.ZERO.subTo(this,this);}function bnpClamp(){var a=this.s&this.DM;while(this.t>0&&this[this.t-1]==a)--this.t;}function bnToString(a){if(this.s<0)return '-'+this.negate().toString(a);var b;if(a==16)b=4;else if(a==8)b=3;else if(a==2)b=1;else if(a==32)b=5;else if(a==4)b=2;else return this.toRadix(a);var c=(1<<b)-1,d,e=false,f='',g=this.t;var h=this.DB-(g*this.DB)%b;if(g-->0){if(h<this.DB&&(d=this[g]>>h)>0){e=true;f=int2char(d);}while(g>=0){if(h<b){d=(this[g]&((1<<h)-1))<<(b-h);d|=this[--g]>>(h+=this.DB-b);}else{d=(this[g]>>(h-=b))&c;if(h<=0){h+=this.DB;--g;}}if(d>0)e=true;if(e)f+=int2char(d);}}return e?f:'0';}function bnNegate(){var a=nbi();BigInteger.ZERO.subTo(this,a);return a;}function bnAbs(){return(this.s<0)?this.negate():this;}function bnCompareTo(a){var b=this.s-a.s;if(b!=0)return b;var c=this.t;b=c-a.t;if(b!=0)return(this.s<0)?-b:b;while(--c>=0)if((b=this[c]-a[c])!=0)return b;return 0;}function nbits(a){var b=1,c;if((c=a>>>16)!=0){a=c;b+=16;}if((c=a>>8)!=0){a=c;b+=8;}if((c=a>>4)!=0){a=c;b+=4;}if((c=a>>2)!=0){a=c;b+=2;}if((c=a>>1)!=0){a=c;b+=1;}return b;}function bnBitLength(){if(this.t<=0)return 0;return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));}function bnpDLShiftTo(a,b){var c;for(c=this.t-1;c>=0;--c)b[c+a]=this[c];for(c=a-1;c>=0;--c)b[c]=0;b.t=this.t+a;b.s=this.s;}function bnpDRShiftTo(a,b){for(var c=a;c<this.t;++c)b[c-a]=this[c];b.t=Math.max(this.t-a,0);b.s=this.s;}function bnpLShiftTo(a,b){var c=a%this.DB;var d=this.DB-c;var e=(1<<d)-1;var f=Math.floor(a/this.DB),g=(this.s<<c)&this.DM,h;for(h=this.t-1;h>=0;--h){b[h+f+1]=(this[h]>>d)|g;g=(this[h]&e)<<c;}for(h=f-1;h>=0;--h)b[h]=0;b[f]=g;b.t=this.t+f+1;b.s=this.s;b.clamp();}";

const char script_js[] = "var base_url='http://192.168.0.1/';var network_list;var public_key;var rsa=new RSAKey();var scanButton=document.getElementById('scan-button');var connectButton=document.getElementById('connect-button');var copyButton=document.getElementById('copy-button');var showButton=document.getElementById('show-button');var deviceID=document.getElementById('device-id');var connectForm=document.getElementById('connect-form');var public_key_callback={success:function(a){console.log('Public key: '+a.b);public_key=a.b;rsa.setPublic(public_key.substring(58,58+256),public_key.substring(318,318+6));},error:function(a,b){console.log(a);window.alert('There was a problem fetching important information from your device. Please verify your connection, then reload this page.');}};var device_id_callback={success:function(a){var b=a.id;deviceID.value=b;},error:function(a,b){console.log(a);var c='COMMUNICATION_ERROR';deviceID.value=c;}};var scan=function(){console.log('Scanning...!');disableButtons();scanButton.innerHTML='Scanning...';connectButton.innerHTML='Connect';document.getElementById('connect-div').style.display='none';document.getElementById('networks-div').style.display='none';getRequest(base_url+'scan-ap',scan_callback);};var scan_callback={success:function(a){network_list=a.scans;console.log('I found:');var b=document.getElementById('networks-div');b.innerHTML='';if(network_list.length>0)for(var c=0;c<network_list.length;c++){ssid=network_list[c].ssid;console.log(network_list[c]);add_wifi_option(b,ssid);document.getElementById('connect-div').style.display='block';}else b.innerHTML='<p class=\\'scanning-error\\'>No networks found.</p>';},error:function(a){console.log('Scanning error:'+a);document.getElementById('networks-div').innerHTML='<p class=\\'scanning-error\\'>Scanning error.</p>';},regardless:function(){scanButton.innerHTML='Re-Scan';enableButtons();document.getElementById('networks-div').style.display='block';}};var configure=function(a){a.preventDefault();var b=get_selected_network();var c=document.getElementById('password').value;if(!b){window.alert('Please select a network!');return false;}var d={idx:0,ssid:b.ssid,pwd:rsa.encrypt(c),sec:b.sec,ch:b.ch};connectButton.innerHTML='Sending credentials...';disableButtons();console.log('Sending credentials: '+JSON.stringify(d));postRequest(base_url+'configure-ap',d,configure_callback);};var configure_callback={success:function(a){console.log('Credentials received.');connectButton.innerHTML='Credentials received...';postRequest(base_url+'connect-ap',{idx:0},connect_callback);},error:function(a,b){console.log('Configure error: '+a);window.alert('The configuration command failed, check that you are still well connected to the device\\'s WiFi hotspot and retry.');connectButton.innerHTML='Retry';enableButtons();}};var connect_callback={success:function(a){console.log('Attempting to connect to the cloud.');connectButton.innerHTML='Attempting to connect...';window.alert('Your device should now start flashing green and attempt to connect to the cloud. This usually takes about 20 seconds, after which it will begin slowly blinking cyan. \\n\\n\\nIf this process fails because you entered the wrong password, the device will flash green indefinitely. In this case, hold the setup button for 6 seconds until the device starts blinking blue again. Then reconnect to the WiFi hotspot it generates and reload this page to try again.');},error:function(a,b){console.log('Connect error: '+a);window.alert('The connect command failed, check that you are still well connected to the device\\'s WiFi hotspot and retry.');connectButton.innerHTML='Retry';enableButtons();}};var disableButtons=function(){connectButton.disabled=true;scanButton.disabled=true;};var enableButtons=function(){connectButton.disabled=false;scanButton.disabled=false;};var add_wifi_option=function(a,b){var c=document.createElement('INPUT');c.type='radio';c.value=b;c.id=b;c.name='ssid';c.className='radio';var d=document.createElement('DIV');d.className='radio-div';d.appendChild(c);var e=document.createElement('label');e.htmlFor=b;e.innerHTML=b;d.appendChild(e);a.appendChild(d);};var get_selected_network=function(){for(var a=0;a<network_list.length;a++){ssid=network_list[a].ssid;if(document.getElementById(ssid).checked)return network_list[a];}};var copy=function(){window.prompt('Copy to clipboard: Ctrl + C, Enter',deviceID.value);};var toggleShow=function(){var a=document.getElementById('password');inputType=a.type;if(inputType==='password'){showButton.innerHTML='Hide';a.type='text';}else{showButton.innerHTML='Show';a.type='password';}};var getRequest=function(a,b){var c=new XMLHttpRequest();c.open('GET',a,true);c.timeout=8000;c.send();c.onreadystatechange=function(){if(c.readyState==4)if(b){if(c.status==200){if(b.success)b.success(JSON.parse(c.responseText));}else if(b.error)b.error(c.status,c.responseText);if(b.regardless)b.regardless();}};};var postRequest=function(a,b,c){var d=JSON.stringify(b);var e=new XMLHttpRequest();e.open('POST',a,true);e.timeout=4000;e.setRequestHeader('Content-Type','multipart/form-data');e.send(d);e.onreadystatechange=function(){if(e.readyState==4)if(c){if(e.status==200){if(c.success)c.success(JSON.parse(e.responseText));}else if(c.error)c.error(e.status,e.responseText);if(c.regardless)c.regardless();}};};if(scanButton.addEventListener){copyButton.addEventListener('click',copy);showButton.addEventListener('click',toggleShow);scanButton.addEventListener('click',scan);connectForm.addEventListener('submit',configure);}else if(scanButton.attachEvent){copyButton.attachEvent('onclick',copy);showButton.attachEvent('onclick',toggleShow);scanButton.attachEvent('onclick',scan);connectForm.attachEvent('onsubmit',configure);}getRequest(base_url+'device-id',device_id_callback);getRequest(base_url+'public-key',public_key_callback);";

const char prng4_js[] = "function Arcfour(){this.i=0;this.j=0;this.S=new Array();}function ARC4init(a){var b,c,d;for(b=0;b<256;++b)this.S[b]=b;c=0;for(b=0;b<256;++b){c=(c+this.S[b]+a[b%a.length])&255;d=this.S[b];this.S[b]=this.S[c];this.S[c]=d;}this.i=0;this.j=0;}function ARC4next(){var a;this.i=(this.i+1)&255;this.j=(this.j+this.S[this.i])&255;a=this.S[this.i];this.S[this.i]=this.S[this.j];this.S[this.j]=a;return this.S[(a+this.S[this.i])&255];}Arcfour.prototype.init=ARC4init;Arcfour.prototype.next=ARC4next;function prng_newstate(){return new Arcfour();}var rng_psize=256;";

Page myPages[] = {
     { "/index.html", "text/html", index_html },
     { "/rsa-utils/rsa.js", "application/javascript", rsa_js },
     { "/style.css", "text/css", style_css },
     { "/rsa-utils/rng.js", "application/javascript", rng_js },
     { "/rsa-utils/jsbn_2.js", "application/javascript", jsbn_2_js },
     { "/rsa-utils/jsbn_1.js", "application/javascript", jsbn_1_js },
     { "/script.js", "application/javascript", script_js },
     { "/rsa-utils/prng4.js", "application/javascript", prng4_js },
     { nullptr }
};

void myPage(const char* url, ResponseCallback* cb, void* cbArg, Reader* body, Writer* result, void* reserved)
{
    Serial.printlnf("handling page %s", url);

    if (strcmp(url,"/index")==0) {
        Serial.println("sending redirect");
        Header h("Location: /index.html\r\n");
        cb(cbArg, 0, 301, "text/plain", &h);
        return;
    }

    int8_t idx = 0;
    for (;;idx++) {
        Page& p = myPages[idx];
        if (!p.url) {
            idx = -1;
            break;
        }
        else if (strcmp(url, p.url)==0) {
            break;
        }
    }

    if (idx==-1) {
        cb(cbArg, 0, 404, nullptr, nullptr);
    }
    else {
        cb(cbArg, 0, 200, myPages[idx].mime_type, nullptr);
        result->write(myPages[idx].data);
    }
}

STARTUP(softap_set_application_page_handler(myPage, nullptr));

// Press SETUP for 3 seconds to make the Photon enter Listening mode
// Navigate to http://192.168.0.1 to setup Wi-Fi

// Include the rest of your application below,
// including your setup and loop functions
//// SYSTEM_MODE(SEMI_AUTOMATIC);


//// ***************************************************************************

PRODUCT_ID(8726);
PRODUCT_VERSION(2);

//// Initialize application variables
#define RAD_TO_DEGREES 57.2957795131
#define DEG_TO_RADIANS 0.0174533
#define PI 3.1415926535
#define ACCEL_SCALE 2 // +/- 2g

int inputPin = D6;  // Digital Pin D6 is used to read the output of the PIR
                    // sensor. D6 goes HIGH when motion is detected and LOW when
                    // there's no motion. When the sensor goes HIGH, it waits for
                    // short period before it goes LOW


int sensorState = LOW;        // Start by assuming no motion detected
int sensorValue = 0;          // Variable for reading the inputPin (D6) status

int SENSORDELAY = 500;  //// 500; //3000; // milliseconds (runs x1)
int EVENTSDELAY = 1000; //// milliseconds (runs x10)
int OTAUPDDELAY = 7000; //// milliseconds (runs x1)
int SLEEP_DELAY = 0;    //// 40 seconds (runs x1) - should get about 24 hours on 2100mAH, 0 to disable and use RELAX_DELAY instead
String SLEEP_DELAY_MIN = "15"; // seconds - easier to store as string then convert to int
String SLEEP_DELAY_STATUS = "OK"; // always OK to start with
int RELAX_DELAY = 5; // seconds (runs x1) - no power impact, just idle/relaxing

// Variables for the I2C scan
byte I2CERR, I2CADR;

//// ***************************************************************************
//// ***************************************************************************

int I2CEN = D2;
int ALGEN = D3;
int LED = D7;

int SOUND = A0;
double SOUNDV = 0; //// Volts Peak-to-Peak Level/Amplitude

int POWR1 = A1;
int POWR2 = A2;
int POWR3 = A3;
double POWR1V = 0; //Watts
double POWR2V = 0; //Watts
double POWR3V = 0; //Watts

int SOILT = A4;
double SOILTV = 0; //// Celsius: temperature (C) = Vout*41.67-40 :: Temperature (F) = Vout*75.006-40

int SOILH = A5;
double SOILHV = 0; //// Volumetric Water Content (VWC): http://www.vegetronix.com/TechInfo/How-To-Measure-VWC.phtml

bool BMP180OK = false;
double BMP180Pressure = 0;    //// hPa
double BMP180Temperature = 0; //// Celsius
double BMP180Altitude = 0;    //// Meters

bool Si7020OK = false;
double Si7020Temperature = 0; //// Celsius
double Si7020Humidity = 0;    //// %Relative Humidity

bool Si1132OK = false;
double Si1132UVIndex = 0; //// UV Index scoring is as follows: 1-2  -> Low, 3-5  -> Moderate, 6-7  -> High, 8-10 -> Very High, 11+  -> Extreme
double Si1132Visible = 0; //// Lux
double Si1132InfraRd = 0; //// Lux

MPU9150 mpu9150;
bool ACCELOK = false;
int cx, cy, cz, ax, ay, az, gx, gy, gz;
double tm; //// Celsius

const unsigned long PUBLISH_PERIOD_MS = 3600000;
const unsigned long FIRST_PUBLISH_MS = 5000;
unsigned long lastPublish = FIRST_PUBLISH_MS - PUBLISH_PERIOD_MS;

String deviceName = "", zoneName = "", itemName = "";
String soundMessage = "Sound has been detected";
String motionMessage = "Motion has been detected";
bool namePublished = false;
bool ZONE_DATA_ON = false;
bool INTERACTION_ON = false;
bool motionDetection = false;
bool bulbsON = false;
int motionCounter = 0;
int soundCounter = 0;
const int INTERACTION_THRESHOLD = 1000;
const int INTERACTION_FIN_COUNT = 5; // loops before an interaction is finished;

String triggers[25][4];
int triggerCount = 0;

String wifiJSON;
bool firstJson;
int positioncounter;
WiFiAccessPoint ap[10];

bool tempSensorOn = false;
bool humSensorOn = false;
bool lightSensorOn = false;
bool motionSensorOn = false;
bool soundSensorOn = false;
bool accelerometerOn = false;

bool tempSensorActive = true;
bool humSensorActive = true;
bool lightSensorActive = true;
bool motionSensorActive = true;
bool soundSensorActive = true;
bool accelerometerActive = true;


int sensorsTestCounter = 0;
//// ***************************************************************************

float mapFloat(float x, float in_min, float in_max, float out_min, float out_max)
{
  return (x - in_min) * (out_max - out_min) / (in_max - in_min) + out_min;
}

void setPinsMode()
{
    pinMode(I2CEN, OUTPUT);
    pinMode(ALGEN, OUTPUT);
    pinMode(LED, OUTPUT);

    pinMode(SOUND, INPUT);

    pinMode(POWR1, INPUT);
    pinMode(POWR2, INPUT);
    pinMode(POWR3, INPUT);

    pinMode(SOILT, INPUT);
    pinMode(SOILH, INPUT);
    pinMode(LED, OUTPUT);         // Sets pin connected to photon LED as output
    pinMode(inputPin, INPUT);     // Sets inputPin as an INPUT
}

void setup()
{
    // opens serial over USB
    Serial.begin(9600);

    int found = WiFi.getCredentials(ap, 10);

    // Set I2C speed
    // 400Khz seems to work best with the Photon with the packaged I2C sensors
    Wire.setSpeed(CLOCK_SPEED_400KHZ);

    Wire.begin();  // Start up I2C, required for LSM303 communication

    // diables interrupts
    noInterrupts();

    // initialises the IO pins
    setPinsMode();

    // initialises MPU9150 inertial measure unit
    initialiseMPU9150();

    //get the device name
    Particle.subscribe("particle/device/name", getDeviceName);
    Particle.publish("particle/device/name");

    Particle.function("resetDevice", resetDevice);

    Particle.subscribe("sensorsTest", getSensorStatus);
    String triggerEventString = "trigger";
    triggerEventString = triggerEventString + System.deviceID();
    Particle.subscribe(triggerEventString, registerTrigger);
    String test = "";

    digitalWrite(LED, LOW);       // Turns LED OFF, i.e. start by assuming no motion
    getSensorStatus("","");
}

void getDeviceName(const char *topic, const char *data){
  char dev_name[32] = "";
  strncpy(dev_name, data, sizeof(dev_name) - 1);
  char *firstPart, *secondPart;
  char i_name[16] = "";
  deviceName = dev_name;

  firstPart = strtok(dev_name, "_");
  secondPart = strtok(NULL, "_");

  if(strstr(firstPart, "Zone") != NULL){
    ZONE_DATA_ON = true;
    zoneName = firstPart;
  } else if(strstr(firstPart, "Interaction") != NULL){
    INTERACTION_ON = true;
    strcpy(i_name, firstPart + 11);
    itemName = i_name;
  }

  if(strstr(secondPart, "Zone") != NULL){
    ZONE_DATA_ON = true;
    zoneName = secondPart;
  } else if(strstr(secondPart, "Interaction") != NULL){
    INTERACTION_ON = true;
    strcpy(i_name, secondPart + 11);
    itemName = i_name;
  }

  namePublished = true;
}

void getSensorStatus(const char *topic, const char *data){
  tempSensorOn = false;
  humSensorOn = false;
  lightSensorOn = false;
  accelerometerOn = false;
  soundSensorOn = false;
  motionSensorOn = false;

  sensorsTestCounter = 10;
}
// Global parser that supports up to 256 bytes of data and 20 tokens
JsonParserStatic<256, 20> parser1;

void registerTrigger(const char *topic, const char *data){
  parser1.clear();
  parser1.addString(data);

  parser1.parse();
  String ifArray;
  String thenArray;
  char triggerIf[128];

  parser1.getOuterValueByKey("ifArray", ifArray);
  parser1.getOuterValueByKey("thenArray", thenArray);

  ifArray.replace("\"","");
  ifArray.toCharArray(triggerIf, 128);

  strtok(triggerIf,",");
  triggers[triggerCount][0] = strtok(NULL, ",");
  triggers[triggerCount][1] = strtok(NULL, ",") ;
  String tempStr = strtok(NULL, ",");
  tempStr.remove(tempStr.length()-1);
  triggers[triggerCount][2]  = tempStr;
  triggers[triggerCount][3] = thenArray;

  triggerCount++;
}


void initialiseMPU9150()
{
  ACCELOK = mpu9150.begin(mpu9150._addr_motion); // Initialize MPU9150

  if (ACCELOK)
  {
      // Clear the 'sleep' bit to start the sensor.
      mpu9150.writeSensor(mpu9150._addr_motion, MPU9150_PWR_MGMT_1, 0);

      /// Set up compass
      mpu9150.writeSensor(mpu9150._addr_compass, 0x0A, 0x00); //PowerDownMode
      mpu9150.writeSensor(mpu9150._addr_compass, 0x0A, 0x0F); //SelfTest
      mpu9150.writeSensor(mpu9150._addr_compass, 0x0A, 0x00); //PowerDownMode

      mpu9150.writeSensor(mpu9150._addr_motion, 0x24, 0x40); //Wait for Data at Slave0
      mpu9150.writeSensor(mpu9150._addr_motion, 0x25, 0x8C); //Set i2c address at slave0 at 0x0C
      mpu9150.writeSensor(mpu9150._addr_motion, 0x26, 0x02); //Set where reading at slave 0 starts
      mpu9150.writeSensor(mpu9150._addr_motion, 0x27, 0x88); //set offset at start reading and enable
      mpu9150.writeSensor(mpu9150._addr_motion, 0x28, 0x0C); //set i2c address at slv1 at 0x0C
      mpu9150.writeSensor(mpu9150._addr_motion, 0x29, 0x0A); //Set where reading at slave 1 starts
      mpu9150.writeSensor(mpu9150._addr_motion, 0x2A, 0x81); //Enable at set length to 1
      mpu9150.writeSensor(mpu9150._addr_motion, 0x64, 0x01); //overvride register
      mpu9150.writeSensor(mpu9150._addr_motion, 0x67, 0x03); //set delay rate
      mpu9150.writeSensor(mpu9150._addr_motion, 0x01, 0x80);

      mpu9150.writeSensor(mpu9150._addr_motion, 0x34, 0x04); //set i2c slv4 delay
      mpu9150.writeSensor(mpu9150._addr_motion, 0x64, 0x00); //override register
      mpu9150.writeSensor(mpu9150._addr_motion, 0x6A, 0x00); //clear usr setting
      mpu9150.writeSensor(mpu9150._addr_motion, 0x64, 0x01); //override register
      mpu9150.writeSensor(mpu9150._addr_motion, 0x6A, 0x20); //enable master i2c mode
      mpu9150.writeSensor(mpu9150._addr_motion, 0x34, 0x13); //disable slv4
    }
    else
    {
      Serial.println("Unable to start MPU5150");
    }
}

void wifi_scan_callback(WiFiAccessPoint* wap, void* data)
{
    WiFiAccessPoint& ap = *wap;
    String ssid = ap.ssid;
    int rssi = ap.rssi;

     if(positioncounter > 0){
       wifiJSON = wifiJSON + ",";
     }
     wifiJSON = wifiJSON + "\"" + positioncounter +"\":{\"ssid\":\"" + ssid + "\",\"rssi\":" + rssi + "}";
     positioncounter ++;
}

void displaywifi(String message)
{
  Particle.publish("wifiData", message, PRIVATE);
}

void loop(void)
{
    //// prints device version and address

    //Serial.print("Device version: "); Serial.println(System.version());
    //Serial.print("Device ID: "); Serial.println(System.deviceID());
    //Serial.print("WiFi IP: "); Serial.println(WiFi.localIP());

    //// ***********************************************************************

    //// powers up sensors
    digitalWrite(I2CEN, HIGH);
    digitalWrite(ALGEN, HIGH);

    //// allows sensors time to warm up
    delay(SENSORDELAY);     //// delay timer

    //// ***********************************************************************

    readMPU9150();          //// reads compass, accelerometer and gyroscope data
    readWeatherSi7020();    //// reads pressure and altitude sensor data
    readWeatherSi1132();    //// reads air temperaure and humidity sensor


    float pitch = getXTilt(ax, az);       //// returns device tilt along x-axis
    float roll =  getYTilt(ay,az);        //// returns device tilt along y-axis


    float accelX = getAccelX(ax);         //// returns scaled acceleration along x axis
    float accelY = getAccelY(ay);         //// returns scaled acceleration along y axis
    float accelZ = getAccelZ(az);         //// returns scaled acceleration along y axis
    float accelXYZ =  getAccelXYZ(ax, ay, az);   //returns the vector sum of the
                                          //acceleration along x, y and z axes


    //// reads and returns sound level
    float soundLevel = readSoundLevel();

    //wait for device name before starting
    while(!namePublished){
        Serial.printf("%s\n","Waiting for device name");
        delay(1000);
    }


    wifiJSON = "{";
    wifiJSON = wifiJSON + "\"zone\":\"" + deviceName + "\",";
    positioncounter = 0;
    int result_count = WiFi.scan(wifi_scan_callback);
    wifiJSON = wifiJSON + "}";

    collectSETData();

    if(sensorsTestCounter > 0){
      if(Si7020Temperature > 0) tempSensorOn = true;
      if(Si7020Humidity > 0) humSensorOn = true;
      if(Si1132Visible > 0) lightSensorOn = true;
      if(accelXYZ > 0) accelerometerOn = true;
      if(analogRead(SOUND) > 0) soundSensorOn = true;
      if(sensorValue == LOW) motionSensorOn = true;

      sensorsTestCounter--;
      if(sensorsTestCounter == 0){
        String testJSON = "";

        if(tempSensorOn)    testJSON = testJSON + "Temperature&";
        if(humSensorOn)     testJSON = testJSON + "Humidity&";
        if(lightSensorOn)   testJSON = testJSON + "Light&";
        if(accelerometerOn) testJSON = testJSON + "Acceleration&";
        if(soundSensorOn)   testJSON = testJSON + "Sound&";
        if(motionSensorOn)  testJSON = testJSON + "Motion&";

        testJSON.remove(testJSON.length() - 1);

        Particle.publish("sensorsList", testJSON, PRIVATE);
      }
    }
    checkTriggers();
    delay(3000);
}

int resetDevice(String bla){
  System.reset();
  return 0;
}

void checkTriggers(){

  for(int i = 0; i < triggerCount; i++){
    if(triggers[i][1] == "less than"){
      if(getSensorValue(triggers[i][0]) < triggers[i][2].toFloat()){
         triggerEvent(i);
         continue;
       }
    }else if(triggers[i][1] == "equals"){
      if(getSensorValue(triggers[i][0]) == triggers[i][2].toFloat()){
         triggerEvent(i);
         continue;
       }
    }else if(triggers[i][1] == "greater than"){
      if(getSensorValue(triggers[i][0]) > triggers[i][2].toFloat()){
         triggerEvent(i);
         continue;
       }
    }else if(triggers[i][1] == "greater than or equal to"){
      if(getSensorValue(triggers[i][0]) >= triggers[i][2].toFloat()){
         triggerEvent(i);
         continue;
       }
    }else if(triggers[i][1] == "less than or equal to"){
      if(getSensorValue(triggers[i][0]) <= triggers[i][2].toFloat()){
         triggerEvent(i);
         continue;
       }
    }
  }
}

double getSensorValue(String name){
  if(name == "Temperature") return Si7020Temperature;
  if(name == "Humidity") return Si7020Humidity;
  if(name == "Light") return Si1132Visible;
  if(name == "Motion") return sensorValue;
  if(name == "Sound") return readSoundLevel();
  if(name == "Accelaration") return getAccelXYZ(ax, ay, az);
}

void triggerEvent(int eventNum){
  Particle.publish("triggerEvent", triggers[eventNum][3], PRIVATE);
}

const String PUBLISH_EVENT_NAME = "publishData";
const String PUBLISH_INTERACTION_EVENT_NAME = "publishInteraction";
const String PUBLISH_DETECTION = "detectionData";

void collectSETData(){
    collectMoitionData();

    char *postDataJSON;
    String dataJSON = "{";

    if(tempSensorActive)    dataJSON = dataJSON + "\"Temperature\":"   + Si7020Temperature       + ",";
    if(humSensorActive)     dataJSON = dataJSON + "\"Humidity\":"    + Si7020Humidity          + ",";
    if(lightSensorActive)   dataJSON = dataJSON + "\"Light\":"   + Si1132Visible           + ",";
    if(motionSensorActive)  dataJSON = dataJSON + "\"Motion\":" + sensorValue   + ",";
    if(soundSensorActive)   dataJSON = dataJSON + "\"Sound\":"  + readSoundLevel()        + ",";
    if(accelerometerActive) dataJSON = dataJSON + "\"Acceleration\":"  + getAccelXYZ(ax, ay, az) + ",";

    dataJSON.remove(dataJSON.length() - 1);
    dataJSON = dataJSON + "}";
    Particle.publish("liveData", dataJSON, PRIVATE);
}

bool interacting = false;
int finCounter = 0;
int doorLightCounter = -1;
bool doorLightFlag = false;

void collectInteractionData(){
  if (interacting == false && (gx > INTERACTION_THRESHOLD
     || gy > INTERACTION_THRESHOLD || gz > INTERACTION_THRESHOLD)){ //device has started to be interacted with
     interacting = true;
     finCounter = 0;
     interactionPublish(itemName, false);
  } else if (interacting == true){
      if(gx < INTERACTION_THRESHOLD && gy < INTERACTION_THRESHOLD && gz < INTERACTION_THRESHOLD){
        finCounter++;
        if(finCounter >= INTERACTION_FIN_COUNT){
          interactionPublish(itemName, true);
          interacting = false;
          if(itemName == "Door"){
            Particle.subscribe("detectionData", doorLightHandler,MY_DEVICES);
            doorLightCounter = 15;
          }
        }
     } else {
       finCounter = 0;
     }
  }

  if(doorLightCounter-- == 0){
    Particle.unsubscribe();
    if(!doorLightFlag){
      actuatorPublish(0,"turn","off");
    }
    doorLightFlag = false;
  }
}

void doorLightHandler(const char *event, const char *data){
  actuatorPublish(0,"turn","on");
  doorLightFlag = true;
}

void interactionPublish(String itemName, boolean finish){
  String dbJSON = "";
  dbJSON = dbJSON + "{\"item\":\"" + itemName + "\"}";
  String cloudJSON = "";
  cloudJSON = cloudJSON + "{\"item\":\"" + itemName + "\",\"state\":";

  if(finish) {
    cloudJSON = cloudJSON + "\"finish\"}";
    Particle.publish(PUBLISH_INTERACTION_EVENT_NAME, dbJSON, PRIVATE);
  } else {
    cloudJSON = cloudJSON + "\"start\"}";
  }
  Particle.publish("interactionLive", cloudJSON, PRIVATE);
}

void detectionPublish(String type, String state){
  String detJSON = "";
  detJSON = detJSON + "{\"zone\":\""+zoneName+"\",\"type\":\""+type+"\",\"state\":\"" + state + "\"}";
  Particle.publish(PUBLISH_DETECTION, detJSON, PRIVATE);
}

void readMPU9150()
{
    //// reads the MPU9150 sensor values. Values are read in order of temperature,
    //// compass, Gyro, Accelerometer

    tm = ( (double) mpu9150.readSensor(mpu9150._addr_motion, MPU9150_TEMP_OUT_L, MPU9150_TEMP_OUT_H) + 12412.0 ) / 340.0;
    cx = mpu9150.readSensor(mpu9150._addr_motion, MPU9150_CMPS_XOUT_L, MPU9150_CMPS_XOUT_H);  //Compass_X
    cy = mpu9150.readSensor(mpu9150._addr_motion, MPU9150_CMPS_YOUT_L, MPU9150_CMPS_YOUT_H);  //Compass_Y
    cz = mpu9150.readSensor(mpu9150._addr_motion, MPU9150_CMPS_ZOUT_L, MPU9150_CMPS_ZOUT_H);  //Compass_Z
    ax = mpu9150.readSensor(mpu9150._addr_motion, MPU9150_ACCEL_XOUT_L, MPU9150_ACCEL_XOUT_H);
    ay = mpu9150.readSensor(mpu9150._addr_motion, MPU9150_ACCEL_YOUT_L, MPU9150_ACCEL_YOUT_H);
    az = mpu9150.readSensor(mpu9150._addr_motion, MPU9150_ACCEL_ZOUT_L, MPU9150_ACCEL_ZOUT_H);
    gx = mpu9150.readSensor(mpu9150._addr_motion, MPU9150_GYRO_XOUT_L, MPU9150_GYRO_XOUT_H);
    gy = mpu9150.readSensor(mpu9150._addr_motion, MPU9150_GYRO_YOUT_L, MPU9150_GYRO_YOUT_H);
    gz = mpu9150.readSensor(mpu9150._addr_motion, MPU9150_GYRO_ZOUT_L, MPU9150_GYRO_ZOUT_H);
}


//// returns air temperature and humidity
int readWeatherSi7020()
{
    Si70xx si7020;
    Si7020OK = si7020.begin(); //// initialises Si7020

    if (Si7020OK)
    {
        Si7020Temperature = si7020.readTemperature();
        Si7020Humidity = si7020.readHumidity();
    }

    return Si7020OK ? 2 : 0;
}


//// returns measurements of UV, InfraRed and Ambient light
int readWeatherSi1132()
{
    Si1132 si1132;
    Si1132OK = si1132.begin(); //// initialises Si1132

    if (Si1132OK)
    {
        Si1132UVIndex = si1132.readUV() / 100;
        Si1132Visible = si1132.readVisible();  ////0 to 1000 Lux
        Si1132InfraRd = si1132.readIR();
    }

    return Si1132OK ? 3 : 0;
}

//// returns accelaration along x-axis, should be 0-1g
float getAccelX(float x)
{
  return x/pow(2,15)*ACCEL_SCALE;
}

//// returns accelaration along z-axis, should be 0-1g
float getAccelY(float y)
{
  return y/pow(2,15)*ACCEL_SCALE;
}

//// returns accelaration along z-axis should be 0-1g
float getAccelZ(float z)
{
  return z/pow(2,15)*ACCEL_SCALE;
}

//// returns the vector sum of the acceleration along x, y and z axes
//// in g units
float getAccelXYZ(float x, float y, float z)
{
  x = getAccelX(x);
  y = getAccelY(y);
  z = getAccelZ(z);

  return sqrt(x*x+y*y+z*z);
}

//// returns tilt along x axis in radians - uses accelerometer
float getXTilt(float accelX, float accelZ)
{
   float tilt = atan2(accelX,accelZ)*RAD_TO_DEGREES; //*RAD_TO_DEGREES;
   if(tilt < 0)
   {
      tilt = tilt+360.0;
   }

   return tilt;
}

//// returns tilt along y-axis in radians
float getYTilt(float accelY, float accelZ)
{
   float tilt = atan2(accelY,accelZ)*RAD_TO_DEGREES;
   if(tilt < 0)
   {
     tilt = tilt+360.0;
   }

   return tilt;
}

//returns sound level measurement in as voltage values (0 to 3.3v)
float readSoundLevel()
{
    unsigned int sampleWindow = 50; // Sample window width in milliseconds (50 milliseconds = 20Hz)
    unsigned long endWindow = millis() + sampleWindow;  // End of sample window

    unsigned int signalSample = 0;
    unsigned int signalMin = 4095; // Minimum is the lowest signal below which we assume silence
    unsigned int signalMax = 0; // Maximum signal starts out the same as the Minimum signal

    // collect data for milliseconds equal to sampleWindow
    while (millis() < endWindow)
    {
        signalSample = analogRead(SOUND);
        if (signalSample > signalMax)
        {
            signalMax = signalSample;  // save just the max levels
        }
        else if (signalSample < signalMin)
        {
            signalMin = signalSample;  // save just the min levels
        }
    }

    //SOUNDV = signalMax - signalMin;  // max - min = peak-peak amplitude
    SOUNDV = mapFloat((signalMax - signalMin), 0, 4095, 0, 3.3);

    //return 1;
    return SOUNDV;
}

void collectMoitionData(){
  sensorValue = digitalRead(inputPin);  // Reads sensor output connected to pin D6

  if (sensorValue == HIGH)              // If the input pin is HIGH turn LED ON
  {
    digitalWrite(LED, HIGH);
    if (sensorState == LOW) //Checks if sensor state has changed from its previous state
     {
       sensorState = HIGH;                    // preserves current sensor stat
    }
  }
  else
  {
    digitalWrite(LED, LOW);                  // Turns LED OFF
    if (sensorState == HIGH) //Checks if sensor state has changed from its previous state
    {
      sensorState = LOW;                    // preserves current sensor state
    }
  }
}

void collectSoundData(){
  float signalSample = readSoundLevel();
  if(signalSample > 0.5){
    if(soundCounter == 0){
      detectionPublish("sound", "on");
    }
    soundCounter = 5;
  } else {
    if(soundCounter > 0){
      if(--soundCounter == 0){
        detectionPublish("sound", "off");
      }
    }
  }
  Serial.println(signalSample);

  if(signalSample > 1.5){
    if(bulbsON){
      if(zoneName == "Zone2"){
        actuatorPublish(2, "turn", "off");
      } else if (zoneName == "Zone3"){
        actuatorPublish(3, "turn", "off");
      }
      bulbsON = false;
    } else {
      if(zoneName == "Zone2"){
        actuatorPublish(2, "turn", "on");
      } else if (zoneName == "Zone3"){
        actuatorPublish(3, "turn", "on");
      }
      bulbsON = true;
    }
    Serial.println(signalSample);
  }
}

void actuatorPublish(int zone, String command, String value){
  if(command == "turn"){
    value = "\"" + value + "\"";
  }
  String JSON = "";
  JSON = JSON + "{\"zone\":"+zone+",\"command\":\""+command+"\",\"value\":" + value + "}";
  Particle.publish("serverActuator", JSON, PRIVATE);
  // if(zone >=0 && zone <= 3){
  //   JSON = "";
  //   JSON = JSON + "{\"zone\":"+zone+",\"command\":\"colour\",\"value\":-1}";
  //   Particle.publish("serverActuator", JSON, PRIVATE);
  //   JSON = "";
  //   JSON = JSON + "{\"zone\":"+zone+",\"command\":\"brightness\",\"value\":24}";
  //   Particle.publish("serverActuator", JSON, PRIVATE);
  // }
}
