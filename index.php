<?php
session_start();

/* ================== CONFIG ================== */
$correctPasswords = ['admin'];
ini_set('upload_max_filesize', '80M');
ini_set('post_max_size', '900M');
ini_set('memory_limit', '256M');
ini_set('max_execution_time', '600');
ini_set('max_input_time', '600');

/* ---------- helpers ---------- */
$selfPath = '/' . ltrim(basename(parse_url($_SERVER['SCRIPT_NAME'] ?? '', PHP_URL_PATH)), '/');
if ($selfPath === '/' || $selfPath === '') $selfPath = '/index.php';
$selfUrl = $selfPath;

function h($v){return htmlspecialchars($v,ENT_QUOTES,'UTF-8');}
function sanitizeFileName($name){
    $name = basename($name);
    $name = preg_replace('/[^\PC]/u','',$name);
    $name = preg_replace('/[^A-Za-z0-9._ -]/','_',$name);
    if ($name === '' || $name === '.' || $name === '..') $name = 'file';
    return $name;
}
function safePathJoin($base,$file){
    $base = rtrim($base,'/\\');
    $path = $base . '/' . $file;
    $realBase = realpath($base) ?: $base;
    $realPath = realpath($path);
    if ($realPath === false) $realPath = $path;
    $realBase = str_replace('\\','/',$realBase);
    $realPath = str_replace('\\','/',$realPath);
    if (strpos($realPath,$realBase.'/') !== 0 && $realPath !== $realBase){
        throw new RuntimeException('Invalid path');
    }
    return $realPath;
}
function getDateCategory($ts) {
    $today = strtotime('today'); $yesterday = strtotime('yesterday');
    if ($ts >= $today) return 'Today';
    if ($ts >= $yesterday) return 'Yesterday';
    return date('d M Y', $ts);
}
function formatFileSize($bytes) {
    if ($bytes >= 1073741824) return number_format($bytes/1073741824,2).' GB';
    if ($bytes >= 1048576) return number_format($bytes/1048576,2).' MB';
    if ($bytes >= 1024) return number_format($bytes/1024,2).' KB';
    return $bytes.' bytes';
}
function isUrl($str) { return (bool)filter_var(trim($str), FILTER_VALIDATE_URL); }
function getMeta($metadata, $file) {
    $m = $metadata[$file] ?? null;
    if ($m === null) return ['time'=>0,'permanent'=>false,'fav'=>false,'folder'=>'','downloads'=>0];
    if (is_int($m) || is_float($m)) return ['time'=>(int)$m,'permanent'=>false,'fav'=>false,'folder'=>'','downloads'=>0];
    return [
        'time'=>(int)($m['time']??0),
        'permanent'=>(bool)($m['permanent']??false),
        'fav'=>(bool)($m['fav']??false),
        'folder'=>(string)($m['folder']??''),
        'downloads'=>(int)($m['downloads']??0),
    ];
}
function getTextFilePreview($filePath, $lines=5) {
    $h = @fopen($filePath,'r'); if (!$h) return '';
    $out=''; $i=0;
    while (($l=fgets($h))!==false && $i<$lines) { $out.=$l; $i++; }
    fclose($h); return $out;
}
function getRememberToken(){return bin2hex(random_bytes(32));}
function getRememberCookieParams(): array {
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    return ['expires'=>time()+(30*24*60*60),'path'=>'/','secure'=>$secure,'httponly'=>true,'samesite'=>'Lax'];
}
function getRememberCookieClearParams(): array {
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    return ['expires'=>time()-3600,'path'=>'/','secure'=>$secure,'httponly'=>true,'samesite'=>'Lax'];
}
/* Generate a share token */
function generateShareToken(){ return bin2hex(random_bytes(16)); }

/* ================== URL METADATA FETCH (SSRF-safe) ================== */
if (isset($_GET['fetch_meta']) && !empty($_GET['url'])) {
    header('Content-Type: application/json');
    $rawUrl = trim($_GET['url']);
    if (!filter_var($rawUrl, FILTER_VALIDATE_URL)) { echo json_encode(['error'=>'Invalid URL']); exit; }
    $parsed = parse_url($rawUrl);
    if (!isset($parsed['scheme']) || !in_array(strtolower($parsed['scheme']),['http','https'])) { echo json_encode(['error'=>'Only HTTP/HTTPS allowed']); exit; }
    $host = $parsed['host'] ?? '';
    $blockedPatterns = ['/^localhost$/i','/^127\./','/^10\./','/^172\.(1[6-9]|2[0-9]|3[01])\./','/^192\.168\./','/^169\.254\./','/^::1$/','/ ^fc00:/','/ ^fe80:/','/ ^0\.0\.0\.0$/','/ metadata\.google\.internal/i','/^169\.254\.169\.254$/'];
    foreach ($blockedPatterns as $pat) { if (preg_match($pat, $host)) { echo json_encode(['error'=>'Blocked host']); exit; } }
    $resolvedIp = @gethostbyname($host);
    foreach (['127.','10.','192.168.','169.254.','fc00:','fe80:','::1'] as $r) { if (strpos($resolvedIp,$r)===0) { echo json_encode(['error'=>'Blocked resolved IP']); exit; } }
    $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
    $oembedEndpoints = ['instagram.com'=>'https://graph.facebook.com/v18.0/instagram_oembed?url=','www.instagram.com'=>'https://graph.facebook.com/v18.0/instagram_oembed?url=','youtube.com'=>'https://www.youtube.com/oembed?format=json&url=','www.youtube.com'=>'https://www.youtube.com/oembed?format=json&url=','youtu.be'=>'https://www.youtube.com/oembed?format=json&url=','twitter.com'=>'https://publish.twitter.com/oembed?url=','x.com'=>'https://publish.twitter.com/oembed?url=','vimeo.com'=>'https://vimeo.com/api/oembed.json?url=','www.vimeo.com'=>'https://vimeo.com/api/oembed.json?url='];
    $meta = ['url'=>$rawUrl,'title'=>'','description'=>'','image'=>'','favicon'=>'','domain'=>$host];
    $oembedUrl = null;
    foreach ($oembedEndpoints as $oeDomain => $endpoint) { if (strcasecmp($host,$oeDomain)===0) { $oembedUrl=$endpoint.urlencode($rawUrl); break; } }
    if ($oembedUrl) {
        $ch2=curl_init(); curl_setopt_array($ch2,[CURLOPT_URL=>$oembedUrl,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>6,CURLOPT_CONNECTTIMEOUT=>4,CURLOPT_USERAGENT=>$ua,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>0]);
        $oembedBody=curl_exec($ch2); $oembedCode=curl_getinfo($ch2,CURLINFO_HTTP_CODE); curl_close($ch2);
        if ($oembedBody && $oembedCode===200) { $oe=@json_decode($oembedBody,true); if($oe){$meta['title']=mb_substr($oe['title']??'',0,200);$meta['description']=mb_substr($oe['author_name']??'',0,200);$meta['image']=$oe['thumbnail_url']??'';$meta['favicon']=$parsed['scheme'].'://'.$host.'/favicon.ico';$meta['domain']=$host;echo json_encode($meta);exit;} }
    }
    $ch=curl_init(); curl_setopt_array($ch,[CURLOPT_URL=>$rawUrl,CURLOPT_RETURNTRANSFER=>true,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_MAXREDIRS=>5,CURLOPT_TIMEOUT=>10,CURLOPT_CONNECTTIMEOUT=>5,CURLOPT_USERAGENT=>$ua,CURLOPT_HTTPHEADER=>['Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','Accept-Language: en-US,en;q=0.9','Accept-Encoding: identity','Cache-Control: no-cache','Pragma: no-cache'],CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>0,CURLOPT_ENCODING=>'identity']);
    $html=curl_exec($ch); $httpCode=curl_getinfo($ch,CURLINFO_HTTP_CODE); $finalUrl=curl_getinfo($ch,CURLINFO_EFFECTIVE_URL); curl_close($ch);
    $finalParsed=parse_url($finalUrl?:$rawUrl); $finalHost=$finalParsed['host']??$host; $finalScheme=$finalParsed['scheme']??$parsed['scheme']; $meta['domain']=$finalHost;
    if (!$html||strlen(trim($html))<100||$httpCode>=400) { $meta['favicon']=$finalScheme.'://'.$finalHost.'/favicon.ico'; echo json_encode($meta); exit; }
    $headEnd=stripos($html,'</head>'); $head=$headEnd!==false?substr($html,0,$headEnd+7):substr($html,0,15000);
    $getM=function($patterns) use ($head){foreach((array)$patterns as $p){if(preg_match($p,$head,$m)){$v=html_entity_decode(trim($m[1]),ENT_QUOTES,'UTF-8');if($v!=='')return $v;}}return '';};
    $meta['title']=$getM(['/<meta[^>]+property=["\']og:title["\'][^>]+content=["\'](.*?)["\']/i','/<meta[^>]+content=["\'](.*?)["\']\s+property=["\']og:title["\']/i','/<meta[^>]+name=["\']twitter:title["\'][^>]+content=["\'](.*?)["\']/i','/<title[^>]*>\s*(.*?)\s*<\/title>/si']);
    $meta['description']=$getM(['/<meta[^>]+property=["\']og:description["\'][^>]+content=["\'](.*?)["\']/i','/<meta[^>]+content=["\'](.*?)["\']\s+property=["\']og:description["\']/i','/<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']/i']);
    $meta['image']=$getM(['/<meta[^>]+property=["\']og:image["\'][^>]+content=["\'](.*?)["\']/i','/<meta[^>]+content=["\'](.*?)["\']\s+property=["\']og:image["\']/i','/<meta[^>]+name=["\']twitter:image["\'][^>]+content=["\'](.*?)["\']/i']);
    if($meta['image']&&!filter_var($meta['image'],FILTER_VALIDATE_URL))$meta['image']=$finalScheme.'://'.$finalHost.'/'.ltrim($meta['image'],'/');
    if($meta['image']&&!preg_match('/^https?:\/\//i',$meta['image']))$meta['image']='';
    $fav=$getM(['/<link[^>]+rel=["\']shortcut icon["\'][^>]+href=["\'](.*?)["\']/i','/<link[^>]+rel=["\']icon["\'][^>]+href=["\'](.*?)["\']/i']);
    if(!$fav)$fav=$finalScheme.'://'.$finalHost.'/favicon.ico';elseif(!filter_var($fav,FILTER_VALIDATE_URL)){if(strpos($fav,'//')===0)$fav=$finalScheme.':'.$fav;else $fav=$finalScheme.'://'.$finalHost.'/'.ltrim($fav,'/');}
    $meta['favicon']=$fav; $meta['title']=mb_substr($meta['title'],0,200); $meta['description']=mb_substr($meta['description'],0,500);
    echo json_encode($meta); exit;
}

/* ================== SHAREABLE LINKS ================== */
$uploadDir = __DIR__ . '/uploads';
$shareFile = $uploadDir . '/shares.json';

// Handle share link access (public, no auth needed)
if (isset($_GET['share'])) {
    $token = preg_replace('/[^A-Za-z0-9]/','',$_GET['share']);
    $shares = file_exists($shareFile) ? json_decode(file_get_contents($shareFile),true) : [];
    if (!is_array($shares)) $shares = [];
    $share = $shares[$token] ?? null;
    $shareError = null;
    if (!$share) { $shareError = 'This share link is invalid or has expired.'; }
    else {
        // Check expiry
        if ($share['expires'] !== 0 && time() > $share['expires']) { $shareError = 'This share link has expired.'; }
        // Check download limit
        elseif ($share['max_downloads'] > 0 && ($share['downloads'] ?? 0) >= $share['max_downloads']) { $shareError = 'Download limit reached for this link.'; }
    }
    // Password check
    $sharePasswordOk = empty($share['password']);
    if (!$sharePasswordOk && isset($_POST['share_password'])) {
        $sharePasswordOk = password_verify($_POST['share_password'], $share['password']);
        if (!$sharePasswordOk) $sharePasswordError = true;
    }

    if (!$shareError && !$sharePasswordOk) {
        // Show password form
        ?><!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Protected Link — Fast Transfer</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,sans-serif;background:#0d0d18;color:#e8e6f4;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.box{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:32px;max-width:400px;width:100%;text-align:center}h2{font-size:20px;margin-bottom:8px}p{color:#a9a7bb;font-size:14px;margin-bottom:24px}input{width:100%;padding:12px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);border-radius:8px;color:#e8e6f4;font-size:15px;margin-bottom:12px;outline:none}.err{color:#f87171;font-size:13px;margin-bottom:12px}button{width:100%;padding:13px;background:linear-gradient(135deg,#7c6aff,#a78bfa);color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}</style>
</head><body><div class="box"><div style="font-size:48px;margin-bottom:16px">🔒</div>
<h2>Password Protected</h2><p>This file requires a password to access.</p>
<?php if(isset($sharePasswordError)):?><div class="err">❌ Incorrect password</div><?php endif;?>
<form method="POST"><input type="password" name="share_password" placeholder="Enter password" autofocus required><button type="submit">Unlock →</button></form>
</div></body></html><?php exit;
    }

    if (!$shareError && $sharePasswordOk) {
        $file = $share['file'];
        $filePath = $uploadDir.'/'.$file;
        if (!is_file($filePath)) { $shareError = 'The file no longer exists.'; }
        else {
            // Track download
            $shares[$token]['downloads'] = ($shares[$token]['downloads'] ?? 0) + 1;
            file_put_contents($shareFile, json_encode($shares, JSON_UNESCAPED_SLASHES));
            // Stream file
            while (ob_get_level()) ob_end_clean();
            $size = filesize($filePath);
            $finfo = function_exists('finfo_open') ? finfo_open(FILEINFO_MIME_TYPE) : false;
            $mime  = $finfo ? @finfo_file($finfo,$filePath) : 'application/octet-stream';
            if ($finfo) finfo_close($finfo);
            if (!$mime) $mime = 'application/octet-stream';
            header('Content-Description: File Transfer');
            header('Content-Type: '.$mime);
            header('Content-Disposition: attachment; filename="'.rawurlencode($file).'"');
            header('Content-Transfer-Encoding: binary');
            header('Content-Length: '.$size);
            header('Cache-Control: no-cache, must-revalidate');
            $fp = fopen($filePath,'rb');
            if ($fp) { while(!feof($fp)){echo fread($fp,262144);flush();} fclose($fp); }
            exit;
        }
    }
    ?><!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Share Link — Fast Transfer</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,sans-serif;background:#0d0d18;color:#e8e6f4;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.box{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:32px;max-width:420px;width:100%;text-align:center}h2{font-size:20px;margin-bottom:8px}p{color:#a9a7bb;font-size:14px}</style>
</head><body><div class="box"><div style="font-size:56px;margin-bottom:16px">❌</div>
<h2>Link Unavailable</h2><p><?= h($shareError ?? 'Unknown error') ?></p>
</div></body></html><?php exit;
}

/* ================== CREATE SHARE LINK (AJAX) ================== */
if (isset($_GET['create_share']) && !empty($_GET['file'])) {
    // Auth check happens after auth block — we skip here and re-check below
    // (will be validated below after auth)
}

/* ================== DOWNLOAD ZIP BY DATE ================== */
if (isset($_GET['download_zip'])) {
    set_time_limit(0); ini_set('memory_limit','512M');
    $dateCategory = $_GET['download_zip'];
    $metaFile  = $uploadDir . '/metadata.json';
    $metadata = file_exists($metaFile) ? json_decode(file_get_contents($metaFile), true) : [];
    $zipName = 'files_' . preg_replace('/[^A-Za-z0-9_-]/','_',$dateCategory) . '.zip';
    $filesToZip = [];
    $allFiles = array_diff(scandir($uploadDir), ['.','..','texts.json','chunks','metadata.json','shares.json','folders.json']);
    foreach ($allFiles as $file) {
        $filePath = $uploadDir.'/'.$file;
        if (is_file($filePath)) {
            $m = $metadata[$file] ?? null;
            $uploadTime = is_array($m) ? ($m['time'] ?? filemtime($filePath)) : (is_int($m) ? $m : filemtime($filePath));
            if (getDateCategory($uploadTime) === $dateCategory) $filesToZip[] = ['path'=>$filePath,'name'=>$file];
        }
    }
    if (empty($filesToZip)) exit('No files found for this date');
    while (ob_get_level()) ob_end_clean();
    $tempZip = sys_get_temp_dir().'/'.uniqid('zip_',true).'.zip';
    $zip = new ZipArchive();
    if ($zip->open($tempZip, ZipArchive::CREATE|ZipArchive::OVERWRITE) === TRUE) {
        foreach ($filesToZip as $fd) $zip->addFile($fd['path'],$fd['name']);
        $zip->close();
        if (file_exists($tempZip)) {
            header('Content-Type: application/zip'); header('Content-Disposition: attachment; filename="'.$zipName.'"');
            header('Content-Length: '.filesize($tempZip)); header('Cache-Control: no-cache, must-revalidate');
            $handle = fopen($tempZip,'rb');
            if ($handle) { while(!feof($handle)){echo fread($handle,1048576);flush();} fclose($handle); }
            @unlink($tempZip); exit;
        }
    }
    exit('Failed to create ZIP');
}

/* ================== DELETE FILES BY DAY ================== */
if (isset($_GET['delete_day'])) {
    $dateCategory = $_GET['delete_day'];
    $metaFile = $uploadDir . '/metadata.json';
    $metadata = file_exists($metaFile) ? json_decode(file_get_contents($metaFile), true) : [];
    $allFiles = array_diff(scandir($uploadDir), ['.','..','texts.json','chunks','metadata.json','shares.json','folders.json']);
    foreach ($allFiles as $file) {
        $filePath = $uploadDir.'/'.$file;
        if (is_file($filePath)) {
            $m = $metadata[$file] ?? null;
            $uploadTime = is_array($m) ? ($m['time'] ?? filemtime($filePath)) : (is_int($m) ? $m : filemtime($filePath));
            if (getDateCategory($uploadTime) === $dateCategory) { @unlink($filePath); unset($metadata[$file]); }
        }
    }
    file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));
    header('Location: '.$selfUrl); exit;
}

/* ================== DELETE TEXTS BY DAY ================== */
if (isset($_GET['delete_texts_day'])) {
    $dateCategory = $_GET['delete_texts_day'];
    $textFile  = $uploadDir . '/texts.json';
    $texts = file_exists($textFile) ? json_decode(file_get_contents($textFile), true) : [];
    if (!is_array($texts)) $texts = [];
    $filtered = array_filter($texts, function($item) use ($dateCategory) { return getDateCategory($item['time']) !== $dateCategory; });
    file_put_contents($textFile, json_encode(array_values($filtered), JSON_UNESCAPED_SLASHES));
    header('Location: '.$selfUrl); exit;
}

/* ================== DOWNLOAD ================== */
if (isset($_GET['download'])) {
    $file = sanitizeFileName($_GET['download']);
    $filePath = safePathJoin($uploadDir, $file);
    if (!is_file($filePath)) { http_response_code(404); exit('File not found'); }
    // Track downloads
    $metaFile = $uploadDir . '/metadata.json';
    $metadata = file_exists($metaFile) ? json_decode(file_get_contents($metaFile), true) : [];
    if (!is_array($metadata)) $metadata = [];
    if (isset($metadata[$file]) && is_array($metadata[$file])) {
        $metadata[$file]['downloads'] = ($metadata[$file]['downloads'] ?? 0) + 1;
        file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));
    }
    while (ob_get_level()) ob_end_clean();
    $size = filesize($filePath);
    $finfo = function_exists('finfo_open') ? finfo_open(FILEINFO_MIME_TYPE) : false;
    $mime  = $finfo ? @finfo_file($finfo,$filePath) : 'application/octet-stream';
    if ($finfo) finfo_close($finfo);
    if (!$mime) $mime = 'application/octet-stream';
    header('Content-Description: File Transfer');
    header('Content-Type: '.$mime);
    header('Content-Disposition: attachment; filename="'.rawurlencode($file).'"');
    header('Content-Transfer-Encoding: binary');
    header('Content-Length: '.$size);
    header('Cache-Control: no-cache, must-revalidate');
    header('Pragma: public');
    $fp = fopen($filePath,'rb');
    if ($fp === false) { http_response_code(500); exit('Cannot open file'); }
    ignore_user_abort(true);
    while (!feof($fp)) {
        $buffer = fread($fp, 262144); echo $buffer;
        if (function_exists('fastcgi_finish_request')) fastcgi_finish_request(); else flush();
        if (connection_status() != CONNECTION_NORMAL) break;
    }
    fclose($fp); exit;
}

/* ================== AUTH ================== */
$remFile = __DIR__ . '/remember_tokens.json';
$remember = file_exists($remFile) ? json_decode(file_get_contents($remFile), true) : [];
if (!is_array($remember)) $remember = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password']) && !isset($_POST['chunk']) && !isset($_POST['text']) && !isset($_POST['edit_text'])) {
    if (in_array($_POST['password'], $correctPasswords, true)) {
        $_SESSION['logged_in'] = true;
        if (isset($_POST['remember'])) {
            $token = getRememberToken();
            $remember[$token] = ['created'=>time()];
            file_put_contents($remFile, json_encode($remember, JSON_UNESCAPED_SLASHES));
            setcookie('transfer_auth', $token, getRememberCookieParams());
        }
        header('Location: '.$selfUrl); exit;
    } else { $loginError = true; }
}

if (isset($_GET['logout'])) {
    session_destroy();
    if (isset($_COOKIE['transfer_auth'])) {
        $t = $_COOKIE['transfer_auth'];
        if (isset($remember[$t])) { unset($remember[$t]); file_put_contents($remFile, json_encode($remember, JSON_UNESCAPED_SLASHES)); }
        setcookie('transfer_auth', '', getRememberCookieClearParams());
    }
    header('Location: '.$selfUrl); exit;
}

$isLoggedIn = isset($_SESSION['logged_in']);
if (!$isLoggedIn && isset($_COOKIE['transfer_auth'])) {
    $t = $_COOKIE['transfer_auth'];
    if (is_string($t) && isset($remember[$t])) { $_SESSION['logged_in'] = true; $isLoggedIn = true; }
}

if (!$isLoggedIn) {
?><!DOCTYPE html>
<html lang="en">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login — Fast Transfer</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
    <style>
        :root{--bg:#0a0a12;--card:rgba(255,255,255,.05);--border:rgba(255,255,255,.08);--accent:#7c6aff;--accent2:#a78bfa;--text:#e8e6f0;--muted:#7a7890}
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'DM Sans',sans-serif;background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;position:relative;overflow:hidden}
        body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 60% at 50% -10%,rgba(124,106,255,.3),transparent),radial-gradient(ellipse 60% 40% at 80% 80%,rgba(167,139,250,.15),transparent);pointer-events:none}
        .box{background:var(--card);backdrop-filter:blur(24px);border:1px solid var(--border);border-radius:20px;padding:40px 32px;max-width:420px;width:100%;box-shadow:0 32px 64px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.06);position:relative;z-index:1}
        .logo{text-align:center;margin-bottom:28px}
        .logo-icon{width:52px;height:52px;background:linear-gradient(135deg,var(--accent),var(--accent2));border-radius:14px;margin:0 auto 14px;display:flex;align-items:center;justify-content:center;font-size:22px;box-shadow:0 8px 24px rgba(124,106,255,.4)}
        h1{font-family:'Syne',sans-serif;font-weight:800;font-size:24px;color:var(--text);text-align:center}
        .sub{color:var(--muted);text-align:center;font-size:13px;margin-top:5px}
        .err{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);color:#fca5a5;padding:11px 14px;border-radius:10px;margin:0 0 18px;text-align:center;font-size:13px}
        label.lbl{display:block;color:var(--muted);font-size:11px;font-weight:500;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
        .field{margin-bottom:14px}
        input[type=password]{width:100%;padding:13px 15px;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:11px;font-size:15px;color:var(--text);font-family:'DM Sans',sans-serif;transition:border-color .2s,box-shadow .2s;outline:none}
        input[type=password]:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(124,106,255,.15)}
        input[type=password]::placeholder{color:var(--muted)}
        .rem{display:flex;align-items:center;gap:10px;margin-bottom:18px;color:var(--muted);font-size:14px;cursor:pointer}
        .rem input{width:18px;height:18px;accent-color:var(--accent);flex-shrink:0}
        button[type=submit]{width:100%;padding:14px;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:11px;font-size:15px;font-weight:600;cursor:pointer;font-family:'DM Sans',sans-serif;transition:opacity .2s,transform .15s;box-shadow:0 4px 16px rgba(124,106,255,.35)}
        button[type=submit]:hover{opacity:.9;transform:translateY(-1px)}
        button[type=submit]:active{transform:none}
        @media(max-width:480px){body{padding:12px;align-items:flex-end}.box{border-radius:20px 20px 0 0;padding:28px 20px 32px;max-width:100%}h1{font-size:22px}}
    </style>
</head>
<body>
<div class="box">
    <div class="logo">
        <div class="logo-icon">⚡</div>
        <h1>Fast Transfer</h1>
        <p class="sub">Enter your access password</p>
    </div>
    <?php if (isset($loginError)): ?><div class="err">❌ Incorrect password. Try again.</div><?php endif; ?>
    <form method="POST">
        <div class="field">
            <label class="lbl" for="pw">Password</label>
            <input type="password" id="pw" name="password" placeholder="••••••••" required autofocus>
        </div>
        <label class="rem"><input type="checkbox" name="remember"> Remember me for 30 days</label>
        <button type="submit">Sign In →</button>
    </form>
</div>
</body></html>
<?php exit; }

/* ================== SETUP ================== */
$chunksDir = __DIR__ . '/uploads/chunks';
$textFile  = $uploadDir . '/texts.json';
$metaFile  = $uploadDir . '/metadata.json';
$foldersFile = $uploadDir . '/folders.json';

if (!is_dir($uploadDir)) mkdir($uploadDir, 0777, true);
if (!is_dir($chunksDir)) mkdir($chunksDir, 0777, true);

$metadata = file_exists($metaFile) ? json_decode(file_get_contents($metaFile), true) : [];
if (!is_array($metadata)) $metadata = [];

$folders = file_exists($foldersFile) ? json_decode(file_get_contents($foldersFile), true) : [];
if (!is_array($folders)) $folders = [];

$shares = file_exists($shareFile) ? json_decode(file_get_contents($shareFile), true) : [];
if (!is_array($shares)) $shares = [];

/* ================== CREATE SHARE LINK (AJAX, post-auth) ================== */
if (isset($_GET['create_share'])) {
    header('Content-Type: application/json');
    $file = sanitizeFileName($_GET['file'] ?? '');
    $expiry = (int)($_GET['expires'] ?? 0); // 0=perm, 3600=1h, 86400=1d
    $maxDl = (int)($_GET['max_dl'] ?? 0);
    $rawPass = trim($_GET['password'] ?? '');
    $hashedPass = $rawPass !== '' ? password_hash($rawPass, PASSWORD_DEFAULT) : '';
    $token = generateShareToken();
    $expiresAt = $expiry > 0 ? time() + $expiry : 0;
    $shares[$token] = ['file'=>$file,'created'=>time(),'expires'=>$expiresAt,'max_downloads'=>$maxDl,'downloads'=>0,'password'=>$hashedPass];
    file_put_contents($shareFile, json_encode($shares, JSON_UNESCAPED_SLASHES));
    $protocol = (!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?"https://":"http://";
    $shareUrl = $protocol.$_SERVER['HTTP_HOST'].dirname($selfUrl).'/?share='.$token;
    if(dirname($selfUrl)==='/') $shareUrl = $protocol.$_SERVER['HTTP_HOST'].'/?share='.$token;
    echo json_encode(['success'=>true,'url'=>$shareUrl,'token'=>$token]);
    exit;
}

/* ================== REVOKE SHARE ================== */
if (isset($_GET['revoke_share'])) {
    $token = preg_replace('/[^A-Za-z0-9]/','',$_GET['revoke_share']);
    unset($shares[$token]);
    file_put_contents($shareFile, json_encode($shares, JSON_UNESCAPED_SLASHES));
    header('Location: '.$selfUrl); exit;
}

/* ================== FOLDER ACTIONS ================== */
if (isset($_GET['create_folder']) && !empty($_GET['name'])) {
    $fname = trim($_GET['name']);
    $fname = preg_replace('/[^A-Za-z0-9 _\-]/','_',$fname);
    if ($fname !== '' && !in_array($fname,$folders)) {
        $folders[] = $fname;
        file_put_contents($foldersFile, json_encode($folders, JSON_UNESCAPED_SLASHES));
    }
    header('Location: '.$selfUrl); exit;
}
if (isset($_GET['delete_folder'])) {
    $fname = $_GET['delete_folder'];
    $folders = array_values(array_filter($folders, fn($f) => $f !== $fname));
    file_put_contents($foldersFile, json_encode($folders, JSON_UNESCAPED_SLASHES));
    // Remove folder from files
    foreach ($metadata as $f => $m) {
        if (is_array($m) && ($m['folder']??'') === $fname) { $metadata[$f]['folder'] = ''; }
    }
    file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));
    header('Location: '.$selfUrl); exit;
}
if (isset($_GET['move_file']) && !empty($_GET['file']) && isset($_GET['folder'])) {
    $mf = sanitizeFileName($_GET['file']);
    $mfolder = trim($_GET['folder']);
    if (isset($metadata[$mf]) && is_array($metadata[$mf])) {
        $metadata[$mf]['folder'] = $mfolder;
        file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));
    }
    header('Location: '.$selfUrl); exit;
}

/* ================== TOGGLE FAVORITE ================== */
if (isset($_GET['toggle_fav'])) {
    $tf = sanitizeFileName($_GET['toggle_fav']);
    if (isset($metadata[$tf]) && is_array($metadata[$tf])) {
        $metadata[$tf]['fav'] = !($metadata[$tf]['fav'] ?? false);
        file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));
    }
    header('Location: '.$selfUrl); exit;
}

/* ================== DELETE FILE ================== */
if (isset($_GET['delete_file'])) {
    $fileToDelete = sanitizeFileName($_GET['delete_file']);
    try {
        $filePath = safePathJoin($uploadDir, $fileToDelete);
        if (file_exists($filePath) && is_file($filePath)) {
            unlink($filePath); unset($metadata[$fileToDelete]);
            file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));
        }
    } catch (Throwable $e) {}
    header('Location: '.$selfUrl); exit;
}

/* ================== DELETE TEXT ================== */
if (isset($_GET['delete_text'])) {
    $textIndex = (int)$_GET['delete_text'];
    $texts = file_exists($textFile) ? json_decode(file_get_contents($textFile), true) : [];
    if (isset($texts[$textIndex])) { array_splice($texts, $textIndex, 1); file_put_contents($textFile, json_encode(array_values($texts), JSON_UNESCAPED_SLASHES)); }
    header('Location: '.$selfUrl); exit;
}

/* ================== EDIT TEXT ================== */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_text']) && isset($_POST['text_index'])) {
    $texts = file_exists($textFile) ? json_decode(file_get_contents($textFile), true) : [];
    if (!is_array($texts)) $texts = [];
    $index = (int)$_POST['text_index'];
    if (isset($texts[$index])) {
        $isPerm = !empty($texts[$index]['permanent']);
        $oldTime = time() - (72*60*60);
        if ($isPerm || $texts[$index]['time'] >= $oldTime) {
            $texts[$index]['content'] = $_POST['edit_text'];
            file_put_contents($textFile, json_encode($texts, JSON_UNESCAPED_SLASHES));
        }
    }
    header('Location: '.$selfUrl); exit;
}

/* ================== TOGGLE PERMANENT (TEXT) ================== */
if (isset($_GET['toggle_perm_text'])) {
    $idx = (int)$_GET['toggle_perm_text'];
    $texts = file_exists($textFile) ? json_decode(file_get_contents($textFile), true) : [];
    if (!is_array($texts)) $texts = [];
    if (isset($texts[$idx])) { $texts[$idx]['permanent'] = !((bool)($texts[$idx]['permanent'] ?? false)); file_put_contents($textFile, json_encode($texts, JSON_UNESCAPED_SLASHES)); }
    header('Location: '.$selfUrl); exit;
}

/* ================== TOGGLE PERMANENT (FILE) ================== */
if (isset($_GET['toggle_perm_file'])) {
    $fileToToggle = sanitizeFileName($_GET['toggle_perm_file']);
    $m = getMeta($metadata, $fileToToggle);
    $metadata[$fileToToggle] = array_merge(is_array($metadata[$fileToToggle]??null)?$metadata[$fileToToggle]:[], ['time'=>$m['time'],'permanent'=>!$m['permanent']]);
    file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));
    header('Location: '.$selfUrl); exit;
}

/* ================== CHUNKED UPLOAD ================== */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['chunk']) && !isset($_POST['text']) && !isset($_POST['edit_text'])) {
    header('Content-Type: application/json');
    $chunk = (int)$_POST['chunk'];
    $totalChunks = (int)$_POST['totalChunks'];
    $fileNameRaw = $_POST['fileName'] ?? 'file';
    $fileName = sanitizeFileName($fileNameRaw);
    $isPermanent = !empty($_POST['permanent']) && $_POST['permanent'] === '1';
    $fileFolder = trim($_POST['folder'] ?? '');
    $uploadIdRaw = $_POST['uploadId'] ?? '';
    $uploadId = preg_replace('/[^A-Za-z0-9_-]/','', $uploadIdRaw);
    if ($uploadId === '') $uploadId = bin2hex(random_bytes(8));

    $chunkBaseName = $uploadId.'_'.$chunk;
    try { $chunkFile = safePathJoin($chunksDir, $chunkBaseName); }
    catch (Throwable $e) { echo json_encode(['success'=>false,'error'=>'Invalid path']); exit; }

    if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
        if (!move_uploaded_file($_FILES['file']['tmp_name'], $chunkFile)) { echo json_encode(['success'=>false,'error'=>'Move failed']); exit; }
        $allChunksUploaded = true;
        for ($i = 0; $i < $totalChunks; $i++) {
            try { $chkPath = safePathJoin($chunksDir, $uploadId.'_'.$i); } catch (Throwable $e) { $allChunksUploaded = false; break; }
            if (!file_exists($chkPath)) { $allChunksUploaded = false; break; }
        }
        if ($allChunksUploaded) {
            $info = pathinfo($fileName); $base = $info['filename'] ?? 'file'; $ext = isset($info['extension']) ? '.'.$info['extension'] : '';
            $safeBase = preg_replace('/[^A-Za-z0-9._-]/','_',$base); if ($safeBase === '') $safeBase = 'file';
            $fileName = $safeBase.$ext;
            try { $finalFile = safePathJoin($uploadDir, $fileName); } catch (Throwable $e) { echo json_encode(['success'=>false,'error'=>'Invalid final path']); exit; }
            if (file_exists($finalFile)) { $c=1; do { $altName=$safeBase.'_'.$c.$ext; $finalFile=safePathJoin($uploadDir,$altName); $c++; } while(file_exists($finalFile)); $fileName = basename($finalFile); }
            $out = fopen($finalFile,'wb'); if ($out === false) { echo json_encode(['success'=>false,'error'=>'Cannot open final file']); exit; }
            for ($i = 0; $i < $totalChunks; $i++) {
                try { $chunkPath = safePathJoin($chunksDir, $uploadId.'_'.$i); } catch (Throwable $e) { continue; }
                if (!is_file($chunkPath)) continue;
                $in = fopen($chunkPath,'rb'); if ($in) { stream_copy_to_stream($in,$out); fclose($in); } @unlink($chunkPath);
            }
            fclose($out);
            $metadata[$fileName] = ['time'=>time(),'permanent'=>$isPermanent,'fav'=>false,'folder'=>$fileFolder,'downloads'=>0];
            file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));
            echo json_encode(['success'=>true,'completed'=>true]);
        } else { echo json_encode(['success'=>true,'completed'=>false]); }
    } else { echo json_encode(['success'=>false,'error'=>'Upload failed']); }
    exit;
}

/* ================== TEXT SAVE ================== */
$texts = file_exists($textFile) ? json_decode(file_get_contents($textFile), true) : [];
if (!is_array($texts)) $texts = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['text']) && !isset($_POST['chunk']) && !isset($_POST['edit_text'])) {
    $isPermanent = !empty($_POST['text_permanent']) && $_POST['text_permanent'] === '1';
    $texts[] = ['time'=>time(),'content'=>$_POST['text'],'permanent'=>$isPermanent];
    file_put_contents($textFile, json_encode($texts, JSON_UNESCAPED_SLASHES));
    header('Location: '.$selfUrl); exit;
}

/* ================== AUTO DELETE ================== */
$oldTime = time() - (72*60*60);
$metadataChanged = false;

$allFilesInDir = array_diff(scandir($uploadDir), ['.','..','texts.json','chunks','metadata.json','shares.json','folders.json']);
foreach ($allFilesInDir as $file) {
    $filePath = $uploadDir.'/'.$file;
    if (is_file($filePath) && !isset($metadata[$file])) {
        $metadata[$file] = ['time'=>filemtime($filePath),'permanent'=>false,'fav'=>false,'folder'=>'','downloads'=>0]; $metadataChanged = true;
    }
}
foreach ($metadata as $fileName => $rawMeta) {
    $m = getMeta($metadata, $fileName); $filePath = $uploadDir.'/'.$fileName;
    if (!$m['permanent'] && $m['time'] < $oldTime) {
        if (file_exists($filePath)) @unlink($filePath);
        unset($metadata[$fileName]); $metadataChanged = true;
    }
}
foreach ($metadata as $fileName => $rawMeta) {
    if (!file_exists($uploadDir.'/'.$fileName)) { unset($metadata[$fileName]); $metadataChanged = true; }
}
if ($metadataChanged) file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));

$chunkFiles = @scandir($chunksDir);
if ($chunkFiles) { foreach ($chunkFiles as $chunk) { if ($chunk==='.'||$chunk==='..') continue; $cp=$chunksDir.'/'.$chunk; if (@filemtime($cp)<time()-3600)@unlink($cp); } }

$oldTexts = $texts;
$texts = array_filter($texts, function($item) use ($oldTime) { return !empty($item['permanent']) || (isset($item['time']) && $item['time'] >= $oldTime); });
if (count($texts) !== count($oldTexts)) { file_put_contents($textFile, json_encode(array_values($texts), JSON_UNESCAPED_SLASHES)); }

/* ================== VIEW DATA PREP ================== */
$filesByDate = [];
$allFiles = array_diff(scandir($uploadDir), ['.','..','texts.json','chunks','metadata.json','shares.json','folders.json']);

// Compute stats
$totalStorageBytes = 0;
$totalDownloads = 0;
$favFiles = [];

foreach ($allFiles as $file) {
    $filePath = $uploadDir.'/'.$file;
    if (is_file($filePath)) {
        $m = getMeta($metadata, $file);
        $cat = getDateCategory($m['time'] ?: filemtime($filePath));
        if (!isset($filesByDate[$cat])) $filesByDate[$cat] = [];
        $filesByDate[$cat][] = ['name'=>$file,'path'=>$filePath,'time'=>$m['time'],'permanent'=>$m['permanent'],'fav'=>$m['fav'],'folder'=>$m['folder'],'downloads'=>$m['downloads']];
        $totalStorageBytes += filesize($filePath);
        $totalDownloads += $m['downloads'];
        if ($m['fav']) $favFiles[] = $file;
    }
}
uksort($filesByDate, function($a,$b){ if($a==='Today')return -1;if($b==='Today')return 1;if($a==='Yesterday')return -1;if($b==='Yesterday')return 1;return strtotime($b)-strtotime($a); });

$textsByDate = [];
foreach ($texts as $index => $item) {
    $cat = getDateCategory($item['time']);
    if (!isset($textsByDate[$cat])) $textsByDate[$cat] = [];
    $textsByDate[$cat][] = ['index'=>$index,'content'=>$item['content'],'time'=>$item['time'],'permanent'=>!empty($item['permanent'])];
}
uksort($textsByDate, function($a,$b){ if($a==='Today')return -1;if($b==='Today')return 1;if($a==='Yesterday')return -1;if($b==='Yesterday')return 1;return strtotime($b)-strtotime($a); });

$protocol = (!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?"https://":"http://";
$currentURL = $protocol.$_SERVER['HTTP_HOST'].$selfUrl;
$totalFiles = count($allFiles);
$totalTexts = count($texts);
$totalStorageFmt = formatFileSize($totalStorageBytes);

// Build shares index (file => tokens)
$fileShares = [];
foreach ($shares as $tok => $s) {
    if (!empty($s['file'])) $fileShares[$s['file']][] = $tok;
}
?><!DOCTYPE html>
<?php
$htmlTheme = 'dark';
if (!empty($_COOKIE['ft_theme']) && in_array($_COOKIE['ft_theme'], ['dark','light'])) $htmlTheme = $_COOKIE['ft_theme'];
?>
<html lang="en" data-theme="<?= $htmlTheme ?>">
<head>
    <script>
    (function(){
        var ls=localStorage.getItem('ft_theme');
        var ck=(document.cookie.match(/(?:^|;\s*)ft_theme=([^;]+)/)||[])[1];
        var t=ls||ck||'dark';
        document.documentElement.setAttribute('data-theme',t);
        if(!ck||ck!==t)document.cookie='ft_theme='+t+';path=/;max-age=31536000;samesite=Lax';
        if(!ls)localStorage.setItem('ft_theme',t);
    })();
    </script>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>⚡ Fast Transfer</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600&display=swap" rel="stylesheet">
    <!-- PWA Manifest inline -->
    <link rel="manifest" href="data:application/json;charset=utf-8,<?= urlencode(json_encode(['name'=>'Fast Transfer','short_name'=>'Transfer','start_url'=>'/','display'=>'standalone','background_color'=>'#0d0d18','theme_color'=>'#7c6aff','icons'=>[['src'=>'https://api.iconify.design/twemoji:zap.svg','sizes'=>'192x192','type'=>'image/svg+xml']]])) ?>">
    <meta name="theme-color" content="#7c6aff">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-title" content="Fast Transfer">
    <style>
    /* ========== CSS VARIABLES ========== */
    :root {
        --bg:#0d0d18; --bg2:#13131f;
        --card:rgba(255,255,255,.044); --card-hov:rgba(255,255,255,.075);
        --border:rgba(255,255,255,.08); --border2:rgba(255,255,255,.13);
        --accent:#7c6aff; --accent2:#a78bfa;
        --accent-g:linear-gradient(135deg,#7c6aff,#a78bfa);
        --green:#34d399; --red:#f87171; --yellow:#fbbf24; --orange:#fb923c;
        --text:#e8e6f4; --text2:#a9a7bb; --muted:#5e5c72;
        --shadow:0 8px 32px rgba(0,0,0,.45);
        --r:16px; --rsm:10px; --rxs:7px;
        --tr:.2s cubic-bezier(.4,0,.2,1);
    }
    [data-theme="light"] {
        --bg:#f0eff8; --bg2:#e8e6f2;
        --card:rgba(255,255,255,.8); --card-hov:rgba(255,255,255,.97);
        --border:rgba(100,90,160,.1); --border2:rgba(100,90,160,.18);
        --text:#1a1830; --text2:#4a4866; --muted:#c8c4e3;
        --shadow:0 4px 24px rgba(80,60,180,.1);
    }
    *{margin:0;padding:0;box-sizing:border-box}
    html{scroll-behavior:smooth}
    body{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:24px 16px 60px;overflow-x:hidden;position:relative}
    body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 90% 50% at 20% -10%,rgba(124,106,255,.18),transparent),radial-gradient(ellipse 60% 40% at 90% 90%,rgba(167,139,250,.1),transparent);pointer-events:none;z-index:0}
    a{color:inherit;text-decoration:none}
    button,textarea,input{font-family:'DM Sans',sans-serif}

    /* ========== LAYOUT ========== */
    .container{max-width:1180px;margin:0 auto;position:relative;z-index:1}

    /* ========== HEADER ========== */
    .site-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;gap:12px;flex-wrap:wrap}
    .site-title{font-family:'Syne',sans-serif;font-weight:800;font-size:clamp(20px,4vw,28px);background:var(--accent-g);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
    .header-r{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
    .url-pill{display:inline-flex;align-items:center;gap:7px;background:var(--card);border:1px solid var(--border);border-radius:999px;padding:6px 14px;font-size:12px;color:var(--text2);max-width:240px;overflow:hidden;white-space:nowrap}
    .url-pill span{overflow:hidden;text-overflow:ellipsis}
    .icon-btn{width:36px;height:36px;border-radius:999px;background:var(--card);border:1px solid var(--border);color:var(--text2);display:flex;align-items:center;justify-content:center;font-size:15px;transition:background var(--tr),border-color var(--tr),color var(--tr);cursor:pointer;flex-shrink:0}
    .icon-btn:hover{background:var(--card-hov);border-color:var(--border2);color:var(--text)}
    .logout-btn{padding:7px 14px;width:auto;border-radius:999px;font-size:13px;font-weight:500;display:flex;align-items:center;gap:6px;background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.2);color:var(--red)}
    .logout-btn:hover{background:rgba(248,113,113,.2)}

    /* ========== SEARCH BAR ========== */
    .search-bar{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
    .search-wrap{flex:1;min-width:200px;position:relative}
    .search-wrap svg{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--muted);pointer-events:none}
    #searchInput{width:100%;padding:9px 12px 9px 36px;background:var(--card);border:1px solid var(--border2);border-radius:var(--rsm);font-size:13px;color:var(--text);outline:none;transition:border-color var(--tr),box-shadow var(--tr)}
    #searchInput:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(124,106,255,.12)}
    #searchInput::placeholder{color:var(--muted)}
    .filter-chips{display:flex;gap:6px;flex-wrap:wrap}
    .fchip{padding:5px 12px;border-radius:999px;border:1px solid var(--border2);background:var(--card);font-size:12px;color:var(--text2);cursor:pointer;transition:background var(--tr),color var(--tr),border-color var(--tr)}
    .fchip.active{background:rgba(124,106,255,.18);color:var(--accent2);border-color:rgba(124,106,255,.3)}

    /* ========== SECTIONS ========== */
    .section{background:var(--card);backdrop-filter:blur(16px);border:1px solid var(--border);border-radius:var(--r);padding:22px;margin-bottom:18px;box-shadow:var(--shadow);transition:border-color var(--tr)}
    .section:hover{border-color:var(--border2)}
    .sec-title{font-family:'Syne',sans-serif;font-weight:700;font-size:15px;color:var(--text);margin-bottom:16px;display:flex;align-items:center;gap:8px}
    .sec-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;gap:10px;flex-wrap:wrap}
    .sec-head .sec-title{margin-bottom:0}

    /* ========== STATS ========== */
    .stats-bar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:18px;font-size:12px;color:var(--text2)}
    .stat-chip{display:flex;align-items:center;gap:5px;background:var(--card);border:1px solid var(--border);border-radius:999px;padding:5px 12px;transition:border-color var(--tr)}
    .stat-chip:hover{border-color:var(--border2)}
    .stat-chip strong{color:var(--text);font-weight:700}

    /* ========== DROP ZONE ========== */
    .drop-zone{border:2px dashed var(--border2);border-radius:var(--rsm);padding:28px 20px;text-align:center;color:var(--text2);background:rgba(124,106,255,.04);cursor:pointer;transition:background var(--tr),border-color var(--tr),transform var(--tr)}
    .drop-zone:hover,.drop-zone.dragover{background:rgba(124,106,255,.1);border-color:var(--accent);transform:scale(1.005)}
    .drop-zone .dz-icon{font-size:34px;margin-bottom:8px;display:block;transition:transform var(--tr)}
    .drop-zone:hover .dz-icon{transform:translateY(-4px)}
    .drop-zone .dz-label{font-size:14px;font-weight:500;margin-bottom:3px}
    .drop-zone small{font-size:12px;color:var(--muted)}
    #fileInput{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}

    /* ========== TOGGLE ========== */
    .toggle-row{display:inline-flex;align-items:center;gap:9px;background:rgba(124,106,255,.06);border:1px solid rgba(124,106,255,.14);border-radius:var(--rxs);padding:7px 13px;font-size:13px;color:var(--text2);user-select:none;cursor:pointer;transition:background var(--tr)}
    .toggle-row:hover{background:rgba(124,106,255,.11)}
    .toggle-track{width:34px;height:19px;border-radius:999px;background:var(--muted);position:relative;transition:background var(--tr);flex-shrink:0}
    .toggle-track::after{content:'';width:13px;height:13px;border-radius:50%;background:#fff;position:absolute;top:3px;left:3px;transition:transform var(--tr)}
    .toggle-row.on .toggle-track{background:var(--accent)}
    .toggle-row.on .toggle-track::after{transform:translateX(15px)}

    /* ========== BUTTONS ========== */
    .btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;padding:9px 18px;border-radius:var(--rxs);border:none;font-size:13px;font-weight:600;cursor:pointer;transition:opacity var(--tr),transform var(--tr),background var(--tr)}
    .btn:hover{opacity:.85;transform:translateY(-1px)}
    .btn:active{transform:none}
    .btn:disabled{opacity:.35;cursor:not-allowed;transform:none}
    .btn-primary{background:var(--accent-g);color:#fff;box-shadow:0 4px 14px rgba(124,106,255,.28);width:100%;margin-top:12px}
    .btn-green{background:rgba(52,211,153,.12);color:var(--green);border:1px solid rgba(52,211,153,.22)}
    .btn-red{background:rgba(248,113,113,.1);color:var(--red);border:1px solid rgba(248,113,113,.18)}
    .btn-ghost{background:var(--card);color:var(--text2);border:1px solid var(--border2)}
    .btn-accent{background:rgba(124,106,255,.15);color:var(--accent2);border:1px solid rgba(124,106,255,.25)}
    .btn-sm{padding:5px 11px;font-size:12px}

    /* ========== FOLDER TABS ========== */
    .folder-tabs{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:16px}
    .ftab{padding:6px 14px;border-radius:999px;border:1px solid var(--border2);background:var(--card);font-size:12px;font-weight:600;color:var(--text2);cursor:pointer;transition:background var(--tr),color var(--tr),border-color var(--tr);display:flex;align-items:center;gap:5px}
    .ftab.active{background:rgba(124,106,255,.18);color:var(--accent2);border-color:rgba(124,106,255,.3)}
    .ftab:hover:not(.active){background:var(--card-hov);color:var(--text)}
    .ftab .tab-del{width:14px;height:14px;border-radius:50%;background:rgba(248,113,113,.2);color:var(--red);display:flex;align-items:center;justify-content:center;font-size:10px;line-height:1;transition:background var(--tr)}
    .ftab .tab-del:hover{background:rgba(248,113,113,.5)}

    /* ========== PROGRESS ========== */
    .progress-wrap{display:none;margin-top:12px}
    .progress-track{height:5px;background:var(--border);border-radius:999px;overflow:hidden}
    .progress-fill{height:100%;width:0%;background:var(--accent-g);border-radius:999px;transition:width .3s ease;position:relative}
    .progress-fill::after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.25),transparent);animation:shimmer 1.4s infinite}
    @keyframes shimmer{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}
    .progress-meta{display:flex;justify-content:space-between;margin-top:5px;font-size:11px;color:var(--text2)}

    /* ========== TEXTAREA ========== */
    textarea{width:100%;padding:13px;background:rgba(255,255,255,.04);border:1px solid var(--border2);border-radius:var(--rsm);font-size:14px;color:var(--text);resize:vertical;min-height:88px;transition:border-color var(--tr),box-shadow var(--tr);outline:none;line-height:1.6}
    textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(124,106,255,.12)}
    textarea::placeholder{color:var(--muted)}
    input[type=text],input[type=number]{background:rgba(255,255,255,.04);border:1px solid var(--border2);border-radius:var(--rxs);padding:8px 12px;color:var(--text);font-size:13px;outline:none;transition:border-color var(--tr)}
    input[type=text]:focus,input[type=number]:focus{border-color:var(--accent)}

    /* ========== DATE GROUPS ========== */
    .date-group{margin-bottom:26px}
    .date-header{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}
    .date-label{display:flex;align-items:center;gap:7px;font-family:'Syne',sans-serif;font-weight:700;font-size:13px;color:var(--text2);text-transform:uppercase;letter-spacing:.06em}
    .date-count{background:var(--card);border:1px solid var(--border);border-radius:999px;padding:2px 9px;font-size:11px;font-weight:700;color:var(--text2)}
    .btn-group{display:flex;gap:7px;flex-wrap:wrap}

    /* ========== FILE CARDS ========== */
    .files{display:grid;grid-template-columns:repeat(auto-fill,minmax(205px,1fr));gap:13px}
    .file-card{background:var(--card);border:1px solid var(--border);border-radius:var(--rsm);overflow:hidden;position:relative;transition:transform var(--tr),border-color var(--tr),box-shadow var(--tr);display:flex;flex-direction:column}
    .file-card:hover{transform:translateY(-3px);border-color:var(--border2);box-shadow:0 12px 30px rgba(0,0,0,.3)}
    .file-card.is-fav{border-color:rgba(251,191,36,.3)}

    .file-thumb{width:100%;height:142px;background:rgba(255,255,255,.03);display:flex;align-items:center;justify-content:center;overflow:hidden;position:relative;cursor:pointer;flex-shrink:0}
    .file-thumb img{width:100%;height:100%;object-fit:cover;transition:transform .35s}
    .file-card:hover .file-thumb img{transform:scale(1.04)}
    .file-thumb video{width:100%;height:100%;object-fit:cover}
    .file-icon-big{font-size:40px;display:flex;flex-direction:column;align-items:center;gap:7px}
    .file-icon-big span{font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-family:'Syne',sans-serif}
    .audio-thumb{width:100%;height:142px;background:linear-gradient(135deg,rgba(124,106,255,.14),rgba(167,139,250,.08));display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;padding:10px}

    .prev-overlay{position:absolute;inset:0;background:rgba(0,0,0,.42);display:flex;align-items:center;justify-content:center;opacity:0;transition:opacity var(--tr)}
    .file-thumb:hover .prev-overlay{opacity:1}
    .prev-btn{background:rgba(124,106,255,.8);backdrop-filter:blur(4px);color:#fff;border:none;border-radius:999px;padding:7px 16px;font-size:12px;font-weight:700;display:flex;align-items:center;gap:5px;transition:background var(--tr)}

    .file-body{padding:11px;flex:1;display:flex;flex-direction:column}
    .file-name{font-weight:600;font-size:12px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:4px}
    .file-meta-row{font-size:10px;color:var(--muted);margin-bottom:9px;display:flex;gap:5px;align-items:center;flex-wrap:wrap}
    .fmtag{background:var(--card);border:1px solid var(--border);border-radius:4px;padding:1px 5px;font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.05em;color:var(--text2)}
    .file-actions{display:flex;gap:5px;margin-top:auto;align-items:center}
    .file-dl-btn{flex:1;padding:7px;background:var(--accent-g);color:#fff;border:none;border-radius:var(--rxs);font-size:11px;font-weight:700;text-align:center;display:block;transition:opacity var(--tr),transform var(--tr)}
    .file-dl-btn:hover{opacity:.84;transform:translateY(-1px)}

    /* File card overlay buttons */
    .card-del{position:absolute;top:7px;right:7px;background:rgba(248,113,113,.16);backdrop-filter:blur(4px);color:var(--red);border:1px solid rgba(248,113,113,.22);padding:5px;border-radius:7px;width:28px;height:28px;display:flex;align-items:center;justify-content:center;z-index:10;transition:background var(--tr),transform var(--tr)}
    .card-del:hover{background:rgba(248,113,113,.32);transform:scale(1.08)}
    .card-del svg{width:13px;height:13px}
    .card-fav{position:absolute;top:38px;right:7px;backdrop-filter:blur(4px);border:1px solid transparent;padding:3px;border-radius:7px;width:28px;height:28px;display:flex;align-items:center;justify-content:center;z-index:10;transition:background var(--tr),transform var(--tr);background:rgba(0,0,0,.35);color:var(--muted);font-size:14px;text-decoration:none}
    .card-fav:hover{background:rgba(251,191,36,.2);transform:scale(1.08)}
    .card-fav.on{background:rgba(251,191,36,.22);color:var(--yellow)}
    .card-share{position:absolute;top:69px;right:7px;backdrop-filter:blur(4px);border:1px solid transparent;padding:3px;border-radius:7px;width:28px;height:28px;display:flex;align-items:center;justify-content:center;z-index:10;transition:background var(--tr),transform var(--tr);background:rgba(0,0,0,.35);color:var(--muted);font-size:13px;text-decoration:none;cursor:pointer}
    .card-share:hover{background:rgba(124,106,255,.25);color:var(--accent2);transform:scale(1.08)}
    .card-share.has-share{background:rgba(52,211,153,.18);color:var(--green)}

    .card-perm{position:absolute;top:7px;left:7px;backdrop-filter:blur(4px);padding:3px 8px;border-radius:999px;font-size:10px;font-weight:700;z-index:10;transition:background var(--tr),color var(--tr),border-color var(--tr);white-space:nowrap;text-decoration:none;display:flex;align-items:center;gap:3px;background:rgba(0,0,0,.42);color:var(--muted);border:1px solid transparent}
    .card-perm.perm{background:rgba(124,106,255,.25);color:var(--accent2);border-color:rgba(124,106,255,.35)}
    .card-perm.soon{background:rgba(248,113,113,.22);color:var(--red);border-color:rgba(248,113,113,.3)}
    .card-perm.mid{background:rgba(251,191,36,.18);color:var(--yellow);border-color:rgba(251,191,36,.28)}
    .card-perm.ok{background:rgba(0,0,0,.42);color:var(--muted);border:1px solid transparent}
    .card-perm:hover{background:rgba(124,106,255,.3);color:var(--accent2)}

    /* ========== TEXT CARDS ========== */
    .texts-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:13px;align-items:start}
    .text-item{background:var(--card);border:1px solid var(--border);border-radius:var(--rsm);padding:13px;display:flex;flex-direction:column;gap:9px;transition:transform var(--tr),border-color var(--tr),box-shadow var(--tr)}
    .text-item:hover{transform:translateY(-2px);border-color:var(--border2);box-shadow:0 8px 22px rgba(0,0,0,.22)}
    .text-item.is-url{padding:10px}
    .text-item.is-url .url-preview-wrap{margin:-2px -2px 0}
    .url-preview-wrap{overflow:hidden;border-radius:var(--rxs)}
    .text-content{font-size:13px;line-height:1.65;color:var(--text2);word-break:break-word}
    .text-actions-row{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
    .text-time{font-size:10px;color:var(--muted);margin-right:auto}
    .tact{width:28px;height:28px;border-radius:7px;border:1px solid var(--border2);background:var(--card);color:var(--text2);display:flex;align-items:center;justify-content:center;cursor:pointer;transition:background var(--tr),color var(--tr),border-color var(--tr);flex-shrink:0}
    .tact:hover{background:var(--card-hov);color:var(--text)}
    .tact.del:hover{background:rgba(248,113,113,.13);color:var(--red);border-color:rgba(248,113,113,.22)}
    .tact.edit:hover{background:rgba(251,191,36,.1);color:var(--yellow);border-color:rgba(251,191,36,.22)}
    .tact.copy:hover{background:rgba(124,106,255,.13);color:var(--accent2);border-color:rgba(124,106,255,.22)}
    .tact.copied{background:rgba(52,211,153,.13);color:var(--green);border-color:rgba(52,211,153,.28)}
    .tact svg{width:13px;height:13px;pointer-events:none}

    /* ========== COUNTDOWN TIMER BADGE ========== */
    .ttl-badge{display:inline-flex;align-items:center;gap:4px;border-radius:999px;padding:3px 9px;font-size:10px;font-weight:700;white-space:nowrap;cursor:pointer;transition:background var(--tr),color var(--tr),border-color var(--tr);text-decoration:none;border:1px solid transparent}
    .ttl-badge.perm{background:rgba(124,106,255,.18);color:var(--accent2);border-color:rgba(124,106,255,.3)}
    .ttl-badge.soon{background:rgba(248,113,113,.15);color:var(--red);border-color:rgba(248,113,113,.25)}
    .ttl-badge.mid{background:rgba(251,191,36,.12);color:var(--yellow);border-color:rgba(251,191,36,.22)}
    .ttl-badge.ok{background:var(--card);color:var(--muted);border-color:var(--border)}
    .ttl-badge:hover{opacity:.8}

    /* ========== IMAGE ZOOM VIEWER ========== */
    .img-viewer{position:relative;width:100%;display:flex;flex-direction:column;gap:10px}
    .img-viewer-wrap{overflow:hidden;border-radius:var(--rxs);background:rgba(0,0,0,.3);display:flex;align-items:center;justify-content:center;max-height:65vh;min-height:200px;cursor:grab;user-select:none}
    .img-viewer-wrap:active{cursor:grabbing}
    .img-viewer-wrap img{max-width:100%;max-height:65vh;object-fit:contain;border-radius:var(--rxs);transition:transform .15s ease;transform-origin:center center;pointer-events:none}
    .img-controls{display:flex;align-items:center;justify-content:center;gap:8px;flex-wrap:wrap}
    .img-ctrl-btn{width:34px;height:34px;border-radius:8px;background:var(--card);border:1px solid var(--border2);color:var(--text2);display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:16px;transition:background var(--tr),color var(--tr);flex-shrink:0}
    .img-ctrl-btn:hover{background:var(--card-hov);color:var(--text)}
    .img-zoom-label{font-size:12px;color:var(--text2);min-width:42px;text-align:center;font-weight:600}

    /* ========== VIDEO SEEK CONTROLS ========== */
    .vid-wrap{position:relative;width:100%;border-radius:var(--rxs);overflow:hidden;background:#000}
    .vid-wrap video{width:100%;max-height:65vh;display:block}
    .vid-seek-bar{display:flex;align-items:center;justify-content:center;gap:8px;padding:8px 6px 2px;flex-wrap:wrap}
    .seek-btn{display:flex;align-items:center;gap:4px;background:var(--card);border:1px solid var(--border2);color:var(--text2);border-radius:8px;padding:5px 12px;font-size:12px;font-weight:700;cursor:pointer;transition:background var(--tr),color var(--tr);white-space:nowrap}
    .seek-btn:hover{background:var(--card-hov);color:var(--text)}
    .vid-time-lbl{font-size:11px;color:var(--text2);margin:0 4px;min-width:90px;text-align:center}

    /* ========== URL PREVIEW ========== */
    .url-preview-card{border-radius:var(--rxs);border:1px solid var(--border2);overflow:hidden;background:rgba(255,255,255,.03);display:block;transition:background var(--tr),border-color var(--tr);cursor:pointer}
    .url-preview-card:hover{background:rgba(255,255,255,.06);border-color:var(--accent)}
    .url-pimg{width:100%;height:112px;object-fit:cover;display:block}
    .url-pbody{padding:9px 11px;display:flex;flex-direction:column;gap:3px}
    .url-pdomain{display:flex;align-items:center;gap:5px;font-size:10px;color:var(--muted);font-weight:500}
    .url-ptitle{font-size:12px;font-weight:600;color:var(--text);line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
    .url-pdesc{font-size:11px;color:var(--text2);line-height:1.5;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
    .url-loader{display:flex;align-items:center;gap:8px;padding:9px;font-size:12px;color:var(--muted)}
    .spinner{width:13px;height:13px;border:2px solid var(--border2);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0}
    @keyframes spin{to{transform:rotate(360deg)}}

    /* ========== MODALS ========== */
    .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(8px);z-index:2000;align-items:center;justify-content:center;padding:16px}
    .modal-overlay.show{display:flex}
    .modal-box{background:var(--bg2);border:1px solid var(--border2);border-radius:var(--r);padding:22px;max-width:800px;width:100%;max-height:92vh;display:flex;flex-direction:column;gap:14px;box-shadow:0 32px 80px rgba(0,0,0,.6);animation:mIn .18s cubic-bezier(.4,0,.2,1)}
    @keyframes mIn{from{opacity:0;transform:scale(.96) translateY(8px)}to{opacity:1;transform:none}}
    .modal-head{display:flex;align-items:center;justify-content:space-between;gap:10px}
    .modal-ttl{font-family:'Syne',sans-serif;font-weight:700;font-size:15px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .modal-close{width:30px;height:30px;border-radius:7px;flex-shrink:0;background:var(--card);border:1px solid var(--border2);color:var(--text2);display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:17px;transition:background var(--tr),color var(--tr)}
    .modal-close:hover{background:rgba(248,113,113,.13);color:var(--red)}
    .modal-body{flex:1;overflow:auto;display:flex;align-items:center;justify-content:center;min-height:180px}
    .modal-body img{max-width:100%;max-height:68vh;border-radius:var(--rxs);object-fit:contain}
    .modal-body video,.modal-body audio{width:100%;border-radius:var(--rxs)}
    .modal-body iframe{width:100%;height:65vh;border:none;border-radius:var(--rxs)}
    .modal-body pre{background:rgba(0,0,0,.28);border:1px solid var(--border);border-radius:var(--rxs);padding:14px;font-size:11px;color:var(--text2);overflow:auto;max-height:60vh;width:100%;white-space:pre-wrap;word-break:break-word;line-height:1.6}
    .modal-foot{display:flex;gap:7px;justify-content:flex-end}
    /* Share modal */
    .share-modal-box{max-width:480px}
    .share-opt{display:flex;flex-direction:column;gap:12px}
    .share-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
    .share-row label{font-size:12px;color:var(--text2);min-width:100px;font-weight:500}
    .share-url-wrap{display:flex;gap:8px;align-items:center}
    .share-url-box{flex:1;padding:9px 12px;background:rgba(124,106,255,.1);border:1px solid rgba(124,106,255,.25);border-radius:var(--rxs);font-size:12px;color:var(--accent2);word-break:break-all;font-family:monospace}
    .share-chip{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:999px;border:1px solid var(--border2);background:var(--card);font-size:12px;color:var(--text2);cursor:pointer;transition:background var(--tr),color var(--tr),border-color var(--tr)}
    .share-chip.active{background:rgba(124,106,255,.18);color:var(--accent2);border-color:rgba(124,106,255,.3)}
    /* Folder modal */
    .folder-modal-box{max-width:400px}

    /* ========== TOAST NOTIFICATIONS ========== */
    #toastContainer{position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none}
    .toast{background:var(--bg2);border:1px solid var(--border2);border-radius:12px;padding:12px 18px;font-size:13px;color:var(--text);box-shadow:0 8px 24px rgba(0,0,0,.4);display:flex;align-items:center;gap:10px;pointer-events:all;animation:toastIn .25s cubic-bezier(.4,0,.2,1);max-width:320px;min-width:220px}
    .toast.out{animation:toastOut .25s forwards}
    .toast-icon{font-size:16px;flex-shrink:0}
    .toast.ok{border-color:rgba(52,211,153,.25)}
    .toast.ok .toast-icon::after{content:'✅'}
    .toast.err{border-color:rgba(248,113,113,.25)}
    .toast.err .toast-icon::after{content:'❌'}
    .toast.info{border-color:rgba(124,106,255,.25)}
    .toast.info .toast-icon::after{content:'📋'}
    @keyframes toastIn{from{opacity:0;transform:translateY(16px) scale(.95)}to{opacity:1;transform:none}}
    @keyframes toastOut{to{opacity:0;transform:translateY(8px) scale(.95)}}

    /* ========== MESSAGE ========== */
    .message{background:rgba(52,211,153,.09);color:var(--green);border:1px solid rgba(52,211,153,.22);border-radius:var(--rxs);padding:11px 14px;margin-bottom:14px;font-size:13px;text-align:center}

    /* ========== UPLOAD OPTIONS ROW ========== */
    .upload-opts{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:12px;flex-wrap:wrap}
    .file-count-lbl{font-size:12px;color:var(--accent2);flex:1}

    /* ========== FOLDER SELECT ========== */
    .folder-select{padding:7px 10px;background:var(--card);border:1px solid var(--border2);border-radius:var(--rxs);color:var(--text2);font-size:12px;cursor:pointer;outline:none}
    .folder-select:focus{border-color:var(--accent)}

    /* ========== EMPTY STATE ========== */
    .empty-state{text-align:center;padding:36px 20px;color:var(--muted);font-size:13px}
    .empty-state span{font-size:40px;display:block;margin-bottom:10px}

    /* ========== RESPONSIVE ========== */
    @media(max-width:900px){
        body{padding:16px 12px 60px}
        .site-header{gap:10px;margin-bottom:16px}
        .header-r{gap:6px}
        .section{padding:16px;border-radius:12px;margin-bottom:14px}
        .files{grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:11px}
        .texts-grid{grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:11px}
        .modal-box{padding:18px;gap:12px}
    }
    @media(max-width:768px){
        .stats-bar{gap:6px}
        .stat-chip{padding:4px 10px;font-size:11px}
        .url-pill{max-width:180px;font-size:11px;padding:5px 11px}
        .date-header{flex-direction:row;flex-wrap:wrap;gap:8px}
        .btn-group{flex-wrap:wrap;gap:6px}
        .drop-zone{padding:22px 16px}
        .upload-opts{flex-direction:column;align-items:stretch;gap:8px}
        .toggle-row{width:100%;justify-content:center}
        .file-count-lbl{text-align:center}
        .file-thumb{height:130px}
    }
    @media(max-width:480px){
        body{padding:12px 10px 70px}
        .site-header{flex-direction:column;align-items:stretch;gap:8px;margin-bottom:16px}
        .header-r{justify-content:space-between;width:100%}
        .url-pill{display:none}
        .logout-btn .logout-text{display:none}
        .site-title{text-align:center;font-size:22px}
        .stats-bar{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:14px}
        .stat-chip{justify-content:center;font-size:11px;padding:5px 8px;border-radius:8px}
        .section{padding:13px;border-radius:10px;margin-bottom:12px}
        .sec-title{font-size:14px;margin-bottom:12px}
        .date-header{flex-direction:column;align-items:flex-start;gap:8px}
        .btn-group{width:100%;display:grid;grid-template-columns:1fr 1fr;gap:6px}
        .btn-group .btn{width:100%;justify-content:center}
        .btn-sm{padding:8px 10px;font-size:12px}
        .files{grid-template-columns:repeat(2,1fr);gap:9px}
        .file-thumb{height:115px}
        .file-body{padding:9px}
        .file-name{font-size:11px}
        .file-meta-row{font-size:10px;margin-bottom:7px}
        .file-dl-btn{padding:7px 6px;font-size:11px}
        .card-perm{font-size:9px;padding:2px 6px}
        .card-del{width:26px;height:26px}
        .texts-grid{grid-template-columns:1fr;gap:9px}
        .text-item{padding:11px;gap:8px}
        .btn-primary{padding:13px;font-size:15px}
        .modal-overlay{padding:0;align-items:flex-end}
        .modal-box{border-radius:16px 16px 0 0;max-height:95vh;max-width:100%;padding:16px;gap:10px;animation:sheetIn .22s cubic-bezier(.4,0,.2,1)}
        @keyframes sheetIn{from{transform:translateY(100%)}to{transform:translateY(0)}}
        .modal-foot{flex-direction:row;gap:8px}
        .modal-foot .btn{flex:1;padding:11px}
        .img-ctrl-btn{width:40px;height:40px;font-size:18px}
        .seek-btn{padding:8px 14px;font-size:13px}
        #toastContainer{bottom:16px;right:12px;left:12px}
        .toast{max-width:100%}
    }
    @media(max-width:360px){
        body{padding:10px 8px 70px}
        .files{grid-template-columns:repeat(2,1fr);gap:7px}
        .file-thumb{height:100px}
        .stat-chip{font-size:10px;padding:4px 6px}
        .section{padding:11px}
    }
    @media(min-width:481px) and (max-width:768px){
        .files{grid-template-columns:repeat(auto-fill,minmax(160px,1fr))}
        .texts-grid{grid-template-columns:repeat(2,1fr)}
    }
    @media(hover:none){
        .prev-overlay{opacity:1;background:rgba(0,0,0,.25)}
        .prev-btn{font-size:11px;padding:5px 12px}
        .file-card:hover{transform:none;box-shadow:none}
        .text-item:hover{transform:none;box-shadow:none}
    }
    </style>
</head>
<body>
<!-- Toast Container -->
<div id="toastContainer"></div>

<div class="container">

<!-- HEADER -->
<header class="site-header">
    <h1 class="site-title">⚡ Fast Transfer</h1>
    <div class="header-r">
        <div class="url-pill" title="<?= h($currentURL) ?>">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15 15 0 0 1 4 10 15 15 0 0 1-4 10 15 15 0 0 1-4-10 15 15 0 0 1 4-10z"/></svg>
            <span><?= h($currentURL) ?></span>
        </div>
        <button class="icon-btn" id="themeToggle" onclick="toggleTheme()" title="Toggle theme">🌙</button>
        <a href="?logout" class="icon-btn logout-btn" onclick="return confirm('Log out?')">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            <span class="logout-text">Logout</span>
        </a>
    </div>
</header>

<!-- STATS -->
<div class="stats-bar">
    <div class="stat-chip">📁 <strong><?= $totalFiles ?></strong> files</div>
    <div class="stat-chip">💾 <strong><?= $totalStorageFmt ?></strong> used</div>
    <div class="stat-chip">📋 <strong><?= $totalTexts ?></strong> texts</div>
    <div class="stat-chip">⬇ <strong><?= $totalDownloads ?></strong> downloads</div>
    <div class="stat-chip">🗑️ Auto-delete <strong>72h</strong></div>
    <?php if (!empty($favFiles)): ?>
    <div class="stat-chip">⭐ <strong><?= count($favFiles) ?></strong> favorites</div>
    <?php endif; ?>
</div>

<!-- SEARCH & FILTERS -->
<div class="search-bar">
    <div class="search-wrap">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input type="text" id="searchInput" placeholder="Search files by name…" oninput="filterFiles()" autocomplete="off">
    </div>
    <div class="filter-chips" id="filterChips">
        <span class="fchip active" data-type="all" onclick="setFilter(this,'all')">All</span>
        <span class="fchip" data-type="image" onclick="setFilter(this,'image')">🖼 Images</span>
        <span class="fchip" data-type="video" onclick="setFilter(this,'video')">🎬 Video</span>
        <span class="fchip" data-type="audio" onclick="setFilter(this,'audio')">🎵 Audio</span>
        <span class="fchip" data-type="document" onclick="setFilter(this,'document')">📄 Docs</span>
        <span class="fchip" data-type="fav" onclick="setFilter(this,'fav')">⭐ Favorites</span>
    </div>
</div>

<!-- UPLOAD FILES -->
<div class="section">
    <div class="sec-title">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
        Upload Files
    </div>
    <form id="uploadForm">
        <div id="dropZone" class="drop-zone">
            <span class="dz-icon">📂</span>
            <div class="dz-label">Drag &amp; drop files here or paste (Ctrl+V)</div>
            <small>click to select · max 200MB per file</small>
        </div>
        <input type="file" id="fileInput" multiple>
        <div class="upload-opts">
            <span class="file-count-lbl" id="fileCount"></span>
            <label class="toggle-row" id="filePermToggle" title="Keep files forever">
                <div class="toggle-track"></div>
                <span>Keep Forever</span>
            </label>
            <?php if (!empty($folders)): ?>
            <select class="folder-select" id="uploadFolderSelect">
                <option value="">📁 No folder</option>
                <?php foreach ($folders as $f): ?>
                <option value="<?= h($f) ?>"><?= h($f) ?></option>
                <?php endforeach; ?>
            </select>
            <?php endif; ?>
        </div>
        <button type="submit" class="btn btn-primary" id="uploadBtn">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
            Upload Files
        </button>
        <div class="progress-wrap" id="progressContainer">
            <div class="progress-track"><div class="progress-fill" id="progressFill"></div></div>
            <div class="progress-meta"><span id="uploadSpeed">Preparing…</span><span id="progressPct">0%</span></div>
        </div>
    </form>
</div>

<!-- SAVE TEXT / URL -->
<div class="section">
    <div class="sec-title">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
        Save Text or URL
    </div>
    <form id="textForm" method="POST">
        <textarea name="text" id="textArea" placeholder="Paste text or a URL — URLs get a rich preview… (also try Ctrl+V to paste screenshots as files)" required></textarea>
        <input type="hidden" name="text_permanent" id="textPermInput" value="0">
        <div class="upload-opts">
            <span style="font-size:12px;color:var(--muted)">URLs auto-detected &amp; previewed.</span>
            <label class="toggle-row" id="textPermToggle" title="Keep text forever">
                <div class="toggle-track"></div>
                <span>Keep Forever</span>
            </label>
        </div>
        <button type="submit" class="btn btn-primary" style="margin-top:10px">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
            Save
        </button>
    </form>
</div>

<!-- FOLDERS SECTION -->
<div class="section">
    <div class="sec-head">
        <div class="sec-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
            Folders
        </div>
        <button class="btn btn-accent btn-sm" onclick="openFolderModal()">+ New Folder</button>
    </div>
    <div class="folder-tabs" id="folderTabs">
        <span class="ftab active" data-folder="__all__" onclick="setFolderTab(this,'__all__')">📁 All Files</span>
        <?php foreach ($folders as $f): ?>
        <span class="ftab" data-folder="<?= h($f) ?>" onclick="setFolderTab(this,'<?= h(addslashes($f)) ?>')">
            📂 <?= h($f) ?>
            <a href="?delete_folder=<?= urlencode($f) ?>" class="tab-del" onclick="event.stopPropagation();return confirm('Delete folder <?= h(addslashes($f)) ?>? Files will be moved to All.')" title="Delete folder">×</a>
        </span>
        <?php endforeach; ?>
    </div>
</div>

<!-- SAVED TEXTS -->
<?php if (!empty($texts)): ?>
<div class="section">
    <div class="sec-title">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        Saved Texts (<?= $totalTexts ?>)
    </div>
    <?php foreach ($textsByDate as $dateCategory => $dateTexts): ?>
    <div class="date-group">
        <div class="date-header">
            <div class="date-label">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
                <?= h($dateCategory) ?> <span class="date-count"><?= count($dateTexts) ?></span>
            </div>
            <a href="?delete_texts_day=<?= urlencode($dateCategory) ?>" class="btn btn-red btn-sm" onclick="return confirm('Delete all texts from <?= h($dateCategory) ?>?')">🗑️ Delete Day</a>
        </div>
        <div class="texts-grid">
        <?php foreach ($dateTexts as $textData):
            $isPerm  = $textData['permanent'];
            $content = $textData['content'];
            $isUrl   = isUrl(trim($content));
            $canEdit = $isPerm || ($textData['time'] >= (time()-72*60*60));
        ?>
        <div class="text-item<?= $isUrl?' is-url':'' ?>">
            <?php if ($isUrl): ?>
                <div class="url-preview-wrap" data-url="<?= h(trim($content)) ?>">
                    <div class="url-loader"><div class="spinner"></div> Loading preview…</div>
                </div>
            <?php else: ?>
                <div class="text-content"><?= h(mb_strlen($content)>220 ? mb_substr($content,0,220).'…' : $content) ?></div>
            <?php endif; ?>
            <div class="text-actions-row">
                <span class="text-time"><?= date('H:i', $textData['time']) ?></span>
                <a href="?toggle_perm_text=<?= (int)$textData['index'] ?>" class="ttl-badge <?= $isPerm?'perm':'' ?>" data-expires="<?= $isPerm ? '0' : ($textData['time'] + 72*60*60) ?>" data-perm="<?= $isPerm?'1':'0' ?>" title="Click to toggle permanent"><?= $isPerm ? '🔒 Perm' : '' ?></a>
                <?php if ($canEdit): ?>
                <button class="tact edit" onclick="openEditModal(<?= (int)$textData['index'] ?>)" title="Edit">
                    <svg fill="currentColor" viewBox="0 0 24 24"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
                </button>
                <?php endif; ?>
                <button class="tact copy" onclick="copyText(this,<?= (int)$textData['index'] ?>)" title="Copy">
                    <svg fill="currentColor" viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
                </button>
                <a href="?delete_text=<?= (int)$textData['index'] ?>" class="tact del" onclick="return confirm('Delete this text?')" title="Delete">
                    <svg fill="currentColor" viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
                </a>
                <textarea id="full-text-<?= (int)$textData['index'] ?>" style="display:none;position:absolute;left:-9999px"><?= h($textData['content']) ?></textarea>
            </div>
        </div>
        <?php endforeach; ?>
        </div>
    </div>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<!-- FILES -->
<?php if (!empty($filesByDate)): ?>
<div class="section" id="filesSection">
    <div class="sec-title">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
        Files (<?= $totalFiles ?>)
    </div>
    <div id="noResults" class="empty-state" style="display:none"><span>🔍</span>No files match your search.</div>
    <?php foreach ($filesByDate as $dateCategory => $dateFiles): ?>
    <div class="date-group" id="dg-<?= h(preg_replace('/[^A-Za-z0-9]/','-',$dateCategory)) ?>">
        <div class="date-header">
            <div class="date-label">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
                <?= h($dateCategory) ?> <span class="date-count" id="cnt-<?= h(preg_replace('/[^A-Za-z0-9]/','-',$dateCategory)) ?>"><?= count($dateFiles) ?></span>
            </div>
            <div class="btn-group">
                <a href="?download_zip=<?= urlencode($dateCategory) ?>" class="btn btn-green btn-sm">📦 ZIP</a>
                <a href="?delete_day=<?= urlencode($dateCategory) ?>" class="btn btn-red btn-sm" onclick="return confirm('Delete all files from <?= h($dateCategory) ?>?')">🗑️ Delete Day</a>
            </div>
        </div>
        <div class="files" id="fg-<?= h(preg_replace('/[^A-Za-z0-9]/','-',$dateCategory)) ?>">
        <?php foreach ($dateFiles as $fd):
            $file     = $fd['name'];
            $filePath = $fd['path'];
            $isPerm   = $fd['permanent'];
            $isFav    = $fd['fav'];
            $fileFolder = $fd['folder'];
            $dlCount  = $fd['downloads'];
            $ext      = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $fileSize = formatFileSize(filesize($filePath));
            $fileType = strtoupper($ext);
            $hasShare = !empty($fileShares[$file]);

            $imgExts  = ['jpg','jpeg','png','gif','webp','bmp','svg'];
            $vidExts  = ['mp4','webm','ogg','mov','avi','mkv'];
            $pdfExts  = ['pdf'];
            $audExts  = ['mp3','wav','ogg','aac','flac','m4a','opus'];
            $txtExts  = ['txt','md','csv','json','xml','html','css','js','php','py','sh','log'];
            $zipExts  = ['zip','rar','7z','tar','gz'];

            $isImg  = in_array($ext,$imgExts);
            $isVid  = in_array($ext,$vidExts);
            $isPdf  = in_array($ext,$pdfExts);
            $isAud  = in_array($ext,$audExts);
            $isTxt  = in_array($ext,$txtExts);
            $isZip  = in_array($ext,$zipExts);

            // File type category for filtering
            $typeClass = 'type-other';
            if ($isImg) $typeClass = 'type-image';
            elseif ($isVid) $typeClass = 'type-video';
            elseif ($isAud) $typeClass = 'type-audio';
            elseif ($isPdf || $isTxt) $typeClass = 'type-document';

            $icons=['pdf'=>'📄','doc'=>'📝','docx'=>'📝','xls'=>'📊','xlsx'=>'📊','ppt'=>'📽','pptx'=>'📽','zip'=>'📦','rar'=>'📦','7z'=>'📦','tar'=>'📦','gz'=>'📦','exe'=>'⚙️','apk'=>'📱','iso'=>'💿','txt'=>'📃','md'=>'📃','csv'=>'📊','json'=>'📋','xml'=>'📋','html'=>'🌐','css'=>'🎨','js'=>'⚡','php'=>'🐘','py'=>'🐍','sh'=>'🖥️'];
            $icon=$icons[$ext]??'📎';
        ?>
        <div class="file-card <?= $isFav?'is-fav':'' ?> <?= $typeClass ?>"
             data-name="<?= h(strtolower($file)) ?>"
             data-folder="<?= h($fileFolder) ?>"
             data-fav="<?= $isFav?'1':'0' ?>">
            <!-- Delete -->
            <a href="?delete_file=<?= urlencode($file) ?>" class="card-del" onclick="return confirm('Delete <?= h(addslashes($file)) ?>?')">
                <svg fill="currentColor" viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
            </a>
            <!-- Favorite -->
            <a href="?toggle_fav=<?= urlencode($file) ?>" class="card-fav <?= $isFav?'on':'' ?>" title="<?= $isFav?'Unstar':'Star this file' ?>">⭐</a>
            <!-- Share -->
            <button class="card-share <?= $hasShare?'has-share':'' ?>" onclick="openShareModal('<?= h(addslashes($file)) ?>')" title="Share link">🔗</button>
            <!-- TTL Badge -->
            <a href="?toggle_perm_file=<?= urlencode($file) ?>" class="card-perm <?= $isPerm?'perm':'' ?>" data-expires="<?= $isPerm ? '0' : ($fd['time'] + 72*60*60) ?>" data-perm="<?= $isPerm?'1':'0' ?>" title="Click to toggle permanent"><?= $isPerm ? '🔒 Perm' : '' ?></a>

            <!-- Thumbnail -->
            <div class="file-thumb" onclick="openPreview('<?= h(addslashes($file)) ?>','<?= $ext ?>','<?= h(addslashes($fileSize)) ?>')">
                <?php if ($isImg): ?>
                    <img src="<?= h('uploads/'.$file) ?>" alt="<?= h($file) ?>" loading="lazy">
                    <div class="prev-overlay"><button class="prev-btn">👁 Preview</button></div>
                <?php elseif ($isVid): ?>
                    <video preload="metadata" muted><source src="<?= h('uploads/'.$file) ?>" type="video/<?= h($ext) ?>"></video>
                    <div class="prev-overlay"><button class="prev-btn">▶ Play</button></div>
                <?php elseif ($isPdf): ?>
                    <div class="file-icon-big">📄<span>PDF</span></div>
                    <div class="prev-overlay"><button class="prev-btn">👁 View</button></div>
                <?php elseif ($isAud): ?>
                    <div class="audio-thumb">
                        <div style="font-size:36px">🎵</div>
                        <div style="font-size:10px;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.08em;font-family:'Syne',sans-serif;margin-top:4px"><?= h($fileType) ?></div>
                    </div>
                    <div class="prev-overlay"><button class="prev-btn">▶ Play</button></div>
                <?php elseif ($isTxt): ?>
                    <?php $prev = getTextFilePreview($filePath, 4); ?>
                    <div style="width:100%;height:100%;padding:8px;font-size:9.5px;color:var(--muted);font-family:monospace;background:rgba(0,0,0,.18);overflow:hidden;display:flex;align-items:flex-start;text-align:left;cursor:pointer">
                        <pre style="margin:0;white-space:pre-wrap;word-break:break-all;line-height:1.5"><?= h($prev) ?></pre>
                    </div>
                    <div class="prev-overlay"><button class="prev-btn">📄 View</button></div>
                <?php else: ?>
                    <div class="file-icon-big"><?= $icon ?><span><?= h($fileType) ?></span></div>
                    <?php if (!$isZip): ?><div class="prev-overlay"><button class="prev-btn">👁 Info</button></div><?php endif; ?>
                <?php endif; ?>
            </div>

            <div class="file-body">
                <div class="file-name" title="<?= h($file) ?>"><?= h($file) ?></div>
                <div class="file-meta-row">
                    <span class="fmtag"><?= h($fileType) ?></span>
                    <span><?= h($fileSize) ?></span>
                    <?php if ($dlCount > 0): ?><span>⬇ <?= $dlCount ?></span><?php endif; ?>
                    <?php if ($fileFolder): ?><span style="color:var(--accent2)">📂 <?= h($fileFolder) ?></span><?php endif; ?>
                </div>
                <div class="file-actions">
                    <a href="?download=<?= urlencode($file) ?>" class="file-dl-btn">⬇ Download</a>
                    <?php if (!empty($folders)): ?>
                    <select class="folder-select" style="flex:none;padding:5px 6px;font-size:10px;max-width:90px" onchange="moveFile('<?= h(addslashes($file)) ?>',this.value)" title="Move to folder">
                        <option value="">📁</option>
                        <?php foreach ($folders as $f): ?>
                        <option value="<?= h($f) ?>" <?= $fileFolder===$f?'selected':'' ?>><?= h($f) ?></option>
                        <?php endforeach; ?>
                    </select>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <?php endforeach; ?>
        </div>
    </div>
    <?php endforeach; ?>
</div>
<?php else: ?>
<div class="section"><div class="empty-state"><span>📂</span>No files uploaded yet. Drop something above!</div></div>
<?php endif; ?>

</div><!-- /container -->

<!-- EDIT TEXT MODAL -->
<div class="modal-overlay" id="editModal">
    <div class="modal-box" style="max-width:500px">
        <div class="modal-head">
            <span class="modal-ttl">✏️ Edit Text</span>
            <button class="modal-close" onclick="closeEditModal()">×</button>
        </div>
        <div class="modal-body" style="display:block">
            <form method="POST" id="editForm">
                <textarea name="edit_text" id="editTextArea" required style="width:100%;height:170px;resize:vertical"></textarea>
                <input type="hidden" name="text_index" id="editTextIndex">
            </form>
        </div>
        <div class="modal-foot">
            <button class="btn btn-primary" style="width:auto" onclick="document.getElementById('editForm').submit()">Save</button>
            <button class="btn btn-ghost" style="width:auto" onclick="closeEditModal()">Cancel</button>
        </div>
    </div>
</div>

<!-- FILE PREVIEW MODAL -->
<div class="modal-overlay" id="previewModal">
    <div class="modal-box">
        <div class="modal-head">
            <span class="modal-ttl" id="previewTitle">Preview</span>
            <button class="modal-close" onclick="closePreview()">×</button>
        </div>
        <div class="modal-body" id="previewBody"></div>
        <div class="modal-foot">
            <a id="previewDl" href="#" class="btn btn-primary" style="width:auto">⬇ Download</a>
            <button class="btn btn-ghost" style="width:auto" onclick="closePreview()">Close</button>
        </div>
    </div>
</div>

<!-- SHARE MODAL -->
<div class="modal-overlay" id="shareModal">
    <div class="modal-box share-modal-box">
        <div class="modal-head">
            <span class="modal-ttl">🔗 Share Link</span>
            <button class="modal-close" onclick="closeShareModal()">×</button>
        </div>
        <div class="modal-body" style="display:block;overflow:visible;min-height:unset">
            <div class="share-opt" id="shareOpt">
                <div id="shareFileName" style="font-size:13px;color:var(--text2);font-weight:500"></div>
                <!-- Expiry -->
                <div class="share-row">
                    <label>Expiry</label>
                    <div style="display:flex;gap:6px;flex-wrap:wrap">
                        <span class="share-chip active" data-val="0" onclick="selectShareChip(this,'expiry')">♾ Permanent</span>
                        <span class="share-chip" data-val="3600" onclick="selectShareChip(this,'expiry')">1 Hour</span>
                        <span class="share-chip" data-val="86400" onclick="selectShareChip(this,'expiry')">1 Day</span>
                        <span class="share-chip" data-val="604800" onclick="selectShareChip(this,'expiry')">7 Days</span>
                    </div>
                </div>
                <!-- Download limit -->
                <div class="share-row">
                    <label>Max Downloads</label>
                    <div style="display:flex;gap:6px;flex-wrap:wrap">
                        <span class="share-chip active" data-val="0" onclick="selectShareChip(this,'maxdl')">Unlimited</span>
                        <span class="share-chip" data-val="1" onclick="selectShareChip(this,'maxdl')">1×</span>
                        <span class="share-chip" data-val="5" onclick="selectShareChip(this,'maxdl')">5×</span>
                        <span class="share-chip" data-val="10" onclick="selectShareChip(this,'maxdl')">10×</span>
                    </div>
                </div>
                <!-- Password -->
                <div class="share-row">
                    <label>Password</label>
                    <input type="password" id="sharePassword" placeholder="Optional — leave blank for none" style="flex:1">
                </div>
                <button class="btn btn-primary" style="width:100%;margin-top:0" onclick="createShareLink()">🔗 Generate Link</button>
                <div id="shareResult" style="display:none">
                    <div class="share-url-wrap">
                        <div class="share-url-box" id="shareUrlBox"></div>
                        <button class="btn btn-accent btn-sm" onclick="copyShareUrl()">Copy</button>
                    </div>
                    <div style="font-size:11px;color:var(--muted);margin-top:6px" id="shareInfo"></div>
                </div>
            </div>
        </div>
        <div class="modal-foot">
            <button class="btn btn-ghost" style="width:auto" onclick="closeShareModal()">Close</button>
        </div>
    </div>
</div>

<!-- FOLDER MODAL -->
<div class="modal-overlay" id="folderModal">
    <div class="modal-box folder-modal-box">
        <div class="modal-head">
            <span class="modal-ttl">📁 New Folder</span>
            <button class="modal-close" onclick="closeFolderModal()">×</button>
        </div>
        <div class="modal-body" style="display:block;min-height:unset">
            <input type="text" id="folderNameInput" placeholder="Folder name…" style="width:100%" maxlength="40">
        </div>
        <div class="modal-foot">
            <button class="btn btn-primary" style="width:auto" onclick="createFolder()">Create</button>
            <button class="btn btn-ghost" style="width:auto" onclick="closeFolderModal()">Cancel</button>
        </div>
    </div>
</div>

<script>
/* ====================================================
   CONSTANTS
==================================================== */
const CHUNK_SIZE   = 15 * 1024 * 1024;
const MAX_FILE_SIZE = 200 * 1024 * 1024;
const MAX_PARALLEL = 3;

/* ====================================================
   TOAST NOTIFICATIONS
==================================================== */
function toast(msg, type='ok', dur=3200) {
    const tc = document.getElementById('toastContainer');
    const t = document.createElement('div');
    t.className = 'toast '+type;
    t.innerHTML = `<span class="toast-icon"></span><span>${msg}</span>`;
    tc.appendChild(t);
    setTimeout(()=>{ t.classList.add('out'); setTimeout(()=>t.remove(),300); }, dur);
}

/* ====================================================
   THEME TOGGLE
==================================================== */
function toggleTheme() {
    const html=document.documentElement, isLight=html.dataset.theme==='light', next=isLight?'dark':'light';
    html.dataset.theme=next;
    document.getElementById('themeToggle').textContent=isLight?'🌙':'☀️';
    localStorage.setItem('ft_theme',next);
    document.cookie='ft_theme='+next+';path=/;max-age=31536000;samesite=Lax';
}
(function(){
    const t=localStorage.getItem('ft_theme')||(document.cookie.match(/(?:^|;\s*)ft_theme=([^;]+)/)||[])[1]||'dark';
    const btn=document.getElementById('themeToggle');
    if(btn) btn.textContent=(t==='light')?'☀️':'🌙';
})();

/* ====================================================
   AUTO DARK MODE (system preference)
==================================================== */
if(!localStorage.getItem('ft_theme')) {
    const mq=window.matchMedia('(prefers-color-scheme: light)');
    if(mq.matches){ document.documentElement.setAttribute('data-theme','light'); document.getElementById('themeToggle').textContent='☀️'; }
    mq.addEventListener('change',e=>{
        if(!localStorage.getItem('ft_theme_manual')) {
            document.documentElement.setAttribute('data-theme',e.matches?'light':'dark');
            document.getElementById('themeToggle').textContent=e.matches?'☀️':'🌙';
        }
    });
}

/* ====================================================
   KEEP-FOREVER TOGGLES
==================================================== */
let fileIsPermanent = false;
document.getElementById('filePermToggle').addEventListener('click', function(){
    this.classList.toggle('on'); fileIsPermanent=this.classList.contains('on');
});
document.getElementById('textPermToggle').addEventListener('click', function(){
    this.classList.toggle('on'); document.getElementById('textPermInput').value=this.classList.contains('on')?'1':'0';
});

/* ====================================================
   SEARCH & FILTER
==================================================== */
let currentFilter = 'all';
let currentFolder = '__all__';

function filterFiles() {
    const q = document.getElementById('searchInput').value.toLowerCase().trim();
    let visibleTotal = 0;
    document.querySelectorAll('.file-card').forEach(card => {
        const name = card.dataset.name || '';
        const folder = card.dataset.folder || '';
        const isFav = card.dataset.fav === '1';
        let typeMatch = false;
        if (currentFilter === 'all') typeMatch = true;
        else if (currentFilter === 'fav') typeMatch = isFav;
        else typeMatch = card.classList.contains('type-'+currentFilter);
        const folderMatch = currentFolder === '__all__' || folder === currentFolder;
        const searchMatch = q === '' || name.includes(q);
        const visible = typeMatch && folderMatch && searchMatch;
        card.style.display = visible ? '' : 'none';
        if (visible) visibleTotal++;
    });
    // Show/hide date groups
    document.querySelectorAll('.date-group').forEach(dg => {
        const visible = Array.from(dg.querySelectorAll('.file-card')).some(c=>c.style.display!=='none');
        dg.style.display = visible ? '' : 'none';
    });
    document.getElementById('noResults') && (document.getElementById('noResults').style.display = visibleTotal===0?'block':'none');
}

function setFilter(el, type) {
    document.querySelectorAll('.fchip').forEach(c=>c.classList.remove('active'));
    el.classList.add('active'); currentFilter = type; filterFiles();
}
function setFolderTab(el, folder) {
    document.querySelectorAll('.ftab').forEach(t=>t.classList.remove('active'));
    el.classList.add('active'); currentFolder = folder; filterFiles();
}

/* ====================================================
   DROP ZONE
==================================================== */
const fileInput = document.getElementById('fileInput');
const fileCount = document.getElementById('fileCount');
const dropZone  = document.getElementById('dropZone');

fileInput.addEventListener('change', e => {
    const c = e.target.files.length;
    fileCount.textContent = c ? `📁 ${c} file(s) selected` : '';
});
['dragenter','dragover','dragleave','drop'].forEach(ev=>dropZone.addEventListener(ev,e=>{e.preventDefault();e.stopPropagation();}));
['dragenter','dragover'].forEach(ev=>dropZone.addEventListener(ev,()=>dropZone.classList.add('dragover')));
['dragleave','drop'].forEach(ev=>dropZone.addEventListener(ev,()=>dropZone.classList.remove('dragover')));
dropZone.addEventListener('click', ()=>fileInput.click());
dropZone.addEventListener('drop', e=>{
    const f=e.dataTransfer.files; if(!f||!f.length)return;
    fileInput.files=f; fileCount.textContent=`📁 ${f.length} file(s) selected`;
});

/* ====================================================
   PASTE UPLOAD (Ctrl+V screenshots)
==================================================== */
document.addEventListener('paste', async e => {
    const items = [...(e.clipboardData?.items||[])];
    const imgItem = items.find(i=>i.type.startsWith('image/'));
    if (!imgItem) return;
    e.preventDefault();
    const blob = imgItem.getAsFile();
    if (!blob) return;
    const ts = new Date().toISOString().replace(/[:.]/g,'_').replace('T','_').slice(0,19);
    const ext = blob.type.split('/')[1]||'png';
    const named = new File([blob], `paste_${ts}.${ext}`, {type:blob.type});
    const dt = new DataTransfer(); dt.items.add(named);
    fileInput.files = dt.files;
    fileCount.textContent = `📋 1 screenshot ready to upload`;
    toast('Screenshot captured — click Upload to save', 'info');
});

/* ====================================================
   UPLOAD FORM
==================================================== */
document.getElementById('uploadForm').addEventListener('submit', async e => {
    e.preventDefault();
    const files = Array.from(fileInput.files);
    if (!files.length) return;
    const btn=document.getElementById('uploadBtn');
    const pWrap=document.getElementById('progressContainer');
    const pFill=document.getElementById('progressFill');
    const pSpeed=document.getElementById('uploadSpeed');
    const pPct=document.getElementById('progressPct');
    btn.disabled=true; pWrap.style.display='block';
    const total=files.length; let done=0;
    const prog=new Map(); const t0=Date.now();
    const update=()=>{ let sum=0;prog.forEach(p=>sum+=p);const pct=Math.round((sum/total)*100);pFill.style.width=pct+'%';pPct.textContent=pct+'%';const elapsed=(Date.now()-t0)/1000;const spd=elapsed>0?(done/elapsed).toFixed(2):'0';pSpeed.textContent=`⚡ ${done}/${total} · ${spd} files/sec`; };
    for (let i=0;i<total;i+=MAX_PARALLEL) {
        const batch=files.slice(i,i+MAX_PARALLEL);
        await Promise.all(batch.map(async(file,idx)=>{
            const g=i+idx; prog.set(g,0);
            try {
                if(file.size>MAX_FILE_SIZE){ toast(`"${file.name}" exceeds 200MB limit`,'err'); prog.set(g,1); }
                else { await uploadChunked(file,p=>{prog.set(g,p);update();}); }
                done++;update();
            } catch(err){console.error(err);toast(`Failed: "${file.name}"`,'err');}
        }));
    }
    pSpeed.textContent=`✅ Done ${done}/${total}`;
    pFill.style.width='100%'; pPct.textContent='100%';
    toast(`Uploaded ${done}/${total} file(s)`,'ok');
    setTimeout(()=>location.reload(),900);
});

/* ====================================================
   CHUNKED UPLOAD
==================================================== */
async function uploadChunked(file, onProgress) {
    const chunks=Math.ceil(file.size/CHUNK_SIZE);
    const id=Date.now()+'_'+Math.random().toString(36).substr(2,9);
    const folder=document.getElementById('uploadFolderSelect')?.value||'';
    for(let i=0;i<chunks;i++){
        const chunk=file.slice(i*CHUNK_SIZE,Math.min((i+1)*CHUNK_SIZE,file.size));
        const fd=new FormData();
        fd.append('file',chunk); fd.append('chunk',i); fd.append('totalChunks',chunks);
        fd.append('fileName',file.name); fd.append('uploadId',id);
        fd.append('permanent',fileIsPermanent?'1':'0');
        fd.append('folder',folder);
        const res=await fetch(location.pathname,{method:'POST',body:fd});
        const r=await res.json(); if(!r.success)throw new Error('Chunk failed');
        onProgress((i+1)/chunks);
    }
}

/* ====================================================
   TEXT FORM
==================================================== */
document.getElementById('textForm').addEventListener('submit', e=>{
    e.preventDefault();
    if(!document.getElementById('textArea').value.trim())return;
    document.getElementById('textForm').submit();
});

/* ====================================================
   COPY TEXT
==================================================== */
function copyText(btn, idx) {
    const ta=document.getElementById('full-text-'+idx); if(!ta)return;
    (navigator.clipboard?navigator.clipboard.writeText(ta.value):Promise.resolve(
        (ta.style.display='block',ta.select(),document.execCommand('copy'),ta.style.display='none')
    )).then(()=>toast('Copied to clipboard','ok')).catch(()=>{});
    btn.classList.add('copied');
    btn.innerHTML='<svg fill="currentColor" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>';
    setTimeout(()=>{ btn.classList.remove('copied'); btn.innerHTML='<svg fill="currentColor" viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>'; },2000);
}

/* ====================================================
   EDIT MODAL
==================================================== */
function openEditModal(idx) {
    const ta=document.getElementById('full-text-'+idx);
    document.getElementById('editTextArea').value=ta?ta.value:'';
    document.getElementById('editTextIndex').value=idx;
    document.getElementById('editModal').classList.add('show');
}
function closeEditModal(){ document.getElementById('editModal').classList.remove('show'); }

/* ====================================================
   FOLDER MODAL
==================================================== */
function openFolderModal(){ document.getElementById('folderModal').classList.add('show'); setTimeout(()=>document.getElementById('folderNameInput').focus(),50); }
function closeFolderModal(){ document.getElementById('folderModal').classList.remove('show'); }
function createFolder(){
    const name=document.getElementById('folderNameInput').value.trim();
    if(!name)return;
    location.href='?create_folder=1&name='+encodeURIComponent(name);
}
document.getElementById('folderNameInput').addEventListener('keydown',e=>{ if(e.key==='Enter')createFolder(); });

/* ====================================================
   MOVE FILE TO FOLDER
==================================================== */
function moveFile(file, folder) {
    location.href='?move_file=1&file='+encodeURIComponent(file)+'&folder='+encodeURIComponent(folder);
}

/* ====================================================
   SHARE MODAL
==================================================== */
let _shareFile = '';
let _shareExpiry = 0;
let _shareMaxDl = 0;

function openShareModal(file) {
    _shareFile=file; _shareExpiry=0; _shareMaxDl=0;
    document.getElementById('shareFileName').textContent='📎 '+file;
    document.getElementById('shareResult').style.display='none';
    document.getElementById('sharePassword').value='';
    // Reset chips
    document.querySelectorAll('.share-chip').forEach(c=>{
        c.classList.remove('active');
        if(c.dataset.val==='0')c.classList.add('active');
    });
    document.getElementById('shareModal').classList.add('show');
}
function closeShareModal(){ document.getElementById('shareModal').classList.remove('show'); }

function selectShareChip(el, group) {
    el.closest('.share-row').querySelectorAll('.share-chip').forEach(c=>c.classList.remove('active'));
    el.classList.add('active');
    if(group==='expiry') _shareExpiry=parseInt(el.dataset.val);
    else if(group==='maxdl') _shareMaxDl=parseInt(el.dataset.val);
}

async function createShareLink() {
    const pw=document.getElementById('sharePassword').value;
    const url=`?create_share=1&file=${encodeURIComponent(_shareFile)}&expires=${_shareExpiry}&max_dl=${_shareMaxDl}&password=${encodeURIComponent(pw)}`;
    try {
        const r=await fetch(url); const d=await r.json();
        if(d.success){
            document.getElementById('shareUrlBox').textContent=d.url;
            document.getElementById('shareResult').style.display='block';
            let info=''; 
            if(_shareExpiry>0){const h=_shareExpiry/3600;info+=h<24?`Expires in ${h}h`:`Expires in ${h/24}d`;}
            else info+='Never expires';
            if(_shareMaxDl>0)info+=` · max ${_shareMaxDl} downloads`;
            if(pw)info+=' · password protected';
            document.getElementById('shareInfo').textContent=info;
            toast('Share link created!','ok');
        }
    } catch(e){ toast('Failed to create link','err'); }
}

function copyShareUrl(){
    const url=document.getElementById('shareUrlBox').textContent;
    navigator.clipboard?.writeText(url).then(()=>toast('Link copied!','ok')).catch(()=>{});
}

/* ====================================================
   COUNTDOWN TIMERS
==================================================== */
function fmtCountdown(expiresTs) {
    const now=Math.floor(Date.now()/1000), diff=expiresTs-now;
    if(diff<=0)return{text:'Expired',cls:'soon'};
    const h=Math.floor(diff/3600),m=Math.floor((diff%3600)/60);
    if(h>=48)return{text:`~${Math.ceil(diff/86400)}d`,cls:'ok'};
    if(h>=6)return{text:`${h}h ${m}m`,cls:'ok'};
    if(h>=1)return{text:`${h}h ${m}m`,cls:'mid'};
    return{text:`${m}m`,cls:'soon'};
}
function updateCountdowns() {
    document.querySelectorAll('.ttl-badge[data-expires]').forEach(el=>{
        if(el.dataset.perm==='1')return;
        const exp=parseInt(el.dataset.expires,10); if(!exp)return;
        const{text,cls}=fmtCountdown(exp); el.className='ttl-badge '+cls; el.textContent='⏱ '+text;
    });
    document.querySelectorAll('.card-perm[data-expires]').forEach(el=>{
        if(el.dataset.perm==='1')return;
        const exp=parseInt(el.dataset.expires,10); if(!exp)return;
        const{text,cls}=fmtCountdown(exp); el.className='card-perm '+cls; el.textContent='⏱ '+text;
    });
}
updateCountdowns(); setInterval(updateCountdowns,60000);

/* ====================================================
   FILE PREVIEW MODAL
==================================================== */
const _imgs=['jpg','jpeg','png','gif','webp','bmp','svg'];
const _vids=['mp4','webm','ogg','mov','avi','mkv'];
const _auds=['mp3','wav','ogg','aac','flac','m4a','opus'];
const _txts=['txt','md','csv','json','xml','html','css','js','php','py','sh','log'];

function _esc(s){return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function _isUrl(s){try{const u=new URL(s.trim());return u.protocol==='http:'||u.protocol==='https:';}catch{return false;}}

function openPreview(file,ext,size){
    const modal=document.getElementById('previewModal');
    const body=document.getElementById('previewBody');
    const url='uploads/'+encodeURIComponent(file);
    document.getElementById('previewTitle').textContent=file;
    document.getElementById('previewDl').href='?download='+encodeURIComponent(file);
    body.innerHTML='';

    if(_imgs.includes(ext)){
        let scale=1,startX=0,startY=0,tx=0,ty=0,isDragging=false,rot=0;
        const MIN_SCALE=0.5,MAX_SCALE=8;
        body.innerHTML=`<div class="img-viewer"><div class="img-viewer-wrap" id="imgWrap"><img id="zoomImg" src="${_esc(url)}" alt="${_esc(file)}"></div><div class="img-controls"><button class="img-ctrl-btn" id="zoomOut">−</button><span class="img-zoom-label" id="zoomPct">100%</span><button class="img-ctrl-btn" id="zoomIn">+</button><button class="img-ctrl-btn" id="zoomReset" style="font-size:12px">↺</button><button class="img-ctrl-btn" id="rotateBtn">⟳</button></div></div>`;
        const wrap=document.getElementById('imgWrap'),img=document.getElementById('zoomImg');
        function applyTransform(){img.style.transform=`translate(${tx}px,${ty}px) scale(${scale}) rotate(${rot}deg)`;document.getElementById('zoomPct').textContent=Math.round(scale*100)+'%';}
        document.getElementById('zoomIn').onclick=()=>{scale=Math.min(MAX_SCALE,scale+0.25);tx=0;ty=0;applyTransform();};
        document.getElementById('zoomOut').onclick=()=>{scale=Math.max(MIN_SCALE,scale-0.25);tx=0;ty=0;applyTransform();};
        document.getElementById('zoomReset').onclick=()=>{scale=1;tx=0;ty=0;rot=0;applyTransform();};
        document.getElementById('rotateBtn').onclick=()=>{rot=(rot+90)%360;applyTransform();};
        wrap.addEventListener('wheel',e=>{e.preventDefault();scale=Math.min(MAX_SCALE,Math.max(MIN_SCALE,scale+(e.deltaY<0?0.15:-0.15)));applyTransform();},{passive:false});
        wrap.addEventListener('mousedown',e=>{if(scale<=1)return;isDragging=true;startX=e.clientX-tx;startY=e.clientY-ty;});
        window.addEventListener('mousemove',e=>{if(!isDragging)return;tx=e.clientX-startX;ty=e.clientY-startY;applyTransform();});
        window.addEventListener('mouseup',()=>{isDragging=false;});
        let lastDist=0;
        wrap.addEventListener('touchstart',e=>{if(e.touches.length===2)lastDist=Math.hypot(e.touches[0].clientX-e.touches[1].clientX,e.touches[0].clientY-e.touches[1].clientY);});
        wrap.addEventListener('touchmove',e=>{if(e.touches.length===2){e.preventDefault();const d=Math.hypot(e.touches[0].clientX-e.touches[1].clientX,e.touches[0].clientY-e.touches[1].clientY);scale=Math.min(MAX_SCALE,Math.max(MIN_SCALE,scale*(d/lastDist)));lastDist=d;applyTransform();}},{passive:false});
    } else if(_vids.includes(ext)){
        body.innerHTML=`<div style="width:100%;display:flex;flex-direction:column;gap:8px"><div class="vid-wrap"><video id="previewVid" controls style="width:100%;max-height:60vh;display:block"><source src="${_esc(url)}" type="video/${ext}"></video></div><div class="vid-seek-bar"><button class="seek-btn" onclick="seekVid(-10)">⏪ 10s</button><button class="seek-btn" onclick="seekVid(-5)">◀ 5s</button><span class="vid-time-lbl" id="vidTimeLbl">0:00 / 0:00</span><button class="seek-btn" onclick="seekVid(5)">5s ▶</button><button class="seek-btn" onclick="seekVid(10)">10s ⏩</button></div></div>`;
        const vid=document.getElementById('previewVid');
        function updateTime(){const fmt=t=>{const m=Math.floor(t/60),s=Math.floor(t%60);return m+':'+(s<10?'0':'')+s};const lbl=document.getElementById('vidTimeLbl');if(lbl)lbl.textContent=fmt(vid.currentTime)+' / '+fmt(vid.duration||0);}
        vid.addEventListener('timeupdate',updateTime); vid.addEventListener('loadedmetadata',updateTime);
    } else if(ext==='pdf'){
        body.innerHTML=`<iframe src="${_esc(url)}#toolbar=1" style="width:100%;height:65vh;border:none;border-radius:8px"></iframe>`;
    } else if(_auds.includes(ext)){
        body.innerHTML=`<div style="width:100%;text-align:center;padding:30px 0"><div style="font-size:60px;margin-bottom:14px">🎵</div><p style="color:var(--text);font-size:14px;font-weight:600;margin-bottom:4px">${_esc(file)}</p><p style="color:var(--muted);font-size:11px;margin-bottom:16px">${_esc(size)}</p><audio controls autoplay style="width:100%"><source src="${_esc(url)}"></audio></div>`;
    } else if(_txts.includes(ext)){
        body.innerHTML='<div class="url-loader"><div class="spinner"></div> Loading…</div>';
        fetch(url).then(r=>r.text()).then(txt=>{const pre=document.createElement('pre');pre.textContent=txt.length>60000?txt.substr(0,60000)+'\n…(truncated)':txt;body.innerHTML='';body.appendChild(pre);}).catch(()=>{body.innerHTML='<p style="color:var(--red);padding:20px">Could not load.</p>';});
    } else {
        body.innerHTML=`<div style="text-align:center;padding:40px"><div style="font-size:68px;margin-bottom:14px">📎</div><p style="color:var(--text2);font-size:13px">${_esc(file)}</p><p style="color:var(--muted);font-size:11px;margin-top:5px">${_esc(size)}</p></div>`;
    }
    modal.classList.add('show');
}
function seekVid(secs){const v=document.getElementById('previewVid');if(!v)return;v.currentTime=Math.max(0,Math.min(v.duration||0,v.currentTime+secs));}
function closePreview(){const m=document.getElementById('previewModal');m.classList.remove('show');m.querySelectorAll('video,audio').forEach(el=>{try{el.pause();el.src='';}catch{}});document.getElementById('previewBody').innerHTML='';}

/* ====================================================
   URL PREVIEW
==================================================== */
function renderUrlPreview(el,meta,rawUrl){
    let domain=meta.domain||''; if(!domain){try{domain=new URL(rawUrl||meta.url||'').hostname;}catch{}}
    const dispDomain=domain.replace(/^www\./,'');
    const fav=meta.favicon?`<img src="${_esc(meta.favicon)}" onerror="this.style.display='none'" alt="" style="width:14px;height:14px;border-radius:3px;flex-shrink:0">`:'<span style="font-size:13px">🌐</span>';
    const showImg=meta.image&&/^https?:\/\//i.test(meta.image);
    const imgHtml=showImg?`<img style="width:100%;height:110px;object-fit:cover;display:block;border-radius:6px 6px 0 0" src="${_esc(meta.image)}" alt="" onerror="this.remove()" loading="lazy">`:'';
    const displayTitle=meta.title||dispDomain||rawUrl||'';
    el.innerHTML=`<a class="url-preview-card" href="${_esc(rawUrl||meta.url)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">${imgHtml}<div class="url-pbody"><div class="url-pdomain">${fav} <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc(dispDomain)}</span></div>${displayTitle?`<div class="url-ptitle">${_esc(displayTitle)}</div>`:''}${meta.description?`<div class="url-pdesc">${_esc(meta.description)}</div>`:''}</div></a>`;
}
const _previewWraps=document.querySelectorAll('.url-preview-wrap[data-url]');
_previewWraps.forEach((wrap,i)=>{
    const url=wrap.dataset.url; if(!_isUrl(url)){wrap.innerHTML='';return;}
    setTimeout(async()=>{
        try{const res=await fetch(`?fetch_meta&url=${encodeURIComponent(url)}`);if(!res.ok)throw new Error('HTTP '+res.status);const meta=await res.json();renderUrlPreview(wrap,meta,url);}
        catch{let dom='';try{dom=new URL(url).hostname.replace(/^www\./,'');}catch{}wrap.innerHTML=`<a class="url-preview-card" href="${_esc(url)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()"><div class="url-pbody"><div class="url-pdomain"><span style="font-size:13px">🔗</span> <span>${_esc(dom||'Link')}</span></div><div class="url-ptitle" style="color:var(--text2);font-weight:400;font-size:11px;word-break:break-all">${_esc(url.length>80?url.substr(0,80)+'…':url)}</div></div></a>`;}
    },i*150);
});

/* ====================================================
   CLOSE MODALS ON OVERLAY / ESCAPE
==================================================== */
document.querySelectorAll('.modal-overlay').forEach(m=>{
    m.addEventListener('click',e=>{ if(e.target===m){closeEditModal();closePreview();closeShareModal();closeFolderModal();} });
});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeEditModal();closePreview();closeShareModal();closeFolderModal();}});

/* ====================================================
   PWA INSTALL BANNER
==================================================== */
let _deferredInstall=null;
window.addEventListener('beforeinstallprompt',e=>{
    e.preventDefault(); _deferredInstall=e;
    const banner=document.createElement('div');
    banner.id='installBanner';
    banner.style.cssText='position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:var(--bg2);border:1px solid rgba(124,106,255,.3);border-radius:12px;padding:12px 18px;display:flex;align-items:center;gap:12px;box-shadow:0 8px 24px rgba(0,0,0,.4);z-index:9000;font-size:13px;color:var(--text)';
    banner.innerHTML='<span style="font-size:20px">📱</span><span>Install Fast Transfer as an app?</span><button onclick="installPWA()" style="padding:6px 14px;border-radius:7px;background:var(--accent-g);color:#fff;border:none;font-size:12px;font-weight:700;cursor:pointer">Install</button><button onclick="this.parentElement.remove()" style="padding:6px 10px;border-radius:7px;background:var(--card);color:var(--text2);border:1px solid var(--border2);font-size:12px;cursor:pointer">Later</button>';
    document.body.appendChild(banner);
    setTimeout(()=>banner?.remove(),12000);
});
function installPWA(){if(_deferredInstall){_deferredInstall.prompt();_deferredInstall.userChoice.then(()=>{_deferredInstall=null;document.getElementById('installBanner')?.remove();});}}

/* ====================================================
   SERVICE WORKER (PWA offline support)
==================================================== */
if('serviceWorker' in navigator){
    const swCode=`
self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>clients.claim());
self.addEventListener('fetch',e=>{
    if(e.request.method!=='GET')return;
    e.respondWith(fetch(e.request).catch(()=>new Response('<h2>Offline</h2><p>Fast Transfer is offline.</p>',{headers:{'Content-Type':'text/html'}})));
});`;
    const blob=new Blob([swCode],{type:'application/javascript'});
    const swUrl=URL.createObjectURL(blob);
    navigator.serviceWorker.register(swUrl).catch(()=>{});
}
</script>
</body>
</html>
