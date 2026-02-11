<?php
session_start();

$correctPassword = 'Text';

ini_set('upload_max_filesize', '200M');
ini_set('post_max_size', '210M');
ini_set('memory_limit', '256M');
ini_set('max_execution_time', '600');
ini_set('max_input_time', '600');

/* ---------- safe self url for redirects (fix open redirect) ---------- */
$selfPath = '/' . ltrim(basename(parse_url($_SERVER['SCRIPT_NAME'] ?? '', PHP_URL_PATH)), '/');
if ($selfPath === '/' || $selfPath === '') {
    $selfPath = '/index.php';
}
$selfUrl = $selfPath;

/* ---------- small helpers ---------- */
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

/* ---------- DOWNLOAD ---------- */
if (isset($_GET['download'])) {
    $file = sanitizeFileName($_GET['download']);
    $uploadDir = __DIR__ . '/uploads';
    $filePath = safePathJoin($uploadDir, $file);

    if (!is_file($filePath)) {
        http_response_code(404);
        exit('File not found');
    }

    while (ob_get_level()) ob_end_clean();

    $size = filesize($filePath);

    $finfo = function_exists('finfo_open') ? finfo_open(FILEINFO_MIME_TYPE) : false;
    $mime  = $finfo ? @finfo_file($finfo,$filePath) : 'application/octet-stream';
    if ($finfo) finfo_close($finfo);
    if (!$mime) $mime = 'application/octet-stream';

    header('Content-Description: File Transfer');
    header('Content-Type: '.$mime);
    header('Content-Disposition: attachment; filename="' . rawurlencode($file) . '"');
    header('Content-Transfer-Encoding: binary');
    header('Content-Length: ' . $size);
    header('Cache-Control: no-cache, must-revalidate');
    header('Pragma: public');

    $fp = fopen($filePath, 'rb');
    if ($fp === false) {
        http_response_code(500);
        exit('Cannot open file');
    }

    ignore_user_abort(true);
    $chunkSize = 256 * 1024;

    while (!feof($fp)) {
        $buffer = fread($fp, $chunkSize);
        echo $buffer;
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        } else {
            flush();
        }
        if (connection_status() != CONNECTION_NORMAL) break;
    }

    fclose($fp);
    exit;
}

/* ---------- LOGIN / LOGOUT ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password']) && !isset($_POST['chunk'])) {
    if ($_POST['password'] === $correctPassword) {
        $_SESSION['logged_in'] = true;
        if (isset($_POST['remember'])) {
            setcookie('transfer_auth', md5($correctPassword), time() + (30 * 24 * 60 * 60), '/');
        }
        header('Location: ' . $selfUrl);  // FIXED
        exit;
    } else {
        $loginError = true;
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    setcookie('transfer_auth', '', time() - 3600, '/');
    header('Location: ' . $selfUrl);      // FIXED
    exit;
}

$isLoggedIn = isset($_SESSION['logged_in']) ||
              (isset($_COOKIE['transfer_auth']) && $_COOKIE['transfer_auth'] === md5($correctPassword));

if (!$isLoggedIn) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>🔒 Login</title>
        <style>
            *{margin:0;padding:0;box-sizing:border-box}
            body{font-family:Arial;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
            .login-box{background:#fff;border-radius:15px;padding:40px;box-shadow:0 10px 30px rgba(0,0,0,.3);max-width:400px;width:100%}
            h1{text-align:center;color:#667eea;margin-bottom:30px}
            input[type=password]{width:100%;padding:15px;border:2px solid #667eea;border-radius:8px;font-size:16px;margin-bottom:15px}
            button{width:100%;padding:15px;background:#667eea;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;font-weight:bold}
            button:hover{background:#5568d3}
            .error{background:#f8d7da;color:#721c24;padding:12px;border-radius:8px;margin-bottom:15px;text-align:center}
            .remember{margin-bottom:15px;display:flex;align-items:center}
            .remember input{width:auto;margin-right:8px}
        </style>
    </head>
    <body>
        <div class="login-box">
            <h1>🔒 Login</h1>
            <?php if (isset($loginError)): ?>
                <div class="error">❌ Wrong password!</div>
            <?php endif; ?>
            <form method="POST">
                <input type="password" name="password" placeholder="Enter password" required autofocus>
                <div class="remember">
                    <input type="checkbox" name="remember" id="remember">
                    <label for="remember">Remember me for 30 days</label>
                </div>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

/* ---------- SETUP ---------- */
$uploadDir = __DIR__ . '/uploads';
$chunksDir = __DIR__ . '/uploads/chunks';
$textFile  = $uploadDir . '/texts.json';
$metaFile  = $uploadDir . '/metadata.json';

if (!is_dir($uploadDir))  mkdir($uploadDir, 0777, true);
if (!is_dir($chunksDir))  mkdir($chunksDir, 0777, true);

$metadata = file_exists($metaFile) ? json_decode(file_get_contents($metaFile), true) : [];
if (!is_array($metadata)) $metadata = [];

/* ---------- DELETE FILE ---------- */
if (isset($_GET['delete_file'])) {
    $fileToDelete = sanitizeFileName($_GET['delete_file']);
    try {
        $filePath = safePathJoin($uploadDir, $fileToDelete);
        if (file_exists($filePath) && is_file($filePath)) {
            unlink($filePath);
            unset($metadata[$fileToDelete]);
            file_put_contents($metaFile, json_encode($metadata));
        }
    } catch (Throwable $e) { }
    header('Location: ' . $selfUrl);      // FIXED
    exit;
}

/* ---------- DELETE TEXT ---------- */
if (isset($_GET['delete_text'])) {
    $textIndex = (int)$_GET['delete_text'];
    $texts = file_exists($textFile) ? json_decode(file_get_contents($textFile), true) : [];
    if (isset($texts[$textIndex])) {
        array_splice($texts, $textIndex, 1);
        file_put_contents($textFile, json_encode(array_values($texts)));
    }
    header('Location: ' . $selfUrl);      // FIXED
    exit;
}

/* ---------- CHUNKED UPLOAD (same as before, secure paths) ---------- */
/* ... keep the rest of the script exactly as in the previous answer ...
   (chunk handler, text save, auto-delete, HTML, JS, etc.)
*/
