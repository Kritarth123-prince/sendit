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

function getRememberToken(){return bin2hex(random_bytes(32));}
function getRememberCookieParams(): array {
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    return [
        'expires'  => time() + (30 * 24 * 60 * 60),
        'path'     => '/',
        'secure'   => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ];
}
function getRememberCookieClearParams(): array {
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    return [
        'expires'  => time() - 3600,
        'path'     => '/',
        'secure'   => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ];
}

/* ================== DOWNLOAD ZIP BY DATE ================== */
if (isset($_GET['download_zip'])) {
    set_time_limit(0);
    ini_set('memory_limit', '512M');
    
    $dateCategory = $_GET['download_zip'];
    $uploadDir = __DIR__ . '/uploads';
    $metaFile  = $uploadDir . '/metadata.json';
    $metadata = file_exists($metaFile) ? json_decode(file_get_contents($metaFile), true) : [];
    
    $zipName = 'files_' . preg_replace('/[^A-Za-z0-9_-]/', '_', $dateCategory) . '.zip';
    
    $filesToZip = [];
    $allFiles = array_diff(scandir($uploadDir), ['.', '..', 'texts.json', 'chunks', 'metadata.json']);
    
    foreach ($allFiles as $file) {
        $filePath = $uploadDir . '/' . $file;
        if (is_file($filePath)) {
            $uploadTime = isset($metadata[$file]) ? $metadata[$file] : filemtime($filePath);
            $cat = getDateCategory($uploadTime);
            
            if ($cat === $dateCategory) {
                $filesToZip[] = ['path' => $filePath, 'name' => $file];
            }
        }
    }
    
    if (empty($filesToZip)) {
        exit('No files found for this date');
    }
    
    while (ob_get_level()) {
        ob_end_clean();
    }
    
    $tempZip = sys_get_temp_dir() . '/' . uniqid('zip_', true) . '.zip';
    
    $zip = new ZipArchive();
    if ($zip->open($tempZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
        foreach ($filesToZip as $fileData) {
            $zip->addFile($fileData['path'], $fileData['name']);
        }
        $zip->close();
        
        if (file_exists($tempZip)) {
            $fileSize = filesize($tempZip);
            
            header('Content-Type: application/zip');
            header('Content-Disposition: attachment; filename="' . $zipName . '"');
            header('Content-Length: ' . $fileSize);
            header('Cache-Control: no-cache, must-revalidate');
            header('Pragma: public');
            header('Content-Transfer-Encoding: binary');
            
            $handle = fopen($tempZip, 'rb');
            if ($handle) {
                while (!feof($handle)) {
                    $buffer = fread($handle, 1024 * 1024);
                    echo $buffer;
                    flush();
                    
                    if (connection_status() != CONNECTION_NORMAL) {
                        break;
                    }
                }
                fclose($handle);
            }
            
            @unlink($tempZip);
            exit;
        }
    }
    
    exit('Failed to create ZIP');
}

/* ================== DELETE FILES BY DAY ================== */
if (isset($_GET['delete_day'])) {
    $dateCategory = $_GET['delete_day'];
    $uploadDir = __DIR__ . '/uploads';
    $metaFile  = $uploadDir . '/metadata.json';
    $metadata = file_exists($metaFile) ? json_decode(file_get_contents($metaFile), true) : [];
    
    $allFiles = array_diff(scandir($uploadDir), ['.', '..', 'texts.json', 'chunks', 'metadata.json']);
    
    foreach ($allFiles as $file) {
        $filePath = $uploadDir . '/' . $file;
        if (is_file($filePath)) {
            $uploadTime = isset($metadata[$file]) ? $metadata[$file] : filemtime($filePath);
            $cat = getDateCategory($uploadTime);
            
            if ($cat === $dateCategory) {
                @unlink($filePath);
                unset($metadata[$file]);
            }
        }
    }
    
    file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));
    header('Location: ' . $selfUrl);
    exit;
}

/* ================== DELETE TEXTS BY DAY ================== */
if (isset($_GET['delete_texts_day'])) {
    $dateCategory = $_GET['delete_texts_day'];
    $uploadDir = __DIR__ . '/uploads';
    $textFile  = $uploadDir . '/texts.json';
    
    $texts = file_exists($textFile) ? json_decode(file_get_contents($textFile), true) : [];
    if (!is_array($texts)) $texts = [];
    
    $filtered = array_filter($texts, function($item) use ($dateCategory) {
        return getDateCategory($item['time']) !== $dateCategory;
    });
    
    file_put_contents($textFile, json_encode(array_values($filtered), JSON_UNESCAPED_SLASHES));
    header('Location: ' . $selfUrl);
    exit;
}

/* ================== DOWNLOAD ================== */
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

/* ================== AUTH ================== */
$remFile = __DIR__ . '/remember_tokens.json';
$remember = file_exists($remFile) ? json_decode(file_get_contents($remFile), true) : [];
if (!is_array($remember)) $remember = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password']) && !isset($_POST['chunk']) && !isset($_POST['text']) && !isset($_POST['edit_text'])) {
    if (in_array($_POST['password'], $correctPasswords, true)) {
        $_SESSION['logged_in'] = true;

        if (isset($_POST['remember'])) {
            $token = getRememberToken();
            $remember[$token] = ['created' => time()];
            file_put_contents($remFile, json_encode($remember, JSON_UNESCAPED_SLASHES));
            setcookie('transfer_auth', $token, getRememberCookieParams());
        }
        header('Location: ' . $selfUrl);
        exit;
    } else {
        $loginError = true;
    }
}

if (isset($_GET['logout'])) {
    session_destroy();

    if (isset($_COOKIE['transfer_auth'])) {
        $t = $_COOKIE['transfer_auth'];
        if (isset($remember[$t])) {
            unset($remember[$t]);
            file_put_contents($remFile, json_encode($remember, JSON_UNESCAPED_SLASHES));
        }
        setcookie('transfer_auth', '', getRememberCookieClearParams());
    }

    header('Location: ' . $selfUrl);
    exit;
}

$isLoggedIn = isset($_SESSION['logged_in']);

if (!$isLoggedIn && isset($_COOKIE['transfer_auth'])) {
    $t = $_COOKIE['transfer_auth'];
    if (is_string($t) && isset($remember[$t])) {
        $_SESSION['logged_in'] = true;
        $isLoggedIn = true;
    }
}

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

/* ================== SETUP ================== */
$uploadDir = __DIR__ . '/uploads';
$chunksDir = __DIR__ . '/uploads/chunks';
$textFile  = $uploadDir . '/texts.json';
$metaFile  = $uploadDir . '/metadata.json';

if (!is_dir($uploadDir)) mkdir($uploadDir, 0777, true);
if (!is_dir($chunksDir)) mkdir($chunksDir, 0777, true);

$metadata = file_exists($metaFile) ? json_decode(file_get_contents($metaFile), true) : [];
if (!is_array($metadata)) $metadata = [];

/* ================== DELETE FILE ================== */
if (isset($_GET['delete_file'])) {
    $fileToDelete = sanitizeFileName($_GET['delete_file']);
    try {
        $filePath = safePathJoin($uploadDir, $fileToDelete);
        if (file_exists($filePath) && is_file($filePath)) {
            unlink($filePath);
            unset($metadata[$fileToDelete]);
            file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));
        }
    } catch (Throwable $e) {}
    header('Location: ' . $selfUrl);
    exit;
}

/* ================== DELETE TEXT ================== */
if (isset($_GET['delete_text'])) {
    $textIndex = (int)$_GET['delete_text'];
    $texts = file_exists($textFile) ? json_decode(file_get_contents($textFile), true) : [];
    if (isset($texts[$textIndex])) {
        array_splice($texts, $textIndex, 1);
        file_put_contents($textFile, json_encode(array_values($texts), JSON_UNESCAPED_SLASHES));
    }
    header('Location: ' . $selfUrl);
    exit;
}

/* ================== EDIT TEXT ================== */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_text']) && isset($_POST['text_index'])) {
    $texts = file_exists($textFile) ? json_decode(file_get_contents($textFile), true) : [];
    $index = (int)$_POST['text_index'];
    
    if (isset($texts[$index])) {
        $oldTime = time() - (72 * 60 * 60);
        
        if ($texts[$index]['time'] >= $oldTime) {
            $texts[$index]['content'] = $_POST['edit_text'];
            file_put_contents($textFile, json_encode($texts, JSON_UNESCAPED_SLASHES));
            $message = "✅ Text updated!";
        } else {
            $message = "⚠️ Cannot edit - 72 hours expired!";
        }
    }
    header('Location: ' . $selfUrl);
    exit;
}

/* ================== CHUNKED UPLOAD ================== */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['chunk']) && !isset($_POST['text']) && !isset($_POST['edit_text'])) {
    header('Content-Type: application/json');

    $chunk = (int)$_POST['chunk'];
    $totalChunks = (int)$_POST['totalChunks'];
    $fileNameRaw = $_POST['fileName'] ?? 'file';
    $fileName = sanitizeFileName($fileNameRaw);

    $uploadIdRaw = $_POST['uploadId'] ?? '';
    $uploadId = preg_replace('/[^A-Za-z0-9_-]/','',$uploadIdRaw);
    if ($uploadId === '') $uploadId = bin2hex(random_bytes(8));

    $chunkBaseName = $uploadId . '_' . $chunk;
    try {
        $chunkFile = safePathJoin($chunksDir, $chunkBaseName);
    } catch (Throwable $e) {
        echo json_encode(['success'=>false,'error'=>'Invalid path']);
        exit;
    }

    if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
        if (!move_uploaded_file($_FILES['file']['tmp_name'], $chunkFile)) {
            echo json_encode(['success'=>false,'error'=>'Move failed']);
            exit;
        }

        $allChunksUploaded = true;
        for ($i = 0; $i < $totalChunks; $i++) {
            $chkName = $uploadId . '_' . $i;
            try {
                $chkPath = safePathJoin($chunksDir, $chkName);
            } catch (Throwable $e) { $allChunksUploaded = false; break; }
            if (!file_exists($chkPath)) {
                $allChunksUploaded = false;
                break;
            }
        }

        if ($allChunksUploaded) {
            $info = pathinfo($fileName);
            $base = $info['filename'] ?? 'file';
            $ext = isset($info['extension']) ? '.' . $info['extension'] : '';
            $safeBase = preg_replace('/[^A-Za-z0-9._-]/','_',$base);
            if ($safeBase === '') $safeBase = 'file';
            $fileName = $safeBase . $ext;

            try {
                $finalFile = safePathJoin($uploadDir, $fileName);
            } catch (Throwable $e) {
                echo json_encode(['success'=>false,'error'=>'Invalid final path']);
                exit;
            }

            if (file_exists($finalFile)) {
                $c = 1;
                do {
                    $altName = $safeBase . '_' . $c . $ext;
                    $finalFile = safePathJoin($uploadDir, $altName);
                    $c++;
                } while (file_exists($finalFile));
                $fileName = basename($finalFile);
            }

            $out = fopen($finalFile, 'wb');
            if ($out === false) {
                echo json_encode(['success'=>false,'error'=>'Cannot open final file']);
                exit;
            }

            for ($i = 0; $i < $totalChunks; $i++) {
                $chkName = $uploadId . '_' . $i;
                try {
                    $chunkPath = safePathJoin($chunksDir, $chkName);
                } catch (Throwable $e) { continue; }
                if (!is_file($chunkPath)) continue;
                $in = fopen($chunkPath, 'rb');
                if ($in) {
                    stream_copy_to_stream($in, $out);
                    fclose($in);
                }
                @unlink($chunkPath);
            }
            fclose($out);

            $metadata[$fileName] = time();
            file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));

            echo json_encode(['success' => true, 'completed' => true]);
        } else {
            echo json_encode(['success' => true, 'completed' => false]);
        }
    } else {
        echo json_encode(['success' => false, 'error' => 'Upload failed']);
    }
    exit;
}

/* ================== TEXT SAVE ================== */
$texts = file_exists($textFile) ? json_decode(file_get_contents($textFile), true) : [];
if (!is_array($texts)) $texts = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['text']) && !isset($_POST['chunk']) && !isset($_POST['edit_text'])) {
    $texts[] = ['time' => time(), 'content' => $_POST['text']];
    file_put_contents($textFile, json_encode($texts, JSON_UNESCAPED_SLASHES));
    header('Location: ' . $selfUrl);
    exit;
}

/* ================== AUTO DELETE ================== */
$oldTime = time() - (72 * 60 * 60);
$metadataChanged = false;

$allFilesInDir = array_diff(scandir($uploadDir), ['.', '..', 'texts.json', 'chunks', 'metadata.json']);

foreach ($allFilesInDir as $file) {
    $filePath = $uploadDir . '/' . $file;
    if (is_file($filePath) && !isset($metadata[$file])) {
        $metadata[$file] = filemtime($filePath);
        $metadataChanged = true;
    }
}

foreach ($metadata as $fileName => $uploadTime) {
    $filePath = $uploadDir . '/' . $fileName;
    if ($uploadTime < $oldTime) {
        if (file_exists($filePath)) @unlink($filePath);
        unset($metadata[$fileName]);
        $metadataChanged = true;
    }
}

foreach ($metadata as $fileName => $uploadTime) {
    $filePath = $uploadDir . '/' . $fileName;
    if (!file_exists($filePath)) {
        unset($metadata[$fileName]);
        $metadataChanged = true;
    }
}

if ($metadataChanged) {
    file_put_contents($metaFile, json_encode($metadata, JSON_UNESCAPED_SLASHES));
}

$chunkFiles = @scandir($chunksDir);
if ($chunkFiles) {
    foreach ($chunkFiles as $chunk) {
        if ($chunk === '.' || $chunk === '..') continue;
        $chunkPath = $chunksDir . '/' . $chunk;
        if (@filemtime($chunkPath) < time() - 3600) @unlink($chunkPath);
    }
}

$oldTexts = $texts;
$texts = array_filter($texts, function($item) use ($oldTime) {
    return isset($item['time']) && $item['time'] >= $oldTime;
});
if (count($texts) !== count($oldTexts)) {
    file_put_contents($textFile, json_encode(array_values($texts), JSON_UNESCAPED_SLASHES));
}

/* ================== VIEW HELPERS ================== */
function getDateCategory($ts) {
    $today = strtotime('today');
    $yesterday = strtotime('yesterday');
    if ($ts >= $today) return 'Today';
    if ($ts >= $yesterday) return 'Yesterday';
    return date('d M Y', $ts);
}
function formatFileSize($bytes) {
    if ($bytes >= 1073741824) return number_format($bytes / 1073741824, 2) . ' GB';
    if ($bytes >= 1048576) return number_format($bytes / 1048576, 2) . ' MB';
    if ($bytes >= 1024) return number_format($bytes / 1024, 2) . ' KB';
    return $bytes . ' bytes';
}

$filesByDate = [];
$allFiles = array_diff(scandir($uploadDir), ['.', '..', 'texts.json', 'chunks', 'metadata.json']);

foreach ($allFiles as $file) {
    $filePath = $uploadDir . '/' . $file;
    if (is_file($filePath)) {
        $uploadTime = isset($metadata[$file]) ? $metadata[$file] : filemtime($filePath);
        $cat = getDateCategory($uploadTime);
        if (!isset($filesByDate[$cat])) $filesByDate[$cat] = [];
        $filesByDate[$cat][] = ['name' => $file, 'path' => $filePath, 'time' => $uploadTime];
    }
}

uksort($filesByDate, function($a, $b) {
    if ($a === 'Today') return -1;
    if ($b === 'Today') return 1;
    if ($a === 'Yesterday') return -1;
    if ($b === 'Yesterday') return 1;
    return strtotime($b) - strtotime($a);
});

$textsByDate = [];
foreach ($texts as $index => $item) {
    $cat = getDateCategory($item['time']);
    if (!isset($textsByDate[$cat])) $textsByDate[$cat] = [];
    $textsByDate[$cat][] = ['index' => $index, 'content' => $item['content'], 'time' => $item['time']];
}

uksort($textsByDate, function($a, $b) {
    if ($a === 'Today') return -1;
    if ($b === 'Today') return 1;
    if ($a === 'Yesterday') return -1;
    if ($b === 'Yesterday') return 1;
    return strtotime($b) - strtotime($a);
});

$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
$currentURL = $protocol . $_SERVER['HTTP_HOST'] . $selfUrl;

$totalFiles = count($allFiles);
$totalTexts = count($texts);
?>
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>⚡ Fast Transfer</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:Arial;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);padding:20px}
        .container{max-width:1200px;margin:0 auto;background:#fff;border-radius:15px;padding:20px;box-shadow:0 10px 30px rgba(0,0,0,.3)}
        h1{text-align:center;color:#667eea;margin-bottom:10px}
        .ip{text-align:center;background:#f0f0f0;padding:10px;border-radius:8px;margin-bottom:10px;font-size:14px;word-break:break-all}
        .section{margin-bottom:25px}
        .section h2{font-size:18px;margin-bottom:10px;color:#333}
        .date-group{margin-bottom:20px}
        .date-header{font-size:16px;font-weight:bold;color:#667eea;margin-bottom:12px;padding-bottom:8px;border-bottom:2px solid #667eea;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
        .date-label{display:flex;align-items:center;gap:8px}
        .date-label::before{content:'📅'}
        .btn-group{display:flex;gap:8px;flex-wrap:wrap}
        .btn-group a{color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;text-decoration:none;display:inline-block;font-weight:bold}
        .zip-btn{background:#28a745}
        .zip-btn:hover{background:#218838}
        .del-btn{background:#dc3545;padding:8px 12px}
        .del-btn:hover{background:#c82333}
        .del-btn svg{width:16px;height:16px;vertical-align:middle}
        textarea{width:100%;padding:12px;border:2px solid #667eea;border-radius:8px;font-size:14px;height:80px;resize:none}
        button{width:100%;padding:12px;background:#667eea;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:10px;font-weight:bold}
        button:hover{background:#5568d3}
        button:disabled{background:#ccc;cursor:not-allowed}
        .message{background:#d4edda;color:#155724;padding:12px;border-radius:8px;margin-bottom:15px;text-align:center}
        .files{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:15px}
        .file-card{background:#f8f9fa;border-radius:10px;overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,.1);transition:transform .2s;position:relative}
        .file-card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.15)}
        .file-preview{width:100%;height:140px;background:#e9ecef;display:flex;align-items:center;justify-content:center;overflow:hidden}
        .file-preview img,.file-preview video{width:100%;height:100%;object-fit:cover}
        .file-preview iframe{width:100%;height:100%;border:none}
        .file-icon{font-size:50px}
        .file-info{padding:12px}
        .file-name{font-weight:bold;color:#333;margin-bottom:5px;word-break:break-word;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
        .file-meta{font-size:11px;color:#666;margin-bottom:8px}
        .download-btn{display:block;width:100%;padding:8px;background:#667eea;color:#fff;text-align:center;text-decoration:none;border-radius:5px;font-weight:bold;font-size:13px}
        .download-btn:hover{background:#5568d3}
        .delete-btn{position:absolute;top:8px;right:8px;background:#dc3545;color:#fff;border:none;padding:6px;border-radius:50%;cursor:pointer;width:32px;height:32px;display:flex;align-items:center;justify-content:center;z-index:10;box-shadow:0 2px 4px rgba(0,0,0,.2);transition:all .2s}
        .delete-btn:hover{background:#c82333;transform:scale(1.1)}
        .delete-btn svg{width:16px;height:16px}
        .texts-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:15px}
        .text-item{background:#fff9e6;padding:15px;padding-top:45px;border-radius:10px;position:relative;border-left:4px solid #ffc107;min-height:100px;box-shadow:0 2px 6px rgba(0,0,0,.1);transition:transform .2s}
        .text-item:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.15)}
        .text-content{color:#333;word-break:break-word;font-size:14px;line-height:1.5}
        .copy-btn,.edit-btn{position:absolute;top:8px;background:#667eea;color:#fff;border:none;padding:8px;border-radius:6px;cursor:pointer;width:32px;height:32px;display:flex;align-items:center;justify-content:center}
        .copy-btn{right:48px}
        .edit-btn{right:88px;background:#ff9800}
        .edit-btn:hover{background:#e68900}
        .copy-btn:hover{background:#5568d3}
        .copy-btn svg,.edit-btn svg{width:16px;height:16px}
        .copied{background:#28a745!important}
        .info{text-align:center;color:#666;font-size:12px;margin-bottom:15px}
        .logout{text-align:center;margin-bottom:15px}
        .logout a{color:#dc3545;text-decoration:none;font-size:14px}
        .file-count{color:#667eea;font-size:13px;margin-top:8px}
        .progress-container{display:none;margin-top:10px}
        .progress-bar{width:100%;height:25px;background:#e9ecef;border-radius:8px;overflow:hidden;position:relative}
        .progress-fill{height:100%;background:linear-gradient(90deg,#667eea,#764ba2);transition:width .3s;display:flex;align-items:center;justify-content:center;color:#fff;font-size:12px;font-weight:bold}
        .upload-speed{text-align:center;color:#667eea;font-size:12px;margin-top:5px}
        #fileInput{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}
        .drop-zone{margin-top:10px;padding:20px;border:2px dashed #667eea;border-radius:10px;text-align:center;color:#555;background:#f8f9ff;cursor:pointer;transition:background .2s,border-color .2s}
        .drop-zone.dragover{background:#e0e4ff;border-color:#5568d3}
        .drop-zone small{display:block;color:#777;margin-top:4px}
        .modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.5);z-index:1000;align-items:center;justify-content:center}
        .modal.show{display:flex}
        .modal-content{background:#fff;padding:30px;border-radius:15px;max-width:500px;width:90%}
        .modal-content textarea{height:150px}
        .modal-buttons{display:flex;gap:10px;margin-top:15px}
        .modal-buttons button{margin:0}
        @media(max-width:768px){
            .files{grid-template-columns:repeat(auto-fill,minmax(150px,1fr))}
            .file-preview{height:120px}
            .texts-grid{grid-template-columns:1fr}
            .date-header{flex-direction:column;align-items:flex-start}
            .btn-group{width:100%}
            .btn-group a{flex:1;text-align:center}
        }
    </style>
</head>
<body>
<div class="container">
    <h1>⚡ Fast Media Transfer</h1>
    <div class="logout"><a href="?logout">🔓 Logout</a></div>
    <div class="ip">📡 Share: <strong><?= h($currentURL) ?></strong></div>
    <div class="info">🗑️ Auto-delete after 72 hours • 📦 Max 200MB • ⚡ 3 parallel uploads</div>

    <div class="section">
        <h2>📤 Upload Files</h2>
        <form id="uploadForm">
            <div id="dropZone" class="drop-zone">
                Drag &amp; drop files here
                <small>or click to select</small>
            </div>
            <input type="file" id="fileInput" name="files[]" multiple required>
            <div class="file-count" id="fileCount"></div>
            <button type="submit" id="uploadBtn">Upload Files</button>
            <div class="progress-container" id="progressContainer">
                <div class="progress-bar">
                    <div class="progress-fill" id="progressFill">0%</div>
                </div>
                <div class="upload-speed" id="uploadSpeed"></div>
            </div>
        </form>
    </div>

    <div class="section">
        <h2>📝 Save Text or URL</h2>
        <form id="textForm" method="POST">
            <textarea name="text" id="textArea" placeholder="Paste text or URL..." required></textarea>
            <button type="submit">Save Text</button>
        </form>
    </div>

    <?php if (!empty($texts)): ?>
        <div class="section">
            <h2>📋 Saved Texts (<?= $totalTexts ?>)</h2>
            <?php foreach ($textsByDate as $dateCategory => $dateTexts): ?>
                <div class="date-group">
                    <div class="date-header">
                        <div class="date-label"><?= h($dateCategory) ?> (<?= count($dateTexts) ?>)</div>
                        <a href="?delete_texts_day=<?= urlencode($dateCategory) ?>" class="del-btn" onclick="return confirm('Delete all texts from <?= h($dateCategory) ?>?')">
                            <svg fill="currentColor" viewBox="0 0 24 24">
                                <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/>
                            </svg>
                        </a>
                    </div>
                    <div class="texts-grid">
                        <?php foreach ($dateTexts as $textData): 
                            $canEdit = ($textData['time'] >= (time() - 72 * 60 * 60));
                        ?>
                            <div class="text-item">
                                <?php if ($canEdit): ?>
                                <button class="edit-btn" onclick="openEditModal(<?= (int)$textData['index'] ?>)">
                                    <svg fill="currentColor" viewBox="0 0 24 24">
                                        <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/>
                                    </svg>
                                </button>
                                <?php endif; ?>
                                <button class="copy-btn" onclick="copyText(this, <?= (int)$textData['index'] ?>)">
                                    <svg fill="currentColor" viewBox="0 0 24 24">
                                        <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
                                    </svg>
                                </button>
                                <a href="?delete_text=<?= (int)$textData['index'] ?>" class="delete-btn" onclick="return confirm('Delete this text?')">
                                    <svg fill="currentColor" viewBox="0 0 24 24">
                                        <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/>
                                    </svg>
                                </a>
                                <div class="text-content">
                                    <?php
                                    $content = h($textData['content']);
                                    echo strlen($content) > 150 ? substr($content, 0, 150) . '...' : $content;
                                    ?>
                                </div>
                                <textarea id="full-text-<?= (int)$textData['index'] ?>" style="display:none;"><?= h($textData['content']) ?></textarea>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($filesByDate)): ?>
        <div class="section">
            <h2>📥 Files (<?= $totalFiles ?>)</h2>
            <?php foreach ($filesByDate as $dateCategory => $dateFiles): ?>
                <div class="date-group">
                    <div class="date-header">
                        <div class="date-label"><?= h($dateCategory) ?> (<?= count($dateFiles) ?>)</div>
                        <div class="btn-group">
                            <a href="?download_zip=<?= urlencode($dateCategory) ?>" class="zip-btn">📦 Download ZIP</a>
                            <a href="?delete_day=<?= urlencode($dateCategory) ?>" class="del-btn" onclick="return confirm('Delete all files from <?= h($dateCategory) ?>?')">🗑️ Delete Day</a>
                        </div>
                    </div>
                    <div class="files">
                        <?php foreach ($dateFiles as $fileData):
                            $file = $fileData['name'];
                            $filePath = $fileData['path'];
                            $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                            $fileSize = formatFileSize(filesize($filePath));
                            $fileType = strtoupper($ext);
                            $imageExts = ['jpg','jpeg','png','gif','webp','bmp'];
                            $videoExts = ['mp4','webm','ogg','mov','avi'];
                            $pdfExts = ['pdf'];
                            $audioExts = ['mp3','wav','ogg','aac'];
                            ?>
                            <div class="file-card">
                                <a href="?delete_file=<?= urlencode($file) ?>" class="delete-btn" onclick="return confirm('Delete <?= h($file) ?>?')">
                                    <svg fill="currentColor" viewBox="0 0 24 24">
                                        <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/>
                                    </svg>
                                </a>
                                <div class="file-preview">
                                    <?php if (in_array($ext, $imageExts)): ?>
                                        <img src="<?= h('uploads/'.$file) ?>" alt="<?= h($file) ?>">
                                    <?php elseif (in_array($ext, $videoExts)): ?>
                                        <video controls>
                                            <source src="<?= h('uploads/'.$file) ?>" type="video/<?= h($ext) ?>">
                                        </video>
                                    <?php elseif (in_array($ext, $pdfExts)): ?>
                                        <iframe src="<?= h('uploads/'.$file) ?>#toolbar=0"></iframe>
                                    <?php elseif (in_array($ext, $audioExts)): ?>
                                        <div class="file-icon">🎵</div>
                                    <?php elseif ($ext === 'doc' || $ext === 'docx'): ?>
                                        <div class="file-icon">📝</div>
                                    <?php elseif ($ext === 'zip' || $ext === 'rar'): ?>
                                        <div class="file-icon">📦</div>
                                    <?php else: ?>
                                        <div class="file-icon">📎</div>
                                    <?php endif; ?>
                                </div>
                                <div class="file-info">
                                    <div class="file-name" title="<?= h($file) ?>"><?= h($file) ?></div>
                                    <div class="file-meta"><?= h($fileType) ?> • <?= h($fileSize) ?></div>
                                    <a href="?download=<?= urlencode($file) ?>" class="download-btn">Download</a>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<!-- Edit Modal -->
<div class="modal" id="editModal">
    <div class="modal-content">
        <h2>✏️ Edit Text</h2>
        <form method="POST" id="editForm">
            <textarea name="edit_text" id="editTextArea" required></textarea>
            <input type="hidden" name="text_index" id="editTextIndex">
            <div class="modal-buttons">
                <button type="submit" style="background:#28a745">Save Changes</button>
                <button type="button" onclick="closeEditModal()" style="background:#dc3545">Cancel</button>
            </div>
        </form>
    </div>
</div>

<script>
const CHUNK_SIZE = 15 * 1024 * 1024;
const MAX_FILE_SIZE = 200 * 1024 * 1024;
const MAX_PARALLEL = 3;

const fileInput = document.getElementById('fileInput');
const fileCount = document.getElementById('fileCount');
const dropZone = document.getElementById('dropZone');
const textForm = document.getElementById('textForm');
const textArea = document.getElementById('textArea');

fileInput.addEventListener('change', e => {
    const c = e.target.files.length;
    fileCount.textContent = c ? `📁 ${c} file(s) selected` : '';
});

['dragenter','dragover','dragleave','drop'].forEach(ev=>{
    dropZone.addEventListener(ev,e=>{e.preventDefault();e.stopPropagation();});
});
['dragenter','dragover'].forEach(ev=>{
    dropZone.addEventListener(ev,()=>dropZone.classList.add('dragover'));
});
['dragleave','drop'].forEach(ev=>{
    dropZone.addEventListener(ev,()=>dropZone.classList.remove('dragover'));
});
dropZone.addEventListener('click',()=>fileInput.click());
dropZone.addEventListener('drop',e=>{
    const files=e.dataTransfer.files;
    if(!files||!files.length)return;
    fileInput.files=files;
    fileCount.textContent=`📁 ${files.length} file(s) selected`;
});

document.getElementById('uploadForm').addEventListener('submit',async e=>{
    e.preventDefault();
    const files = Array.from(fileInput.files);
    if(!files.length)return;

    const uploadBtn = document.getElementById('uploadBtn');
    const progressContainer=document.getElementById('progressContainer');
    const progressFill=document.getElementById('progressFill');
    const uploadSpeed=document.getElementById('uploadSpeed');

    uploadBtn.disabled=true;
    progressContainer.style.display='block';

    const totalFiles=files.length;
    let completedFiles=0;
    const fileProgress=new Map();
    const startTime=Date.now();

    const updateProgress=()=>{
        let totalProgress=0;
        fileProgress.forEach(p=>totalProgress+=p);
        const overall=((totalProgress/totalFiles)*100).toFixed(0);
        progressFill.style.width=overall+'%';
        progressFill.textContent=overall+'%';

        const elapsed=(Date.now()-startTime)/1000;
        const speed=(completedFiles/elapsed).toFixed(2);
        uploadSpeed.textContent=`⚡ ${completedFiles}/${totalFiles} files • ${speed} files/sec`;
    };

    for(let i=0;i<totalFiles;i+=MAX_PARALLEL){
        const batch=files.slice(i,i+MAX_PARALLEL);

        await Promise.all(batch.map(async (file,idx)=>{
            const idxGlobal=i+idx;
            fileProgress.set(idxGlobal,0);

            try{
                if(file.size>MAX_FILE_SIZE){
                    alert(`File ${file.name} exceeds 200MB limit`);
                    fileProgress.set(idxGlobal,1);
                }else{
                    await uploadChunked(file,p=>{
                        fileProgress.set(idxGlobal,p);
                        updateProgress();
                    });
                }
                completedFiles++;
                updateProgress();
            }catch(err){
                console.error('Upload failed:',err);
                alert(`Failed to upload ${file.name}`);
            }
        }));
    }

    uploadSpeed.textContent=`✅ Completed ${completedFiles}/${totalFiles}`;
    setTimeout(()=>location.reload(),1000);
});

textForm.addEventListener('submit',e=>{
    e.preventDefault();
    if(!textArea.value.trim())return;
    textForm.submit();
});

async function uploadChunked(file,onProgress){
    const totalChunks=Math.ceil(file.size/CHUNK_SIZE);
    const uploadId=Date.now()+'_'+Math.random().toString(36).substr(2,9);

    for(let i=0;i<totalChunks;i++){
        const chunk=file.slice(i*CHUNK_SIZE,Math.min((i+1)*CHUNK_SIZE,file.size));
        const formData=new FormData();
        formData.append('file',chunk);
        formData.append('chunk',i);
        formData.append('totalChunks',totalChunks);
        formData.append('fileName',file.name);
        formData.append('uploadId',uploadId);

        const res=await fetch(window.location.pathname,{method:'POST',body:formData});
        const result=await res.json();
        if(!result.success) throw new Error('Chunk failed');
        onProgress((i+1)/totalChunks);
    }
}

function copyText(btn,index){
    const textarea=document.getElementById('full-text-'+index);
    textarea.style.display='block';
    textarea.select();
    document.execCommand('copy');
    textarea.style.display='none';

    btn.innerHTML='<svg fill="currentColor" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>';
    btn.classList.add('copied');
    setTimeout(()=>{
        btn.innerHTML='<svg fill="currentColor" viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>';
        btn.classList.remove('copied');
    },2000);
}

function openEditModal(index){
    const textarea=document.getElementById('full-text-'+index);
    document.getElementById('editTextArea').value=textarea.value;
    document.getElementById('editTextIndex').value=index;
    document.getElementById('editModal').classList.add('show');
}

function closeEditModal(){
    document.getElementById('editModal').classList.remove('show');
}
</script>
</body>
</html>
