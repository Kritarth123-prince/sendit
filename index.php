<?php
session_start();

// ⚠️ CHANGE THIS PASSWORD
$correctPassword = 'Text';

// Match server configuration
ini_set('upload_max_filesize', '20M');
ini_set('post_max_size', '30M');
ini_set('memory_limit', '512M');
ini_set('max_execution_time', '300');

// Security function: Get safe redirect URL
function getSafeRedirectUrl() {
    // Use only the script name, no path info
    return basename($_SERVER['SCRIPT_NAME']);
}

// Security function: Sanitize filename
function sanitizeFilename($filename) {
    $filename = basename($filename);
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '_', $filename);
    $filename = preg_replace('/\.+/', '.', $filename);
    $filename = ltrim($filename, '.');
    if (strlen($filename) > 255) {
        $filename = substr($filename, 0, 255);
    }
    return $filename ?: 'unnamed_file';
}

// Security function: Validate upload ID
function validateUploadId($uploadId) {
    return preg_match('/^[a-zA-Z0-9_]+$/', $uploadId) ? $uploadId : false;
}

// Security function: Validate chunk number
function validateChunkNumber($chunk, $totalChunks) {
    if (!is_numeric($chunk) || !is_numeric($totalChunks)) {
        return false;
    }
    $chunk = intval($chunk);
    $totalChunks = intval($totalChunks);
    if ($chunk < 0 || $totalChunks < 1 || $chunk >= $totalChunks || $totalChunks > 1000) {
        return false;
    }
    return true;
}

// Security function: Validate path is within directory
function isPathSafe($filePath, $baseDir) {
    $realBase = realpath($baseDir);
    if ($realBase === false) {
        return false;
    }
    
    if (file_exists($filePath)) {
        $realPath = realpath($filePath);
        if ($realPath === false) {
            return false;
        }
    } else {
        $parentDir = dirname($filePath);
        $realParent = realpath($parentDir);
        if ($realParent === false) {
            return false;
        }
        $realPath = $realParent . DIRECTORY_SEPARATOR . basename($filePath);
    }
    
    return strpos($realPath, $realBase . DIRECTORY_SEPARATOR) === 0;
}

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    if ($_POST['password'] === $correctPassword) {
        $_SESSION['logged_in'] = true;
        if (isset($_POST['remember'])) {
            setcookie('transfer_auth', hash('sha256', $correctPassword . 'salt'), time() + (30 * 24 * 60 * 60), '/', '', true, true);
        }
        header('Location: ' . getSafeRedirectUrl());
        exit;
    } else {
        $loginError = true;
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    setcookie('transfer_auth', '', time() - 3600, '/', '', true, true);
    header('Location: ' . getSafeRedirectUrl());
    exit;
}

// Check authentication
$isLoggedIn = isset($_SESSION['logged_in']) || (isset($_COOKIE['transfer_auth']) && $_COOKIE['transfer_auth'] === hash('sha256', $correctPassword . 'salt'));

if (!$isLoggedIn) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>🔒 Login - Fast Transfer</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
            .login-box { background: white; border-radius: 15px; padding: 40px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); max-width: 400px; width: 100%; }
            h1 { text-align: center; color: #667eea; margin-bottom: 30px; }
            input[type="password"] { width: 100%; padding: 15px; border: 2px solid #667eea; border-radius: 8px; font-size: 16px; margin-bottom: 15px; }
            button { width: 100%; padding: 15px; background: #667eea; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; font-weight: bold; }
            button:hover { background: #5568d3; }
            .error { background: #f8d7da; color: #721c24; padding: 12px; border-radius: 8px; margin-bottom: 15px; text-align: center; }
            .remember { margin-bottom: 15px; display: flex; align-items: center; }
            .remember input { width: auto; margin-right: 8px; }
            .remember label { font-size: 14px; color: #666; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h1>🔒 Fast Transfer Login</h1>
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

// Main application code
$uploadDir = realpath(__DIR__ . '/uploads') . DIRECTORY_SEPARATOR;
$chunksDir = realpath(__DIR__ . '/uploads/chunks') . DIRECTORY_SEPARATOR;
$textFile = $uploadDir . 'texts.json';

// Ensure directories exist
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
    file_put_contents($uploadDir . '.htaccess', 'Options -Indexes');
}
if (!is_dir($chunksDir)) {
    mkdir($chunksDir, 0755, true);
    file_put_contents($chunksDir . '.htaccess', 'deny from all');
}

// Re-get real paths after creation
$uploadDir = realpath(__DIR__ . '/uploads') . DIRECTORY_SEPARATOR;
$chunksDir = realpath(__DIR__ . '/uploads/chunks') . DIRECTORY_SEPARATOR;
$textFile = $uploadDir . 'texts.json';

// Handle chunked upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['chunk'])) {
    header('Content-Type: application/json');
    
    $chunk = isset($_POST['chunk']) ? intval($_POST['chunk']) : -1;
    $totalChunks = isset($_POST['totalChunks']) ? intval($_POST['totalChunks']) : -1;
    $fileName = isset($_POST['fileName']) ? sanitizeFilename($_POST['fileName']) : '';
    $uploadId = isset($_POST['uploadId']) ? validateUploadId($_POST['uploadId']) : false;
    
    if (!$uploadId) {
        echo json_encode(['success' => false, 'error' => 'Invalid upload ID']);
        exit;
    }
    
    if (!validateChunkNumber($chunk, $totalChunks)) {
        echo json_encode(['success' => false, 'error' => 'Invalid chunk number']);
        exit;
    }
    
    if (empty($fileName)) {
        echo json_encode(['success' => false, 'error' => 'Invalid filename']);
        exit;
    }
    
    $safeUploadId = preg_replace('/[^a-zA-Z0-9_]/', '', $uploadId);
    $chunkFileName = $safeUploadId . '_' . $chunk;
    $chunkFile = $chunksDir . $chunkFileName;
    
    if (!isPathSafe($chunkFile, $chunksDir)) {
        echo json_encode(['success' => false, 'error' => 'Invalid chunk path']);
        exit;
    }
    
    if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
        if ($_FILES['file']['size'] > 20 * 1024 * 1024) {
            echo json_encode(['success' => false, 'error' => 'Chunk too large']);
            exit;
        }
        
        if (move_uploaded_file($_FILES['file']['tmp_name'], $chunkFile)) {
            $allChunksUploaded = true;
            $chunkPaths = [];
            
            for ($i = 0; $i < $totalChunks; $i++) {
                $checkChunkName = $safeUploadId . '_' . $i;
                $checkChunk = $chunksDir . $checkChunkName;
                
                if (!isPathSafe($checkChunk, $chunksDir) || !file_exists($checkChunk)) {
                    $allChunksUploaded = false;
                    break;
                }
                $chunkPaths[] = $checkChunk;
            }
            
            if ($allChunksUploaded) {
                $finalFileName = $fileName;
                $finalFile = $uploadDir . $finalFileName;
                
                if (file_exists($finalFile)) {
                    $fileInfo = pathinfo($fileName);
                    $baseName = preg_replace('/[^a-zA-Z0-9_-]/', '_', $fileInfo['filename']);
                    $extension = isset($fileInfo['extension']) ? '.' . preg_replace('/[^a-zA-Z0-9]/', '', $fileInfo['extension']) : '';
                    $counter = 1;
                    
                    do {
                        $finalFileName = $baseName . '_' . $counter . $extension;
                        $finalFile = $uploadDir . $finalFileName;
                        $counter++;
                    } while (file_exists($finalFile) && $counter < 1000);
                }
                
                if (!isPathSafe($finalFile, $uploadDir)) {
                    echo json_encode(['success' => false, 'error' => 'Invalid final path']);
                    exit;
                }
                
                $output = fopen($finalFile, 'wb');
                if ($output === false) {
                    echo json_encode(['success' => false, 'error' => 'Cannot create file']);
                    exit;
                }
                
                $success = true;
                foreach ($chunkPaths as $chunkPath) {
                    if (!isPathSafe($chunkPath, $chunksDir)) {
                        $success = false;
                        break;
                    }
                    
                    $input = fopen($chunkPath, 'rb');
                    if ($input === false) {
                        $success = false;
                        break;
                    }
                    
                    stream_copy_to_stream($input, $output);
                    fclose($input);
                    
                    if (isPathSafe($chunkPath, $chunksDir)) {
                        unlink($chunkPath);
                    }
                }
                
                fclose($output);
                
                if ($success) {
                    echo json_encode(['success' => true, 'completed' => true]);
                } else {
                    if (file_exists($finalFile) && isPathSafe($finalFile, $uploadDir)) {
                        unlink($finalFile);
                    }
                    echo json_encode(['success' => false, 'error' => 'Combination failed']);
                }
            } else {
                echo json_encode(['success' => true, 'completed' => false]);
            }
        } else {
            echo json_encode(['success' => false, 'error' => 'Move failed']);
        }
    } else {
        echo json_encode(['success' => false, 'error' => 'Upload failed']);
    }
    exit;
}

// Load saved texts
$texts = file_exists($textFile) ? json_decode(file_get_contents($textFile), true) : [];
if (!is_array($texts)) $texts = [];

// Auto-delete files and texts older than 3 days
$threeDaysAgo = time() - (3 * 24 * 60 * 60);

// Clean old files
if (is_dir($uploadDir)) {
    $allFiles = array_diff(scandir($uploadDir), ['.', '..', 'texts.json', 'chunks', '.htaccess']);
    foreach ($allFiles as $file) {
        $filePath = $uploadDir . $file;
        if (is_file($filePath) && isPathSafe($filePath, $uploadDir) && filemtime($filePath) < $threeDaysAgo) {
            unlink($filePath);
        }
    }
}

// Clean old chunks (older than 1 hour)
$oneHourAgo = time() - 3600;
if (is_dir($chunksDir)) {
    $chunkFiles = array_diff(scandir($chunksDir), ['.', '..', '.htaccess']);
    foreach ($chunkFiles as $chunk) {
        $chunkPath = $chunksDir . $chunk;
        if (is_file($chunkPath) && isPathSafe($chunkPath, $chunksDir) && filemtime($chunkPath) < $oneHourAgo) {
            unlink($chunkPath);
        }
    }
}

// Clean old texts
$texts = array_filter($texts, function($item) use ($threeDaysAgo) {
    return isset($item['time']) && $item['time'] >= $threeDaysAgo;
});
// Re-index array to ensure sequential numeric keys
$texts = array_values($texts);
file_put_contents($textFile, json_encode($texts));

// Handle text/URL save
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['text'])) {
    $text = isset($_POST['text']) ? substr(trim($_POST['text']), 0, 10000) : '';
    if (!empty($text)) {
        $texts[] = ['time' => time(), 'content' => $text];
        file_put_contents($textFile, json_encode($texts));
        $message = "✅ Text saved!";
    }
}

// Get all files
$files = [];
if (is_dir($uploadDir)) {
    $files = array_diff(scandir($uploadDir), ['.', '..', 'texts.json', 'chunks', '.htaccess']);
    arsort($files);
}

// Function to format file size
function formatFileSize($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } else {
        return $bytes . ' bytes';
    }
}

// Get current URL
$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
$host = htmlspecialchars($_SERVER['HTTP_HOST'], ENT_QUOTES, 'UTF-8');
$script = htmlspecialchars(basename($_SERVER['SCRIPT_NAME']), ENT_QUOTES, 'UTF-8');
$currentURL = $protocol . $host . '/' . $script;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>⚡ Fast Transfer</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 15px; padding: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
        h1 { text-align: center; color: #667eea; margin-bottom: 10px; }
        .ip { text-align: center; background: #f0f0f0; padding: 10px; border-radius: 8px; margin-bottom: 10px; font-size: 14px; word-break: break-all; }
        .section { margin-bottom: 25px; }
        .section h2 { font-size: 18px; margin-bottom: 10px; color: #333; }
        input[type="file"], textarea { width: 100%; padding: 12px; border: 2px dashed #667eea; border-radius: 8px; font-size: 14px; }
        textarea { height: 80px; resize: none; border-style: solid; }
        button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; margin-top: 10px; font-weight: bold; }
        button:hover { background: #5568d3; }
        button:disabled { background: #ccc; cursor: not-allowed; }
        .message { background: #d4edda; color: #155724; padding: 12px; border-radius: 8px; margin-bottom: 15px; text-align: center; }
        .files { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 15px; }
        .file-card { background: #f8f9fa; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.1); transition: transform 0.2s; }
        .file-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .file-preview { width: 100%; height: 140px; background: #e9ecef; display: flex; align-items: center; justify-content: center; position: relative; overflow: hidden; }
        .file-preview img { width: 100%; height: 100%; object-fit: cover; }
        .file-preview video { width: 100%; height: 100%; object-fit: cover; }
        .file-preview iframe { width: 100%; height: 100%; border: none; }
        .file-icon { font-size: 50px; }
        .file-info { padding: 12px; }
        .file-name { font-weight: bold; color: #333; margin-bottom: 5px; word-break: break-word; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .file-meta { font-size: 11px; color: #666; margin-bottom: 8px; }
        .download-btn { display: block; width: 100%; padding: 8px; background: #667eea; color: white; text-align: center; text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 13px; }
        .download-btn:hover { background: #5568d3; }
        .texts-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; }
        .text-item { background: #fff9e6; padding: 15px; padding-top: 45px; border-radius: 10px; position: relative; border-left: 4px solid #ffc107; min-height: 100px; box-shadow: 0 2px 6px rgba(0,0,0,0.1); transition: transform 0.2s; }
        .text-item:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .text-content { color: #333; word-break: break-word; font-size: 14px; line-height: 1.5; }
        .copy-btn { position: absolute; top: 8px; right: 8px; background: #667eea; color: white; border: none; padding: 8px; border-radius: 6px; cursor: pointer; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; }
        .copy-btn:hover { background: #5568d3; }
        .copy-btn svg { width: 16px; height: 16px; }
        .copied { background: #28a745 !important; }
        .info { text-align: center; color: #666; font-size: 12px; margin-bottom: 15px; }
        .logout { text-align: center; margin-bottom: 15px; }
        .logout a { color: #dc3545; text-decoration: none; font-size: 14px; }
        .logout a:hover { text-decoration: underline; }
        .file-count { color: #667eea; font-size: 13px; margin-top: 8px; }
        .progress-container { display: none; margin-top: 10px; }
        .progress-bar { width: 100%; height: 25px; background: #e9ecef; border-radius: 8px; overflow: hidden; position: relative; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); transition: width 0.3s; display: flex; align-items: center; justify-content: center; color: white; font-size: 12px; font-weight: bold; }
        .upload-speed { text-align: center; color: #667eea; font-size: 12px; margin-top: 5px; }
        
        @media (max-width: 768px) {
            .files { grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); }
            .file-preview { height: 120px; }
            .texts-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ Fast Media Transfer</h1>
        <div class="logout"><a href="?logout">🔓 Logout</a></div>
        <div class="ip">📡 Share this URL: <strong><?= $currentURL ?></strong></div>
        <div class="info">🗑️ Files auto-delete after 3 days • 📦 Supports files up to 200MB • ⚡ 3 parallel uploads</div>
        
        <?php if (isset($message)): ?>
            <div class="message"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <div class="section">
            <h2>📤 Upload Files (Images, Videos, PDFs, etc.)</h2>
            <form id="uploadForm">
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
            <form method="POST">
                <textarea name="text" placeholder="Paste text or URL here..." required maxlength="10000"></textarea>
                <button type="submit">Save Text</button>
            </form>
        </div>

        <?php if (!empty($texts)): ?>
        <div class="section">
            <h2>📋 Saved Texts (<?= count($texts) ?>)</h2>
            <div class="texts-grid">
                <?php foreach (array_reverse($texts) as $index => $item): ?>
                    <?php 
                    // Ensure index is a safe integer
                    $safeIndex = intval($index);
                    if (isset($item['content']) && is_string($item['content'])): 
                    ?>
                    <div class="text-item">
                        <button class="copy-btn" data-index="<?= $safeIndex ?>" aria-label="Copy text">
                            <svg fill="currentColor" viewBox="0 0 24 24">
                                <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
                            </svg>
                        </button>
                        <div class="text-content">
                            <?php
                            $content = htmlspecialchars($item['content'], ENT_QUOTES, 'UTF-8');
                            echo mb_strlen($content) > 150 ? mb_substr($content, 0, 150) . '...' : $content;
                            ?>
                        </div>
                        <textarea id="full-text-<?= $safeIndex ?>" style="display:none;" readonly><?= htmlspecialchars($item['content'], ENT_QUOTES, 'UTF-8') ?></textarea>
                    </div>
                    <?php endif; ?>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>

        <div class="section">
            <h2>📥 Files (<?= count($files) ?>)</h2>
            <div class="files">
                <?php foreach ($files as $file): 
                    $filePath = $uploadDir . $file;
                    if (!is_file($filePath) || !isPathSafe($filePath, $uploadDir)) continue;
                    
                    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                    $fileSize = formatFileSize(filesize($filePath));
                    $fileType = strtoupper($ext);
                    
                    $imageExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'];
                    $videoExts = ['mp4', 'webm', 'ogg', 'mov', 'avi'];
                    $pdfExts = ['pdf'];
                    $audioExts = ['mp3', 'wav', 'ogg', 'aac'];
                    
                    $relPath = 'uploads/' . htmlspecialchars($file, ENT_QUOTES, 'UTF-8');
                ?>
                    <div class="file-card">
                        <div class="file-preview">
                            <?php if (in_array($ext, $imageExts)): ?>
                                <img src="<?= $relPath ?>" alt="<?= htmlspecialchars($file, ENT_QUOTES, 'UTF-8') ?>">
                            <?php elseif (in_array($ext, $videoExts)): ?>
                                <video controls>
                                    <source src="<?= $relPath ?>" type="video/<?= htmlspecialchars($ext, ENT_QUOTES, 'UTF-8') ?>">
                                </video>
                            <?php elseif (in_array($ext, $pdfExts)): ?>
                                <iframe src="<?= $relPath ?>#toolbar=0" type="application/pdf"></iframe>
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
                            <div class="file-name" title="<?= htmlspecialchars($file, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($file, ENT_QUOTES, 'UTF-8') ?></div>
                            <div class="file-meta"><?= htmlspecialchars($fileType, ENT_QUOTES, 'UTF-8') ?> • <?= htmlspecialchars($fileSize, ENT_QUOTES, 'UTF-8') ?></div>
                            <a href="<?= $relPath ?>" download class="download-btn">Download</a>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <script>
        const CHUNK_SIZE = 15 * 1024 * 1024;
        const MAX_FILE_SIZE = 20 * 1024 * 1024;
        const MAX_PARALLEL = 3;

        function sanitizeFilename(filename) {
            return filename.replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 255);
        }

        function generateUploadId() {
            return Date.now() + '_' + Math.random().toString(36).substr(2, 9).replace(/[^a-z0-9]/gi, '');
        }

        document.getElementById('fileInput').addEventListener('change', function(e) {
            const count = e.target.files.length;
            const countDiv = document.getElementById('fileCount');
            if (count > 0) {
                countDiv.textContent = '📁 ' + count + ' file(s) selected';
            } else {
                countDiv.textContent = '';
            }
        });

        document.getElementById('uploadForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const fileInput = document.getElementById('fileInput');
            const files = Array.from(fileInput.files);
            const uploadBtn = document.getElementById('uploadBtn');
            const progressContainer = document.getElementById('progressContainer');
            const progressFill = document.getElementById('progressFill');
            const uploadSpeed = document.getElementById('uploadSpeed');
            
            if (files.length === 0) return;
            
            uploadBtn.disabled = true;
            progressContainer.style.display = 'block';
            
            const totalFiles = files.length;
            let completedFiles = 0;
            const fileProgress = new Map();
            
            const startTime = Date.now();
            
            const updateProgress = () => {
                let totalProgress = 0;
                fileProgress.forEach(progress => {
                    totalProgress += progress;
                });
                const overallProgress = (totalProgress / totalFiles * 100).toFixed(0);
                progressFill.style.width = overallProgress + '%';
                progressFill.textContent = overallProgress + '%';
                
                const elapsedSeconds = (Date.now() - startTime) / 1000;
                const filesPerSecond = (completedFiles / elapsedSeconds).toFixed(2);
                uploadSpeed.textContent = '⚡ ' + completedFiles + '/' + totalFiles + ' files • ' + filesPerSecond + ' files/sec';
            };
            
            for (let i = 0; i < totalFiles; i += MAX_PARALLEL) {
                const batch = files.slice(i, i + MAX_PARALLEL);
                
                await Promise.all(batch.map(async (file, index) => {
                    const fileIndex = i + index;
                    fileProgress.set(fileIndex, 0);
                    
                    try {
                        if (file.size > MAX_FILE_SIZE) {
                            await uploadFileInChunks(file, (progress) => {
                                fileProgress.set(fileIndex, progress);
                                updateProgress();
                            });
                        } else {
                            await uploadFileDirect(file);
                            fileProgress.set(fileIndex, 1);
                        }
                        completedFiles++;
                        updateProgress();
                    } catch (error) {
                        console.error('Upload failed:', error);
                        fileProgress.set(fileIndex, 0);
                        updateProgress();
                    }
                }));
            }
            
            uploadSpeed.textContent = '✅ Completed ' + completedFiles + '/' + totalFiles + ' files';
            setTimeout(() => {
                location.reload();
            }, 1000);
        });

        async function uploadFileInChunks(file, progressCallback) {
            const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
            const uploadId = generateUploadId();
            const sanitizedName = sanitizeFilename(file.name);
            
            for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
                const start = chunkIndex * CHUNK_SIZE;
                const end = Math.min(start + CHUNK_SIZE, file.size);
                const chunk = file.slice(start, end);
                
                const formData = new FormData();
                formData.append('file', chunk);
                formData.append('chunk', chunkIndex);
                formData.append('totalChunks', totalChunks);
                formData.append('fileName', sanitizedName);
                formData.append('uploadId', uploadId);
                
                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (!result.success) {
                    throw new Error('Chunk upload failed');
                }
                
                progressCallback((chunkIndex + 1) / totalChunks);
            }
        }

        async function uploadFileDirect(file) {
            const sanitizedName = sanitizeFilename(file.name);
            const formData = new FormData();
            formData.append('file', file);
            formData.append('chunk', 0);
            formData.append('totalChunks', 1);
            formData.append('fileName', sanitizedName);
            formData.append('uploadId', generateUploadId());
            
            const response = await fetch(window.location.href, {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (!result.success) {
                throw new Error('Upload failed');
            }
        }

        // Event delegation for copy buttons
        document.addEventListener('click', function(e) {
            const btn = e.target.closest('.copy-btn');
            if (!btn) return;
            
            const index = btn.getAttribute('data-index');
            if (!index) return;
            
            const textarea = document.getElementById('full-text-' + index);
            if (!textarea) return;
            
            textarea.style.display = 'block';
            textarea.select();
            document.execCommand('copy');
            textarea.style.display = 'none';
            
            btn.innerHTML = '<svg fill="currentColor" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.innerHTML = '<svg fill="currentColor" viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>';
                btn.classList.remove('copied');
            }, 2000);
        });
    </script>
</body>
</html>
