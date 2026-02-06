<?php
session_start();

// ⚠️ CHANGE THIS PASSWORD
$correctPassword = 'Text';

// Match server configuration
ini_set('upload_max_filesize', '20M');
ini_set('post_max_size', '30M');
ini_set('memory_limit', '512M');
ini_set('max_execution_time', '300');

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    if ($_POST['password'] === $correctPassword) {
        $_SESSION['logged_in'] = true;
        if (isset($_POST['remember'])) {
            setcookie('transfer_auth', md5($correctPassword), time() + (30 * 24 * 60 * 60), '/');
        }
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $loginError = true;
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    setcookie('transfer_auth', '', time() - 3600, '/');
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Check authentication
$isLoggedIn = isset($_SESSION['logged_in']) || (isset($_COOKIE['transfer_auth']) && $_COOKIE['transfer_auth'] === md5($correctPassword));

if (!$isLoggedIn) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
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
$uploadDir = 'uploads/';
$chunksDir = 'uploads/chunks/';
$textFile = 'uploads/texts.json';
if (!is_dir($uploadDir)) mkdir($uploadDir, 0777, true);
if (!is_dir($chunksDir)) mkdir($chunksDir, 0777, true);

// Handle chunked upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['chunk'])) {
    header('Content-Type: application/json');
    
    $chunk = $_POST['chunk'];
    $totalChunks = $_POST['totalChunks'];
    $fileName = $_POST['fileName'];
    $uploadId = $_POST['uploadId'];
    
    $chunkFile = $chunksDir . $uploadId . '_' . $chunk;
    
    if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
        move_uploaded_file($_FILES['file']['tmp_name'], $chunkFile);
        
        // Check if all chunks uploaded
        $allChunksUploaded = true;
        for ($i = 0; $i < $totalChunks; $i++) {
            if (!file_exists($chunksDir . $uploadId . '_' . $i)) {
                $allChunksUploaded = false;
                break;
            }
        }
        
        if ($allChunksUploaded) {
            // Combine chunks
            $finalFile = $uploadDir . $fileName;
            
            // Handle duplicate names
            if (file_exists($finalFile)) {
                $fileInfo = pathinfo($fileName);
                $baseName = $fileInfo['filename'];
                $extension = isset($fileInfo['extension']) ? '.' . $fileInfo['extension'] : '';
                $counter = 1;
                
                while (file_exists($uploadDir . $baseName . '_' . $counter . $extension)) {
                    $counter++;
                }
                
                $finalFile = $uploadDir . $baseName . '_' . $counter . $extension;
            }
            
            // Combine chunks into final file
            $output = fopen($finalFile, 'wb');
            for ($i = 0; $i < $totalChunks; $i++) {
                $chunkPath = $chunksDir . $uploadId . '_' . $i;
                $input = fopen($chunkPath, 'rb');
                stream_copy_to_stream($input, $output);
                fclose($input);
                unlink($chunkPath); // Delete chunk
            }
            fclose($output);
            
            echo json_encode(['success' => true, 'completed' => true]);
        } else {
            echo json_encode(['success' => true, 'completed' => false]);
        }
    } else {
        echo json_encode(['success' => false, 'error' => 'Upload failed']);
    }
    exit;
}

// Load saved texts
$texts = file_exists($textFile) ? json_decode(file_get_contents($textFile), true) : [];

// Auto-delete files and texts older than 3 days
$threeDaysAgo = time() - (3 * 24 * 60 * 60);

// Clean old files
$allFiles = array_diff(scandir($uploadDir), ['.', '..', 'texts.json', 'chunks']);
foreach ($allFiles as $file) {
    $filePath = $uploadDir . $file;
    if (is_file($filePath) && filemtime($filePath) < $threeDaysAgo) {
        unlink($filePath);
    }
}

// Clean old chunks (older than 1 hour - incomplete uploads)
$oneHourAgo = time() - 3600;
$chunkFiles = array_diff(scandir($chunksDir), ['.', '..']);
foreach ($chunkFiles as $chunk) {
    $chunkPath = $chunksDir . $chunk;
    if (filemtime($chunkPath) < $oneHourAgo) {
        unlink($chunkPath);
    }
}

// Clean old texts
$texts = array_filter($texts, function($item) use ($threeDaysAgo) {
    return $item['time'] >= $threeDaysAgo;
});
file_put_contents($textFile, json_encode(array_values($texts)));

// Handle text/URL save
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['text'])) {
    $text = $_POST['text'];
    $texts[] = ['time' => time(), 'content' => $text];
    file_put_contents($textFile, json_encode($texts));
    $message = "✅ Text saved!";
}

// Get all files
$files = array_diff(scandir($uploadDir), ['.', '..', 'texts.json', 'chunks']);
arsort($files);

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
$currentURL = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
?>
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
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
            <div class="message"><?= $message ?></div>
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
                <textarea name="text" placeholder="Paste text or URL here..." required></textarea>
                <button type="submit">Save Text</button>
            </form>
        </div>

        <?php if (!empty($texts)): ?>
        <div class="section">
            <h2>📋 Saved Texts (<?= count($texts) ?>)</h2>
            <div class="texts-grid">
                <?php foreach (array_reverse($texts) as $index => $item): ?>
                    <div class="text-item">
                        <button class="copy-btn" onclick="copyText(this, <?= $index ?>)">
                            <svg fill="currentColor" viewBox="0 0 24 24">
                                <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
                            </svg>
                        </button>
                        <div class="text-content">
                            <?php
                            $content = htmlspecialchars($item['content']);
                            echo strlen($content) > 150 ? substr($content, 0, 150) . '...' : $content;
                            ?>
                        </div>
                        <textarea id="full-text-<?= $index ?>" style="display:none;"><?= htmlspecialchars($item['content']) ?></textarea>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>

        <div class="section">
            <h2>📥 Files (<?= count($files) ?>)</h2>
            <div class="files">
                <?php foreach ($files as $file): 
                    $filePath = $uploadDir . $file;
                    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                    $fileSize = formatFileSize(filesize($filePath));
                    $fileType = strtoupper($ext);
                    
                    $imageExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'];
                    $videoExts = ['mp4', 'webm', 'ogg', 'mov', 'avi'];
                    $pdfExts = ['pdf'];
                    $audioExts = ['mp3', 'wav', 'ogg', 'aac'];
                ?>
                    <div class="file-card">
                        <div class="file-preview">
                            <?php if (in_array($ext, $imageExts)): ?>
                                <img src="<?= $filePath ?>" alt="<?= $file ?>">
                            <?php elseif (in_array($ext, $videoExts)): ?>
                                <video controls>
                                    <source src="<?= $filePath ?>" type="video/<?= $ext ?>">
                                </video>
                            <?php elseif (in_array($ext, $pdfExts)): ?>
                                <iframe src="<?= $filePath ?>#toolbar=0" type="application/pdf"></iframe>
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
                            <div class="file-name" title="<?= htmlspecialchars($file) ?>"><?= htmlspecialchars($file) ?></div>
                            <div class="file-meta"><?= $fileType ?> • <?= $fileSize ?></div>
                            <a href="<?= $filePath ?>" download class="download-btn">Download</a>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <script>
        const CHUNK_SIZE = 15 * 1024 * 1024; // 15MB chunks
        const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20MB threshold
        const MAX_PARALLEL = 3; // Upload 3 files at once

        // Show selected file count
        document.getElementById('fileInput').addEventListener('change', function(e) {
            const count = e.target.files.length;
            const countDiv = document.getElementById('fileCount');
            if (count > 0) {
                countDiv.textContent = `📁 ${count} file(s) selected`;
            } else {
                countDiv.textContent = '';
            }
        });

        // Handle file upload with parallel processing
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
            
            // Update overall progress
            const updateProgress = () => {
                let totalProgress = 0;
                fileProgress.forEach(progress => {
                    totalProgress += progress;
                });
                const overallProgress = (totalProgress / totalFiles * 100).toFixed(0);
                progressFill.style.width = overallProgress + '%';
                progressFill.textContent = overallProgress + '%';
                
                // Calculate speed
                const elapsedSeconds = (Date.now() - startTime) / 1000;
                const filesPerSecond = (completedFiles / elapsedSeconds).toFixed(2);
                uploadSpeed.textContent = `⚡ ${completedFiles}/${totalFiles} files • ${filesPerSecond} files/sec`;
            };
            
            // Upload files in batches of MAX_PARALLEL
            for (let i = 0; i < totalFiles; i += MAX_PARALLEL) {
                const batch = files.slice(i, i + MAX_PARALLEL);
                
                await Promise.all(batch.map(async (file, index) => {
                    const fileIndex = i + index;
                    fileProgress.set(fileIndex, 0);
                    
                    try {
                        if (file.size > MAX_FILE_SIZE) {
                            // Upload in chunks
                            await uploadFileInChunks(file, (progress) => {
                                fileProgress.set(fileIndex, progress);
                                updateProgress();
                            });
                        } else {
                            // Direct upload
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
            
            // Success
            uploadSpeed.textContent = `✅ Completed ${completedFiles}/${totalFiles} files`;
            setTimeout(() => {
                location.reload();
            }, 1000);
        });

        async function uploadFileInChunks(file, progressCallback) {
            const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
            const uploadId = Date.now() + '_' + Math.random().toString(36).substr(2, 9);
            
            for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
                const start = chunkIndex * CHUNK_SIZE;
                const end = Math.min(start + CHUNK_SIZE, file.size);
                const chunk = file.slice(start, end);
                
                const formData = new FormData();
                formData.append('file', chunk);
                formData.append('chunk', chunkIndex);
                formData.append('totalChunks', totalChunks);
                formData.append('fileName', file.name);
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
            const formData = new FormData();
            formData.append('file', file);
            formData.append('chunk', 0);
            formData.append('totalChunks', 1);
            formData.append('fileName', file.name);
            formData.append('uploadId', Date.now() + '_' + Math.random().toString(36).substr(2, 9));
            
            const response = await fetch(window.location.href, {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (!result.success) {
                throw new Error('Upload failed');
            }
        }

        function copyText(btn, index) {
            const textarea = document.getElementById('full-text-' + index);
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
        }
    </script>
</body>
</html>