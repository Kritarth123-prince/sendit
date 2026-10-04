<?php
/**
 * Generates the PWA / favicon icons with PHP GD (W2-ADMIN, docs/ARCHITECTURE.md §12.6):
 * a champagne-gold gradient (#ecd3a0 → #c9a063, the default palette's --accent-g) rounded square
 * with a graphite lightning bolt (--on-accent), lightly embossed.
 *
 *   php tools/make-icons.php            writes assets/icons/*.png and assets/img/icon.svg
 *
 * Output:
 *   icon-192.png, icon-512.png       "any" purpose (rounded square, transparent corners)
 *   maskable-512.png                 full-bleed background, bolt inside the 80 % safe zone
 *   apple-touch-icon.png (180)       full-bleed (iOS applies its own mask)
 *   favicon-32.png                   small favicon fallback
 *   badge-72.png                     white bolt on transparent (Android notification badge: alpha only)
 * Shapes are drawn at 4x and downsampled, which gives smooth anti-aliased edges.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
if (!extension_loaded('gd') || !function_exists('imagecreatetruecolor')) {
    fwrite(STDERR, "The GD extension is required.\n");
    exit(1);
}

$root = dirname(__DIR__);
$iconsDir = $root . '/assets/icons';
$imgDir = $root . '/assets/img';
foreach ([$iconsDir, $imgDir] as $d) {
    if (!is_dir($d) && !mkdir($d, 0775, true) && !is_dir($d)) {
        fwrite(STDERR, "Cannot create {$d}\n");
        exit(1);
    }
}

const FROM = [0xec, 0xd3, 0xa0];
const TO = [0xc9, 0xa0, 0x63];
/** Bolt on the gold tile (the palette's --on-accent) and its embossed highlight. */
const BOLT_RGB = [0x1b, 0x15, 0x0b];
const EMBOSS_RGBA = [255, 246, 226, 70];
/** Lightning bolt on a 24-unit grid (same shape as the app's "bolt" icon), centred on (12, 12). */
const BOLT = [[13, 2], [3, 14], [12, 14], [11, 22], [21, 10], [12, 10]];
const SS = 4;

/** Gradient colour at t ∈ [0,1]. @return int[] */
function mix(float $t): array
{
    return [
        (int) round(FROM[0] + (TO[0] - FROM[0]) * $t),
        (int) round(FROM[1] + (TO[1] - FROM[1]) * $t),
        (int) round(FROM[2] + (TO[2] - FROM[2]) * $t),
    ];
}

/** Bolt polygon points (flat list) for a canvas of $s px with the bolt $frac of the height. */
function boltPoints(int $s, float $frac, float $dx = 0.0, float $dy = 0.0): array
{
    $unit = $s * $frac / 20.0;
    $pts = [];
    foreach (BOLT as [$x, $y]) {
        $pts[] = (int) round($s / 2 + ($x - 12) * $unit + $dx);
        $pts[] = (int) round($s / 2 + ($y - 12) * $unit + $dy);
    }
    return $pts;
}

/**
 * @param float $radius corner radius as a fraction of the size (0 = full-bleed square)
 * @param float $bolt   bolt height as a fraction of the size
 */
function render(int $size, float $radius, float $bolt, bool $background = true, bool $shadow = true): \GdImage
{
    $s = $size * SS;
    $im = imagecreatetruecolor($s, $s);
    imagealphablending($im, false);
    imagesavealpha($im, true);
    imagefill($im, 0, 0, imagecolorallocatealpha($im, 0, 0, 0, 127));

    if ($background) {
        // 135° gradient: anti-diagonal lines x + y = k are exact on the pixel grid.
        $max = 2 * ($s - 1);
        for ($k = 0; $k <= $max; $k++) {
            [$r, $g, $b] = mix($k / $max);
            $c = imagecolorallocate($im, $r, $g, $b);
            $xa = max(0, $k - ($s - 1));
            $xb = min($k, $s - 1);
            imageline($im, $xa, $k - $xa, $xb, $k - $xb, $c);
        }
        // Rounded corners: clear what lies outside each corner's quarter circle. Cleared pixels
        // keep the gradient colour (alpha 127) so downsampling leaves no dark fringe.
        $rad = (int) round($radius * $s);
        if ($rad > 0) {
            foreach ([[0, 0], [$s - $rad, 0], [0, $s - $rad], [$s - $rad, $s - $rad]] as [$ox, $oy]) {
                $cx = $ox === 0 ? $rad : $s - $rad;
                $cy = $oy === 0 ? $rad : $s - $rad;
                for ($y = $oy; $y < $oy + $rad; $y++) {
                    for ($x = $ox; $x < $ox + $rad; $x++) {
                        $ddx = $x + 0.5 - $cx;
                        $ddy = $y + 0.5 - $cy;
                        if ($ddx * $ddx + $ddy * $ddy > $rad * $rad) {
                            [$r, $g, $b] = mix(($x + $y) / $max);
                            imagesetpixel($im, $x, $y, imagecolorallocatealpha($im, $r, $g, $b, 127));
                        }
                    }
                }
            }
        }
    }

    imagealphablending($im, true);
    if ($shadow && $background) {
        // A pale highlight just below the bolt reads as a bolt stamped into the metal.
        imagefilledpolygon($im, boltPoints($s, $bolt, 0, $s * 0.014), imagecolorallocatealpha($im, ...EMBOSS_RGBA));
    }
    // On the gold tile the bolt is graphite; the notification badge (no tile) stays white.
    [$br, $bg, $bb] = $background ? BOLT_RGB : [255, 255, 255];
    imagefilledpolygon($im, boltPoints($s, $bolt), imagecolorallocatealpha($im, $br, $bg, $bb, 0));

    $out = imagecreatetruecolor($size, $size);
    imagealphablending($out, false);
    imagesavealpha($out, true);
    imagefill($out, 0, 0, imagecolorallocatealpha($out, 0, 0, 0, 127));
    imagecopyresampled($out, $im, 0, 0, 0, 0, $size, $size, $s, $s);
    imagedestroy($im);
    return $out;
}

$jobs = [
    'icon-192.png'         => [192, 0.22, 0.58, true, true],
    'icon-512.png'         => [512, 0.22, 0.58, true, true],
    'maskable-512.png'     => [512, 0.0, 0.40, true, true],
    'apple-touch-icon.png' => [180, 0.0, 0.52, true, true],
    'favicon-32.png'       => [32, 0.22, 0.66, true, false],
    'badge-72.png'         => [72, 0.0, 0.78, false, false],
];
foreach ($jobs as $name => [$size, $radius, $bolt, $bg, $shadow]) {
    $im = render($size, $radius, $bolt, $bg, $shadow);
    $file = $iconsDir . '/' . $name;
    if (!imagepng($im, $file, 9)) {
        fwrite(STDERR, "Could not write {$file}\n");
        exit(1);
    }
    imagedestroy($im);
    printf("%-22s %4dx%-4d %6d bytes\n", $name, $size, $size, filesize($file));
}

// Scalable favicon with the same geometry (64-unit canvas).
$p = boltPoints(64, 0.58);
$pts = [];
for ($i = 0; $i < count($p); $i += 2) {
    $pts[] = $p[$i] . ',' . $p[$i + 1];
}
$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    . '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
    . '<stop offset="0" stop-color="#ecd3a0"/><stop offset="1" stop-color="#c9a063"/></linearGradient></defs>'
    . '<rect width="64" height="64" rx="14" fill="url(#g)"/>'
    . '<polygon points="' . implode(' ', $pts) . '" fill="#1b150b"/>'
    . "</svg>\n";
file_put_contents($imgDir . '/icon.svg', $svg);
printf("%-22s %s\n", 'img/icon.svg', strlen($svg) . ' bytes');
