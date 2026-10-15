# Regenerate the persona assets used by the shell.
#
#   Assets/kohane-avatar.png        the framed portrait in the window header (her standing art)
#   Assets/kohane.ico               the app / taskbar icon (a single 256x256 PNG-compressed image)
#   Assets/kohane-q-*.png           the NORMAL outfit faces, split from the Q sheet
#   Assets/kohane-ultra-q-*.png     the 卍解 faces, split from the Ultra Q sheet
#
# The colours of the whole UI were sampled from the same drawing (see App.xaml), so this script is
# also the record of where the theme - and her faces - came from. Re-run it to restore every asset.
#
# How a sheet is split: the drawings sit on paper white, but NOT on an even grid - the 卍解 sheet's
# first pose swings a wide flame aura and its two rows do not line up with the normal sheet's three.
# So the poses are found as connected ink blobs on a downscaled mask: a blob that fills its own box
# is a drawing (measured: drawings 0.56 - 0.63, the sheet's thin frame 0.008), and small sparks are
# attached to the nearest drawing so a stray flame travels with its pose. Rows are formed wherever
# the vertical gap between pose centres is large, then each row is read left to right.
param(
    [string]$Portrait = "E:\kohane-index-desuno\kohane!!!\122078052_p0.png",
    [string]$NormalSheet = "F:\素材\图\brak 立绘\kohane\Kohane_Q.jpg",
    [string]$NormalSheetFallback = "F:\素材\图\brak 立绘\kohane\Kohane_Q_UwU.bmp",
    [string]$UltraSheet = "F:\素材\图\brak 立绘\kohane\Kohane_Ultra_Q_UwU.bmp",
    [string]$UltraSheetFallback = "F:\素材\图\brak 立绘\kohane\Kohane_Ultra_Q.jpg",
    [string]$AssetDir = (Join-Path (Split-Path -Parent $PSScriptRoot) "src\KohaneStation\Assets"),
    [int]$AvatarSize = 320,
    [int]$MoodSize = 256,
    [int]$SheetWorkWidth = 1152,
    [int]$MaxSourceWidth = 4000,
    [switch]$Diagnose
)

Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = "Stop"
if (-not (Test-Path $AssetDir)) { New-Item -ItemType Directory -Path $AssetDir -Force | Out-Null }

function Save-Square {
    param([System.Drawing.Image]$Image, [int]$Size, [string]$Path, [string]$Format)
    $bmp = New-Object System.Drawing.Bitmap($Size, $Size)
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $gfx.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $gfx.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $gfx.DrawImage($Image, 0, 0, $Size, $Size)
    $gfx.Dispose()
    if ($Format -eq "ico") {
        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $png = $ms.ToArray()
        $ico = New-Object System.IO.MemoryStream
        $bw = New-Object System.IO.BinaryWriter($ico)
        $bw.Write([byte]0); $bw.Write([byte]0); $bw.Write([byte]1); $bw.Write([byte]0)
        $bw.Write([byte]1); $bw.Write([byte]0)
        $bw.Write([byte]0); $bw.Write([byte]0)      # 256 x 256
        $bw.Write([byte]0); $bw.Write([byte]0)
        $bw.Write([byte]1); $bw.Write([byte]0)
        $bw.Write([byte]32); $bw.Write([byte]0)
        $bw.Write([int]$png.Length)
        $bw.Write([int]22)
        $bw.Write($png)
        $bw.Flush()
        [System.IO.File]::WriteAllBytes($Path, $ico.ToArray())
        $bw.Dispose(); $ico.Dispose(); $ms.Dispose()
    } else {
        $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    }
    $bmp.Dispose()
}

# ---------------------------------------------------------------- portrait + icon

if (Test-Path -LiteralPath $Portrait) {
    $portraitImg = [System.Drawing.Bitmap]::FromFile($Portrait)
    Write-Host "portrait: $($portraitImg.Width) x $($portraitImg.Height)"
    $cw = [int]($portraitImg.Width * 0.66)
    $crop = New-Object System.Drawing.Rectangle([int]($portraitImg.Width * 0.12), [int]($portraitImg.Height * 0.03), $cw, $cw)
    $piece = $portraitImg.Clone($crop, $portraitImg.PixelFormat)
    Save-Square -Image $piece -Size $AvatarSize -Path (Join-Path $AssetDir "kohane-avatar.png") -Format "png"
    Save-Square -Image $piece -Size 256 -Path (Join-Path $AssetDir "kohane.ico") -Format "ico"
    $piece.Dispose(); $portraitImg.Dispose()
    Write-Host "wrote  : kohane-avatar.png, kohane.ico"
} else {
    Write-Warning "portrait not found, skipped: $Portrait"
}

# ---------------------------------------------------------------- the sprite sheets

function Export-Poses {
    param(
        [string]$Family,
        [string[]]$Candidates,
        [string]$Prefix,
        [object[]]$Poses
    )

    # Prefer a lossless BMP, but skip one so large that decoding it is pure waste for a 256 px avatar.
    $source = $null
    foreach ($candidate in $Candidates) {
        if (-not (Test-Path -LiteralPath $candidate)) { continue }
        try {
            $probe = [System.Drawing.Bitmap]::FromFile($candidate)
            $ok = $probe.Width -le $MaxSourceWidth
            $probe.Dispose()
        } catch { continue }
        if ($ok) { $source = $candidate; break }
        if (-not $source) { $source = $candidate }
    }
    if (-not $source) { Write-Warning "$Family sheet not found, skipped: $($Candidates -join ' / ')"; return }

    $raw = [System.Drawing.Bitmap]::FromFile($source)
    $workW = $SheetWorkWidth
    $workH = [int][math]::Floor($raw.Height * ($workW / $raw.Width))
    $work = New-Object System.Drawing.Bitmap($workW, $workH, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $g = [System.Drawing.Graphics]::FromImage($work)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.DrawImage($raw, 0, 0, $workW, $workH)
    $g.Dispose(); $raw.Dispose()
    Write-Host "$Family : $source"
    Write-Host "          $workW x $workH working copy"

    $bits = $work.LockBits((New-Object System.Drawing.Rectangle(0, 0, $workW, $workH)), [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $stride = [math]::Abs($bits.Stride)
    $buf = [byte[]]::new($stride * $workH)
    [System.Runtime.InteropServices.Marshal]::Copy($bits.Scan0, $buf, 0, $buf.Length)
    $work.UnlockBits($bits)

    $thr = 244
    $down = 4
    $mw = [int][math]::Floor($workW / $down)
    $mh = [int][math]::Floor($workH / $down)
    $mask = [byte[]]::new($mw * $mh)
    for ($y = 0; $y -lt $workH; $y++) {
        $base = $y * $stride
        # [int] would ROUND here (1151/4 -> 288, one cell past the end); floor is meant.
        $my = [int][math]::Floor($y / $down) * $mw
        for ($x = 0; $x -lt $workW; $x++) {
            $i = $base + $x * 3
            if ($buf[$i] -lt $thr -or $buf[$i + 1] -lt $thr -or $buf[$i + 2] -lt $thr) { $mask[$my + [int][math]::Floor($x / $down)] = 1 }
        }
    }

    # NEVER name this array after a [string] parameter: PowerShell is case-insensitive and a typed
# parameter silently coerces an int[] assignment into the array's type NAME, so the scan below
# walks nothing and reports zero drawings without a single error.
    $labels = [int[]]::new($mw * $mh)
    $stack = New-Object 'System.Collections.Generic.Stack[int]'
    $boxes = @()
    $next = 1
    if ($Diagnose) {
        $inkCells = 0
        foreach ($cell in $mask) { if ($cell -eq 1) { $inkCells++ } }
        Write-Host "          [diag] buffer $($buf.Length) B, mask $($mask.Length) cells, inked cells $inkCells"
        Write-Host "          [diag] first pixels: $($buf[0]),$($buf[1]),$($buf[2]) / mid $($buf[[int]($buf.Length / 2)])"
    }
    for ($p = 0; $p -lt $mask.Length; $p++) {
        if ($mask[$p] -eq 0 -or $labels[$p] -ne 0) { continue }
        $stack.Clear(); $stack.Push($p); $labels[$p] = $next
        $minX = $mw; $maxX = 0; $minY = $mh; $maxY = 0; $area = 0
        while ($stack.Count -gt 0) {
            $q = $stack.Pop(); $area++
            $qx = $q % $mw; $qy = [int](($q - $qx) / $mw)
            if ($qx -lt $minX) { $minX = $qx }
            if ($qx -gt $maxX) { $maxX = $qx }
            if ($qy -lt $minY) { $minY = $qy }
            if ($qy -gt $maxY) { $maxY = $qy }
            for ($dy = -1; $dy -le 1; $dy++) {
                $ny = $qy + $dy; if ($ny -lt 0 -or $ny -ge $mh) { continue }
                for ($dx = -1; $dx -le 1; $dx++) {
                    $nx = $qx + $dx; if ($nx -lt 0 -or $nx -ge $mw) { continue }
                    $n = $ny * $mw + $nx
                    if ($mask[$n] -eq 1 -and $labels[$n] -eq 0) { $labels[$n] = $next; $stack.Push($n) }
                }
            }
        }
        $boxes += , @{ MinX = $minX; MaxX = $maxX; MinY = $minY; MaxY = $maxY; Area = $area }
        $next++
    }

    # a drawing fills its own box; the sheet's thin frame does not
    $minPoseArea = 2000
    $thinFill = 0.2
    $isThin = { param($b) ($b.Area / (($b.MaxX - $b.MinX + 1) * ($b.MaxY - $b.MinY + 1))) -lt $thinFill }

    $found = @($boxes | Where-Object { $_.Area -ge $minPoseArea -and -not (& $isThin $_) } | Sort-Object -Property Area -Descending)
    $reachCells = ($workW / $down) * 0.25
    $attached = 0
    foreach ($speck in @($boxes | Where-Object { $_.Area -lt $minPoseArea -and -not (& $isThin $_) })) {
        $scx = ($speck.MinX + $speck.MaxX) / 2
        $scy = ($speck.MinY + $speck.MaxY) / 2
        $best = -1; $bestDist = [double]::MaxValue
        for ($i = 0; $i -lt $found.Count; $i++) {
            $pcx = ($found[$i].MinX + $found[$i].MaxX) / 2
            $pcy = ($found[$i].MinY + $found[$i].MaxY) / 2
            $d = [math]::Sqrt([math]::Pow($scx - $pcx, 2) + [math]::Pow($scy - $pcy, 2))
            if ($d -lt $bestDist) { $bestDist = $d; $best = $i }
        }
        if ($best -ge 0 -and $bestDist -le $reachCells) {
            $found[$best] = @{
                MinX = [math]::Min($found[$best].MinX, $speck.MinX); MaxX = [math]::Max($found[$best].MaxX, $speck.MaxX)
                MinY = [math]::Min($found[$best].MinY, $speck.MinY); MaxY = [math]::Max($found[$best].MaxY, $speck.MaxY)
                Area = $found[$best].Area
            }
            $attached++
        }
    }
    Write-Host "          poses: $($found.Count) (specks attached: $attached), expected $($Poses.Count)"

    # rows: a new row starts wherever the vertical gap between centres is a large fraction of the
    # typical pose height (the sheets are two and three rows deep, and neither is evenly spaced)
    $byY = @($found | Sort-Object { ($_.MinY + $_.MaxY) / 2 })
    $heights = @($byY | ForEach-Object { $_.MaxY - $_.MinY + 1 } | Sort-Object)
    $medianH = $heights[[int][math]::Floor($heights.Count / 2)]
    $rows = @()
    $current = @()
    for ($i = 0; $i -lt $byY.Count; $i++) {
        if ($i -gt 0) {
            $gap = (($byY[$i].MinY + $byY[$i].MaxY) / 2) - (($byY[$i - 1].MinY + $byY[$i - 1].MaxY) / 2)
            if ($gap -gt 0.55 * $medianH) { $rows += , @($current); $current = @() }
        }
        $current += $byY[$i]
    }
    if ($current.Count -gt 0) { $rows += , @($current) }
    Write-Host "          rows: $($rows.Count) -> $(($rows | ForEach-Object { $_.Count }) -join '+')"

    $ordered = @()
    foreach ($row in $rows) { $ordered += @($row | Sort-Object { ($_.MinX + $_.MaxX) / 2 }) }

    $keyLow = [System.Drawing.Color]::FromArgb(255, 241, 241, 241)
    $keyHigh = [System.Drawing.Color]::FromArgb(255, 255, 255, 255)

    for ($i = 0; $i -lt [math]::Min($ordered.Count, $Poses.Count); $i++) {
        $box = $ordered[$i]
        $m = $Poses[$i]

        $bx0 = $box.MinX * $down; $bx1 = ($box.MaxX + 1) * $down - 1
        $by0 = $box.MinY * $down; $by1 = ($box.MaxY + 1) * $down - 1
        $bw = $bx1 - $bx0 + 1; $bh = $by1 - $by0 + 1

        # Fit the pose into the square canvas at its own aspect ratio with an even margin: nothing
        # outside this pose's own box is ever read, so a neighbouring pose cannot leak in.
        $margin = 0.05
        $fit = $MoodSize * (1 - 2 * $margin)
        $scale = $fit / [math]::Max($bw, $bh)
        $dw = [int][math]::Round($bw * $scale)
        $dh = [int][math]::Round($bh * $scale)
        $dx = [int](($MoodSize - $dw) / 2)
        $dy = [int](($MoodSize - $dh) / 2)

        $out = New-Object System.Drawing.Bitmap($MoodSize, $MoodSize, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $og = [System.Drawing.Graphics]::FromImage($out)
        $og.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $og.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $og.Clear([System.Drawing.Color]::Transparent)
        $attr = New-Object System.Drawing.Imaging.ImageAttributes
        $attr.SetColorKey($keyLow, $keyHigh)
        $og.DrawImage($work, (New-Object System.Drawing.Rectangle($dx, $dy, $dw, $dh)), $bx0, $by0, $bw, $bh, [System.Drawing.GraphicsUnit]::Pixel, $attr)
        $og.Dispose(); $attr.Dispose()

        $file = Join-Path $AssetDir "$Prefix-$($m.Name).png"
        $out.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
        $out.Dispose()
        Write-Host "          $Prefix-$($m.Name).png   pose $($bw)x$($bh) at $bx0,$by0 -> ${dw}x${dh}"
    }
    $work.Dispose()
}

# The normal outfit: nine faces, reading order.
$normalPoses = @(
    @{ Name = "idle" },      # standing, hand on the sword, attentive
    @{ Name = "shy" },       # hand to chest, blushing
    @{ Name = "composed" },  # sword out, level look
    @{ Name = "happy" },     # waving, open smile
    @{ Name = "thinking" },  # hand on the chin
    @{ Name = "panic" },     # sweating, about to cry
    @{ Name = "calm" },      # kneeling, content
    @{ Name = "ready" },     # sword raised, confident smile
    @{ Name = "sleepy" }     # sitting with legs out, eyes closed
)
Export-Poses -Family "normal" -Candidates @($NormalSheet, $NormalSheetFallback) -Prefix "kohane-q" -Poses $normalPoses

# 卍解: six faces, reading order.
$ultraPoses = @(
    @{ Name = "bankai" },    # mid-swing with the odachi, flame aura
    @{ Name = "calm" },      # sitting, eyes closed
    @{ Name = "happy" },     # sword raised, smiling
    @{ Name = "panic" },     # hands on cheeks, flustered
    @{ Name = "sleepy" },    # rubbing an eye, a flame in the other hand
    @{ Name = "pout" }       # arms crossed, a sigh cloud
)
Export-Poses -Family "ultra " -Candidates @($UltraSheet, $UltraSheetFallback) -Prefix "kohane-ultra-q" -Poses $ultraPoses
