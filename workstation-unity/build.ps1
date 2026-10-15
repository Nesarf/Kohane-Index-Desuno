param(
  [string]$Unity = "",
  [string]$Project = (Join-Path $PSScriptRoot "."),
  [string]$Out = (Join-Path $PSScriptRoot "build\kohane-waterfall.exe"),
  [string]$Log = (Join-Path $PSScriptRoot "build\unity-build.log")
)

# A batch build is the only way to check this without a human clicking Play, so it is the acceptance
# step: if Unity builds it, the scripts compile and the project is coherent.
$ErrorActionPreference = "Stop"

if (-not $Unity) {
  foreach ($candidate in @("E:\Unity\Editor\Unity.exe", "C:\Program Files\Unity\Hub\Editor\*\Editor\Unity.exe")) {
    $found = Get-Item $candidate -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $Unity = $found.FullName; break }
  }
}
if (-not $Unity -or -not (Test-Path $Unity)) { throw "Unity.exe not found; pass -Unity <path>" }

$projectPath = (Resolve-Path $Project).Path
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null

Write-Host "unity   : $Unity"
Write-Host "project : $projectPath"
Write-Host "out     : $Out"

$args = @(
  "-batchmode", "-quit",
  "-projectPath", $projectPath,
  "-buildWindows64Player", $Out,
  "-logFile", $Log
)
& $Unity @args
$code = $LASTEXITCODE
if ($code -ne 0) {
  Write-Host "build failed (exit $code) - last lines of the log:"
  if (Test-Path $Log) { Get-Content $Log -Tail 30 }
  exit $code
}
Write-Host "built: $Out"
