# Build the KohaneStation shell from the command line.
#
# Why VS's MSBuild and not `dotnet build`: the WindowsAppSDK XAML targets choose the net472
# XamlCompiler *executable* when the MSBuild runtime is Core (`dotnet`), and that executable's
# assembly binding redirects do not match the assemblies it ships - it fails during assembly load
# and prints nothing, so MSBuild only reports "MSB3073 ... exited with code 1". With the .NET
# Framework MSBuild that ships with Visual Studio the targets use the in-process compiler task
# instead, whose dependencies come from MSBuild itself, and the build succeeds. Details and the
# reproduction recipe are in README.md.
param(
    [string]$Configuration = "Debug",
    [string]$Platform = "x64",
    [switch]$Rebuild
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$project = Join-Path $here "src\KohaneStation\KohaneStation.csproj"

function Find-MSBuild {
    # 1. an explicit override always wins
    if ($env:KOHANE_MSBUILD -and (Test-Path $env:KOHANE_MSBUILD)) { return $env:KOHANE_MSBUILD }

    # 2. the toolchain verified on this machine: Visual Studio 2022 (17.x) ships a .NET Framework
    #    MSBuild, which is what the WindowsAppSDK XAML targets need (see README). Visual Studio 18
    #    (2026) was tried and fails elsewhere - its MrtCore PRI generator task is missing
    #    (MSB4062 in MrtCore.PriGen.targets), which is a different problem with the same symptom.
    $verified = @(
        "E:\VSPnEBs\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    )
    foreach ($c in $verified) { if (Test-Path $c) { return $c } }

    # 3. anything vswhere knows about, preferring a 17.x product line
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $all = & $vswhere -all -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" 2>$null
        foreach ($candidate in $all) {
            if (-not (Test-Path $candidate)) { continue }
            $version = (& $candidate -version -nologo 2>$null | Select-Object -First 1)
            if ($version -like "17.*") { return $candidate }
        }
        $first = $all | Select-Object -First 1
        if ($first -and (Test-Path $first)) { return $first }
    }
    return $null
}

$msbuild = Find-MSBuild
if (-not $msbuild) {
    Write-Error "MSBuild.exe from Visual Studio was not found. Install the .NET desktop workload, or run the build from the Visual Studio IDE."
}

Write-Host "MSBuild : $msbuild"
Write-Host "Project : $project"
Write-Host "Config  : $Configuration / $Platform$(if ($Rebuild) { ' (rebuild)' })"

$args = @($project, "/p:Configuration=$Configuration", "/p:Platform=$Platform", "/v:m", "/nologo")
if ($Rebuild) { $args += "/t:Rebuild" }

& $msbuild @args
$code = $LASTEXITCODE
if ($code -ne 0) {
    Write-Host ""
    Write-Host "build failed (exit $code). Two known shapes on this machine:"
    Write-Host "  * MSB3073 ... net472\XamlCompiler.exe exited with code 1"
    Write-Host "    -> the builder is a .NET (Core) MSBuild; it is forced onto the net472 compiler shim"
    Write-Host "       whose assembly bindings do not match its own DLLs. Use the VS 2022 MSBuild."
    Write-Host "  * MSB4062 ... MrtCore.PriGen.targets (missing task assembly)"
    Write-Host "    -> that Visual Studio install is missing its PRI generator; try another install,"
    Write-Host "       or set KOHANE_MSBUILD to the MSBuild.exe that works."
    Write-Error "build failed with exit code $code"
}

$out = Join-Path $here "src\KohaneStation\bin\$Platform\$Configuration\net8.0-windows10.0.19041.0\win-x64\KohaneStation.exe"
if (Test-Path $out) {
    Write-Host ""
    Write-Host "built : $out"
    Write-Host "run   : start the engine bridge first (engine-bridge\server.mjs), then launch it"
} else {
    Write-Warning "build reported success but $out is missing"
}
