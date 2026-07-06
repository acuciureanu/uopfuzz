# run-sandboxed.ps1
# Run uopfuzz inside the security-hardened container.
#
# Usage:
#   .\run-sandboxed.ps1 versions --library handlebars.js --last 5
#   .\run-sandboxed.ps1 mass --top 20
#   .\run-sandboxed.ps1 --target lodash@4.17.20

param(
    [switch]$Init,
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$CliArgs
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Seccomp   = Join-Path $ScriptDir '.devcontainer\seccomp.json'
$Image     = 'uopfuzz-sandbox'

# Ensure the image exists
$imageExists = docker image inspect $Image 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[uopfuzz] Building sandbox image..."
    docker build -t $Image (Join-Path $ScriptDir '.devcontainer')
}

# Named volumes persist node_modules and results across runs
docker volume create uopfuzz-node-modules 2>$null | Out-Null
docker volume create uopfuzz-results      2>$null | Out-Null

# Base mount args reused everywhere
$sourceMount = "type=bind,source=$ScriptDir,target=/workspace,readonly"
$sharedArgs  = @(
    '--rm',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges:true',
    "--security-opt=seccomp=$Seccomp",
    '--memory=3g', '--memory-swap=3g',
    '--cpus=2',
    '--pids-limit=512',
    '-e', 'UOPFUZZ_CONTAINER=1',
    '--mount', $sourceMount,
    '-v', 'uopfuzz-node-modules:/workspace/node_modules',
    '-v', 'uopfuzz-results:/workspace/results',
    $Image
)

# -Init: run npm install inside the container against the named volume.
# Required once after first build, or after package.json changes.
if ($Init) {
    Write-Host "[uopfuzz] Running npm install inside container..."
    docker run --rm `
        --mount $sourceMount `
        -v uopfuzz-node-modules:/workspace/node_modules `
        -v uopfuzz-results:/workspace/results `
        --user root `
        --entrypoint sh `
        $Image `
        -c "chown -R node:node /workspace/node_modules /workspace/results && su node -c 'cd /workspace && npm install --cache /home/node/.npm --no-package-lock'"
    Write-Host "[uopfuzz] Done. You can now run .\run-sandboxed.ps1 <args>"
    exit 0
}

# Auto-detect if node_modules is missing the fuzzer's own deps
$hasDeps = docker run --rm `
    --mount $sourceMount `
    -v uopfuzz-node-modules:/workspace/node_modules `
    $Image `
    -e "process.exit(require('fs').existsSync('/workspace/node_modules/commander') ? 0 : 1)" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[uopfuzz] node_modules not initialised - running npm install first..."
    docker run --rm `
        --mount $sourceMount `
        -v uopfuzz-node-modules:/workspace/node_modules `
        -v uopfuzz-results:/workspace/results `
        --user root `
        --entrypoint sh `
        $Image `
        -c "chown -R node:node /workspace/node_modules /workspace/results && su node -c 'cd /workspace && npm install --cache /home/node/.npm --no-package-lock'"
    Write-Host "[uopfuzz] Ready."
    Write-Host ""
}

Write-Host "[uopfuzz] Starting sandboxed run: node src/cli.js $CliArgs"
Write-Host "[uopfuzz] Security: cap-drop=ALL, seccomp, no-new-privileges, memory=3g, pids=512"
Write-Host ""

# Use -it when running interactively, -i only when piped
$interactive = if ([Console]::IsInputRedirected) { '-i' } else { '-it' }
docker run --rm $interactive @sharedArgs src/cli.js @CliArgs
