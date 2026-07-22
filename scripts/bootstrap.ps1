[CmdletBinding()]
param(
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

function New-HexSecret([int]$byteCount) {
    $bytes = [byte[]]::new($byteCount)
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    return -join ($bytes | ForEach-Object { $_.ToString("x2") })
}

$createdEnvironment = $false
$adminPassword = $null
if (-not (Test-Path -LiteralPath ".env")) {
    $createdEnvironment = $true
    $adminPassword = New-HexSecret 16
    $content = [IO.File]::ReadAllText((Join-Path $projectRoot ".env.example"))
    $content = $content.Replace("CHANGE_ME_RANDOM_DATABASE_PASSWORD", (New-HexSecret 24))
    $content = $content.Replace("CHANGE_ME_RANDOM_64_CHAR_SECRET", (New-HexSecret 48))
    $content = $content.Replace("CHANGE_ME_DIFFERENT_RANDOM_64_CHAR_SECRET", (New-HexSecret 48))
    $content = $content.Replace("CHANGE_ME_RANDOM_ADMIN_PASSWORD", $adminPassword)
    [IO.File]::WriteAllText((Join-Path $projectRoot ".env"), $content, [Text.UTF8Encoding]::new($false))
    Write-Host "Fichier .env sécurisé créé." -ForegroundColor Green
}

docker compose config --quiet
if ($LASTEXITCODE -ne 0) { throw "Configuration Docker Compose invalide." }

$arguments = @("compose", "up", "-d", "--wait", "--wait-timeout", "1800")
if (-not $NoBuild) { $arguments += "--build" }
& docker @arguments
if ($LASTEXITCODE -ne 0) { throw "Le démarrage Docker a échoué. Consultez: docker compose logs" }

$portLine = Get-Content -LiteralPath ".env" | Where-Object { $_ -match '^HTTP_PORT=' } | Select-Object -First 1
$port = if ($portLine) { ($portLine -split '=', 2)[1].Trim() } else { "8787" }
$ready = Invoke-RestMethod -Uri "http://127.0.0.1:$port/health/ready" -TimeoutSec 15
if ($ready.status -ne "ok") { throw "L'application répond mais ses dépendances ne sont pas prêtes." }

Write-Host ""
Write-Host "MICEPP Scanner est opérationnel: http://127.0.0.1:$port" -ForegroundColor Green
Write-Host "Utilisateur initial: admin"
if ($createdEnvironment) {
    Write-Host "Mot de passe initial: $adminPassword" -ForegroundColor Yellow
    Write-Host "Conservez-le dans un coffre puis créez les comptes nominatifs."
} else {
    Write-Host "Le fichier .env existant a été conservé; utilisez son mot de passe administrateur."
}
