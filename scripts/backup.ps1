[CmdletBinding()]
param(
    [string]$Destination = (Join-Path (Split-Path -Parent $PSScriptRoot) "backups")
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
if (-not (Test-Path -LiteralPath ".env")) { throw "Le fichier .env est requis." }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupPath = Join-Path ([IO.Path]::GetFullPath($Destination)) $stamp
New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

$databaseId = (docker compose ps -q database).Trim()
$apiId = (docker compose ps -q api).Trim()
if (-not $databaseId -or -not $apiId) { throw "Les services database et api doivent être démarrés." }

docker compose exec -T database sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -f /tmp/micepp.dump'
if ($LASTEXITCODE -ne 0) { throw "La sauvegarde PostgreSQL a échoué." }
docker cp "${databaseId}:/tmp/micepp.dump" (Join-Path $backupPath "database.dump")
docker compose exec -T database rm -f /tmp/micepp.dump

docker run --rm --volumes-from $apiId --mount "type=bind,source=$backupPath,target=/backup" alpine:3.21 sh -c 'tar -czf /backup/evidence.tar.gz -C /evidence . && tar -czf /backup/reports.tar.gz -C /reports . && tar -czf /backup/models.tar.gz -C /models .'
if ($LASTEXITCODE -ne 0) { throw "La sauvegarde des volumes a échoué." }

$manifest = Get-ChildItem -LiteralPath $backupPath -File | ForEach-Object {
    $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
    "$($hash.Hash.ToLowerInvariant())  $($_.Name)"
}
[IO.File]::WriteAllLines((Join-Path $backupPath "SHA256SUMS"), $manifest, [Text.UTF8Encoding]::new($false))
Write-Host "Sauvegarde complète créée: $backupPath" -ForegroundColor Green

