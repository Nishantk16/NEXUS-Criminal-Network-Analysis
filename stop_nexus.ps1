$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
try { docker compose -f infra\neo4j\docker-compose.yml down } catch {}
Write-Host "NEXUS Neo4j service stopped. Stop the API terminal with Ctrl+C if it is still running." -ForegroundColor Yellow
