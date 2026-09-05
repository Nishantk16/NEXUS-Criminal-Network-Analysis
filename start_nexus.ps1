$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "=== NEXUS Case Intelligence ===" -ForegroundColor Yellow
Write-Host "PS-26189 | Local deployment launcher" -ForegroundColor DarkGray

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Creating Python virtual environment..." -ForegroundColor Cyan
    python -m venv .venv
}

& "$Root\.venv\Scripts\Activate.ps1"
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt

$spaCyModel = & python -c "import spacy; print('ok' if spacy.util.is_package('en_core_web_sm') else 'missing')"
if ($spaCyModel -eq "missing") {
    Write-Host "Installing spaCy English model..." -ForegroundColor Cyan
    python -m spacy download en_core_web_sm
}

try {
    docker version | Out-Null
    Write-Host "Starting Neo4j..." -ForegroundColor Cyan
    docker compose -f infra\neo4j\docker-compose.yml up -d
    Write-Host "Neo4j: http://127.0.0.1:7474 | Bolt: bolt://127.0.0.1:7687" -ForegroundColor Green
} catch {
    Write-Host "Docker is unavailable. Continuing without Neo4j; NetworkX remains the live graph engine." -ForegroundColor Yellow
}

Write-Host "Starting NEXUS API on http://127.0.0.1:8000 ..." -ForegroundColor Cyan
Write-Host "Keep this terminal open. Frontend: http://127.0.0.1:3002/frontend/dashboard.html" -ForegroundColor Green
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
