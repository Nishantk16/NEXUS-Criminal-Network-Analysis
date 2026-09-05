$ErrorActionPreference = 'Stop'
Write-Host 'NEXUS environment check' -ForegroundColor Yellow
python --version
python -c "import spacy,networkx,pandas,sklearn,fastapi,uvicorn,reportlab; print('core imports: OK'); print('spaCy', spacy.__version__)"
python -m spacy validate
