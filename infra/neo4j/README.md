# Optional Neo4j Development Service

This service is an optional next-stage graph database for NEXUS.

Start it with Docker:

```powershell
docker compose -f infra/neo4j/docker-compose.yml up -d
```

Then set these environment variables for the backend:

```text
NEO4J_URI=bolt://127.0.0.1:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=nexus_dev_password
```

The API exposes:

- `GET /neo4j/status`
- `POST /neo4j/sync`
- `GET /neo4j/graph`

The existing NetworkX pipeline remains the primary source for the current prototype; Neo4j is an optional persistence/query layer until the integration is enabled and tested.

## One-command local deployment
From the project root in PowerShell:

```powershell
.\start_nexus.ps1
```

The launcher creates/uses `.venv`, installs dependencies, installs the spaCy model when missing, starts Neo4j when Docker is available, then starts FastAPI.

Neo4j can be checked at `http://127.0.0.1:7474`. The API exposes `/neo4j/status` and `/neo4j/sync` for the authenticated investigator/admin session.
