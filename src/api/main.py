"""
FastAPI Backend — Criminal Network Analysis System

Exposes the NLP + graph analytics pipeline as REST endpoints
for a frontend dashboard to consume.

Run with:
    python -m uvicorn src.api.main:app --reload --port 8000
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Allow imports from src/nlp and src/graph
sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Depends, HTTPException, Header, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
import networkx as nx

from nlp.entity_extractor import process_fir_file
from nlp.multilingual import language_profile
from graph.advanced_analytics import (
    compute_network_summary,
    compute_person_network_insights,
    shortest_path,
)
from graph.build_graph import (
    build_graph_from_fir_data,
    build_graph_from_cdr,
    build_graph_from_transactions,
    compute_key_influencers,
    detect_communities,
    detect_suspicious_transaction_pattern,
    compute_risk_scores,
)
from api.auth import verify_credentials, create_token, verify_token
from api.security import check_rate_limit, require_role
from api.report import generate_case_report
from api.redaction import redact_name, redact_text, is_complainant
from graph.geodata import LOCATION_COORDS
from graph.ml_anomaly import detect_ml_transaction_anomalies
from api.ai_investigator import answer_question
from graph.neo4j_store import Neo4jStore
from graph.explainability import explain_person
from blockchain.evidence import sha256_bytes, verify_bytes
from api.case_api import router as case_router


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
REALTIME_FILE = DATA_DIR / "realtime_events.json"


# ---------------------------------------------------------------------------
# Real-time event helpers
# ---------------------------------------------------------------------------

def _load_realtime_events() -> list[dict]:
    if not REALTIME_FILE.exists():
        return []

    try:
        with REALTIME_FILE.open(encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _save_realtime_events(events: list[dict]) -> None:
    REALTIME_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = REALTIME_FILE.with_suffix(".tmp")

    with tmp.open("w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    tmp.replace(REALTIME_FILE)


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI-Powered Criminal Network Analysis System",
    description=(
        "NCRB Problem Statement 26189 — Entity extraction, "
        "network graph analytics, anomaly detection, and evidence integrity API"
    ),
    version="0.1.0",
)


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3002",
        "http://127.0.0.1:3002",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://nexus-criminal-network.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dynamic case intake / investigation workflow
app.include_router(case_router)

# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def _build_full_graph() -> nx.MultiDiGraph:
    """Build the current investigation graph from source data files."""
    G = nx.MultiDiGraph()

    build_graph_from_fir_data(
        G,
        DATA_DIR / "extracted_entities.json",
    )
    build_graph_from_cdr(
        G,
        DATA_DIR / "sample_cdr.csv",
    )
    build_graph_from_transactions(
        G,
        DATA_DIR / "sample_transactions.csv",
    )

    return G


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


def require_auth(authorization: str = Header(None)) -> dict:
    """Require a valid bearer token issued by /login."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail=(
                "Missing or malformed Authorization header. "
                "Log in via /login first."
            ),
        )

    token = authorization.removeprefix("Bearer ").strip()
    payload = verify_token(token)

    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired session. Please log in again.",
        )

    return payload


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@app.post("/login")
def login(body: LoginRequest, request: Request):
    """Authenticate an investigator and issue a signed, time-limited token."""
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"login:{client_ip}", limit=10)

    user = verify_credentials(body.username, body.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password.",
        )

    token = create_token(user["username"], user["role"])

    try:
        from blockchain.audit_log import add_evidence_block

        add_evidence_block(
            "USER_LOGIN",
            {
                "username": user["username"],
                "role": user["role"],
            },
        )
    except Exception:
        # Audit logging should never block a legitimate login.
        pass

    return {
        "token": token,
        "username": user["username"],
        "role": user["role"],
        "full_name": user["full_name"],
    }


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

@app.get("/security/status")
def security_status(
    user: dict = Depends(require_role("admin", "investigator")),
):
    return {
        "authentication": "enabled",
        "role_based_access": "enabled",
        "rate_limiting": "enabled",
        "cors": "restricted-local-dev",
        "password_hashing": "PBKDF2-HMAC-SHA256",
        "token_integrity": "HMAC-SHA256 + expiry",
        "audit_logging": "enabled",
        "evidence_integrity": "SHA-256 hash chain",
    }


# ---------------------------------------------------------------------------
# Real-time events
# ---------------------------------------------------------------------------

@app.get("/realtime/events")
def realtime_events(
    limit: int = 20,
    user: dict = Depends(require_auth),
):
    limit = max(1, min(limit, 100))
    events = _load_realtime_events()
    events.sort(
        key=lambda e: e.get("timestamp", ""),
        reverse=True,
    )

    return {
        "events": events[:limit],
        "count": len(events),
        "mode": "demo_polling",
    }


@app.post("/realtime/events")
def ingest_realtime_event(
    event: dict,
    user: dict = Depends(require_role("admin", "investigator")),
):
    allowed = {
        "type",
        "entity",
        "message",
        "source",
        "severity",
        "metadata",
    }

    clean = {
        key: event[key]
        for key in event
        if key in allowed
    }

    if not clean.get("type") or not clean.get("message"):
        raise HTTPException(
            status_code=400,
            detail="type and message are required.",
        )

    clean["timestamp"] = datetime.now(timezone.utc).isoformat()
    clean["submitted_by"] = user.get("username", "unknown")

    events = _load_realtime_events()
    events.append(clean)
    _save_realtime_events(events[-500:])

    return {
        "status": "accepted",
        "event": clean,
    }


# ---------------------------------------------------------------------------
# Health / root
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "nexus-api",
        "problem_statement_id": 26189,
    }


@app.get("/")
def root():
    return {
        "system": "AI-Powered Criminal Network Analysis System",
        "problem_statement_id": 26189,
        "endpoints": [
            "/entities",
            "/graph",
            "/influencers",
            "/communities",
            "/alerts",
            "/risk-scores",
            "/ml-anomalies",
            "/ai-investigator",
            "/explain/{name}",
            "/neo4j/status",
            "/neo4j/sync",
            "/neo4j/graph",
            "/timeline",
            "/heatmap",
            "/audit-chain",
        ],
    }


# ---------------------------------------------------------------------------
# AI Investigator
# ---------------------------------------------------------------------------

@app.post("/ai-investigator")
def ai_investigator(
    payload: dict,
    user: dict = Depends(require_role("admin", "investigator")),
):
    """Answer grounded investigator questions from current graph + FIR data."""
    question = str(payload.get("question", "")).strip()

    if not question:
        raise HTTPException(
            status_code=400,
            detail="question is required",
        )

    G = _build_full_graph()
    fir_reports = process_fir_file(
        str(DATA_DIR / "sample_fir_reports.txt")
    )
    risk_scores = compute_risk_scores(
        G,
        DATA_DIR / "extracted_entities.json",
        DATA_DIR / "sample_transactions.csv",
    )

    return answer_question(
        question,
        G,
        fir_reports,
        risk_scores,
    )


# ---------------------------------------------------------------------------
# Neo4j integration
# ---------------------------------------------------------------------------

_NEO4J = Neo4jStore()


def _neo4j_graph_counts() -> dict[str, int]:
    """Return live node and relationship counts from Neo4j."""
    _NEO4J._ensure_driver()

    with _NEO4J.driver.session() as session:
        node_result = session.run(
            "MATCH (n:Entity) RETURN count(n) AS count"
        ).single()
        relationship_result = session.run(
            "MATCH ()-[r:RELATED_TO]->() RETURN count(r) AS count"
        ).single()

    return {
        "nodes": int(node_result["count"]) if node_result else 0,
        "relationships": int(relationship_result["count"])
        if relationship_result
        else 0,
    }


@app.get("/neo4j/status")
def neo4j_status(
    user: dict = Depends(require_role("admin", "investigator")),
):
    """
    Return live Neo4j connection status plus graph counts.
    This endpoint is intended for the dashboard status indicator.
    """
    try:
        connection = _NEO4J.verify_connection()
        counts = _neo4j_graph_counts()

        return {
            "connected": True,
            "uri": connection.get("uri"),
            "server_time": connection.get("server_time"),
            "database": os.getenv("NEO4J_DATABASE", "neo4j"),
            "nodes": counts["nodes"],
            "relationships": counts["relationships"],
            "status": "CONNECTED",
        }

    except Exception as exc:
        return {
            "connected": False,
            "status": "OFFLINE",
            "error": str(exc),
            "uri": getattr(
                _NEO4J,
                "uri",
                os.getenv(
                    "NEO4J_URI",
                    "bolt://127.0.0.1:7687",
                ),
            ),
            "database": os.getenv("NEO4J_DATABASE", "neo4j"),
            "nodes": 0,
            "relationships": 0,
        }


@app.post("/neo4j/sync")
def neo4j_sync(
    user: dict = Depends(require_role("admin", "investigator")),
):
    """Synchronize the current NetworkX graph into Neo4j."""
    try:
        G = _build_full_graph()
        result = _NEO4J.sync_networkx_graph(G)

        return {
            "status": "synced",
            "nodes": result["nodes"],
            "edges": result["edges"],
            "neo4j": _neo4j_graph_counts(),
        }

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Neo4j sync failed: {exc}",
        ) from exc


@app.get("/neo4j/graph")
def neo4j_graph(
    user: dict = Depends(require_auth),
):
    """Return the graph currently stored in Neo4j."""
    try:
        return _NEO4J.fetch_network()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Neo4j graph unavailable: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# Multilingual NLP
# ---------------------------------------------------------------------------

@app.post("/multilingual/analyze")
def multilingual_analyze(
    payload: dict,
    user: dict = Depends(require_auth),
):
    text = str(payload.get("text", "")).strip()

    if not text:
        raise HTTPException(
            status_code=400,
            detail="text is required",
        )

    profile = language_profile(text)

    return {
        "profile": profile,
        "next_step": (
            "Use language-aware extraction pipeline for supported language."
        ),
        "mode": "script_detection_and_cue_routing",
    }


# ---------------------------------------------------------------------------
# Entities / graph analytics
# ---------------------------------------------------------------------------

@app.get("/entities")
def get_entities(
    redact: bool = True,
    user: dict = Depends(require_auth),
):
    reports = process_fir_file(
        str(DATA_DIR / "sample_fir_reports.txt")
    )

    if redact:
        for report in reports:
            report["raw_text"] = redact_text(
                report["raw_text"],
                True,
            )
            report["entities"]["persons"] = [
                redact_name(person, True)
                for person in report["entities"]["persons"]
            ]

    return reports


@app.get("/graph")
def get_graph(
    redact: bool = True,
    user: dict = Depends(require_auth),
):
    G = _build_full_graph()

    nodes = [
        {
            "id": redact_name(n, redact),
            "type": data.get("type", "Unknown"),
        }
        for n, data in G.nodes(data=True)
    ]

    edges = [
        {
            "source": redact_name(u, redact),
            "target": redact_name(v, redact),
            "relation": data.get("relation", ""),
            "source_type": data.get("source_type", ""),
        }
        for u, v, data in G.edges(data=True)
    ]

    return {
        "nodes": nodes,
        "edges": edges,
    }


@app.get("/influencers")
def get_influencers(
    top_n: int = 5,
    user: dict = Depends(require_auth),
):
    G = _build_full_graph()
    return compute_key_influencers(
        G,
        top_n=top_n,
    )


@app.get("/communities")
def get_communities(
    user: dict = Depends(require_auth),
):
    G = _build_full_graph()
    return detect_communities(G)


@app.get("/alerts")
def get_alerts(
    user: dict = Depends(require_auth),
):
    return detect_suspicious_transaction_pattern(
        DATA_DIR / "sample_transactions.csv"
    )


@app.get("/risk-scores")
def get_risk_scores(
    redact: bool = True,
    user: dict = Depends(require_auth),
):
    G = _build_full_graph()

    scores = compute_risk_scores(
        G,
        DATA_DIR / "extracted_entities.json",
        DATA_DIR / "sample_transactions.csv",
    )

    for entry in scores:
        entry["name"] = redact_name(
            entry["name"],
            redact,
        )

    return scores


@app.get("/ml-anomalies")
def get_ml_anomalies(
    user: dict = Depends(require_auth),
):
    return detect_ml_transaction_anomalies(
        DATA_DIR / "sample_transactions.csv"
    )


@app.get("/advanced-analytics")
def advanced_analytics(
    user: dict = Depends(require_auth),
):
    G = _build_full_graph()

    return {
        "summary": compute_network_summary(G),
        "top_network_insights": compute_person_network_insights(
            G,
            top_n=10,
        ),
    }


@app.get("/shortest-path")
def get_shortest_path(
    source: str,
    target: str,
    user: dict = Depends(require_auth),
):
    G = _build_full_graph()
    result = shortest_path(G, source, target)

    return {
        "source": source,
        "target": target,
        **result,
    }


@app.get("/explain/{name}")
def explain_entity(
    name: str,
    user: dict = Depends(require_auth),
):
    G = _build_full_graph()

    result = explain_person(
        G,
        name,
        DATA_DIR / "extracted_entities.json",
        DATA_DIR / "sample_transactions.csv",
    )

    if "error" in result:
        raise HTTPException(
            status_code=404,
            detail=result["error"],
        )

    return result


# ---------------------------------------------------------------------------
# Evidence hashing / verification
# ---------------------------------------------------------------------------

@app.post("/evidence/hash")
async def hash_evidence(
    file: UploadFile = File(...),
    event_type: str = Form("EVIDENCE_REGISTERED"),
    user: dict = Depends(require_auth),
):
    data = await file.read()

    if not data:
        raise HTTPException(
            status_code=400,
            detail="Empty evidence file is not allowed.",
        )

    digest = sha256_bytes(data)

    from blockchain.audit_log import add_evidence_block

    block = add_evidence_block(
        event_type,
        {
            "evidence_filename": file.filename,
            "sha256": digest,
            "size_bytes": len(data),
            "uploaded_by": user.get(
                "username",
                "unknown",
            ),
        },
    )

    return {
        "filename": file.filename,
        "size_bytes": len(data),
        "sha256": digest,
        "integrity": "VERIFIED",
        "audit_block_index": block["index"],
        "blockchain_status": "SMART_CONTRACT_READY_NOT_DEPLOYED",
    }


@app.post("/evidence/verify")
async def verify_evidence(
    file: UploadFile = File(...),
    expected_sha256: str = Form(...),
    user: dict = Depends(require_auth),
):
    data = await file.read()

    if not data:
        raise HTTPException(
            status_code=400,
            detail="Empty evidence file is not allowed.",
        )

    return {
        "filename": file.filename,
        **verify_bytes(
            data,
            expected_sha256.strip().lower(),
        ),
    }


# ---------------------------------------------------------------------------
# Blockchain status / audit chain
# ---------------------------------------------------------------------------

@app.get("/blockchain/status")
def blockchain_status(
    user: dict = Depends(require_role("admin", "investigator")),
):
    return {
        "local_hash_chain": "enabled",
        "sha256_evidence_hashing": "enabled",
        "soroban_contract": "present_in_repository",
        "on_chain_deployment": "pending",
        "raw_sensitive_evidence_on_chain": False,
    }


@app.get("/audit-chain")
def get_audit_chain(
    user: dict = Depends(require_auth),
):
    chain_file = DATA_DIR / "audit_chain.json"

    if not chain_file.exists():
        return []

    with chain_file.open(encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

@app.get("/search")
def search_entities(
    q: str,
    redact: bool = True,
    user: dict = Depends(require_auth),
):
    G = _build_full_graph()
    q_lower = q.lower().strip()

    if not q_lower:
        return []

    matches = [
        {
            "id": redact_name(n, redact),
            "type": data.get("type", "Unknown"),
            "actual_name": n,
        }
        for n, data in G.nodes(data=True)
        if (
            q_lower in n.lower()
            or q_lower
            in redact_name(
                n,
                redact,
            ).lower()
        )
    ]

    return matches[:10]


# ---------------------------------------------------------------------------
# Entity detail
# ---------------------------------------------------------------------------

@app.get("/entity/{name}")
def get_entity_detail(
    name: str,
    redact: bool = True,
    user: dict = Depends(require_auth),
):
    return _build_entity_detail(
        name,
        redact=redact,
    )


def _build_entity_detail(
    name: str,
    redact: bool = True,
) -> dict:
    G = _build_full_graph()

    if name not in G.nodes:
        return {
            "error": (
                f"No entity named '{name}' "
                "found in the network."
            )
        }

    entity_type = G.nodes[name].get(
        "type",
        "Unknown",
    )

    # Direct connections
    connections = []
    seen = set()

    for u, v, data in G.edges(data=True):
        if u == name and v not in seen:
            connections.append(
                {
                    "name": redact_name(v, redact),
                    "relation": data.get("relation", ""),
                    "direction": "outgoing",
                }
            )
            seen.add(v)

        elif v == name and u not in seen:
            connections.append(
                {
                    "name": redact_name(u, redact),
                    "relation": data.get("relation", ""),
                    "direction": "incoming",
                }
            )
            seen.add(u)

    # FIR mentions
    fir_mentions = []

    for report in process_fir_file(
        str(DATA_DIR / "sample_fir_reports.txt")
    ):
        if (
            name in report["entities"]["persons"]
            or name in report["entities"]["locations"]
        ):
            fir_mentions.append(
                redact_text(
                    report["raw_text"],
                    redact,
                )
            )

    # CDR records
    call_records = []

    with open(
        DATA_DIR / "sample_cdr.csv",
        encoding="utf-8",
    ) as f:
        for row in csv.DictReader(f):
            if (
                row["caller_name"] == name
                or row["receiver_name"] == name
            ):
                other = (
                    row["receiver_name"]
                    if row["caller_name"] == name
                    else row["caller_name"]
                )

                call_records.append(
                    {
                        "with": redact_name(
                            other,
                            redact,
                        ),
                        "timestamp": row["timestamp"],
                        "duration_sec": row[
                            "duration_sec"
                        ],
                        "location": row[
                            "tower_location"
                        ],
                        "direction": (
                            "outgoing"
                            if row["caller_name"] == name
                            else "incoming"
                        ),
                    }
                )

    # Transactions
    transactions = []

    with open(
        DATA_DIR / "sample_transactions.csv",
        encoding="utf-8",
    ) as f:
        for row in csv.DictReader(f):
            if (
                row["sender_name"] == name
                or row["receiver_name"] == name
            ):
                other = (
                    row["receiver_name"]
                    if row["sender_name"] == name
                    else row["sender_name"]
                )

                transactions.append(
                    {
                        "with": redact_name(
                            other,
                            redact,
                        ),
                        "amount": row["amount"],
                        "timestamp": row["timestamp"],
                        "mode": row["mode"],
                        "direction": (
                            "sent"
                            if row["sender_name"] == name
                            else "received"
                        ),
                    }
                )

    # Centrality rank
    rank_info = None

    if entity_type == "Person":
        influencers = compute_key_influencers(
            G,
            top_n=100,
        )

        for i, person in enumerate(
            influencers,
            1,
        ):
            if person["name"] == name:
                rank_info = {
                    "rank": i,
                    **{
                        key: value
                        for key, value in person.items()
                        if key != "name"
                    },
                }
                break

    # Risk
    risk_info = None

    if entity_type == "Person":
        all_scores = compute_risk_scores(
            G,
            DATA_DIR / "extracted_entities.json",
            DATA_DIR / "sample_transactions.csv",
        )

        for entry in all_scores:
            if entry["name"] == name:
                risk_info = entry
                break

    return {
        "name": redact_name(name, redact),
        "type": entity_type,
        "is_complainant": is_complainant(name),
        "rank": rank_info,
        "risk": risk_info,
        "connections": connections,
        "fir_mentions": fir_mentions,
        "call_records": call_records,
        "transactions": transactions,
    }


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.get("/report/{name}")
def download_case_report(
    name: str,
    redact: bool = True,
    user: dict = Depends(require_auth),
):
    detail = _build_entity_detail(
        name,
        redact=redact,
    )

    if "error" in detail:
        raise HTTPException(
            status_code=404,
            detail=detail["error"],
        )

    chain_file = DATA_DIR / "audit_chain.json"

    audit_chain = (
        json.load(
            open(
                chain_file,
                encoding="utf-8",
            )
        )
        if chain_file.exists()
        else []
    )

    pdf_bytes = generate_case_report(
        detail,
        generated_by=user["sub"],
        audit_chain=audit_chain,
    )

    try:
        from blockchain.audit_log import add_evidence_block

        add_evidence_block(
            "REPORT_GENERATED",
            {
                "entity": name,
                "generated_by": user["sub"],
            },
        )
    except Exception:
        pass

    safe_filename = name.replace(" ", "_")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="case_report_{safe_filename}.pdf"'
            )
        },
    )


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

@app.get("/timeline")
def get_timeline(
    redact: bool = True,
    user: dict = Depends(require_auth),
):
    events = []
    date_pattern = re.compile(
        r"(\d{2})/(\d{2})/(\d{4})"
    )

    # FIR events
    for report in process_fir_file(
        str(DATA_DIR / "sample_fir_reports.txt")
    ):
        match = date_pattern.search(
            report["raw_text"]
        )

        if match:
            day, month, year = match.groups()
            sort_key = (
                f"{year}-{month}-{day} 00:00:00"
            )

            events.append(
                {
                    "date": f"{day}/{month}/{year}",
                    "sort_key": sort_key,
                    "type": "FIR",
                    "description": redact_text(
                        report["raw_text"],
                        redact,
                    ),
                }
            )

    # Call events
    with open(
        DATA_DIR / "sample_cdr.csv",
        encoding="utf-8",
    ) as f:
        for row in csv.DictReader(f):
            events.append(
                {
                    "date": row["timestamp"].split(" ")[0],
                    "sort_key": row["timestamp"],
                    "type": "CALL",
                    "description": (
                        f"{redact_name(row['caller_name'], redact)} "
                        f"called "
                        f"{redact_name(row['receiver_name'], redact)} "
                        f"({row['duration_sec']}s, "
                        f"{row['tower_location']})"
                    ),
                }
            )

    # Transaction events
    with open(
        DATA_DIR / "sample_transactions.csv",
        encoding="utf-8",
    ) as f:
        for row in csv.DictReader(f):
            events.append(
                {
                    "date": row["timestamp"].split(" ")[0],
                    "sort_key": row["timestamp"],
                    "type": "TRANSACTION",
                    "description": (
                        f"₹{int(row['amount']):,} transferred from "
                        f"{redact_name(row['sender_name'], redact)} to "
                        f"{redact_name(row['receiver_name'], redact)} "
                        f"via {row['mode']}"
                    ),
                }
            )

    events.sort(key=lambda e: e["sort_key"])
    return events


# ---------------------------------------------------------------------------
# Heatmap
# ---------------------------------------------------------------------------

@app.get("/heatmap")
def get_heatmap(
    user: dict = Depends(require_auth),
):
    from collections import Counter

    counts = Counter()

    for report in process_fir_file(
        str(DATA_DIR / "sample_fir_reports.txt")
    ):
        for loc in report["entities"]["locations"]:
            counts[loc] += 1

    with open(
        DATA_DIR / "sample_cdr.csv",
        encoding="utf-8",
    ) as f:
        for row in csv.DictReader(f):
            counts[row["tower_location"]] += 1

    points = []

    for name, (lat, lng) in LOCATION_COORDS.items():
        points.append(
            {
                "name": name,
                "lat": lat,
                "lng": lng,
                "mentions": counts.get(name, 0),
            }
        )

    return points