from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import networkx as nx
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from api.auth import verify_token

router = APIRouter(prefix="/api/cases", tags=["Dynamic Cases"])
CASES: dict[str, dict[str, Any]] = {}


def require_case_auth(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Login required")
    payload = verify_token(authorization.removeprefix("Bearer ").strip())
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return payload


class CaseCreate(BaseModel):
    title: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=2000)


class EvidenceCreate(BaseModel):
    type: str
    source: str = "manual"
    subject: str = ""
    target: str = ""
    amount: float = 0
    relation: str = "RELATED_TO"
    details: str = ""


class ConclusionCreate(BaseModel):
    conclusion: str = Field(min_length=2, max_length=4000)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return f"NXS-{datetime.now().strftime('%Y%m%d')}-{uuid4().hex[:6].upper()}"


def _graph(case: dict[str, Any]) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    for e in case["evidence"]:
        s, t = e.get("subject", "").strip(), e.get("target", "").strip()
        if s:
            g.add_node(s, type="Person")
        if t:
            g.add_node(t, type="Person")
        if s and t:
            g.add_edge(s, t, relation=e.get("relation", "RELATED_TO"), amount=e.get("amount", 0))
    return g


def _analyze(case: dict[str, Any]) -> dict[str, Any]:
    g = _graph(case)
    money_in: dict[str, float] = {}
    money_out: dict[str, float] = {}
    for e in case["evidence"]:
        s, t = e.get("subject", ""), e.get("target", "")
        amount = float(e.get("amount", 0) or 0)
        if amount and s and t:
            money_out[s] = money_out.get(s, 0) + amount
            money_in[t] = money_in.get(t, 0) + amount

    scores: dict[str, float] = {}
    for n in g.nodes:
        degree = g.degree(n)
        score = degree * 10 + min(40, money_in.get(n, 0) / 250000) + min(20, money_out.get(n, 0) / 500000)
        scores[n] = round(min(100, score), 1)

    top = max(scores.items(), key=lambda x: x[1], default=("No entity", 0))
    if top[1] >= 70:
        level = "HIGH"
    elif top[1] >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    nodes = [{"id": n, "label": n, "type": g.nodes[n].get("type", "Person"), "risk": scores.get(n, 0)} for n in g.nodes]
    edges = [{"from": s, "to": t, "label": d.get("relation", "RELATED_TO")} for s, t, d in g.edges(data=True)]

    case["analysis"] = {
        "status": "ANALYZED",
        "analyzed_at": _now(),
        "risk_level": level,
        "top_entity": top[0],
        "top_risk": top[1],
        "explanation": f"{top[0]} is the highest-scoring connected entity based on observed relationships and financial activity in this case.",
        "node_count": len(nodes),
        "relationship_count": len(edges),
        "nodes": nodes,
        "edges": edges,
        "risk_scores": [{"entity": n, "score": s} for n, s in sorted(scores.items(), key=lambda x: x[1], reverse=True)],
    }
    case["status"] = "UNDER_INVESTIGATION"
    return case["analysis"]


@router.post("")
def create_case(body: CaseCreate, user: dict = Depends(require_case_auth)):
    case_id = _new_id()
    case = {
        "case_id": case_id,
        "title": body.title,
        "description": body.description,
        "status": "OPEN",
        "created_at": _now(),
        "created_by": user.get("username", "investigator"),
        "evidence": [],
        "analysis": None,
        "conclusion": None,
    }
    CASES[case_id] = case
    return case


@router.get("")
def list_cases(user: dict = Depends(require_case_auth)):
    return {"cases": list(CASES.values())}


@router.get("/{case_id}")
def get_case(case_id: str, user: dict = Depends(require_case_auth)):
    case = CASES.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("/{case_id}/evidence")
def add_evidence(case_id: str, body: EvidenceCreate, user: dict = Depends(require_case_auth)):
    case = CASES.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if not body.subject and not body.details:
        raise HTTPException(status_code=400, detail="Subject or details required")
    evidence = body.model_dump()
    evidence["id"] = f"EV-{len(case['evidence']) + 1:03d}"
    evidence["timestamp"] = _now()
    evidence["submitted_by"] = user.get("username", "investigator")
    case["evidence"].append(evidence)
    case["status"] = "EVIDENCE_ADDED"
    case["analysis"] = None
    return evidence


@router.post("/{case_id}/demo-evidence")
def add_demo_evidence(case_id: str, user: dict = Depends(require_case_auth)):
    case = CASES.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    demo = [
        {"type":"transaction","source":"Bank Record","subject":"Aman","target":"Rohit","amount":500000,"relation":"TRANSFERRED_TO","details":"NEFT"},
        {"type":"transaction","source":"Bank Record","subject":"Rohit","target":"Karan","amount":1200000,"relation":"TRANSFERRED_TO","details":"RTGS"},
        {"type":"transaction","source":"Bank Record","subject":"Karan","target":"Neha","amount":800000,"relation":"TRANSFERRED_TO","details":"IMPS"},
        {"type":"call","source":"CDR","subject":"Aman","target":"Rohit","amount":0,"relation":"CALLED","details":"8 min"},
        {"type":"call","source":"CDR","subject":"Rohit","target":"Karan","amount":0,"relation":"CALLED","details":"12 min"},
        {"type":"vehicle","source":"Vehicle Record","subject":"Karan","target":"KA01XX1234","amount":0,"relation":"ASSOCIATED_WITH","details":"Registered vehicle"},
        {"type":"location","source":"Location Record","subject":"Karan","target":"Location A","amount":0,"relation":"LOCATED_AT","details":"Observed location"},
    ]
    case["evidence"] = []
    for item in demo:
        case["evidence"].append({**item, "id": f"EV-{len(case['evidence'])+1:03d}", "timestamp": _now(), "submitted_by": user.get("username", "investigator")})
    case["status"] = "EVIDENCE_ADDED"
    case["analysis"] = None
    return {"count": len(case["evidence"]), "evidence": case["evidence"]}


@router.post("/{case_id}/analyze")
def analyze_case(case_id: str, user: dict = Depends(require_case_auth)):
    case = CASES.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if not case["evidence"]:
        raise HTTPException(status_code=400, detail="Add evidence before analysis")
    return _analyze(case)


@router.post("/{case_id}/conclusion")
def conclude_case(case_id: str, body: ConclusionCreate, user: dict = Depends(require_case_auth)):
    case = CASES.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    case["conclusion"] = {"text": body.conclusion, "closed_at": _now(), "closed_by": user.get("username", "investigator")}
    case["status"] = "SOLVED"
    return {"status": "SOLVED", "case": case}
