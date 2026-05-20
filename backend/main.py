import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from scanner import scan
from threat_analyzer import analyze, ThreatAnalysis

# ── Configuration ──────────────────────────────────────────────────────────────
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")
MAX_PAYLOAD_BYTES = 200 * 1024  # 200 KB — well above the 100 KB file target (§4.1)

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="ClearSight AI Security Scanner API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Restrict CORS to known frontend origin only
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# ── Request / Response Models ──────────────────────────────────────────────────

class ScanRequest(BaseModel):
    text: str = Field(..., max_length=200_000, description="Content to scan (max 200 KB)")
    mode: str = Field(
        "strict",
        pattern=r"^(strict|sanitize|report)$",
        description="strict=block, sanitize=strip+pass, report=log only",
    )
    density_threshold: float = Field(
        0.01, ge=0.0, le=1.0,
        description="Invisible-char ratio that triggers a threat (default 1 %)",
    )

    @field_validator("text")
    @classmethod
    def text_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("text must not be empty")
        return v


class DetectionDetail(BaseModel):
    category: str
    count: int
    decoded: str | None
    harm_categories: list[str]
    positions: list[int]


class ScanResponse(BaseModel):
    status: str
    threat_detected: bool
    density_score: float
    detections: list[DetectionDetail]
    sanitized_text: str | None
    scan_time_ms: float
    timed_out: bool


class ThreatFindingDetail(BaseModel):
    category: str
    severity: str
    description: str
    evidence: str | None
    position: int | None
    source: str  # "rule" | "llm"


class ThreatAnalysisResponse(BaseModel):
    # Stego-scan fields (same as ScanResponse)
    status: str
    threat_detected: bool
    density_score: float
    detections: list[DetectionDetail]
    sanitized_text: str | None
    scan_time_ms: float
    timed_out: bool
    # Semantic threat analysis fields
    rule_findings: list[ThreatFindingDetail]
    llm_findings: list[ThreatFindingDetail]
    execution_summary: str
    overall_risk: str
    llm_available: bool
    analysis_time_ms: float


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/scan", response_model=ScanResponse)
@limiter.limit("30/minute")
async def scan_text(request: Request, body: ScanRequest):
    # §4.1 Payload size guard (belt-and-suspenders over Pydantic max_length)
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_PAYLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Payload too large (max 200 KB)")

    result = scan(body.text, mode=body.mode, density_threshold=body.density_threshold)

    # Derive human-readable status
    if body.mode == "strict":
        status = "blocked" if result.threat_detected else "clean"
    elif body.mode == "sanitize":
        status = "sanitized" if result.threat_detected else "clean"
    else:
        status = "threat_detected" if result.threat_detected else "clean"

    return ScanResponse(
        status=status,
        threat_detected=result.threat_detected,
        density_score=result.density_score,
        detections=[
            DetectionDetail(
                category=d.category,
                count=d.count,
                decoded=d.decoded,
                harm_categories=d.harm_categories,
                positions=d.positions,
            )
            for d in result.detections
        ],
        sanitized_text=result.sanitized_text,
        scan_time_ms=result.scan_time_ms,
        timed_out=result.timed_out,
    )


@app.post("/api/analyze", response_model=ThreatAnalysisResponse)
@limiter.limit("10/minute")
async def analyze_text(request: Request, body: ScanRequest):
    """Run stego scan *and* semantic threat analysis on the submitted text."""
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_PAYLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Payload too large (max 200 KB)")

    scan_result = scan(body.text, mode=body.mode, density_threshold=body.density_threshold)
    threat_result: ThreatAnalysis = analyze(body.text)

    if body.mode == "strict":
        status = "blocked" if scan_result.threat_detected else "clean"
    elif body.mode == "sanitize":
        status = "sanitized" if scan_result.threat_detected else "clean"
    else:
        status = "threat_detected" if scan_result.threat_detected else "clean"

    return ThreatAnalysisResponse(
        status=status,
        threat_detected=scan_result.threat_detected,
        density_score=scan_result.density_score,
        detections=[
            DetectionDetail(
                category=d.category,
                count=d.count,
                decoded=d.decoded,
                harm_categories=d.harm_categories,
                positions=d.positions,
            )
            for d in scan_result.detections
        ],
        sanitized_text=scan_result.sanitized_text,
        scan_time_ms=scan_result.scan_time_ms,
        timed_out=scan_result.timed_out,
        rule_findings=[
            ThreatFindingDetail(
                category=f.category,
                severity=f.severity,
                description=f.description,
                evidence=f.evidence,
                position=f.position,
                source=f.source,
            )
            for f in threat_result.rule_findings
        ],
        llm_findings=[
            ThreatFindingDetail(
                category=f.category,
                severity=f.severity,
                description=f.description,
                evidence=f.evidence,
                position=f.position,
                source=f.source,
            )
            for f in threat_result.llm_findings
        ],
        execution_summary=threat_result.execution_summary,
        overall_risk=threat_result.overall_risk,
        llm_available=threat_result.llm_available,
        analysis_time_ms=threat_result.analysis_time_ms,
    )