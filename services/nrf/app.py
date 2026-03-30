from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
import time, uuid, logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("nrf")

app = FastAPI(title="NRF – Network Repository Function")

NF_PROFILES: dict[str, dict] = {}


class NFService(BaseModel):
    serviceInstanceId: str = ""
    serviceName: str = ""
    scheme: str = "http"


class NFProfile(BaseModel):
    nfInstanceId: str = Field(default_factory=lambda: str(uuid.uuid4()))
    nfType: str
    nfStatus: str = "REGISTERED"
    heartbeatTimer: int = 30
    fqdn: Optional[str] = None
    ipv4Addresses: list[str] = []
    nfServices: list[NFService] = []
    allowedNfTypes: list[str] = []


@app.get("/health")
def health():
    return {
        "ok": True,
        "nf": "nrf",
        "registered_nfs": len(NF_PROFILES),
        "nf_types": list({e["profile"]["nfType"] for e in NF_PROFILES.values()}),
    }


# ── 3GPP NF Management (TS 29.510) ──────────────────────────


@app.put("/nnrf-nfm/v1/nf-instances/{nf_instance_id}")
async def register_nf(nf_instance_id: str, profile: NFProfile, request: Request):
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    profile.nfInstanceId = nf_instance_id
    profile.nfStatus = "REGISTERED"
    NF_PROFILES[nf_instance_id] = {
        "profile": profile.model_dump(),
        "registered_at": time.time(),
        "last_heartbeat": time.time(),
    }
    logger.info("[%s] registered %s  id=%s", trace, profile.nfType, nf_instance_id)
    return {
        "nfInstanceId": nf_instance_id,
        "nfStatus": "REGISTERED",
        "heartbeatTimer": profile.heartbeatTimer,
    }


@app.patch("/nnrf-nfm/v1/nf-instances/{nf_instance_id}")
async def heartbeat_nf(nf_instance_id: str, request: Request):
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    if nf_instance_id not in NF_PROFILES:
        raise HTTPException(404, "NF not registered")
    NF_PROFILES[nf_instance_id]["last_heartbeat"] = time.time()
    logger.info("[%s] heartbeat from %s", trace, nf_instance_id)
    return {"nfInstanceId": nf_instance_id, "heartbeat": "ok"}


@app.delete("/nnrf-nfm/v1/nf-instances/{nf_instance_id}")
async def deregister_nf(nf_instance_id: str, request: Request):
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    removed = NF_PROFILES.pop(nf_instance_id, None)
    nf_type = removed["profile"]["nfType"] if removed else "unknown"
    logger.info("[%s] deregistered %s  id=%s", trace, nf_type, nf_instance_id)
    return {"nfInstanceId": nf_instance_id, "status": "DEREGISTERED"}


# ── 3GPP NF Discovery (TS 29.510) ───────────────────────────


@app.get("/nnrf-disc/v1/nf-instances")
async def discover_nf(request: Request, target_nf_type: str | None = None):
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    results = [
        entry["profile"]
        for entry in NF_PROFILES.values()
        if not target_nf_type or entry["profile"]["nfType"] == target_nf_type
    ]
    logger.info(
        "[%s] discovery target-nf-type=%s  found=%d", trace, target_nf_type, len(results)
    )
    return {"validityPeriod": 3600, "nfInstances": results}


# ── Legacy endpoints (backward compat) ──────────────────────


@app.post("/register")
async def legacy_register(request: Request):
    body = await request.json()
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    nf_id = str(uuid.uuid4())
    NF_PROFILES[nf_id] = {
        "profile": {
            "nfInstanceId": nf_id,
            "nfType": body.get("name", "UNKNOWN").upper(),
            "nfStatus": "REGISTERED",
            "fqdn": body.get("url"),
        },
        "registered_at": time.time(),
        "last_heartbeat": time.time(),
    }
    return {
        "trace_id": trace,
        "event": "registered",
        "name": body.get("name"),
        "url": body.get("url"),
        "ts": time.time(),
    }


@app.get("/discover/{name}")
async def legacy_discover(name: str, request: Request):
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    url = None
    for entry in NF_PROFILES.values():
        if entry["profile"].get("nfType", "").upper() == name.upper():
            url = entry["profile"].get("fqdn")
            break
    return {
        "trace_id": trace,
        "event": "discover",
        "name": name,
        "url": url,
        "known": [e["profile"]["nfType"] for e in NF_PROFILES.values()],
        "ts": time.time(),
    }
