from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
import asyncio, os, uuid, time, logging, hmac, hashlib
from urllib.parse import urlparse
import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("upf")

NRF_URL = os.environ.get("NRF_URL", "http://nrf.core.local:8080")
NF_INSTANCE_ID = str(uuid.uuid4())
HEARTBEAT_SEC = 20


# Session table -- programmed by the SMF via the N4 interface equivalent.
# Key: sessionId, Value: session rule (supi, dnn, ueIpAddress, counters).
SESSION_TABLE: dict[str, dict] = {}

# DNN-based N6 policy: which data networks allow public internet vs internal only.
# "internet" = allow any URL (real N6 to public internet); others = internal (*.core.local) only.
DNN_POLICY = {
    "internet": {"allow_public": True},
    "ims": {"allow_public": False, "internal_only": True},
}
DEFAULT_DNN_POLICY = {"allow_public": False, "internal_only": True}


async def _register_and_heartbeat():
    await asyncio.sleep(4)
    async with httpx.AsyncClient(timeout=5.0) as client:
        for attempt in range(10):
            try:
                resp = await client.put(
                    f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{NF_INSTANCE_ID}",
                    json={
                        "nfType": "UPF",
                        "fqdn": "upf.core.local",
                        "nfServices": [
                            {"serviceName": "nupf-dp", "scheme": "http",
                             "versions": [{"apiVersionInUri": "v1"}]},
                        ],
                    },
                    headers={"x-trace-id": f"upf-reg-{attempt}"},
                )
                logger.info("Registered with NRF: %s", resp.json())
                break
            except Exception as e:
                logger.warning("NRF registration attempt %d failed: %s", attempt, e)
                await asyncio.sleep(3)

        while True:
            await asyncio.sleep(HEARTBEAT_SEC)
            try:
                await client.patch(
                    f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{NF_INSTANCE_ID}",
                    json={"nfStatus": "REGISTERED"},
                    headers={"x-trace-id": f"upf-hb-{int(time.time())}"},
                )
            except Exception as e:
                logger.warning("Heartbeat failed: %s", e)


@asynccontextmanager
async def lifespan(app_inst):
    task = asyncio.create_task(_register_and_heartbeat())
    yield
    task.cancel()


app = FastAPI(title="UPF – User Plane Function", lifespan=lifespan)


@app.get("/health")
def health():
    return {
        "ok": True,
        "nf": "upf",
        "nfInstanceId": NF_INSTANCE_ID,
        "activeSessions": len(SESSION_TABLE),
    }


# ── N4 interface (SMF → UPF session programming) ─────────────


@app.post("/nupf-dp/v1/sessions")
async def program_session(request: Request):
    """Called by SMF to install a session forwarding rule."""
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    body = await request.json()
    session_id = body["sessionId"]

    SESSION_TABLE[session_id] = {
        "supi": body["supi"],
        "dnn": body["dnn"],
        "ueIpAddress": body["ueIpAddress"],
        "status": "ACTIVE",
        "bytesUp": 0,
        "bytesDown": 0,
        "packetCount": 0,
        "createdAt": time.time(),
    }
    logger.info("[%s] Session %s programmed for %s", trace, session_id, body["supi"])
    return {"sessionId": session_id, "status": "PROGRAMMED"}


@app.delete("/nupf-dp/v1/sessions/{session_id}")
async def remove_session(session_id: str):
    session = SESSION_TABLE.pop(session_id, None)
    if not session:
        raise HTTPException(status_code=404, detail="session not found")
    return {"sessionId": session_id, "status": "REMOVED"}


@app.get("/nupf-dp/v1/sessions")
def list_sessions():
    return {"sessions": SESSION_TABLE}


# ── Data plane forwarding (N6 interface equivalent) ───────────


@app.post("/nupf-dp/v1/forward")
async def forward_data(request: Request):
    """
    Forward an HTTP request through the user plane.
    The caller must provide a valid sessionId (programmed by the SMF)
    and a target URL.  The UPF fetches the URL and returns the response,
    simulating GTP-U decapsulation → routing → N6 forwarding.
    """
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    body = await request.json()
    session_id = body.get("sessionId")
    target_url = body.get("url")

    if not session_id or not target_url:
        raise HTTPException(status_code=400, detail="sessionId and url are required")

    session = SESSION_TABLE.get(session_id)
    if not session:
        raise HTTPException(
            status_code=403,
            detail=f"No active session '{session_id}'. Establish a PDU session first.",
        )
    if session["status"] != "ACTIVE":
        raise HTTPException(status_code=403, detail=f"Session is {session['status']}")

    # N6 policy: DNN determines whether public internet is allowed (3GPP-style).
    policy = DNN_POLICY.get(session["dnn"], DEFAULT_DNN_POLICY)
    if policy.get("internal_only") and not policy.get("allow_public"):
        try:
            host = urlparse(target_url).hostname or ""
        except Exception:
            host = ""
        if not host.endswith(".core.local"):
            raise HTTPException(
                status_code=403,
                detail=f"DNN '{session['dnn']}' does not allow public internet; use internal URL (*.core.local) or DNN 'internet'.",
            )

    logger.info(
        "[%s] Forwarding for %s  session=%s  target=%s",
        trace, session["supi"], session_id, target_url,
    )
    # Single, grep-friendly log line for AWS Console: external (N6) request = SSRF/exfil visible in CloudWatch
    try:
        host = urlparse(target_url).hostname or ""
        if not host.endswith(".core.local"):
            logger.warning(
                "N6_EXTERNAL_REQUEST url=%s supi=%s sessionId=%s trace=%s",
                target_url, session["supi"], session_id, trace,
            )
    except Exception:
        pass

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(target_url, headers={"x-trace-id": trace})
    except Exception as e:
        logger.error("[%s] Forward failed: %s", trace, e)
        raise HTTPException(status_code=502, detail=f"UPF forwarding error: {e}")

    content_bytes = len(resp.content)
    session["bytesDown"] += content_bytes
    session["packetCount"] += 1

    body_preview = resp.text[:2000] if resp.text else ""

    return {
        "trace_id": trace,
        "sessionId": session_id,
        "supi": session["supi"],
        "ueIpAddress": session["ueIpAddress"],
        "dnn": session["dnn"],
        "target": target_url,
        "response": {
            "statusCode": resp.status_code,
            "contentType": resp.headers.get("content-type", ""),
            "contentLength": content_bytes,
            "body": body_preview,
        },
        "counters": {
            "bytesDown": session["bytesDown"],
            "packetCount": session["packetCount"],
        },
        "ts": time.time(),
    }
