from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
import asyncio, os, uuid, time, logging
import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("smf")

NRF_URL = os.environ.get("NRF_URL", "http://nrf.core.local:8080")
UPF_URL = os.environ.get("UPF_URL", "http://upf.core.local:8080")
NF_INSTANCE_ID = str(uuid.uuid4())
HEARTBEAT_SEC = 20

SESSIONS: dict[str, dict] = {}
_ip_counter = 1


def _allocate_ip():
    global _ip_counter
    _ip_counter += 1
    return f"10.45.0.{_ip_counter}"


async def _register_and_heartbeat():
    await asyncio.sleep(6)
    async with httpx.AsyncClient(timeout=5.0) as client:
        for attempt in range(10):
            try:
                resp = await client.put(
                    f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{NF_INSTANCE_ID}",
                    json={
                        "nfType": "SMF",
                        "fqdn": "smf.core.local",
                        "nfServices": [
                            {"serviceName": "nsmf-pdusession", "scheme": "http",
                             "versions": [{"apiVersionInUri": "v1"}]},
                        ],
                    },
                    headers={"x-trace-id": f"smf-reg-{attempt}"},
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
                    headers={"x-trace-id": f"smf-hb-{int(time.time())}"},
                )
            except Exception as e:
                logger.warning("Heartbeat failed: %s", e)


@asynccontextmanager
async def lifespan(app_inst):
    task = asyncio.create_task(_register_and_heartbeat())
    yield
    task.cancel()


app = FastAPI(title="SMF – Session Management Function", lifespan=lifespan)


@app.get("/health")
def health():
    return {
        "ok": True,
        "nf": "smf",
        "nfInstanceId": NF_INSTANCE_ID,
        "activeSessions": len(SESSIONS),
    }


@app.post("/nsmf-pdusession/v1/sm-contexts")
async def create_sm_context(request: Request):
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    body = await request.json()
    supi = body.get("supi")
    dnn = body.get("dnn", "internet")
    s_nssai = body.get("sNssai", {"sst": 1, "sd": "000001"})

    if not supi:
        raise HTTPException(status_code=400, detail="supi is required")

    session_id = str(uuid.uuid4())
    ue_ip = _allocate_ip()

    session = {
        "sessionId": session_id,
        "supi": supi,
        "dnn": dnn,
        "sNssai": s_nssai,
        "ueIpAddress": ue_ip,
        "sessionStatus": "ACTIVE",
        "upfNodeId": "upf.core.local",
        "createdAt": time.time(),
    }
    SESSIONS[session_id] = session

    # Program UPF with session rules (N4 / PFCP equivalent)
    upf_ack = None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{UPF_URL}/nupf-dp/v1/sessions",
                json={
                    "sessionId": session_id,
                    "supi": supi,
                    "dnn": dnn,
                    "ueIpAddress": ue_ip,
                },
                headers={"x-trace-id": trace},
            )
            upf_ack = resp.json()
            logger.info("[%s] UPF programmed for session %s", trace, session_id)
    except Exception as e:
        logger.error("[%s] Failed to program UPF: %s", trace, e)
        session["sessionStatus"] = "UPF_ERROR"

    return {
        "trace_id": trace,
        "sessionId": session_id,
        "supi": supi,
        "dnn": dnn,
        "sNssai": s_nssai,
        "ueIpAddress": ue_ip,
        "upfNodeId": "upf.core.local",
        "sessionStatus": session["sessionStatus"],
        "upfAck": upf_ack,
        "ts": time.time(),
    }


@app.delete("/nsmf-pdusession/v1/sm-contexts/{session_id}")
async def release_sm_context(session_id: str, request: Request):
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))

    session = SESSIONS.pop(session_id, None)
    if not session:
        raise HTTPException(status_code=404, detail="session not found")

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.delete(
                f"{UPF_URL}/nupf-dp/v1/sessions/{session_id}",
                headers={"x-trace-id": trace},
            )
    except Exception as e:
        logger.warning("[%s] UPF session cleanup failed: %s", trace, e)

    return {"trace_id": trace, "sessionId": session_id, "sessionStatus": "RELEASED"}
