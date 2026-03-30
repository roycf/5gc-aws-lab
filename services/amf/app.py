from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import asyncio, os, uuid, time, logging, hmac, hashlib
import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("amf")

NRF_URL = os.environ.get("NRF_URL", "http://nrf.core.local:8080")
AUSF_URL = os.environ.get("AUSF_URL", "http://ausf.core.local:8080")
SMF_URL = os.environ.get("SMF_URL", "http://smf.core.local:8080")
NF_INSTANCE_ID = str(uuid.uuid4())
HEARTBEAT_SEC = 20
# Secret for minting the auth cookie token (optional; WAF only checks cookie presence in this lab)
GW_SECRET = os.environ.get("5GC_GW_SECRET", "lab-secret-change-me").encode("utf-8")


def _auth_cookie_token(supi: str) -> str:
    """Token for 5gc-auth cookie: HMAC(supi + timestamp). Client must send this cookie on PDU session request."""
    return hmac.new(GW_SECRET, (supi + str(int(time.time()))).encode("utf-8"), hashlib.sha256).hexdigest()[:32]


async def _register_and_heartbeat():
    """Register this AMF with NRF on startup, then send periodic heartbeats."""
    await asyncio.sleep(3)
    async with httpx.AsyncClient(timeout=5.0) as client:
        for attempt in range(10):
            try:
                resp = await client.put(
                    f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{NF_INSTANCE_ID}",
                    json={
                        "nfType": "AMF",
                        "fqdn": "amf.core.local",
                        "nfServices": [{"serviceName": "namf-comm", "scheme": "http"}],
                    },
                    headers={"x-trace-id": f"amf-reg-{attempt}"},
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
                    headers={"x-trace-id": f"amf-hb-{int(time.time())}"},
                )
            except Exception as e:
                logger.warning("Heartbeat failed: %s", e)


@asynccontextmanager
async def lifespan(app_inst):
    task = asyncio.create_task(_register_and_heartbeat())
    yield
    task.cancel()


app = FastAPI(title="AMF – Access and Mobility Management Function", lifespan=lifespan)


@app.get("/health")
def health():
    return {"ok": True, "nf": "amf", "nfInstanceId": NF_INSTANCE_ID}


# ── 3GPP-style UE registration (TS 29.518) ──────────────────


@app.post("/namf-comm/v1/ue-contexts/{supi}")
async def ue_initial_registration(supi: str, request: Request):
    """
    Simulated UE initial registration.
    Chain: AMF → AUSF (authenticate) → NRF (discover SMF).
    """
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    steps = []

    async with httpx.AsyncClient(timeout=5.0) as client:
        hdrs = {"x-trace-id": trace}

        # 1) Authenticate UE via AUSF
        try:
            auth = await client.post(
                f"{AUSF_URL}/nausf-auth/v1/ue-authentications",
                json={
                    "supiOrSuci": supi,
                    "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org",
                },
                headers=hdrs,
            )
            steps.append({"step": "authentication", "status": "success", "detail": auth.json()})
            logger.info("[%s] UE %s authenticated", trace, supi)
        except Exception as e:
            steps.append({"step": "authentication", "status": "failed", "error": str(e)})
            logger.error("[%s] Auth failed for %s: %s", trace, supi, e)

        # 2) Discover SMF via NRF (for future PDU session)
        try:
            disc = await client.get(
                f"{NRF_URL}/nnrf-disc/v1/nf-instances",
                params={"target_nf_type": "SMF"},
                headers=hdrs,
            )
            disc_data = disc.json()
            steps.append({
                "step": "smf_discovery",
                "status": "success",
                "smf_instances_found": len(disc_data.get("nfInstances", [])),
            })
        except Exception as e:
            steps.append({"step": "smf_discovery", "status": "failed", "error": str(e)})

    payload = {
        "trace_id": trace,
        "event": "ue_initial_registration",
        "supi": supi,
        "serving_amf": NF_INSTANCE_ID,
        "registration_steps": steps,
        "ts": time.time(),
    }
    response = JSONResponse(content=payload)
    # Set cookie so WAF allows subsequent PDU session request (auth-before-PDU defense)
    auth_ok = any(s.get("step") == "authentication" and s.get("status") == "success" for s in steps)
    if auth_ok:
        token = _auth_cookie_token(supi)
        response.set_cookie("5gc-auth", value=token, httponly=True, path="/", max_age=300)
    return response


# ── PDU Session Establishment ────────────────────────────────


@app.post("/namf-comm/v1/pdu-sessions/{supi}")
async def pdu_session_establishment(supi: str, request: Request):
    """
    Establish a PDU session for a registered UE.
    Chain: AMF → SMF (create session) → UPF (program forwarding rules).
    """
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))

    async with httpx.AsyncClient(timeout=5.0) as client:
        hdrs = {"x-trace-id": trace}

        try:
            resp = await client.post(
                f"{SMF_URL}/nsmf-pdusession/v1/sm-contexts",
                json={
                    "supi": supi,
                    "dnn": "internet",
                    "sNssai": {"sst": 1, "sd": "000001"},
                    "servingNfId": NF_INSTANCE_ID,
                },
                headers=hdrs,
            )
            session_data = resp.json()
            logger.info("[%s] PDU session created for %s: %s", trace, supi, session_data.get("sessionId"))
        except Exception as e:
            logger.error("[%s] PDU session creation failed: %s", trace, e)
            return {
                "trace_id": trace,
                "event": "pdu_session_failed",
                "supi": supi,
                "error": str(e),
                "ts": time.time(),
            }

    session_id = session_data.get("sessionId")
    payload = {
        "trace_id": trace,
        "event": "pdu_session_created",
        "supi": supi,
        "serving_amf": NF_INSTANCE_ID,
        "session": session_data,
        "ts": time.time(),
    }
    response = JSONResponse(content=payload)
    return response


# ── Legacy /attach (backward compat with existing ALB rule) ─


@app.post("/attach")
async def attach(request: Request):
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    supi = "imsi-001010000000001"
    steps = []

    async with httpx.AsyncClient(timeout=5.0) as client:
        hdrs = {"x-trace-id": trace}

        try:
            auth = await client.post(
                f"{AUSF_URL}/nausf-auth/v1/ue-authentications",
                json={
                    "supiOrSuci": supi,
                    "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org",
                },
                headers=hdrs,
            )
            steps.append({"step": "authentication", "result": auth.json()})
        except Exception as e:
            steps.append({"step": "authentication", "error": str(e)})

        try:
            disc = await client.get(
                f"{NRF_URL}/nnrf-disc/v1/nf-instances",
                params={"target_nf_type": "SMF"},
                headers=hdrs,
            )
            steps.append({"step": "smf_discovery", "result": disc.json()})
        except Exception as e:
            steps.append({"step": "smf_discovery", "error": str(e)})

    return {
        "trace_id": trace,
        "event": "attach_simulated",
        "supi": supi,
        "nrf_url": NRF_URL,
        "ausf_url": AUSF_URL,
        "steps": steps,
        "ts": time.time(),
    }
