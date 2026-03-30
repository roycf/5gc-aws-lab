from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
import asyncio, os, uuid, time, logging, hashlib
import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("ausf")

NRF_URL = os.environ.get("NRF_URL", "http://nrf.core.local:8080")
UDM_URL = os.environ.get("UDM_URL", "http://udm.core.local:8080")
NF_INSTANCE_ID = str(uuid.uuid4())
HEARTBEAT_SEC = 20


async def _register_and_heartbeat():
    await asyncio.sleep(5)
    async with httpx.AsyncClient(timeout=5.0) as client:
        for attempt in range(10):
            try:
                await client.put(
                    f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{NF_INSTANCE_ID}",
                    json={
                        "nfType": "AUSF",
                        "fqdn": "ausf.core.local",
                        "nfServices": [{"serviceName": "nausf-auth", "scheme": "http"}],
                    },
                    headers={"x-trace-id": f"ausf-reg-{attempt}"},
                )
                logger.info("Registered with NRF")
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
                    headers={"x-trace-id": f"ausf-hb-{int(time.time())}"},
                )
            except Exception:
                pass


@asynccontextmanager
async def lifespan(app_inst):
    task = asyncio.create_task(_register_and_heartbeat())
    yield
    task.cancel()


app = FastAPI(title="AUSF – Authentication Server Function", lifespan=lifespan)


@app.get("/health")
def health():
    return {"ok": True, "nf": "ausf", "nfInstanceId": NF_INSTANCE_ID}


@app.post("/nausf-auth/v1/ue-authentications")
async def ue_authentication(request: Request):
    """Simulated 5G-AKA authentication (TS 29.509).
    Calls UDM to fetch authentication vectors, then runs a
    simplified 5G-AKA challenge/response."""
    body = await request.json()
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    supi = body.get("supiOrSuci", "unknown")
    serving_network = body.get("servingNetworkName", "")

    logger.info("[%s] Auth request for %s on %s", trace, supi, serving_network)

    # 1) Fetch auth vectors from UDM
    auth_vectors = None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{UDM_URL}/nudm-ueau/v1/{supi}/security-information/generate-auth-data",
                json={
                    "servingNetworkName": serving_network,
                    "ausfInstanceId": NF_INSTANCE_ID,
                },
                headers={"x-trace-id": trace},
            )
            auth_vectors = resp.json()
    except Exception as e:
        logger.error("[%s] UDM call failed: %s", trace, e)
        return {"trace_id": trace, "supi": supi, "authResult": "FAILURE", "error": str(e)}

    # 2) Simulate 5G-AKA challenge/response
    av = auth_vectors.get("authenticationVector", {})
    rand = av.get("rand", "")
    xres_star = hashlib.sha256(
        f"{supi}{rand}{serving_network}".encode()
    ).hexdigest()[:32]

    logger.info("[%s] Auth SUCCESS for %s", trace, supi)

    return {
        "trace_id": trace,
        "authType": "5G_AKA",
        "supi": supi,
        "authResult": "SUCCESS",
        "authCtxId": str(uuid.uuid4()),
        "5gAuthData": {
            "rand": rand,
            "hxresStar": xres_star[:16],
            "autn": av.get("autn", ""),
        },
        "ts": time.time(),
    }
