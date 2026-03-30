from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
import asyncio, os, uuid, time, logging, hashlib, secrets
import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("udm")

NRF_URL = os.environ.get("NRF_URL", "http://nrf.core.local:8080")
NF_INSTANCE_ID = str(uuid.uuid4())
HEARTBEAT_SEC = 20

# Simulated subscriber database (keyed by SUPI)
SUBSCRIBER_DB = {
    "imsi-001010000000001": {
        "supi": "imsi-001010000000001",
        "authKey": "465B5CE8B199B49FAA5F0A2EE238A6BC",
        "opc": "E8ED289DEBA952E4283B54E88E6183CA",
        "subscribedNssai": [{"sst": 1, "sd": "000001"}],
        "dnn": ["internet", "ims"],
        "ambr": {"uplink": "100 Mbps", "downlink": "200 Mbps"},
    },
    "imsi-001010000000002": {
        "supi": "imsi-001010000000002",
        "authKey": "0396EB317B6D1C36F19C1C5D968AE823",
        "opc": "D41D8CD98F00B204E9800998ECF8427E",
        "subscribedNssai": [{"sst": 1, "sd": "000001"}],
        "dnn": ["internet"],
        "ambr": {"uplink": "50 Mbps", "downlink": "100 Mbps"},
    },
}


async def _register_and_heartbeat():
    await asyncio.sleep(4)
    async with httpx.AsyncClient(timeout=5.0) as client:
        for attempt in range(10):
            try:
                await client.put(
                    f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{NF_INSTANCE_ID}",
                    json={
                        "nfType": "UDM",
                        "fqdn": "udm.core.local",
                        "nfServices": [
                            {"serviceName": "nudm-ueau", "scheme": "http"},
                            {"serviceName": "nudm-sdm", "scheme": "http"},
                        ],
                    },
                    headers={"x-trace-id": f"udm-reg-{attempt}"},
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
                    headers={"x-trace-id": f"udm-hb-{int(time.time())}"},
                )
            except Exception:
                pass


@asynccontextmanager
async def lifespan(app_inst):
    task = asyncio.create_task(_register_and_heartbeat())
    yield
    task.cancel()


app = FastAPI(title="UDM – Unified Data Management", lifespan=lifespan)


@app.get("/health")
def health():
    return {
        "ok": True,
        "nf": "udm",
        "nfInstanceId": NF_INSTANCE_ID,
        "subscribers": len(SUBSCRIBER_DB),
    }


@app.post("/nudm-ueau/v1/{supi}/security-information/generate-auth-data")
async def generate_auth_data(supi: str, request: Request):
    """Generate 5G-AKA authentication vectors (simulated, TS 29.503)."""
    body = await request.json()
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    serving_network = body.get("servingNetworkName", "")

    subscriber = SUBSCRIBER_DB.get(supi)
    if not subscriber:
        logger.warning("[%s] Unknown SUPI %s — generating ephemeral profile", trace, supi)
        subscriber = {"supi": supi, "authKey": secrets.token_hex(16), "opc": secrets.token_hex(16)}

    rand = secrets.token_hex(16)
    autn = hashlib.sha256(f"{subscriber['authKey']}{rand}".encode()).hexdigest()[:32]
    xres_star = hashlib.sha256(f"{supi}{rand}{serving_network}".encode()).hexdigest()[:32]
    kausf = hashlib.sha256(f"{subscriber['authKey']}{serving_network}".encode()).hexdigest()

    logger.info("[%s] Generated auth vectors for %s", trace, supi)

    return {
        "trace_id": trace,
        "authType": "5G_AKA",
        "supi": supi,
        "authenticationVector": {
            "avType": "5G_HE_AKA",
            "rand": rand,
            "autn": autn,
            "xresStar": xres_star,
            "kausf": kausf,
        },
        "ts": time.time(),
    }


@app.get("/nudm-sdm/v1/{supi}/nssai")
async def get_subscriber_nssai(supi: str, request: Request):
    """Subscribed NSSAI and default DNN (TS 29.503)."""
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    subscriber = SUBSCRIBER_DB.get(supi, {})
    logger.info("[%s] NSSAI query for %s", trace, supi)
    return {
        "trace_id": trace,
        "supi": supi,
        "subscribedNssai": subscriber.get("subscribedNssai", []),
        "defaultDnn": (subscriber.get("dnn") or ["internet"])[0],
        "ambr": subscriber.get("ambr", {}),
    }


@app.get("/nudm-sdm/v1/{supi}/am-data")
async def get_access_and_mobility_data(supi: str, request: Request):
    """Access and mobility subscription data (TS 29.503)."""
    trace = request.headers.get("x-trace-id", str(uuid.uuid4()))
    subscriber = SUBSCRIBER_DB.get(supi, {})
    logger.info("[%s] AM-data query for %s", trace, supi)
    return {
        "trace_id": trace,
        "supi": supi,
        "subscribedNssai": subscriber.get("subscribedNssai", []),
        "dnns": subscriber.get("dnn", []),
        "ambr": subscriber.get("ambr", {}),
    }
