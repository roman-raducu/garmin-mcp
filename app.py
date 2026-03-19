import asyncio
import json
import logging
import os
from typing import Any, Awaitable, Callable

import aiohttp
from aiogarmin import GarminAuth, GarminClient
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response

load_dotenv()

app = FastAPI()
logger = logging.getLogger(__name__)


def _credentials() -> tuple[str, str]:
    email = os.getenv("GARMIN_EMAIL")
    password = os.getenv("GARMIN_PASSWORD")
    if not email or not password:
        raise HTTPException(
            status_code=500,
            detail="GARMIN_EMAIL and GARMIN_PASSWORD must be set.",
        )
    return email, password


def _load_token(name: str) -> dict[str, Any] | None:
    raw = os.getenv(name)
    if not raw:
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"{name} must contain valid JSON.",
        ) from exc

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=500,
            detail=f"{name} must decode to a JSON object.",
        )

    return data


async def _build_auth(session: aiohttp.ClientSession) -> GarminAuth:
    oauth1_token = _load_token("GARMIN_OAUTH1_TOKEN")
    oauth2_token = _load_token("GARMIN_OAUTH2_TOKEN")

    if oauth1_token or oauth2_token:
        if not oauth1_token or not oauth2_token:
            raise HTTPException(
                status_code=500,
                detail="GARMIN_OAUTH1_TOKEN and GARMIN_OAUTH2_TOKEN must both be set.",
            )
        return GarminAuth(
            session,
            oauth1_token=oauth1_token,
            oauth2_token=oauth2_token,
        )

    email, password = _credentials()
    auth = GarminAuth(session)
    login_result = await auth.login(email, password)

    if getattr(login_result, "mfa_required", False):
        raise HTTPException(
            status_code=503,
            detail=(
                "Garmin MFA is enabled. Configure GARMIN_OAUTH1_TOKEN and "
                "GARMIN_OAUTH2_TOKEN, or add an MFA completion flow."
            ),
        )

    return auth


async def _with_client(
    operation: Callable[[GarminClient], Awaitable[Any]],
) -> Any:
    timeout = aiohttp.ClientTimeout(total=30)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            auth = await _build_auth(session)
            client = GarminClient(session, auth)
            return await operation(client)
    except HTTPException:
        raise
    except asyncio.TimeoutError as exc:
        logger.warning("Garmin request timed out: %s", exc)
        raise HTTPException(
            status_code=504,
            detail="Garmin request timed out.",
        ) from exc
    except aiohttp.ClientError as exc:
        logger.warning("Garmin network error: %s", exc)
        raise HTTPException(
            status_code=502,
            detail="Failed to reach Garmin services.",
        ) from exc
    except Exception as exc:
        if type(exc).__name__ == "GarminMFARequired":
            raise HTTPException(
                status_code=503,
                detail=(
                    "Garmin MFA is enabled. This API cannot complete MFA during "
                    "a request. Use stored Garmin OAuth tokens instead."
                ),
            ) from exc
        logger.exception("Unexpected Garmin API failure")
        raise HTTPException(
            status_code=502,
            detail=f"Garmin request failed: {type(exc).__name__}",
        ) from exc


def _extract(data: Any, *keys: str) -> Any:
    if isinstance(data, dict):
        for key in keys:
            if key in data:
                return data[key]
    return data


@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"status": "ok", "message": "Garmin MCP running"}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.head("/healthz")
def healthz_head():
    return Response(status_code=200)


@app.get("/today")
async def today():
    return await _with_client(lambda client: client.get_user_summary())


@app.get("/sleep")
async def sleep():
    async def fetch_sleep(client: GarminClient) -> Any:
        core_data = await client.fetch_core_data()
        return _extract(core_data, "sleep", "sleepData", "sleep_data")

    return await _with_client(fetch_sleep)


@app.get("/activities")
async def activities():
    async def fetch_activities(client: GarminClient) -> Any:
        activity_data = await client.fetch_activity_data()
        activities_list = _extract(activity_data, "activities", "activityData", "activity_data")
        if isinstance(activities_list, list):
            return activities_list[:5]
        return activity_data

    return await _with_client(fetch_activities)
