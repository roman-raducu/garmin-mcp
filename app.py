import os
from typing import Any, Awaitable, Callable

import aiohttp
from aiogarmin import GarminAuth, GarminClient
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException

load_dotenv()

app = FastAPI()


def _credentials() -> tuple[str, str]:
    email = os.getenv("GARMIN_EMAIL")
    password = os.getenv("GARMIN_PASSWORD")
    if not email or not password:
        raise HTTPException(
            status_code=500,
            detail="GARMIN_EMAIL and GARMIN_PASSWORD must be set.",
        )
    return email, password


async def _with_client(
    operation: Callable[[GarminClient], Awaitable[Any]],
) -> Any:
    email, password = _credentials()

    async with aiohttp.ClientSession() as session:
        auth = GarminAuth(session)
        login_result = await auth.login(email, password)

        if getattr(login_result, "mfa_required", False):
            raise HTTPException(
                status_code=503,
                detail="Garmin MFA is required and cannot be completed interactively by this service.",
            )

        client = GarminClient(session, auth)
        return await operation(client)


def _extract(data: Any, *keys: str) -> Any:
    if isinstance(data, dict):
        for key in keys:
            if key in data:
                return data[key]
    return data


@app.get("/")
def root():
    return {"status": "ok", "message": "Garmin MCP running"}


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
