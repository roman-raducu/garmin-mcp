import asyncio
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import aiohttp
import garth
from aiogarmin import GarminAuth, GarminClient
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

load_dotenv()

app = FastAPI()
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger(__name__)

COOKIE_NAME = "garmin_session"
PENDING_AUTH_TTL_SECONDS = 10 * 60


@dataclass
class StoredTokens:
    email: str
    oauth1_token: dict[str, Any]
    oauth2_token: dict[str, Any]
    connected_at: float


@dataclass
class PendingAuth:
    browser_session_id: str
    email: str
    mfa_state: Any
    created_at: float


class GarminLoginRequest(BaseModel):
    email: str
    password: str


class GarminMfaRequest(BaseModel):
    pending_id: str
    code: str


TOKEN_STORE: dict[str, StoredTokens] = {}
PENDING_AUTHS: dict[str, PendingAuth] = {}
GARTH_AUTH_LOCK = asyncio.Lock()


def _now() -> float:
    return time.time()


def _browser_session_id(request: Request) -> str | None:
    return request.cookies.get(COOKIE_NAME)


def _ensure_browser_session_id(request: Request) -> tuple[str, bool]:
    browser_session_id = _browser_session_id(request)
    if browser_session_id:
        return browser_session_id, False
    return secrets.token_urlsafe(24), True


def _set_browser_cookie(response: Response, browser_session_id: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=browser_session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
    )


async def _close_pending_auth(pending_id: str) -> None:
    PENDING_AUTHS.pop(pending_id, None)


async def _cleanup_pending_auths() -> None:
    expired_ids = [
        pending_id
        for pending_id, pending in PENDING_AUTHS.items()
        if _now() - pending.created_at > PENDING_AUTH_TTL_SECONDS
    ]
    for pending_id in expired_ids:
        await _close_pending_auth(pending_id)


async def _clear_browser_auth(browser_session_id: str) -> None:
    TOKEN_STORE.pop(browser_session_id, None)
    pending_ids = [
        pending_id
        for pending_id, pending in PENDING_AUTHS.items()
        if pending.browser_session_id == browser_session_id
    ]
    for pending_id in pending_ids:
        await _close_pending_auth(pending_id)


def _load_env_token(name: str) -> dict[str, Any] | None:
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


def _env_tokens() -> StoredTokens | None:
    oauth1_token = _load_env_token("GARMIN_OAUTH1_TOKEN")
    oauth2_token = _load_env_token("GARMIN_OAUTH2_TOKEN")

    if not oauth1_token and not oauth2_token:
        return None

    if not oauth1_token or not oauth2_token:
        raise HTTPException(
            status_code=500,
            detail="GARMIN_OAUTH1_TOKEN and GARMIN_OAUTH2_TOKEN must both be set.",
        )

    return StoredTokens(
        email=os.getenv("GARMIN_EMAIL", "env-user"),
        oauth1_token=oauth1_token,
        oauth2_token=oauth2_token,
        connected_at=0,
    )


def _extract_garth_tokens(result: Any = None) -> tuple[dict[str, Any], dict[str, Any]]:
    if (
        isinstance(result, tuple)
        and len(result) == 2
        and isinstance(result[0], dict)
        and isinstance(result[1], dict)
    ):
        return result[0], result[1]

    client = getattr(garth, "client", None)
    oauth1_token = getattr(client, "oauth1_token", None)
    oauth2_token = getattr(client, "oauth2_token", None)

    if isinstance(oauth1_token, dict) and isinstance(oauth2_token, dict):
        return oauth1_token, oauth2_token

    raise HTTPException(
        status_code=502,
        detail="Garmin login succeeded but OAuth tokens were not available.",
    )


def _stored_tokens_for_request(request: Request | None) -> StoredTokens | None:
    if request is None:
        return _env_tokens()

    browser_session_id = _browser_session_id(request)
    if browser_session_id and browser_session_id in TOKEN_STORE:
        return TOKEN_STORE[browser_session_id]

    return _env_tokens()


def _credentials() -> tuple[str, str]:
    email = os.getenv("GARMIN_EMAIL")
    password = os.getenv("GARMIN_PASSWORD")
    if not email or not password:
        raise HTTPException(
            status_code=500,
            detail="GARMIN_EMAIL and GARMIN_PASSWORD must be set.",
        )
    return email, password


async def _build_auth(
    session: aiohttp.ClientSession,
    request: Request | None = None,
) -> GarminAuth:
    stored_tokens = _stored_tokens_for_request(request)
    if stored_tokens:
        return GarminAuth(
            session,
            oauth1_token=stored_tokens.oauth1_token,
            oauth2_token=stored_tokens.oauth2_token,
        )

    email, password = _credentials()
    auth = GarminAuth(session)
    login_result = await auth.login(email, password)

    if getattr(login_result, "mfa_required", False):
        raise HTTPException(
            status_code=503,
            detail=(
                "Garmin MFA is enabled. Connect from the web UI or configure "
                "GARMIN_OAUTH1_TOKEN and GARMIN_OAUTH2_TOKEN."
            ),
        )

    return auth


async def _with_client(
    operation: Callable[[GarminClient], Awaitable[Any]],
    request: Request | None = None,
) -> Any:
    timeout = aiohttp.ClientTimeout(total=30)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            auth = await _build_auth(session, request=request)
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
                    "Garmin MFA is enabled. Open the web UI, sign in there, and "
                    "complete the MFA step."
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


def _pending_status_for_browser(browser_session_id: str | None) -> dict[str, Any] | None:
    if not browser_session_id:
        return None

    for pending_id, pending in PENDING_AUTHS.items():
        if pending.browser_session_id == browser_session_id:
            return {
                "pending_id": pending_id,
                "email": pending.email,
                "expires_in": max(0, int(PENDING_AUTH_TTL_SECONDS - (_now() - pending.created_at))),
            }
    return None


def _browser_has_tokens(request: Request) -> bool:
    browser_session_id = _browser_session_id(request)
    return bool(browser_session_id and browser_session_id in TOKEN_STORE)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    await _cleanup_pending_auths()
    browser_session_id, needs_cookie = _ensure_browser_session_id(request)
    if browser_session_id in TOKEN_STORE:
        return RedirectResponse(url="/dashboard", status_code=303)

    response = templates.TemplateResponse(
        request=request,
        name="login.html",
        context={},
    )
    if needs_cookie:
        _set_browser_cookie(response, browser_session_id)
    return response


@app.head("/")
def index_head():
    return Response(status_code=200)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.head("/healthz")
def healthz_head():
    return Response(status_code=200)


@app.get("/api/session")
async def session_status(request: Request):
    await _cleanup_pending_auths()
    browser_session_id = _browser_session_id(request)
    stored_tokens = TOKEN_STORE.get(browser_session_id) if browser_session_id else None
    pending = _pending_status_for_browser(browser_session_id)

    return {
        "connected": stored_tokens is not None,
        "email": stored_tokens.email if stored_tokens else None,
        "pending_mfa": pending is not None,
        "pending": pending,
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    await _cleanup_pending_auths()
    if not _browser_has_tokens(request):
        return RedirectResponse(url="/", status_code=303)

    browser_session_id = _browser_session_id(request)
    stored_tokens = TOKEN_STORE.get(browser_session_id) if browser_session_id else None
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "email": stored_tokens.email if stored_tokens else "",
        },
    )


@app.post("/api/connect")
async def connect_garmin(payload: GarminLoginRequest, request: Request):
    await _cleanup_pending_auths()
    browser_session_id, needs_cookie = _ensure_browser_session_id(request)
    await _clear_browser_auth(browser_session_id)

    try:
        async with GARTH_AUTH_LOCK:
            login_result = await asyncio.to_thread(
                garth.login,
                payload.email,
                payload.password,
                return_on_mfa=True,
            )

        if (
            isinstance(login_result, tuple)
            and len(login_result) == 2
            and login_result[0] == "needs_mfa"
        ):
            pending_id = secrets.token_urlsafe(24)
            PENDING_AUTHS[pending_id] = PendingAuth(
                browser_session_id=browser_session_id,
                email=payload.email,
                mfa_state=login_result[1],
                created_at=_now(),
            )
            response = JSONResponse(
                status_code=202,
                content={
                    "status": "mfa_required",
                    "pending_id": pending_id,
                    "message": "Enter the MFA code from Garmin Connect.",
                },
            )
            if needs_cookie:
                _set_browser_cookie(response, browser_session_id)
            return response

        oauth1_token, oauth2_token = _extract_garth_tokens(login_result)
        TOKEN_STORE[browser_session_id] = StoredTokens(
            email=payload.email,
            oauth1_token=oauth1_token,
            oauth2_token=oauth2_token,
            connected_at=_now(),
        )
        response = JSONResponse({"status": "connected", "email": payload.email})
        if needs_cookie:
            _set_browser_cookie(response, browser_session_id)
        return response
    except Exception as exc:
        if type(exc).__name__ in {"GarminConnectAuthenticationError", "GarthHTTPError", "GarthException"}:
            raise HTTPException(
                status_code=401,
                detail="Garmin authentication failed. Check your email and password.",
            ) from exc

        logger.exception("Garmin sign-in failed")
        raise HTTPException(
            status_code=502,
            detail=f"Garmin sign-in failed: {type(exc).__name__}",
        ) from exc


@app.post("/api/connect/mfa")
async def complete_garmin_mfa(payload: GarminMfaRequest, request: Request):
    await _cleanup_pending_auths()
    browser_session_id, needs_cookie = _ensure_browser_session_id(request)
    pending = PENDING_AUTHS.get(payload.pending_id)

    if not pending:
        raise HTTPException(status_code=404, detail="MFA session expired. Start sign-in again.")

    if pending.browser_session_id != browser_session_id:
        raise HTTPException(status_code=403, detail="This MFA session belongs to a different browser session.")

    try:
        async with GARTH_AUTH_LOCK:
            result = await asyncio.to_thread(
                garth.resume_login,
                pending.mfa_state,
                payload.code,
            )

        oauth1_token, oauth2_token = _extract_garth_tokens(result)

        TOKEN_STORE[browser_session_id] = StoredTokens(
            email=pending.email,
            oauth1_token=oauth1_token,
            oauth2_token=oauth2_token,
            connected_at=_now(),
        )
        await _close_pending_auth(payload.pending_id)
        response = JSONResponse({"status": "connected", "email": pending.email})
        if needs_cookie:
            _set_browser_cookie(response, browser_session_id)
        return response
    except HTTPException:
        raise
    except Exception as exc:
        if type(exc).__name__ in {"GarminConnectAuthenticationError", "GarminMFACodeError", "GarminAuthError", "GarthException"}:
            raise HTTPException(status_code=401, detail="The MFA code was not accepted.") from exc

        logger.exception("Garmin MFA completion failed")
        raise HTTPException(
            status_code=502,
            detail=f"Garmin MFA completion failed: {type(exc).__name__}",
        ) from exc


@app.post("/api/logout")
async def logout(request: Request):
    browser_session_id = _browser_session_id(request)
    if browser_session_id:
        await _clear_browser_auth(browser_session_id)
    response = JSONResponse({"status": "signed_out"})
    response.delete_cookie(COOKIE_NAME)
    return response


@app.get("/today")
async def today(request: Request):
    return await _with_client(lambda client: client.get_user_summary(), request=request)


@app.get("/sleep")
async def sleep(request: Request):
    async def fetch_sleep(client: GarminClient) -> Any:
        core_data = await client.fetch_core_data()
        return _extract(core_data, "sleep", "sleepData", "sleep_data")

    return await _with_client(fetch_sleep, request=request)


@app.get("/activities")
async def activities(request: Request):
    async def fetch_activities(client: GarminClient) -> Any:
        activity_data = await client.fetch_activity_data()
        activities_list = _extract(activity_data, "activities", "activityData", "activity_data")
        if isinstance(activities_list, list):
            return activities_list[:5]
        return activity_data

    return await _with_client(fetch_activities, request=request)
