import asyncio
import base64
import json
import logging
import os
import pickle
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable

import aiohttp
import garth
from aiogarmin import GarminAuth, GarminClient
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from garth.sso import resume_login as garth_resume_login
from pydantic import BaseModel

load_dotenv()

app = FastAPI()
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger(__name__)

COOKIE_NAME = "garmin_session"
PENDING_AUTH_TTL_SECONDS = 10 * 60
TOKEN_DB_PATH = os.getenv("GARMIN_STATE_DB_PATH", "/tmp/garmin_state.db")
CONTEXT_CACHE_TTL_SECONDS = int(os.getenv("GARMIN_CONTEXT_CACHE_TTL_SECONDS", "300"))
APP_ROOT = Path(__file__).resolve().parent
LOGO_PATH = APP_ROOT / "templates" / "logo.png"


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


class GarminChatRequest(BaseModel):
    question: str


class GarminHistorySyncRequest(BaseModel):
    days: int = 45
    offset_days: int = 0


TOKEN_STORE: dict[str, StoredTokens] = {}
PENDING_AUTHS: dict[str, PendingAuth] = {}
GARTH_AUTH_LOCK = asyncio.Lock()
TOKEN_DB_LOCK = threading.Lock()
TREND_WINDOWS: tuple[tuple[str, str, int | None, int | None], ...] = (
    ("7d", "Last 7 days", 7, None),
    ("30d", "Last 30 days", 30, None),
    ("90d", "Last 90 days", 90, None),
    ("3m", "Last 3 months", None, 3),
    ("6m", "Last 6 months", None, 6),
    ("9m", "Last 9 months", None, 9),
    ("12m", "Last 12 months", None, 12),
)


def _init_token_db() -> None:
    db_dir = os.path.dirname(TOKEN_DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    with TOKEN_DB_LOCK:
        with sqlite3.connect(TOKEN_DB_PATH) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS browser_tokens (
                    browser_session_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL,
                    oauth1_token_json TEXT NOT NULL,
                    oauth2_token_json TEXT NOT NULL,
                    connected_at REAL NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS metric_snapshots (
                    email TEXT NOT NULL,
                    calendar_date TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(email, calendar_date)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS context_cache (
                    email TEXT NOT NULL,
                    cache_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(email, cache_key)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS daily_notifications (
                    email TEXT NOT NULL,
                    notification_date TEXT NOT NULL,
                    notification_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    metric_key TEXT,
                    severity TEXT NOT NULL,
                    dismissed_at REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(email, notification_id)
                )
                """
            )
            connection.commit()


def _now() -> float:
    return time.time()


def _browser_session_id(request: Request) -> str | None:
    return request.cookies.get(COOKIE_NAME)


def _ensure_browser_session_id(request: Request) -> tuple[str, bool]:
    browser_session_id = _browser_session_id(request)
    if browser_session_id:
        return browser_session_id, False
    return secrets.token_urlsafe(24), True


def _cookie_secure(request: Request) -> bool:
    configured = os.getenv("GARMIN_COOKIE_SECURE", "auto").strip().lower()
    if configured in {"1", "true", "yes", "on"}:
        return True
    if configured in {"0", "false", "no", "off"}:
        return False
    return request.url.scheme == "https"


def _set_browser_cookie(request: Request, response: Response, browser_session_id: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=browser_session_id,
        httponly=True,
        secure=_cookie_secure(request),
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
    _delete_browser_tokens(browser_session_id)
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


def _token_to_dict(token: Any) -> dict[str, Any] | None:
    if isinstance(token, dict):
        return token
    if hasattr(token, "model_dump"):
        return token.model_dump()
    if hasattr(token, "dict"):
        return token.dict()
    if hasattr(token, "__dict__"):
        return {
            key: value
            for key, value in vars(token).items()
            if not key.startswith("_")
        }
    return None


def _serialize_token(token: dict[str, Any]) -> str:
    try:
        return f"json:{json.dumps(token)}"
    except TypeError:
        payload = pickle.dumps(token, protocol=pickle.HIGHEST_PROTOCOL)
        return f"pickle:{base64.b64encode(payload).decode('ascii')}"


def _deserialize_token(raw: str) -> dict[str, Any]:
    if raw.startswith("json:"):
        return json.loads(raw[5:])
    if raw.startswith("pickle:"):
        payload = base64.b64decode(raw[7:].encode("ascii"))
        return pickle.loads(payload)
    return json.loads(raw)


def _save_browser_tokens(browser_session_id: str, stored_tokens: StoredTokens) -> None:
    oauth1_serialized = _serialize_token(stored_tokens.oauth1_token)
    oauth2_serialized = _serialize_token(stored_tokens.oauth2_token)
    TOKEN_STORE[browser_session_id] = stored_tokens
    with TOKEN_DB_LOCK:
        with sqlite3.connect(TOKEN_DB_PATH) as connection:
            connection.execute(
                """
                INSERT INTO browser_tokens (
                    browser_session_id,
                    email,
                    oauth1_token_json,
                    oauth2_token_json,
                    connected_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(browser_session_id) DO UPDATE SET
                    email = excluded.email,
                    oauth1_token_json = excluded.oauth1_token_json,
                    oauth2_token_json = excluded.oauth2_token_json,
                    connected_at = excluded.connected_at
                """,
                (
                    browser_session_id,
                    stored_tokens.email,
                    oauth1_serialized,
                    oauth2_serialized,
                    stored_tokens.connected_at,
                ),
            )
            connection.commit()


def _load_browser_tokens(browser_session_id: str | None) -> StoredTokens | None:
    if not browser_session_id:
        return None

    cached = TOKEN_STORE.get(browser_session_id)
    if cached is not None:
        return cached

    with TOKEN_DB_LOCK:
        with sqlite3.connect(TOKEN_DB_PATH) as connection:
            row = connection.execute(
                """
                SELECT email, oauth1_token_json, oauth2_token_json, connected_at
                FROM browser_tokens
                WHERE browser_session_id = ?
                """,
                (browser_session_id,),
            ).fetchone()

    if row is None:
        return None

    stored_tokens = StoredTokens(
        email=row[0],
        oauth1_token=_deserialize_token(row[1]),
        oauth2_token=_deserialize_token(row[2]),
        connected_at=float(row[3]),
    )
    TOKEN_STORE[browser_session_id] = stored_tokens
    return stored_tokens


def _delete_browser_tokens(browser_session_id: str) -> None:
    TOKEN_STORE.pop(browser_session_id, None)
    with TOKEN_DB_LOCK:
        with sqlite3.connect(TOKEN_DB_PATH) as connection:
            connection.execute(
                "DELETE FROM browser_tokens WHERE browser_session_id = ?",
                (browser_session_id,),
            )
            connection.commit()


def _extract_auth_tokens(auth: GarminAuth) -> tuple[dict[str, Any], dict[str, Any]] | None:
    oauth1_token = _token_to_dict(getattr(auth, "oauth1_token", None))
    oauth2_token = _token_to_dict(getattr(auth, "oauth2_token", None))
    if oauth1_token and oauth2_token:
        return oauth1_token, oauth2_token
    return None


_init_token_db()


def _extract_garth_tokens(result: Any = None) -> tuple[dict[str, Any], dict[str, Any]]:
    if (
        isinstance(result, tuple)
        and len(result) == 2
    ):
        oauth1_token = _token_to_dict(result[0])
        oauth2_token = _token_to_dict(result[1])
        if oauth1_token and oauth2_token:
            return oauth1_token, oauth2_token

    client = getattr(garth, "client", None)
    oauth1_token = _token_to_dict(getattr(client, "oauth1_token", None))
    oauth2_token = _token_to_dict(getattr(client, "oauth2_token", None))

    if oauth1_token and oauth2_token:
        return oauth1_token, oauth2_token

    raise HTTPException(
        status_code=502,
        detail="Garmin login succeeded but OAuth tokens were not available.",
    )


def _stored_tokens_for_request(request: Request | None) -> StoredTokens | None:
    if request is None:
        return _env_tokens()

    browser_session_id = _browser_session_id(request)
    stored_tokens = _load_browser_tokens(browser_session_id)
    if stored_tokens is not None:
        return stored_tokens

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
    browser_session_id = _browser_session_id(request) if request is not None else None
    stored_tokens = _stored_tokens_for_request(request)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            auth = await _build_auth(session, request=request)
            client = GarminClient(session, auth)
            result = await operation(client)
            if browser_session_id and stored_tokens is not None:
                refreshed_tokens = _extract_auth_tokens(auth)
                if refreshed_tokens is not None:
                    oauth1_token, oauth2_token = refreshed_tokens
                    _save_browser_tokens(
                        browser_session_id,
                        StoredTokens(
                            email=stored_tokens.email,
                            oauth1_token=oauth1_token,
                            oauth2_token=oauth2_token,
                            connected_at=stored_tokens.connected_at,
                        ),
                    )
            return result
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


def _garmin_retry_after_seconds(response: Any) -> int:
    default_retry_after = 1800
    headers = getattr(response, "headers", None)
    if headers is None:
        return default_retry_after

    retry_after = headers.get("Retry-After")
    if retry_after is None:
        return default_retry_after

    try:
        return max(60, int(retry_after))
    except (TypeError, ValueError):
        return default_retry_after


def _response_status_code(response: Any) -> int | None:
    status_code = getattr(response, "status_code", None)
    if status_code is not None:
        return status_code
    return getattr(response, "status", None)


def _response_text(response: Any) -> str:
    text = getattr(response, "text", "")
    if callable(text):
        try:
            text = text()
        except TypeError:
            text = ""
    return (text or "").strip()


def _shift_months(anchor: date, months: int) -> date:
    year = anchor.year
    month = anchor.month - months

    while month <= 0:
        month += 12
        year -= 1

    day = min(
        anchor.day,
        [31, 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1],
    )
    return date(year, month, day)


def _window_start(anchor: date, days: int | None = None, months: int | None = None) -> date:
    if days is not None:
        return anchor - timedelta(days=days - 1)
    if months is not None:
        return _shift_months(anchor, months)
    return anchor


def _coerce_date(value: Any) -> date | None:
    if isinstance(value, date):
        return value
    if not value:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized).date()
        except ValueError:
            try:
                return datetime.strptime(value[:10], "%Y-%m-%d").date()
            except ValueError:
                return None
    return None


def _coerce_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _coerce_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _format_minutes(value: Any) -> str | None:
    minutes = _coerce_int(value)
    if minutes <= 0:
        return None
    hours, remaining_minutes = divmod(minutes, 60)
    if hours and remaining_minutes:
        return f"{hours}h {remaining_minutes}m"
    if hours:
        return f"{hours}h"
    return f"{remaining_minutes}m"


def _format_km(value: Any) -> str | None:
    km = _coerce_float(value)
    if km <= 0:
        return None
    return f"{km:.1f} km"


def _format_ml(value: Any) -> str | None:
    ml = _coerce_int(value)
    if ml <= 0:
        return None
    if ml >= 1000:
        return f"{ml / 1000:.1f} L"
    return f"{ml} ml"


def _first_present(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _humanize_token(value: Any) -> str | None:
    if value in (None, "", [], {}):
        return None
    text = str(value).replace("_", " ").strip()
    if not text:
        return None
    return text.title()


def _extract_activity_type(activity: dict[str, Any]) -> str:
    activity_type = activity.get("activityType")
    if isinstance(activity_type, dict):
        for key in ("typeKey", "parentTypeKey", "displayOrder"):
            value = activity_type.get(key)
            if value:
                return str(value)

    for key in ("activityTypeDTO", "activityTypeKey", "typeKey", "activityName"):
        value = activity.get(key)
        if value:
            return str(value)

    return "unknown"


def _normalize_activities(raw_activities: Any) -> list[dict[str, Any]]:
    if isinstance(raw_activities, dict):
        raw_items = _extract(raw_activities, "activities", "activityData", "activity_data") or []
    elif isinstance(raw_activities, list):
        raw_items = raw_activities
    else:
        raw_items = []

    normalized: list[dict[str, Any]] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue

        activity_date = (
            _coerce_date(item.get("startTimeLocal"))
            or _coerce_date(item.get("startTimeGMT"))
            or _coerce_date(item.get("calendarDate"))
            or _coerce_date(item.get("date"))
        )
        if not activity_date:
            continue

        normalized.append(
            {
                "date": activity_date,
                "type": _extract_activity_type(item),
                "distance_km": _coerce_float(item.get("distance")) / 1000,
                "duration_min": _coerce_float(item.get("duration")) / 60,
                "moving_duration_min": _coerce_float(item.get("movingDuration")) / 60,
                "calories": _coerce_float(item.get("calories")),
                "elevation_gain_m": _coerce_float(item.get("elevationGain")),
                "average_hr": _coerce_float(item.get("averageHR") or item.get("averageHr")),
            }
        )
    return normalized


def _normalize_steps(raw_steps: Any) -> dict[date, int]:
    if isinstance(raw_steps, dict):
        raw_items = _extract(raw_steps, "dailySteps", "steps", "stepData") or []
    elif isinstance(raw_steps, list):
        raw_items = raw_steps
    else:
        raw_items = []

    normalized: dict[date, int] = {}
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        item_date = _coerce_date(item.get("calendarDate") or item.get("date"))
        if not item_date:
            continue
        step_total = _coerce_int(
            item.get("totalSteps")
            or item.get("steps")
            or item.get("value")
        )
        normalized[item_date] = step_total
    return normalized


def _top_activity_types(activities: list[dict[str, Any]], limit: int = 3) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for activity in activities:
        activity_type = activity["type"]
        counts[activity_type] = counts.get(activity_type, 0) + 1

    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [{"type": activity_type, "count": count} for activity_type, count in ranked[:limit]]


def _aggregate_window(
    label: str,
    title: str,
    start: date,
    end: date,
    activities: list[dict[str, Any]],
    daily_steps: dict[date, int],
) -> dict[str, Any]:
    activity_slice = [activity for activity in activities if start <= activity["date"] <= end]
    steps_slice = {day: steps for day, steps in daily_steps.items() if start <= day <= end}

    window_days = (end - start).days + 1
    active_days = len({activity["date"] for activity in activity_slice})
    total_steps = sum(steps_slice.values())
    total_distance_km = round(sum(activity["distance_km"] for activity in activity_slice), 2)
    total_duration_min = round(sum(activity["duration_min"] for activity in activity_slice), 1)
    total_moving_duration_min = round(sum(activity["moving_duration_min"] for activity in activity_slice), 1)
    total_calories = round(sum(activity["calories"] for activity in activity_slice), 1)
    total_elevation_gain_m = round(sum(activity["elevation_gain_m"] for activity in activity_slice), 1)
    best_step_day = max(steps_slice.values(), default=0)
    avg_hr_values = [activity["average_hr"] for activity in activity_slice if activity["average_hr"] > 0]

    return {
        "label": label,
        "title": title,
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "window_days": window_days,
        "steps": {
            "total": total_steps,
            "daily_average": round(total_steps / window_days, 1) if window_days else 0,
            "best_day": best_step_day,
        },
        "activities": {
            "count": len(activity_slice),
            "active_days": active_days,
            "active_day_ratio": round(active_days / window_days, 3) if window_days else 0,
            "total_distance_km": total_distance_km,
            "total_duration_min": total_duration_min,
            "total_moving_duration_min": total_moving_duration_min,
            "total_calories": total_calories,
            "total_elevation_gain_m": total_elevation_gain_m,
            "average_distance_km": round(total_distance_km / len(activity_slice), 2) if activity_slice else 0,
            "average_duration_min": round(total_duration_min / len(activity_slice), 1) if activity_slice else 0,
            "average_heart_rate": round(sum(avg_hr_values) / len(avg_hr_values), 1) if avg_hr_values else 0,
            "top_activity_types": _top_activity_types(activity_slice),
        },
    }


def _build_trend_insights(windows: dict[str, dict[str, Any]]) -> list[str]:
    insights: list[str] = []
    recent = windows.get("7d")
    medium = windows.get("30d")
    long = windows.get("90d")
    yearly = windows.get("12m")

    if recent and medium:
        recent_steps = recent["steps"]["daily_average"]
        medium_steps = medium["steps"]["daily_average"]
        if medium_steps > 0:
            change = (recent_steps - medium_steps) / medium_steps
            if change >= 0.15:
                insights.append("Your last 7 days are materially above your 30-day step baseline.")
            elif change <= -0.15:
                insights.append("Your last 7 days are materially below your 30-day step baseline.")

        recent_activity_density = recent["activities"]["active_day_ratio"]
        medium_activity_density = medium["activities"]["active_day_ratio"]
        if recent_activity_density - medium_activity_density >= 0.15:
            insights.append("Training frequency accelerated over the last 7 days versus the last 30 days.")
        elif medium_activity_density - recent_activity_density >= 0.15:
            insights.append("Training frequency slowed over the last 7 days versus the last 30 days.")

    if medium and long:
        medium_distance_rate = medium["activities"]["total_distance_km"] / max(1, medium["window_days"])
        long_distance_rate = long["activities"]["total_distance_km"] / max(1, long["window_days"])
        if long_distance_rate > 0:
            change = (medium_distance_rate - long_distance_rate) / long_distance_rate
            if change >= 0.15:
                insights.append("Your last 30 days show a higher training volume than your 90-day baseline.")
            elif change <= -0.15:
                insights.append("Your last 30 days show a lower training volume than your 90-day baseline.")

    if yearly:
        top_types = yearly["activities"]["top_activity_types"]
        if top_types:
            insights.append(f"Your dominant activity over the last 12 months is {top_types[0]['type']}.")

    if not insights:
        insights.append("No strong directional pattern stands out yet from the current windows.")

    return insights


def _deep_find_first(data: Any, keys: set[str]) -> Any:
    if isinstance(data, dict):
        for key, value in data.items():
            if key in keys and value not in (None, "", [], {}):
                return value
        for value in data.values():
            found = _deep_find_first(value, keys)
            if found not in (None, "", [], {}):
                return found
    elif isinstance(data, list):
        for item in data:
            found = _deep_find_first(item, keys)
            if found not in (None, "", [], {}):
                return found
    return None


def _deep_find_numeric_key_fragment(
    data: Any,
    include_fragments: tuple[str, ...],
    exclude_fragments: tuple[str, ...] = ("threshold", "warning", "low", "min"),
) -> Any:
    if isinstance(data, dict):
        for key, value in data.items():
            normalized_key = key.lower()
            if (
                any(fragment in normalized_key for fragment in include_fragments)
                and not any(fragment in normalized_key for fragment in exclude_fragments)
            ):
                try:
                    numeric_value = float(value)
                except (TypeError, ValueError):
                    numeric_value = None
                if numeric_value is not None and 0 <= numeric_value <= 100:
                    return value
        for value in data.values():
            found = _deep_find_numeric_key_fragment(value, include_fragments, exclude_fragments)
            if found not in (None, "", [], {}):
                return found
    elif isinstance(data, list):
        for item in data:
            found = _deep_find_numeric_key_fragment(item, include_fragments, exclude_fragments)
            if found not in (None, "", [], {}):
                return found
    return None


def _source_payload(bundle: dict[str, Any], source_name: str) -> Any:
    source = bundle.get(source_name, {})
    if isinstance(source, dict) and source.get("available"):
        return source.get("data")
    return None


def _source_inventory(bundle: dict[str, Any]) -> dict[str, list[str]]:
    available: list[str] = []
    unavailable: list[str] = []
    for name, source in bundle.items():
        if isinstance(source, dict) and source.get("available"):
            available.append(name)
        else:
            unavailable.append(name)
    return {
        "available": sorted(available),
        "unavailable": sorted(unavailable),
    }


def _training_status_payload_map(training_status_data: Any, *keys: str) -> dict[str, Any] | None:
    if not isinstance(training_status_data, dict):
        return None

    current: Any = training_status_data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key, {})

    if not isinstance(current, dict):
        return None

    candidates = [value for value in current.values() if isinstance(value, dict)]
    if not candidates:
        return None

    primary = next((value for value in candidates if value.get("primaryTrainingDevice")), None)
    return primary or candidates[0]


def _build_daily_snapshot(bundle: dict[str, Any], snapshot_date: date) -> dict[str, Any]:
    summary_data = _source_payload(bundle, "summary")
    daily_steps_today = _source_payload(bundle, "daily_steps_today")
    core_data = _source_payload(bundle, "core")
    body_data = _source_payload(bundle, "body")
    training_data = _source_payload(bundle, "training")
    training_readiness_data = _source_payload(bundle, "training_readiness")
    training_status_data = _source_payload(bundle, "training_status")
    hrv_data = _source_payload(bundle, "hrv")
    hydration_data = _source_payload(bundle, "hydration")
    fitness_age_data = _source_payload(bundle, "fitness_age")
    endurance_score_data = _source_payload(bundle, "endurance_score")
    hill_score_data = _source_payload(bundle, "hill_score")
    training_status_payload = _training_status_payload_map(
        training_status_data,
        "mostRecentTrainingStatus",
        "latestTrainingStatusData",
    )
    training_balance_payload = _training_status_payload_map(
        training_status_data,
        "mostRecentTrainingLoadBalance",
        "metricsTrainingLoadBalanceDTOMap",
    )
    hrv_summary = hrv_data.get("hrvSummary", {}) if isinstance(hrv_data, dict) else {}

    sleep_seconds = _first_present(
        core_data.get("sleepTimeSeconds") if isinstance(core_data, dict) else None,
        summary_data.get("sleepingSeconds") if isinstance(summary_data, dict) else None,
    )
    sleep_minutes = round(_coerce_float(sleep_seconds) / 60, 1) if sleep_seconds not in (None, "", [], {}) else None
    body_battery_current = _first_present(
        core_data.get("bodyBatteryMostRecentValue") if isinstance(core_data, dict) else None,
        summary_data.get("bodyBatteryMostRecentValue") if isinstance(summary_data, dict) else None,
        core_data.get("bodyBatteryAtWakeTime") if isinstance(core_data, dict) else None,
        summary_data.get("bodyBatteryAtWakeTime") if isinstance(summary_data, dict) else None,
        core_data.get("bodyBatteryChargedValue") if isinstance(core_data, dict) else None,
        summary_data.get("bodyBatteryChargedValue") if isinstance(summary_data, dict) else None,
    )

    return {
        "calendar_date": snapshot_date.isoformat(),
        "steps": _coerce_int(_first_present(
            _deep_find_first(daily_steps_today, {"totalSteps"}),
            summary_data.get("totalSteps") if isinstance(summary_data, dict) else None,
            core_data.get("totalSteps") if isinstance(core_data, dict) else None,
        )),
        "step_goal": _coerce_int(_first_present(
            _deep_find_first(daily_steps_today, {"stepGoal"}),
            summary_data.get("dailyStepGoal") if isinstance(summary_data, dict) else None,
            core_data.get("dailyStepGoal") if isinstance(core_data, dict) else None,
        )),
        "distance_m": _coerce_float(_first_present(
            _deep_find_first(daily_steps_today, {"totalDistance"}),
            summary_data.get("totalDistanceMeters") if isinstance(summary_data, dict) else None,
            core_data.get("totalDistanceMeters") if isinstance(core_data, dict) else None,
            summary_data.get("wellnessDistanceMeters") if isinstance(summary_data, dict) else None,
        )),
        "active_kcal": _coerce_float(_first_present(
            summary_data.get("activeKilocalories") if isinstance(summary_data, dict) else None,
            core_data.get("activeKilocalories") if isinstance(core_data, dict) else None,
        )),
        "resting_hr": _coerce_int(_first_present(
            summary_data.get("restingHeartRate") if isinstance(summary_data, dict) else None,
            core_data.get("restingHeartRate") if isinstance(core_data, dict) else None,
        )),
        "sleep_score": _coerce_int(_first_present(
            core_data.get("sleepScore") if isinstance(core_data, dict) else None,
            summary_data.get("sleepScore") if isinstance(summary_data, dict) else None,
        )),
        "sleep_minutes": sleep_minutes,
        "body_battery_current": _coerce_int(body_battery_current),
        "body_battery_at_wake": _coerce_int(_first_present(
            core_data.get("bodyBatteryAtWakeTime") if isinstance(core_data, dict) else None,
            summary_data.get("bodyBatteryAtWakeTime") if isinstance(summary_data, dict) else None,
        )),
        "body_battery_high": _coerce_int(_first_present(
            core_data.get("bodyBatteryHighestValue") if isinstance(core_data, dict) else None,
            summary_data.get("bodyBatteryHighestValue") if isinstance(summary_data, dict) else None,
        )),
        "body_battery_low": _coerce_int(_first_present(
            core_data.get("bodyBatteryLowestValue") if isinstance(core_data, dict) else None,
            summary_data.get("bodyBatteryLowestValue") if isinstance(summary_data, dict) else None,
        )),
        "stress_avg": _coerce_int(_first_present(
            summary_data.get("averageStressLevel") if isinstance(summary_data, dict) else None,
            core_data.get("averageStressLevel") if isinstance(core_data, dict) else None,
        )),
        "stress_max": _coerce_int(_first_present(
            summary_data.get("maxStressLevel") if isinstance(summary_data, dict) else None,
            core_data.get("maxStressLevel") if isinstance(core_data, dict) else None,
        )),
        "stress_qualifier": _humanize_token(_first_present(
            summary_data.get("stressQualifier") if isinstance(summary_data, dict) else None,
            core_data.get("stressQualifier") if isinstance(core_data, dict) else None,
        )),
        "intensity_minutes": _coerce_int(_first_present(
            summary_data.get("moderateIntensityMinutes") if isinstance(summary_data, dict) else None,
            core_data.get("moderateIntensityMinutes") if isinstance(core_data, dict) else None,
        )) + _coerce_int(_first_present(
            summary_data.get("vigorousIntensityMinutes") if isinstance(summary_data, dict) else None,
            core_data.get("vigorousIntensityMinutes") if isinstance(core_data, dict) else None,
        )),
        "spo2_latest": _coerce_int(_first_present(
            summary_data.get("latestSpo2") if isinstance(summary_data, dict) else None,
            core_data.get("latestSpo2") if isinstance(core_data, dict) else None,
        )),
        "spo2_average": _coerce_float(_first_present(
            summary_data.get("averageSpo2") if isinstance(summary_data, dict) else None,
            core_data.get("averageSpo2") if isinstance(core_data, dict) else None,
        )),
        "training_readiness": _first_present(
            _deep_find_first(training_readiness_data or training_data, {"trainingReadiness", "trainingReadinessScore", "readinessScore"}),
            _deep_find_first(training_readiness_data or training_data, {"score", "value"}),
        ),
        "training_status": _humanize_token(_first_present(
            training_status_payload.get("trainingStatusFeedbackPhrase") if training_status_payload else None,
            training_balance_payload.get("trainingBalanceFeedbackPhrase") if training_balance_payload else None,
            _deep_find_first(training_status_data or training_data, {"trainingStatusLabel", "trainingStatusText"}),
        )),
        "acute_load_ratio": _coerce_float(_deep_find_first(
            training_status_payload,
            {"dailyAcuteChronicWorkloadRatio"},
        )),
        "vo2max": _coerce_float(_deep_find_first(
            training_status_data,
            {"vo2MaxPreciseValue", "vo2MaxValue"},
        )),
        "hrv_status": _humanize_token(_first_present(
            hrv_summary.get("status") if isinstance(hrv_summary, dict) else None,
            hrv_summary.get("feedbackPhrase") if isinstance(hrv_summary, dict) else None,
        )),
        "hrv_last_night_avg": _coerce_int(hrv_summary.get("lastNightAvg") if isinstance(hrv_summary, dict) else None),
        "hrv_weekly_avg": _coerce_int(hrv_summary.get("weeklyAvg") if isinstance(hrv_summary, dict) else None),
        "hydration_ml": _coerce_int(_first_present(
            hydration_data.get("valueInML") if isinstance(hydration_data, dict) else None,
            body_data.get("valueInML") if isinstance(body_data, dict) else None,
        )),
        "hydration_goal_ml": _coerce_int(_first_present(
            hydration_data.get("goalInML") if isinstance(hydration_data, dict) else None,
            body_data.get("goalInML") if isinstance(body_data, dict) else None,
        )),
        "weight_kg": _coerce_float(_first_present(
            body_data.get("weightKg") if isinstance(body_data, dict) else None,
            body_data.get("weight") if isinstance(body_data, dict) else None,
            _deep_find_first(body_data, {"weightKg", "weight", "weightInKg", "weightKG"}),
        )),
        "body_fat_pct": _coerce_float(_first_present(
            body_data.get("bodyFat") if isinstance(body_data, dict) else None,
            _deep_find_first(body_data, {"bodyFat", "bodyFatPercent", "bodyFatPercentage"}),
        )),
        "fitness_age": _coerce_float(_first_present(
            body_data.get("fitnessAge") if isinstance(body_data, dict) else None,
            _deep_find_first(fitness_age_data or body_data, {"fitnessAge", "fitnessAgeValue", "value"}),
        )),
        "endurance_score": _coerce_float(_deep_find_first(endurance_score_data, {"score", "enduranceScore", "value"})),
        "hill_score": _coerce_float(_deep_find_first(hill_score_data, {"score", "hillScore", "value"})),
        "last_sync_time": _first_present(
            summary_data.get("lastSyncTimestampGMT") if isinstance(summary_data, dict) else None,
            summary_data.get("lastSyncTimestampLocal") if isinstance(summary_data, dict) else None,
        ),
    }


def _build_current_signals(bundle: dict[str, Any]) -> dict[str, Any]:
    snapshot = _build_daily_snapshot(bundle, date.today())
    stress_level = None
    if snapshot["stress_avg"] and snapshot["stress_qualifier"]:
        stress_level = f"{snapshot['stress_avg']} avg ({snapshot['stress_qualifier']})"
    elif snapshot["stress_avg"]:
        stress_level = snapshot["stress_avg"]
    elif snapshot["stress_qualifier"]:
        stress_level = snapshot["stress_qualifier"]

    hydration = None
    if snapshot["hydration_ml"] and snapshot["hydration_goal_ml"]:
        hydration = f"{_format_ml(snapshot['hydration_ml'])} of {_format_ml(snapshot['hydration_goal_ml'])}"
    elif snapshot["hydration_ml"]:
        hydration = _format_ml(snapshot["hydration_ml"])

    hrv_status = snapshot["hrv_status"]
    if snapshot["hrv_last_night_avg"] and snapshot["hrv_weekly_avg"]:
        hrv_status = f"{snapshot['hrv_status'] or 'HRV'} ({snapshot['hrv_last_night_avg']} last night vs {snapshot['hrv_weekly_avg']} weekly)"

    return {
        "steps_today": snapshot["steps"] or None,
        "body_battery": snapshot["body_battery_current"] or snapshot["body_battery_at_wake"] or None,
        "stress_level": stress_level,
        "resting_heart_rate": snapshot["resting_hr"] or None,
        "sleep_score": snapshot["sleep_score"] or None,
        "sleep_minutes": snapshot["sleep_minutes"],
        "training_readiness": snapshot["training_readiness"],
        "training_status": snapshot["training_status"],
        "hrv_status": hrv_status,
        "hydration": hydration,
        "weight_kg": snapshot["weight_kg"] or None,
        "fitness_age": snapshot["fitness_age"] or None,
        "endurance_score": snapshot["endurance_score"] or None,
        "hill_score": snapshot["hill_score"] or None,
        "vo2max": snapshot["vo2max"] or None,
        "stress_avg": snapshot["stress_avg"] or None,
    }


def _save_metric_snapshot(email: str, snapshot: dict[str, Any]) -> None:
    calendar_date = str(snapshot.get("calendar_date"))
    with TOKEN_DB_LOCK:
        with sqlite3.connect(TOKEN_DB_PATH) as connection:
            connection.execute(
                """
                INSERT INTO metric_snapshots (email, calendar_date, snapshot_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(email, calendar_date) DO UPDATE SET
                    snapshot_json = excluded.snapshot_json,
                    updated_at = excluded.updated_at
                """,
                (
                    email,
                    calendar_date,
                    json.dumps(snapshot, default=str),
                    _now(),
                ),
            )
            connection.commit()


def _save_context_cache(email: str, cache_key: str, payload: dict[str, Any]) -> None:
    with TOKEN_DB_LOCK:
        with sqlite3.connect(TOKEN_DB_PATH) as connection:
            connection.execute(
                """
                INSERT INTO context_cache (email, cache_key, payload_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(email, cache_key) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at
                """,
                (
                    email,
                    cache_key,
                    json.dumps(payload, default=str),
                    _now(),
                ),
            )
            connection.commit()


def _load_context_cache(email: str, cache_key: str, max_age_seconds: int = CONTEXT_CACHE_TTL_SECONDS) -> dict[str, Any] | None:
    with TOKEN_DB_LOCK:
        with sqlite3.connect(TOKEN_DB_PATH) as connection:
            row = connection.execute(
                """
                SELECT payload_json, updated_at
                FROM context_cache
                WHERE email = ? AND cache_key = ?
                """,
                (email, cache_key),
            ).fetchone()

    if row is None:
        return None

    updated_at = float(row[1])
    if _now() - updated_at > max_age_seconds:
        return None

    return json.loads(row[0])


def _load_metric_snapshots(email: str, start_date: date, end_date: date) -> list[dict[str, Any]]:
    with TOKEN_DB_LOCK:
        with sqlite3.connect(TOKEN_DB_PATH) as connection:
            rows = connection.execute(
                """
                SELECT snapshot_json
                FROM metric_snapshots
                WHERE email = ? AND calendar_date BETWEEN ? AND ?
                ORDER BY calendar_date ASC
                """,
                (email, start_date.isoformat(), end_date.isoformat()),
            ).fetchall()

    return [json.loads(row[0]) for row in rows]


def _summarize_snapshot_metric(snapshots: list[dict[str, Any]], key: str) -> dict[str, Any]:
    series = [snapshot[key] for snapshot in snapshots if snapshot.get(key) not in (None, "")]
    if not series:
        return {"count": 0, "latest": None, "average": None, "min": None, "max": None}

    numeric_values = [float(value) for value in series]
    return {
        "count": len(numeric_values),
        "latest": round(numeric_values[-1], 1),
        "average": round(sum(numeric_values) / len(numeric_values), 1),
        "min": round(min(numeric_values), 1),
        "max": round(max(numeric_values), 1),
    }


def _build_health_history_windows(snapshots: list[dict[str, Any]], today: date) -> dict[str, dict[str, Any]]:
    by_date = {
        _coerce_date(snapshot.get("calendar_date")): snapshot
        for snapshot in snapshots
        if _coerce_date(snapshot.get("calendar_date")) is not None
    }
    windows: dict[str, dict[str, Any]] = {}

    for label, title, days, months in TREND_WINDOWS:
        start = _window_start(today, days=days, months=months)
        window_snapshots = [
            snapshot
            for day, snapshot in by_date.items()
            if day is not None and start <= day <= today
        ]
        windows[label] = {
            "label": label,
            "title": title,
            "start_date": start.isoformat(),
            "end_date": today.isoformat(),
            "days_covered": len(window_snapshots),
            "steps": _summarize_snapshot_metric(window_snapshots, "steps"),
            "active_kcal": _summarize_snapshot_metric(window_snapshots, "active_kcal"),
            "sleep_score": _summarize_snapshot_metric(window_snapshots, "sleep_score"),
            "sleep_minutes": _summarize_snapshot_metric(window_snapshots, "sleep_minutes"),
            "body_battery": _summarize_snapshot_metric(window_snapshots, "body_battery_current"),
            "stress": _summarize_snapshot_metric(window_snapshots, "stress_avg"),
            "resting_hr": _summarize_snapshot_metric(window_snapshots, "resting_hr"),
            "training_readiness": _summarize_snapshot_metric(window_snapshots, "training_readiness"),
            "vo2max": _summarize_snapshot_metric(window_snapshots, "vo2max"),
            "hrv_last_night_avg": _summarize_snapshot_metric(window_snapshots, "hrv_last_night_avg"),
            "hydration_ml": _summarize_snapshot_metric(window_snapshots, "hydration_ml"),
            "weight_kg": _summarize_snapshot_metric(window_snapshots, "weight_kg"),
            "body_fat_pct": _summarize_snapshot_metric(window_snapshots, "body_fat_pct"),
            "fitness_age": _summarize_snapshot_metric(window_snapshots, "fitness_age"),
            "endurance_score": _summarize_snapshot_metric(window_snapshots, "endurance_score"),
            "hill_score": _summarize_snapshot_metric(window_snapshots, "hill_score"),
            "spo2_average": _summarize_snapshot_metric(window_snapshots, "spo2_average"),
            "intensity_minutes": _summarize_snapshot_metric(window_snapshots, "intensity_minutes"),
        }

    return windows


def _build_health_history_insights(windows: dict[str, dict[str, Any]]) -> list[str]:
    insights: list[str] = []
    short = windows.get("7d", {})
    medium = windows.get("30d", {})

    short_sleep = short.get("sleep_score", {}).get("average")
    medium_sleep = medium.get("sleep_score", {}).get("average")
    if short_sleep is not None and medium_sleep not in (None, 0):
        delta = short_sleep - medium_sleep
        if delta >= 5:
            insights.append("Sleep score is running above your 30-day baseline over the last 7 days.")
        elif delta <= -5:
            insights.append("Sleep score is running below your 30-day baseline over the last 7 days.")

    short_stress = short.get("stress", {}).get("average")
    medium_stress = medium.get("stress", {}).get("average")
    if short_stress is not None and medium_stress not in (None, 0):
        delta = short_stress - medium_stress
        if delta >= 5:
            insights.append("Average stress has been elevated versus your 30-day baseline.")
        elif delta <= -5:
            insights.append("Average stress has been lower than your 30-day baseline.")

    short_battery = short.get("body_battery", {}).get("average")
    medium_battery = medium.get("body_battery", {}).get("average")
    if short_battery is not None and medium_battery not in (None, 0):
        delta = short_battery - medium_battery
        if delta >= 5:
            insights.append("Body Battery has been stronger than usual over the last 7 days.")
        elif delta <= -5:
            insights.append("Body Battery has been softer than your 30-day baseline lately.")

    short_rhr = short.get("resting_hr", {}).get("average")
    medium_rhr = medium.get("resting_hr", {}).get("average")
    if short_rhr is not None and medium_rhr not in (None, 0):
        delta = short_rhr - medium_rhr
        if delta >= 3:
            insights.append("Resting heart rate is running above baseline, which can point to accumulated strain.")
        elif delta <= -3:
            insights.append("Resting heart rate is below baseline, which can point to fresher recovery.")

    short_vo2 = short.get("vo2max", {}).get("average")
    medium_vo2 = medium.get("vo2max", {}).get("average")
    if short_vo2 is not None and medium_vo2 not in (None, 0):
        delta = short_vo2 - medium_vo2
        if delta >= 0.5:
            insights.append("VO2 max has been trending above your 30-day baseline.")
        elif delta <= -0.5:
            insights.append("VO2 max has softened versus your 30-day baseline.")

    return insights


def _build_history_context(email: str | None, today: date) -> dict[str, Any]:
    if not email:
        return {
            "available": False,
            "coverage_start": None,
            "latest_date": None,
            "days_available": 0,
            "windows": {},
            "insights": [],
        }

    oldest_start = min(_window_start(today, days=days, months=months) for _, _, days, months in TREND_WINDOWS)
    snapshots = _load_metric_snapshots(email, oldest_start, today)
    windows = _build_health_history_windows(snapshots, today) if snapshots else {}
    return {
        "available": bool(snapshots),
        "coverage_start": snapshots[0]["calendar_date"] if snapshots else None,
        "latest_date": snapshots[-1]["calendar_date"] if snapshots else None,
        "days_available": len(snapshots),
        "windows": windows,
        "insights": _build_health_history_insights(windows) if windows else [],
    }


def _warning_message(code: str, language: str = "en") -> str:
    mapping = {
        "activity_history_unavailable": {
            "en": "Recent activity history from Garmin is incomplete right now, so training trends may be understated.",
            "ro": "Istoricul recent al activităților din Garmin este incomplet acum, deci trendurile de antrenament pot fi subestimate.",
        },
        "step_history_unavailable": {
            "en": "Step history from Garmin is partially unavailable right now, so movement trends may be less reliable.",
            "ro": "Istoricul pașilor din Garmin este parțial indisponibil acum, deci trendurile de mișcare pot fi mai puțin fiabile.",
        },
    }
    prefix = code.split(":", 1)[0]
    return mapping.get(prefix, {}).get(language) or mapping.get(prefix, {}).get("en") or code


def _present_warnings(warnings: list[str], language: str = "en") -> list[str]:
    seen: set[str] = set()
    presented: list[str] = []
    for code in warnings:
        if code.startswith("step_history_unavailable") or code.startswith("activity_history_unavailable"):
            continue
        message = _warning_message(code, language)
        if message not in seen:
            seen.add(message)
            presented.append(message)
    return presented


def _notification_id(notification_date: date, metric_key: str) -> str:
    return f"{notification_date.isoformat()}:{metric_key}"


def _build_daily_notifications(
    full_context_data: dict[str, Any],
    trend_data: dict[str, Any],
    history_context: dict[str, Any],
    notification_date: date,
) -> list[dict[str, Any]]:
    snapshot = _build_daily_snapshot(full_context_data, notification_date)
    baseline = history_context.get("windows", {}).get("30d", {})
    notifications: list[dict[str, Any]] = []

    def add(metric_key: str, title: str, body: str, severity: str = "info") -> None:
        notifications.append(
            {
                "notification_id": _notification_id(notification_date, metric_key),
                "notification_date": notification_date.isoformat(),
                "metric_key": metric_key,
                "title": title,
                "body": body,
                "severity": severity,
            }
        )

    sleep_score = snapshot.get("sleep_score")
    sleep_baseline = baseline.get("sleep_score", {}).get("average")
    if sleep_score and sleep_baseline not in (None, 0):
        delta = sleep_score - sleep_baseline
        if delta >= 5:
            add(
                "sleep_trend",
                "Sleep is supporting recovery today",
                f"Your sleep score is {sleep_score}, about {delta:.0f} points above your 30-day baseline. Overnight recovery looked better than usual, so today starts from a stronger place.",
                "positive",
            )
        elif delta <= -5:
            add(
                "sleep_trend",
                "Sleep came in below your recent norm",
                f"Your sleep score is {sleep_score}, about {abs(delta):.0f} points below your 30-day baseline. Recovery may be softer than usual, so a lighter day could make more sense.",
                "caution",
            )

    body_battery = snapshot.get("body_battery_current") or snapshot.get("body_battery_at_wake")
    battery_baseline = baseline.get("body_battery", {}).get("average")
    if body_battery and battery_baseline not in (None, 0):
        delta = body_battery - battery_baseline
        if delta >= 5:
            add(
                "body_battery",
                "Body Battery is stronger than usual",
                f"Body Battery is at {body_battery}, roughly {delta:.0f} points above your 30-day norm. Energy reserves look better than they usually do at this point in the day.",
                "positive",
            )
        elif delta <= -5:
            add(
                "body_battery",
                "Energy reserves are lower than your baseline",
                f"Body Battery is at {body_battery}, about {abs(delta):.0f} points below your 30-day norm. That often lines up with accumulated fatigue or incomplete recovery.",
                "caution",
            )

    stress_avg = snapshot.get("stress_avg")
    stress_baseline = baseline.get("stress", {}).get("average")
    if stress_avg and stress_baseline not in (None, 0):
        delta = stress_avg - stress_baseline
        if delta >= 5:
            add(
                "stress",
                "Stress is running higher than usual",
                f"Average stress is {stress_avg}, around {delta:.0f} points above your 30-day baseline. That increases the chance that recovery and overall load are both being taxed today.",
                "caution",
            )
        elif delta <= -5:
            add(
                "stress",
                "Stress is calmer than your recent norm",
                f"Average stress is {stress_avg}, about {abs(delta):.0f} points below baseline. Your system looks calmer than usual, which is generally favorable for recovery.",
                "positive",
            )

    rhr = snapshot.get("resting_hr")
    rhr_baseline = baseline.get("resting_hr", {}).get("average")
    if rhr and rhr_baseline not in (None, 0):
        delta = rhr - rhr_baseline
        if delta >= 3:
            add(
                "resting_hr",
                "Resting heart rate is elevated",
                f"Resting heart rate is {rhr}, about {delta:.0f} bpm above your 30-day baseline. That can be an early sign of accumulated strain or incomplete recovery.",
                "caution",
            )
        elif delta <= -3:
            add(
                "resting_hr",
                "Resting heart rate looks fresher than usual",
                f"Resting heart rate is {rhr}, around {abs(delta):.0f} bpm below your 30-day baseline. That usually points to a calmer recovery state than normal.",
                "positive",
            )

    trend_insight = next((item for item in history_context.get("insights", []) if item), None) or next(
        (item for item in trend_data.get("insights", []) if item),
        None,
    )
    if trend_insight:
        add("daily_overview", "Daily overview", trend_insight, "info")

    if not notifications:
        add(
            "daily_overview",
            "Daily overview",
            "No single metric is breaking away from baseline today, so the overall picture looks fairly stable rather than unusually strong or weak.",
            "info",
        )

    return notifications[:4]


def _save_daily_notifications(email: str, notification_date: date, notifications: list[dict[str, Any]]) -> None:
    now = _now()
    with TOKEN_DB_LOCK:
        with sqlite3.connect(TOKEN_DB_PATH) as connection:
            for item in notifications:
                connection.execute(
                    """
                    INSERT INTO daily_notifications (
                        email, notification_date, notification_id, title, body, metric_key, severity, dismissed_at, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                    ON CONFLICT(email, notification_id) DO UPDATE SET
                        title = excluded.title,
                        body = excluded.body,
                        metric_key = excluded.metric_key,
                        severity = excluded.severity,
                        updated_at = excluded.updated_at
                    """,
                    (
                        email,
                        notification_date.isoformat(),
                        item["notification_id"],
                        item["title"],
                        item["body"],
                        item.get("metric_key"),
                        item.get("severity", "info"),
                        now,
                        now,
                    ),
                )
            connection.commit()


def _dismiss_daily_notification(email: str, notification_id: str) -> None:
    with TOKEN_DB_LOCK:
        with sqlite3.connect(TOKEN_DB_PATH) as connection:
            connection.execute(
                """
                UPDATE daily_notifications
                SET dismissed_at = ?, updated_at = ?
                WHERE email = ? AND notification_id = ?
                """,
                (_now(), _now(), email, notification_id),
            )
            connection.commit()


def _load_daily_notifications(email: str, limit: int = 20) -> dict[str, Any]:
    with TOKEN_DB_LOCK:
        with sqlite3.connect(TOKEN_DB_PATH) as connection:
            rows = connection.execute(
                """
                SELECT notification_date, notification_id, title, body, metric_key, severity, dismissed_at
                FROM daily_notifications
                WHERE email = ?
                ORDER BY notification_date DESC, created_at DESC
                LIMIT ?
                """,
                (email, limit),
            ).fetchall()

    items = [
        {
            "date": row[0],
            "id": row[1],
            "title": row[2],
            "body": row[3],
            "metric_key": row[4],
            "severity": row[5],
            "dismissed": row[6] is not None,
        }
        for row in rows
    ]
    return {
        "active": [item for item in items if not item["dismissed"]],
        "history": items,
    }


def _current_metric_rows(bundle: dict[str, Any]) -> list[dict[str, str]]:
    snapshot = _build_daily_snapshot(bundle, date.today())
    rows: list[tuple[str, str | None]] = [
        ("Steps", f"{snapshot['steps']} / {snapshot['step_goal']}" if snapshot["step_goal"] else str(snapshot["steps"] or 0)),
        ("Distance", _format_km(snapshot["distance_m"] / 1000) if snapshot["distance_m"] else None),
        ("Active kcal", str(int(snapshot["active_kcal"])) if snapshot["active_kcal"] else None),
        ("Resting HR", str(snapshot["resting_hr"]) if snapshot["resting_hr"] else None),
        ("Sleep score", str(snapshot["sleep_score"]) if snapshot["sleep_score"] else None),
        ("Sleep", _format_minutes(snapshot["sleep_minutes"])),
        ("Body Battery score", str(snapshot["body_battery_current"]) if snapshot["body_battery_current"] else None),
        ("Body Battery at wake", str(snapshot["body_battery_at_wake"]) if snapshot["body_battery_at_wake"] else None),
        ("Stress avg", str(snapshot["stress_avg"]) if snapshot["stress_avg"] else None),
        ("Stress max", str(snapshot["stress_max"]) if snapshot["stress_max"] else None),
        ("Stress state", snapshot["stress_qualifier"]),
        ("Training readiness", str(snapshot["training_readiness"]) if snapshot["training_readiness"] not in (None, "") else None),
        ("Training status", snapshot["training_status"]),
        ("Acute/chronic load", f"{snapshot['acute_load_ratio']}" if snapshot["acute_load_ratio"] else None),
        ("VO2 max", f"{snapshot['vo2max']}" if snapshot["vo2max"] else None),
        ("HRV status", snapshot["hrv_status"]),
        ("HRV last night", str(snapshot["hrv_last_night_avg"]) if snapshot["hrv_last_night_avg"] else None),
        ("Hydration", _format_ml(snapshot["hydration_ml"])),
        ("Hydration goal", _format_ml(snapshot["hydration_goal_ml"])),
        ("Weight", f"{snapshot['weight_kg']:.1f} kg" if snapshot["weight_kg"] else None),
        ("Body fat", f"{snapshot['body_fat_pct']:.1f}%" if snapshot["body_fat_pct"] else None),
        ("Fitness age", f"{snapshot['fitness_age']:.1f}" if snapshot["fitness_age"] else None),
        ("Endurance score", f"{snapshot['endurance_score']:.1f}" if snapshot["endurance_score"] else None),
        ("Hill score", f"{snapshot['hill_score']:.1f}" if snapshot["hill_score"] else None),
        ("SpO2 latest", str(snapshot["spo2_latest"]) if snapshot["spo2_latest"] else None),
        ("SpO2 average", f"{snapshot['spo2_average']:.1f}" if snapshot["spo2_average"] else None),
        ("Intensity minutes", str(snapshot["intensity_minutes"]) if snapshot["intensity_minutes"] else None),
        ("Last Garmin sync", str(snapshot["last_sync_time"]) if snapshot["last_sync_time"] else None),
    ]
    return [{"label": label, "value": value} for label, value in rows if value not in (None, "", "0")]


def _extract_primary_device(bundle: dict[str, Any]) -> dict[str, Any] | None:
    devices_data = _source_payload(bundle, "devices")
    if not isinstance(devices_data, list):
        return None
    device = next((item for item in devices_data if isinstance(item, dict) and item.get("primary")), None)
    if device is None:
        device = next((item for item in devices_data if isinstance(item, dict)), None)
    return device


def _extract_device_status(bundle: dict[str, Any]) -> dict[str, Any]:
    device = _extract_primary_device(bundle) or {}
    settings = _source_payload(bundle, "device_settings")
    battery_percent = _deep_find_first(device, {"batteryLevel", "batteryPercent", "batteryPercentage"})
    if battery_percent in (None, "", [], {}):
        battery_percent = _deep_find_first(settings, {"batteryLevel", "batteryPercent", "batteryPercentage"})
    device_id = (
        device.get("deviceId")
        or device.get("unitId")
        or device.get("id")
        or device.get("deviceTypePk")
    )
    return {
        "name": device.get("productDisplayName") or device.get("deviceTypeSimpleName") or device.get("applicationKey"),
        "image_url": device.get("imageUrl"),
        "battery_percent": _coerce_int(battery_percent) if battery_percent not in (None, "", [], {}) else None,
        "device_id": device_id,
    }


def _build_chat_brief(
    full_context_data: dict[str, Any],
    trend_data: dict[str, Any],
    history_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    windows = trend_data["windows"]
    current_signals = _build_current_signals(full_context_data)
    inventory = _source_inventory(full_context_data)
    profile = _source_payload(full_context_data, "profile")
    history_context = history_context or {
        "available": False,
        "windows": {},
        "insights": [],
        "days_available": 0,
    }

    observations: list[str] = []
    if current_signals["training_readiness"] not in (None, ""):
        observations.append(f"Training readiness today: {current_signals['training_readiness']}.")
    if current_signals["body_battery"] not in (None, ""):
        observations.append(f"Body Battery signal today: {current_signals['body_battery']}.")
    if current_signals["sleep_score"] not in (None, ""):
        observations.append(f"Sleep score today: {current_signals['sleep_score']}.")
    if current_signals["resting_heart_rate"] not in (None, ""):
        observations.append(f"Resting heart rate today: {current_signals['resting_heart_rate']}.")
    if current_signals["steps_today"] not in (None, ""):
        observations.append(f"Steps today so far: {current_signals['steps_today']}.")

    suggested_questions = [
        "How is my current week tracking versus my 30-day baseline?",
        "Am I building or losing training momentum over the last 90 days?",
        "What signals suggest recovery is good or poor today?",
        "What patterns stand out across sleep, readiness, and activity volume?",
    ]

    return {
        "profile": {
            "display_name": _deep_find_first(profile, {"displayName", "fullName", "userName"}),
            "location": _deep_find_first(profile, {"location", "countryCode"}),
            "gender": _deep_find_first(profile, {"gender"}),
        },
        "current_signals": current_signals,
        "trend_windows": windows,
        "trend_insights": trend_data["insights"],
        "health_history_windows": history_context.get("windows", {}),
        "health_history_insights": history_context.get("insights", []),
        "history_days_available": history_context.get("days_available", 0),
        "source_inventory": inventory,
        "observations": observations,
        "suggested_questions": suggested_questions,
    }


def _extract_recent_activities(bundle: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    activity_payload = _source_payload(bundle, "activity")
    activities = sorted(
        _normalize_activities(activity_payload),
        key=lambda item: item["date"],
        reverse=True,
    )
    return activities[:limit]


def _summarize_shortcuts(
    full_context_data: dict[str, Any],
    trend_data: dict[str, Any],
    history_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    history_context = history_context or {"available": False, "days_available": 0, "insights": []}
    brief = _build_chat_brief(full_context_data, trend_data, history_context=history_context)
    current = brief["current_signals"]
    recent_activities = _extract_recent_activities(full_context_data)
    windows = trend_data.get("windows", {})
    last_activity = recent_activities[0] if recent_activities else None
    history_insights = history_context.get("insights", [])
    history_days = history_context.get("days_available", 0)

    cards = [
        {
            "id": "today",
            "title": "How am I today?",
            "headline": f"{current.get('steps_today') or 'No'} steps, {current.get('training_readiness') or 'no'} readiness score",
            "details": [
                value
                for value in [
                    f"Body Battery {current['body_battery']}" if current.get("body_battery") not in (None, "") else None,
                    f"Sleep score {current['sleep_score']}" if current.get("sleep_score") not in (None, "") else None,
                    f"Resting HR {current['resting_heart_rate']}" if current.get("resting_heart_rate") not in (None, "") else None,
                ]
                if value
            ],
            "question": "How am I doing today based on all my Garmin signals?",
        },
        {
            "id": "sleep",
            "title": "Sleep and recovery",
            "headline": _format_minutes(current.get("sleep_minutes")) or "Sleep details available",
            "details": [
                value
                for value in [
                    f"Sleep score {current['sleep_score']}" if current.get("sleep_score") not in (None, "") else None,
                    f"Stress {current['stress_level']}" if current.get("stress_level") not in (None, "") else None,
                    f"HRV {current['hrv_status']}" if current.get("hrv_status") not in (None, "") else None,
                ]
                if value
            ],
            "question": "How did I sleep and what does it mean for recovery today?",
        },
        {
            "id": "training",
            "title": "Training trend",
            "headline": trend_data.get("insights", ["Trend data is limited right now."])[0],
            "details": [
                value
                for value in [
                    f"7d avg steps {windows['7d']['steps']['daily_average']}" if "7d" in windows else None,
                    f"30d avg steps {windows['30d']['steps']['daily_average']}" if "30d" in windows else None,
                    f"90d distance {windows['90d']['activities']['total_distance_km']} km" if "90d" in windows else None,
                ]
                if value
            ],
            "question": "What trend stands out across my 7, 30, and 90 day data?",
        },
        {
            "id": "activity",
            "title": "Last workout",
            "headline": (
                f"{last_activity['type']} for {_format_km(last_activity['distance_km']) or '0 km'}"
                if last_activity
                else "No recent activity found"
            ),
            "details": [
                value
                for value in [
                    last_activity["date"].isoformat() if last_activity else None,
                    _format_minutes(last_activity["duration_min"]) if last_activity else None,
                    f"Avg HR {round(last_activity['average_hr'])}" if last_activity and last_activity["average_hr"] > 0 else None,
                ]
                if value
            ],
            "question": "What should I know about my most recent activity?",
        },
    ]

    return {
        "summary": {
            "headline": "",
            "subheadline": "",
            "observations": [],
        },
        "cards": cards,
        "current_metrics": _current_metric_rows(full_context_data),
        "device_status": _extract_device_status(full_context_data),
        "source_inventory": brief["source_inventory"],
        "suggested_questions": brief["suggested_questions"],
        "warnings": _present_warnings(trend_data.get("warnings", [])) + (
            []
            if history_days
            else ["Health history is still thin. Sleep, stress, recovery, and Body Battery trends get better after syncing more days."]
        ),
    }


def _question_matches(question: str, *keywords: str) -> bool:
    lowered = question.lower()
    return any(keyword in lowered for keyword in keywords)


def _question_language(question: str) -> str:
    lowered = question.lower()
    romanian_markers = {
        "ă", "â", "î", "ș", "ş", "ț", "ţ",
        "cum", "azi", "maine", "mâine", "ieri", "somn", "stres", "recuperare",
        "antrenament", "pași", "pasi", "activitate", "ultimele", "trend", "luni",
    }
    return "ro" if any(marker in lowered for marker in romanian_markers) else "en"


def _localized_suggested_questions(language: str) -> list[str]:
    if language == "ro":
        return [
            "Cum se compară săptămâna asta cu baseline-ul meu pe 30 de zile?",
            "Îmi construiesc sau îmi pierd momentum-ul de antrenament în ultimele 90 de zile?",
            "Ce semnale arată dacă recuperarea de azi este bună sau slabă?",
            "Ce pattern-uri ies în evidență între somn, readiness și volum de activitate?",
        ]
    return [
        "How is my current week tracking versus my 30-day baseline?",
        "Am I building or losing training momentum over the last 90 days?",
        "What signals suggest recovery is good or poor today?",
        "What patterns stand out across sleep, readiness, and activity volume?",
    ]


def _translate_history_insight(text: str, language: str) -> str:
    if language != "ro":
        return text
    translations = {
        "Sleep score is running above your 30-day baseline over the last 7 days.": "Scorul de somn este peste baseline-ul tău pe 30 de zile în ultimele 7 zile.",
        "Sleep score is running below your 30-day baseline over the last 7 days.": "Scorul de somn este sub baseline-ul tău pe 30 de zile în ultimele 7 zile.",
        "Average stress has been elevated versus your 30-day baseline.": "Stresul mediu a fost mai ridicat decât baseline-ul tău pe 30 de zile.",
        "Average stress has been lower than your 30-day baseline.": "Stresul mediu a fost mai scăzut decât baseline-ul tău pe 30 de zile.",
        "Body Battery has been stronger than usual over the last 7 days.": "Body Battery a fost mai bun decât de obicei în ultimele 7 zile.",
        "Body Battery has been softer than your 30-day baseline lately.": "Body Battery a fost sub baseline-ul tău pe 30 de zile în ultima perioadă.",
        "Resting heart rate is running above baseline, which can point to accumulated strain.": "Pulsul în repaus este peste baseline, ceea ce poate indica oboseală acumulată.",
        "Resting heart rate is below baseline, which can point to fresher recovery.": "Pulsul în repaus este sub baseline, ceea ce poate indica o recuperare mai bună.",
        "No strong directional pattern stands out yet from the current windows.": "Nu se vede încă un pattern direcțional puternic în ferestrele actuale.",
    }
    return translations.get(text, text)


def _translate_observation(text: str, language: str) -> str:
    if language != "ro":
        return text
    translations = {
        "Training readiness today: ": "Training readiness azi: ",
        "Body Battery signal today: ": "Semnal Body Battery azi: ",
        "Sleep score today: ": "Scor somn azi: ",
        "Resting heart rate today: ": "Puls în repaus azi: ",
        "Steps today so far: ": "Pași azi până acum: ",
    }
    translated = text
    for source, target in translations.items():
        if translated.startswith(source):
            return translated.replace(source, target, 1)
    return translated


def _metric_focus(question: str) -> dict[str, Any] | None:
    catalog = [
        {"id": "weight_kg", "history": "weight_kg", "keywords": ("weight", "greutate", "kilograme", "kg"), "label_en": "weight", "label_ro": "greutatea"},
        {"id": "body_fat_pct", "history": "body_fat_pct", "keywords": ("body fat", "grasime", "grăsime", "fat"), "label_en": "body fat", "label_ro": "procentul de grăsime"},
        {"id": "hydration_ml", "history": "hydration_ml", "keywords": ("hydration", "water", "hidrata", "apă", "apa"), "label_en": "hydration", "label_ro": "hidratarea"},
        {"id": "vo2max", "history": "vo2max", "keywords": ("vo2", "vo2max"), "label_en": "VO2 max", "label_ro": "VO2 max"},
        {"id": "hrv_last_night_avg", "history": "hrv_last_night_avg", "keywords": ("hrv",), "label_en": "HRV", "label_ro": "HRV"},
        {"id": "spo2_average", "history": "spo2_average", "keywords": ("spo2", "oxygen", "oxigen"), "label_en": "SpO2", "label_ro": "SpO2"},
        {"id": "training_readiness", "history": "training_readiness", "keywords": ("readiness", "ready", "recuperare", "pregatit", "pregătit"), "label_en": "training readiness", "label_ro": "training readiness"},
        {"id": "endurance_score", "history": "endurance_score", "keywords": ("endurance",), "label_en": "endurance score", "label_ro": "endurance score"},
        {"id": "hill_score", "history": "hill_score", "keywords": ("hill score", "hill"), "label_en": "hill score", "label_ro": "hill score"},
        {"id": "fitness_age", "history": "fitness_age", "keywords": ("fitness age", "vârst", "varsta"), "label_en": "fitness age", "label_ro": "fitness age"},
        {"id": "intensity_minutes", "history": "intensity_minutes", "keywords": ("intensity", "intensity minutes", "minute intense"), "label_en": "intensity minutes", "label_ro": "minutele de intensitate"},
        {"id": "active_kcal", "history": "active_kcal", "keywords": ("calories", "kcal", "calorii"), "label_en": "active calories", "label_ro": "caloriile active"},
        {"id": "steps", "history": "steps", "keywords": ("steps", "pași", "pasi"), "label_en": "steps", "label_ro": "pașii"},
        {"id": "stress_avg", "history": "stress", "keywords": ("stress", "stres"), "label_en": "stress", "label_ro": "stresul"},
        {"id": "resting_hr", "history": "resting_hr", "keywords": ("resting heart", "rhr", "puls", "heart rate"), "label_en": "resting heart rate", "label_ro": "pulsul în repaus"},
        {"id": "sleep_score", "history": "sleep_score", "keywords": ("sleep score", "scor somn"), "label_en": "sleep score", "label_ro": "scorul de somn"},
        {"id": "body_battery_current", "history": "body_battery", "keywords": ("body battery",), "label_en": "Body Battery", "label_ro": "Body Battery"},
    ]
    lowered = question.lower()
    return next((item for item in catalog if any(keyword in lowered for keyword in item["keywords"])), None)


def _format_metric_response_value(metric_id: str, snapshot: dict[str, Any]) -> str | None:
    value = snapshot.get(metric_id)
    if value in (None, "", 0):
        return None
    if metric_id == "weight_kg":
        return f"{float(value):.1f} kg"
    if metric_id == "body_fat_pct":
        return f"{float(value):.1f}%"
    if metric_id == "hydration_ml":
        return _format_ml(value)
    if metric_id == "vo2max":
        return f"{float(value):.1f}"
    if metric_id == "spo2_average":
        return f"{float(value):.1f}%"
    if metric_id == "fitness_age":
        return f"{float(value):.1f}"
    if metric_id == "endurance_score":
        return f"{float(value):.1f}"
    if metric_id == "hill_score":
        return f"{float(value):.1f}"
    if metric_id == "active_kcal":
        return f"{int(float(value))} kcal"
    if metric_id == "sleep_minutes":
        return _format_minutes(value)
    return str(value)


def _should_try_ollama(question: str) -> bool:
    if _question_matches(
        question,
        "sleep", "slept", "bed", "overnight", "recovery sleep", "somn", "dormit",
        "readiness", "recover", "recovery", "body battery", "hrv", "fatigue", "ready", "recuperare", "gata",
        "activity", "activities", "workout", "run", "ride", "training", "recent", "activitate", "antrenament",
        "trend", "baseline", "30 day", "90 day", "7 day", "month", "momentum", "progress", "volume", "bază", "luni",
        "weight", "greutate", "body fat", "grasime", "hydration", "hidrata", "vo2", "spo2", "oxygen", "endurance", "hill", "fitness age", "calories", "calorii", "stress", "stres",
    ):
        return False
    return len(question.split()) >= 6


def _ollama_language_matches(answer: str, language: str) -> bool:
    lowered = answer.lower()
    if language == "ro":
        romanian_markers = (" este ", " sunt ", " și ", " pentru ", " azi", "somn", "recuper", "antren")
        return any(marker in lowered for marker in romanian_markers)
    english_markers = (" the ", " and ", " your ", " today", "sleep", "recovery", "training")
    return any(marker in lowered for marker in english_markers)


def _build_chat_answer(
    question: str,
    full_context_data: dict[str, Any],
    trend_data: dict[str, Any],
    history_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    history_context = history_context or {"windows": {}, "insights": [], "days_available": 0}
    brief = _build_chat_brief(full_context_data, trend_data, history_context=history_context)
    language = _question_language(question)
    current = brief["current_signals"]
    current_snapshot = _build_daily_snapshot(full_context_data, date.today())
    recent_activities = _extract_recent_activities(full_context_data)
    windows = trend_data.get("windows", {})
    health_windows = history_context.get("windows", {})
    warnings = _present_warnings(trend_data.get("warnings", []), language=language)
    answer = (
        "Îți pot citi datele Garmin, dar am nevoie de o întrebare puțin mai clară ca să-ți dau un răspuns bun."
        if language == "ro"
        else "I can read your Garmin data, but I need a slightly clearer angle to give you a strong answer."
    )
    supporting_points: list[str] = []
    follow_ups = _localized_suggested_questions(language)[:3]
    metric_focus = _metric_focus(question)

    if metric_focus and metric_focus["id"] in {"vo2max", "stress_avg", "steps", "hydration_ml", "hrv_last_night_avg"}:
        current_value = _format_metric_response_value(metric_focus["id"], current_snapshot)
        avg_7d = _history_average(history_context, "7d", metric_focus["history"])
        avg_30d = _history_average(history_context, "30d", metric_focus["history"])
        avg_90d = _history_average(history_context, "90d", metric_focus["history"])
        label = metric_focus["label_ro"] if language == "ro" else metric_focus["label_en"]
        answer = (
            f"Nu văd încă suficiente date istorice despre {label} ca să descriu un trend credibil."
            if language == "ro"
            else f"I don’t yet have enough historical data for {label} to describe a credible trend."
        )

        if current_value:
            answer = (
                f"Acum, {label} este {current_value}. Îți răspund pe această metrică, nu pe Body Battery, pentru că asta ai întrebat."
                if language == "ro"
                else f"Right now, your {label} is {current_value}. I’m answering on that metric specifically rather than defaulting to Body Battery."
            )

        if avg_7d is not None and avg_30d is not None:
            delta = avg_7d - avg_30d
            if metric_focus["id"] == "vo2max":
                if delta >= 0.5:
                    answer = (
                        f"VO2 max arată constructiv: media pe 7 zile este {avg_7d:.1f}, peste media pe 30 de zile de {avg_30d:.1f}."
                        if language == "ro"
                        else f"Your VO2 max trend looks constructive: the 7-day average is {avg_7d:.1f}, above the 30-day average of {avg_30d:.1f}."
                    )
                elif delta <= -0.5:
                    answer = (
                        f"VO2 max pare ușor în recul: media pe 7 zile este {avg_7d:.1f}, sub media pe 30 de zile de {avg_30d:.1f}."
                        if language == "ro"
                        else f"Your VO2 max looks slightly softer: the 7-day average is {avg_7d:.1f}, below the 30-day average of {avg_30d:.1f}."
                    )
                else:
                    answer = (
                        f"VO2 max este destul de stabil: media pe 7 zile este {avg_7d:.1f}, foarte aproape de media pe 30 de zile de {avg_30d:.1f}."
                        if language == "ro"
                        else f"Your VO2 max looks fairly stable: the 7-day average is {avg_7d:.1f}, very close to the 30-day average of {avg_30d:.1f}."
                    )
            elif metric_focus["id"] == "stress_avg":
                if delta >= 5:
                    answer = (
                        f"Stresul a crescut în ultima săptămână: media pe 7 zile este {avg_7d:.1f}, față de {avg_30d:.1f} pe 30 de zile."
                        if language == "ro"
                        else f"Stress has been elevated over the last week: the 7-day average is {avg_7d:.1f} versus {avg_30d:.1f} over 30 days."
                    )
                elif delta <= -5:
                    answer = (
                        f"Stresul arată mai bine decât baseline-ul recent: media pe 7 zile este {avg_7d:.1f}, față de {avg_30d:.1f} pe 30 de zile."
                        if language == "ro"
                        else f"Stress looks better than your recent baseline: the 7-day average is {avg_7d:.1f} versus {avg_30d:.1f} over 30 days."
                    )
            elif metric_focus["id"] == "steps":
                if delta >= 1000:
                    answer = (
                        f"Te-ai mișcat mai mult în ultima săptămână: media pe 7 zile este {avg_7d:.0f} pași, peste baseline-ul de 30 de zile de {avg_30d:.0f}."
                        if language == "ro"
                        else f"You’ve been moving more over the last week: the 7-day average is {avg_7d:.0f} steps, above the 30-day baseline of {avg_30d:.0f}."
                    )
                elif delta <= -1000:
                    answer = (
                        f"Volumul de pași a scăzut în ultima săptămână: media pe 7 zile este {avg_7d:.0f}, sub baseline-ul de 30 de zile de {avg_30d:.0f}."
                        if language == "ro"
                        else f"Your step volume has dipped over the last week: the 7-day average is {avg_7d:.0f}, below the 30-day baseline of {avg_30d:.0f}."
                    )
            elif metric_focus["id"] == "hydration_ml":
                answer = (
                    f"Hidratarea medie pe 7 zile este {avg_7d:.0f} ml, față de {avg_30d:.0f} ml pe 30 de zile."
                    if language == "ro"
                    else f"Your 7-day average hydration is {avg_7d:.0f} ml versus {avg_30d:.0f} ml over 30 days."
                )
            elif metric_focus["id"] == "hrv_last_night_avg":
                answer = (
                    f"HRV-ul recent este {avg_7d:.1f} pe 7 zile, față de {avg_30d:.1f} pe 30 de zile."
                    if language == "ro"
                    else f"Your recent HRV is {avg_7d:.1f} over 7 days versus {avg_30d:.1f} over 30 days."
                )

        if current_value:
            supporting_points.append(
                f"{'Valoare curentă' if language == 'ro' else 'Current value'}: {current_value}."
            )
        if avg_7d is not None:
            supporting_points.append(
                f"{'Media pe 7 zile' if language == 'ro' else '7-day average'}: {avg_7d:.1f}."
            )
        if avg_30d is not None:
            supporting_points.append(
                f"{'Media pe 30 de zile' if language == 'ro' else '30-day average'}: {avg_30d:.1f}."
            )
        if avg_90d is not None:
            supporting_points.append(
                f"{'Media pe 90 de zile' if language == 'ro' else '90-day average'}: {avg_90d:.1f}."
            )

        if metric_focus["id"] == "vo2max" and _question_matches(question, "improve", "improve it", "îmbunătățesc", "imbunatatesc", "cresc", "cres"):
            supporting_points.append(
                "Ca să-l îmbunătățești, urmărește volum aerobic consecvent, una-două sesiuni mai intense pe săptămână și zile de recuperare suficient de bune încât să poți susține progresul."
                if language == "ro"
                else "To improve it, the usual levers are consistent aerobic volume, one or two harder sessions each week, and recovery that is good enough to absorb them."
            )
        follow_ups = (
            [
                "Ce alt semnal confirmă trendul ăsta?",
                "Cum se leagă această metrică de somn și recovery?",
            ]
            if language == "ro"
            else [
                "What other Garmin signal confirms this trend?",
                "How does this metric line up with sleep and recovery?",
            ]
        )
    elif _question_matches(question, "sleep", "slept", "bed", "overnight", "recovery sleep", "somn", "dormit"):
        sleep_duration = _format_minutes(current.get("sleep_minutes"))
        answer = (
            "Recuperarea de peste noapte pare decentă, dar o judec în contextul somnului, stresului și energiei disponibile azi."
            if language == "ro"
            else "Your overnight recovery looks reasonably solid, but I’d read it in the context of sleep, stress, and available energy today."
        )
        if current.get("sleep_score") not in (None, ""):
            answer = (
                f"Scorul tău de somn este {current['sleep_score']}, iar acesta este cel mai bun indicator overnight disponibil pentru cum începe ziua."
                if language == "ro"
                else f"Your sleep score is {current['sleep_score']}, and that is the strongest overnight signal for how you’re starting the day."
            )
        if sleep_duration:
            supporting_points.append(f"{'Durata somnului' if language == 'ro' else 'Sleep duration'}: {sleep_duration}.")
        if current.get("body_battery") not in (None, ""):
            supporting_points.append(f"{'Body Battery azi' if language == 'ro' else 'Body Battery today'}: {current['body_battery']}.")
        if current.get("stress_level") not in (None, ""):
            supporting_points.append(f"{'Semnal stres' if language == 'ro' else 'Stress signal'}: {current['stress_level']}.")
        recent_sleep = health_windows.get("7d", {}).get("sleep_score", {}).get("average")
        baseline_sleep = health_windows.get("30d", {}).get("sleep_score", {}).get("average")
        if recent_sleep is not None and baseline_sleep is not None:
            answer += (
                f" Pe termen scurt, somnul tău rulează la {recent_sleep} față de un baseline pe 30 de zile de {baseline_sleep}."
                if language == "ro"
                else f" In short-term context, your 7-day sleep average is {recent_sleep} against a 30-day baseline of {baseline_sleep}."
            )
        follow_ups = (
            [
                "Somnul și readiness-ul indică o zi grea sau una ușoară?",
                "Cum se compară azi cu baseline-ul meu recent?",
            ]
            if language == "ro"
            else [
                "Do my sleep and readiness point to a hard session or an easy day?",
                "How does today compare with my recent baseline?",
            ]
        )
    elif _question_matches(question, "readiness", "recover", "recovery", "body battery", "hrv", "fatigue", "ready", "recuperare", "gata"):
        answer = (
            "Pentru întrebarea asta mă uit în primul rând la readiness, Body Battery, HRV, stres și somn, fiindcă împreună descriu cel mai bine cât de bine ai absorbit efortul recent."
            if language == "ro"
            else "For this question I’m weighting readiness, Body Battery, HRV, stress, and sleep, because together they describe how well you absorbed recent load."
        )
        if current.get("training_readiness") not in (None, ""):
            answer = (
                f"Training readiness este {current['training_readiness']}, ceea ce sugerează cât de pregătit pari pentru încărcare azi."
                if language == "ro"
                else f"Training readiness is {current['training_readiness']}, which is the clearest single signal of how ready you are for load today."
            )
        for value in [
            f"{'Body Battery' if language == 'ro' else 'Body Battery'}: {current['body_battery']}." if current.get("body_battery") not in (None, "") else None,
            f"{'Status HRV' if language == 'ro' else 'HRV status'}: {current['hrv_status']}." if current.get("hrv_status") not in (None, "") else None,
            f"{'Scor somn' if language == 'ro' else 'Sleep score'}: {current['sleep_score']}." if current.get("sleep_score") not in (None, "") else None,
            f"{'Nivel stres' if language == 'ro' else 'Stress level'}: {current['stress_level']}." if current.get("stress_level") not in (None, "") else None,
            f"{'Status antrenament' if language == 'ro' else 'Training status'}: {current['training_status']}." if current.get("training_status") not in (None, "") else None,
        ]:
            if value:
                supporting_points.append(value)
        recent_battery = health_windows.get("7d", {}).get("body_battery", {}).get("average")
        baseline_battery = health_windows.get("30d", {}).get("body_battery", {}).get("average")
        if recent_battery is not None and baseline_battery is not None:
            answer += (
                f" În același timp, media Body Battery pe 7 zile este {recent_battery} față de un baseline pe 30 de zile de {baseline_battery}, ceea ce îți spune dacă azi vine dintr-o perioadă mai bună sau mai grea."
                if language == "ro"
                else f" Your 7-day Body Battery average is {recent_battery} against a 30-day baseline of {baseline_battery}, which helps show whether today sits on top of stronger or softer recent recovery."
            )
        follow_ups = (
            [
                "Ar trebui să trag tare azi sau să reduc intensitatea?",
                "Care este acum cel mai puternic semnal de recuperare?",
            ]
            if language == "ro"
            else [
                "Should I train hard today or back off?",
                "What is the strongest recovery signal right now?",
            ]
        )
    elif _question_matches(question, "activity", "activities", "workout", "run", "ride", "training", "recent", "activitate", "antrenament"):
        last_activity = recent_activities[0] if recent_activities else None
        if last_activity:
            answer = (
                f"Cea mai recentă activitate vizibilă este {last_activity['type']} din {last_activity['date'].isoformat()}, iar asta îți oferă cel mai bun reper pentru încărcarea ta imediat anterioară."
                if language == "ro"
                else f"The clearest recent anchor I can see is a {last_activity['type']} from {last_activity['date'].isoformat()}, which is the best reference point for your most recent load."
            )
            for value in [
                _format_km(last_activity["distance_km"]),
                _format_minutes(last_activity["duration_min"]),
                f"{'Puls mediu' if language == 'ro' else 'Average HR'} {round(last_activity['average_hr'])}" if last_activity["average_hr"] > 0 else None,
            ]:
                if value:
                    supporting_points.append(str(value))
        else:
            answer = (
                "Nu văd acum o activitate recentă suficient de detaliată pentru un rezumat bun."
                if language == "ro"
                else "I can’t see a detailed recent activity record to summarize well right now."
            )
        if "30d" in windows:
            supporting_points.append(
                f"{'Număr activități pe 30 zile' if language == 'ro' else '30-day activity count'}: {windows['30d']['activities']['count']}."
            )
        follow_ups = (
            [
                "Cum se compară ultimul antrenament cu trendul meu recent?",
                "Îmi construiesc sau îmi pierd momentum-ul de antrenament?",
            ]
            if language == "ro"
            else [
                "How does my last workout compare with my recent trend?",
                "Am I building or losing training momentum?",
            ]
        )
    elif _question_matches(question, "trend", "baseline", "30 day", "90 day", "7 day", "month", "momentum", "progress", "volume", "trend", "bază", "baseline", "luni"):
        insight = trend_data.get("insights", ["Trend data is limited right now."])[0]
        answer = history_context.get("insights", [insight])[0] if history_context.get("insights") else insight
        answer = _translate_history_insight(answer, language)
        for label in ("7d", "30d", "90d", "12m"):
            window = windows.get(label)
            if not window:
                continue
            steps_average = window["steps"]["daily_average"]
            history_steps_average = _history_average(history_context, label, "steps")
            if (steps_average in (None, 0, 0.0)) and history_steps_average not in (None, 0, 0.0):
                steps_average = history_steps_average
            supporting_points.append(
                (
                    f"{label}: {steps_average} pași medii, "
                    f"{window['activities']['count']} activități, "
                    f"{window['activities']['total_distance_km']} km."
                    if language == "ro"
                    else f"{label}: {steps_average} avg steps, "
                    f"{window['activities']['count']} activities, "
                    f"{window['activities']['total_distance_km']} km."
                )
            )
        for label in ("7d", "30d", "90d", "12m"):
            window = health_windows.get(label)
            if not window:
                continue
            stress_average = window["stress"]["average"]
            sleep_average = window["sleep_score"]["average"]
            if stress_average is not None or sleep_average is not None:
                supporting_points.append(
                    (
                        f"{label}: scor somn mediu {sleep_average if sleep_average is not None else 'n/a'}, "
                        f"stres mediu {stress_average if stress_average is not None else 'n/a'}."
                        if language == "ro"
                        else f"{label}: sleep score avg {sleep_average if sleep_average is not None else 'n/a'}, "
                        f"stress avg {stress_average if stress_average is not None else 'n/a'}."
                    )
                )
        follow_ups = (
            [
                "Ultima săptămână este peste sau sub baseline?",
                "Ce s-a schimbat cel mai mult în ultimele 90 de zile?",
            ]
            if language == "ro"
            else [
                "Is my last week above or below baseline?",
                "What changed most over the last 90 days?",
            ]
        )
    elif _question_matches(
        question,
        "weight", "body fat", "body composition", "kg", "kilograms", "weigh",
        "greutate", "kilograme", "masa", "grasime", "grăsime", "compozitie", "compoziție",
    ):
        weight = current_snapshot.get("weight_kg")
        body_fat = current_snapshot.get("body_fat_pct")
        fitness_age = current_snapshot.get("fitness_age")
        answer = (
            "Nu văd suficiente date recente despre compoziția corporală ca să trag o concluzie puternică."
            if language == "ro"
            else "I’m not seeing enough recent body-composition data to make a strong call yet."
        )
        if weight not in (None, ""):
            answer = (
                f"Ultima greutate disponibilă este {weight:.1f} kg. Mă uit la ea împreună cu body fat și fitness age, dacă există, ca să nu interpretez numărul izolat."
                if language == "ro"
                else f"The latest available weight is {weight:.1f} kg. I’d read that together with body fat and fitness age if they are present, rather than as an isolated number."
            )
        if weight not in (None, ""):
            supporting_points.append(
                f"{'Greutate' if language == 'ro' else 'Weight'}: {weight:.1f} kg."
            )
        if body_fat not in (None, "", 0):
            supporting_points.append(
                f"{'Body fat' if language == 'ro' else 'Body fat'}: {body_fat:.1f}%."
            )
        if fitness_age not in (None, "", 0):
            supporting_points.append(
                f"{'Fitness age' if language == 'ro' else 'Fitness age'}: {fitness_age:.1f}."
            )
        weight_7d = health_windows.get("7d", {}).get("weight_kg", {}).get("average")
        weight_30d = health_windows.get("30d", {}).get("weight_kg", {}).get("average")
        if weight_7d is not None and weight_30d is not None:
            answer += (
                f" Media pe 7 zile este {weight_7d} kg față de {weight_30d} kg pe 30 de zile, ceea ce îți spune dacă vorbim de un semnal stabil sau de o variație scurtă."
                if language == "ro"
                else f" Your 7-day average is {weight_7d} kg versus {weight_30d} kg over 30 days, which helps show whether this is stable or just short-term variation."
            )
        follow_ups = (
            [
                "Greutatea mea se mișcă real sau doar fluctuează?",
                "Cum se leagă greutatea de somn, stres și activitate?",
            ]
            if language == "ro"
            else [
                "Is my weight actually moving or just fluctuating?",
                "How does my weight line up with sleep, stress, and activity?",
            ]
        )
    elif _metric_focus(question):
        metric = _metric_focus(question)
        metric_id = metric["id"]
        history_key = metric["history"]
        metric_label = metric["label_ro"] if language == "ro" else metric["label_en"]
        current_value = _format_metric_response_value(metric_id, current_snapshot)
        baseline_7d = health_windows.get("7d", {}).get(history_key, {}).get("average")
        baseline_30d = health_windows.get("30d", {}).get(history_key, {}).get("average")

        answer = (
            f"În momentul ăsta nu văd o valoare curentă clară pentru {metric_label}, dar pot interpreta trendul imediat ce Garmin o livrează."
            if language == "ro"
            else f"I’m not seeing a clean current value for {metric_label} right now, but I can interpret the trend as soon as Garmin provides it."
        )
        if current_value:
            answer = (
                f"Valoarea curentă pentru {metric_label} este {current_value}."
                if language == "ro"
                else f"The current value for {metric_label} is {current_value}."
            )
            if baseline_30d not in (None, 0):
                answer += (
                    f" Față de media ta pe 30 de zile de {baseline_30d}, asta îmi spune dacă ești peste normă, sub normă sau aproape de obișnuit."
                    if language == "ro"
                    else f" Against your 30-day average of {baseline_30d}, that tells me whether you’re running above normal, below normal, or close to baseline."
                )
        if baseline_7d not in (None, 0):
            supporting_points.append(
                f"{'Media pe 7 zile' if language == 'ro' else '7-day average'}: {baseline_7d}."
            )
        if baseline_30d not in (None, 0):
            supporting_points.append(
                f"{'Media pe 30 de zile' if language == 'ro' else '30-day average'}: {baseline_30d}."
            )
        if baseline_7d not in (None, 0) and baseline_30d not in (None, 0):
            delta = baseline_7d - baseline_30d
            if abs(delta) >= 0.5:
                supporting_points.append(
                    (
                        f"Trendul scurt este {'în urcare' if delta > 0 else 'în coborâre'} față de baseline."
                        if language == "ro"
                        else f"The short-term trend is {'rising' if delta > 0 else 'falling'} versus baseline."
                    )
                )
        follow_ups = (
            [
                f"Cum se mișcă {metric_label} față de baseline-ul meu?",
                f"Ce legătură are {metric_label} cu restul semnalelor mele Garmin?",
            ]
            if language == "ro"
            else [
                f"How is my {metric_label} moving versus baseline?",
                f"How does my {metric_label} relate to the rest of my Garmin signals?",
            ]
        )
    else:
        answer = (
            "Iată citirea cea mai utilă pe care o pot face acum, combinând semnalele Garmin între ele, nu doar listând valori."
            if language == "ro"
            else "Here’s the most useful read I can give right now by combining your Garmin signals instead of just listing them."
        )
        localized_history = [_translate_history_insight(item, language) for item in history_context.get("insights", [])]
        localized_observations = [_translate_observation(item, language) for item in brief["observations"]]
        supporting_points.extend((localized_history + localized_observations)[:3])
        if recent_activities:
            supporting_points.append(
                (
                    f"Cea mai recentă activitate: {recent_activities[0]['type']} din {recent_activities[0]['date'].isoformat()}."
                    if language == "ro"
                    else f"Latest activity: {recent_activities[0]['type']} on {recent_activities[0]['date'].isoformat()}."
                )
            )

    return {
        "question": question,
        "answer": answer,
        "supporting_points": supporting_points[:4],
        "follow_ups": follow_ups,
        "warnings": warnings,
        "used_sources": brief["source_inventory"]["available"],
    }


def _ollama_base_url() -> str:
    return os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")


def _ollama_model() -> str:
    return os.getenv("OLLAMA_MODEL", "gemma3:1b")


def _ollama_enabled() -> bool:
    configured = os.getenv("OLLAMA_ENABLED", "true").strip().lower()
    return configured not in {"0", "false", "no", "off"}


def _build_ollama_prompt(
    question: str,
    full_context_data: dict[str, Any],
    trend_data: dict[str, Any],
    history_context: dict[str, Any] | None = None,
) -> str:
    history_context = history_context or {"windows": {}, "insights": [], "days_available": 0}
    brief = _build_chat_brief(full_context_data, trend_data, history_context=history_context)
    recent_activities = _extract_recent_activities(full_context_data)
    current_snapshot = _build_daily_snapshot(full_context_data, date.today())
    compact_trend_windows = {
        label: {
            "steps_avg": window["steps"]["daily_average"],
            "activities": window["activities"]["count"],
            "distance_km": window["activities"]["total_distance_km"],
        }
        for label, window in trend_data.get("windows", {}).items()
    }
    compact_health_windows = {
        label: {
            "sleep_score_avg": window["sleep_score"]["average"],
            "sleep_minutes_avg": window["sleep_minutes"]["average"],
            "body_battery_avg": window["body_battery"]["average"],
            "stress_avg": window["stress"]["average"],
            "resting_hr_avg": window["resting_hr"]["average"],
        }
        for label, window in history_context.get("windows", {}).items()
    }
    compact_context = {
        "current_signals": brief["current_signals"],
        "observations": brief["observations"],
        "current_snapshot": {
            key: value
            for key, value in current_snapshot.items()
            if key in {
                "calendar_date",
                "steps",
                "step_goal",
                "distance_m",
                "active_kcal",
                "resting_hr",
                "sleep_score",
                "sleep_minutes",
                "body_battery_current",
                "body_battery_at_wake",
                "stress_avg",
                "stress_qualifier",
                "training_readiness",
                "training_status",
                "vo2max",
                "hrv_status",
                "hrv_last_night_avg",
                "hydration_ml",
                "hydration_goal_ml",
                "weight_kg",
                "body_fat_pct",
                "fitness_age",
                "endurance_score",
                "hill_score",
            }
        },
        "trend_windows": compact_trend_windows,
        "trend_insights": trend_data.get("insights", []),
        "health_history_windows": compact_health_windows,
        "health_history_insights": history_context.get("insights", []),
        "history_days_available": history_context.get("days_available", 0),
        "recent_activities": [
            {
                "date": item["date"].isoformat(),
                "type": item["type"],
                "distance_km": item["distance_km"],
                "duration_min": item["duration_min"],
                "average_hr": item["average_hr"],
            }
            for item in recent_activities[:3]
        ],
        "available_sources": brief["source_inventory"]["available"],
        "warnings": trend_data.get("warnings", []),
    }

    return (
        "You are a Garmin performance assistant. Answer only from the Garmin context provided below. "
        "Do not invent metrics that are not present. Write in concise natural language for a human. "
        "Respond in the same language as the user's question. Prefer short paragraphs over bullet spam. "
        "If some historical data is unavailable, say that clearly.\n\n"
        f"Question: {question}\n\n"
        f"Garmin context:\n{json.dumps(compact_context, default=str)}"
    )


async def _ask_ollama(
    question: str,
    full_context_data: dict[str, Any],
    trend_data: dict[str, Any],
    history_context: dict[str, Any] | None = None,
) -> str | None:
    if not _ollama_enabled():
        return None

    configured_timeout = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "9"))
    timeout = aiohttp.ClientTimeout(total=min(configured_timeout, 12.0))
    payload = {
        "model": _ollama_model(),
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": "You are a concise Garmin health and training assistant.",
            },
            {
                "role": "user",
                "content": _build_ollama_prompt(question, full_context_data, trend_data, history_context=history_context),
            },
        ],
    }

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(f"{_ollama_base_url()}/api/chat", json=payload) as response:
                if response.status >= 400:
                    logger.warning("Ollama chat failed with status %s", response.status)
                    return None
                data = await response.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        logger.warning("Ollama unavailable: %s", exc)
        return None

    content = (
        data.get("message", {}).get("content")
        or data.get("response")
        or ""
    ).strip()
    return content or None


async def _fetch_trend_windows(client: GarminClient, today: date) -> dict[str, Any]:
    oldest_start = min(_window_start(today, days=days, months=months) for _, _, days, months in TREND_WINDOWS)
    warnings: list[str] = []

    try:
        activities_raw = await client.get_activities_by_date(oldest_start, today)
        activities_data = _normalize_activities(activities_raw)
    except Exception as exc:
        logger.warning("Failed to fetch activity history: %s", type(exc).__name__)
        activities_data = []
        warnings.append(f"activity_history_unavailable:{type(exc).__name__}")

    try:
        steps_raw = await client.get_daily_steps(oldest_start, today)
        steps_data = _normalize_steps(steps_raw)
    except Exception as exc:
        logger.warning("Failed to fetch step history: %s", type(exc).__name__)
        steps_data = {}
        warnings.append(f"step_history_unavailable:{type(exc).__name__}")

    windows: dict[str, dict[str, Any]] = {}
    for label, title, days, months in TREND_WINDOWS:
        start = _window_start(today, days=days, months=months)
        windows[label] = _aggregate_window(
            label=label,
            title=title,
            start=start,
            end=today,
            activities=activities_data,
            daily_steps=steps_data,
        )

    return {
        "as_of": today.isoformat(),
        "coverage_start": oldest_start.isoformat(),
        "available": bool(activities_data or steps_data),
        "windows": windows,
        "insights": _build_trend_insights(windows),
        "warnings": warnings,
    }


async def _fetch_metric_snapshot_bundle(client: GarminClient, target_date: date) -> dict[str, Any]:
    tasks = {
        "daily_steps_today": _call_optional_client_method(client, "get_daily_steps", target_date, target_date),
        "core": _call_optional_client_method(client, "fetch_core_data", target_date=target_date),
        "body": _call_optional_client_method(client, "fetch_body_data", target_date=target_date),
        "training_readiness": _call_optional_client_method(client, "get_training_readiness", target_date=target_date),
        "training_status": _call_optional_client_method(client, "get_training_status", target_date=target_date),
        "hrv": _call_optional_client_method(client, "get_hrv_data", target_date=target_date),
        "hydration": _call_optional_client_method(client, "get_hydration_data", target_date=target_date),
        "fitness_age": _call_optional_client_method(client, "get_fitness_age", target_date=target_date),
        "endurance_score": _call_optional_client_method(client, "get_endurance_score", target_date=target_date),
        "hill_score": _call_optional_client_method(client, "get_hill_score", target_date=target_date),
    }
    names = list(tasks.keys())
    results = await asyncio.gather(*tasks.values())
    return {name: result for name, result in zip(names, results)}


async def _fetch_runtime_context(
    client: GarminClient,
    email: str | None,
    today: date,
    force_refresh: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if email and not force_refresh:
        cached_trends = _load_context_cache(email, f"trend_context:{today.isoformat()}")
        if cached_trends is not None:
            full_context_data = await _fetch_full_context_bundle(client, today)
            return full_context_data, cached_trends

    full_context_data, trend_data = await asyncio.gather(
        _fetch_full_context_bundle(client, today),
        _fetch_trend_windows(client, today),
    )

    if email:
        _save_context_cache(email, f"trend_context:{today.isoformat()}", trend_data)

    return full_context_data, trend_data


async def _call_optional_client_method(
    client: GarminClient,
    method_name: str,
    *args: Any,
    **kwargs: Any,
) -> dict[str, Any]:
    method = getattr(client, method_name, None)
    if method is None:
        return {"available": False, "error": "unsupported_by_library"}

    try:
        data = await method(*args, **kwargs)
        return {"available": True, "data": data}
    except Exception as exc:
        logger.warning("Failed to fetch %s: %s", method_name, type(exc).__name__)
        return {"available": False, "error": type(exc).__name__}


async def _fetch_full_context_bundle(client: GarminClient, today: date) -> dict[str, Any]:
    tasks = {
        "profile": _call_optional_client_method(client, "get_user_profile"),
        "summary": _call_optional_client_method(client, "get_user_summary"),
        "daily_steps_today": _call_optional_client_method(client, "get_daily_steps", today, today),
        "core": _call_optional_client_method(client, "fetch_core_data", target_date=today),
        "body": _call_optional_client_method(client, "fetch_body_data", target_date=today),
        "activity": _call_optional_client_method(client, "fetch_activity_data"),
        "training": _call_optional_client_method(client, "fetch_training_data"),
        "training_readiness": _call_optional_client_method(client, "get_training_readiness", target_date=today),
        "training_status": _call_optional_client_method(client, "get_training_status", target_date=today),
        "hrv": _call_optional_client_method(client, "get_hrv_data", target_date=today),
        "hydration": _call_optional_client_method(client, "get_hydration_data", target_date=today),
        "fitness_age": _call_optional_client_method(client, "get_fitness_age", target_date=today),
        "endurance_score": _call_optional_client_method(client, "get_endurance_score", target_date=today),
        "hill_score": _call_optional_client_method(client, "get_hill_score", target_date=today),
        "goals": _call_optional_client_method(client, "fetch_goals_data"),
        "gear": _call_optional_client_method(client, "fetch_gear_data"),
        "workouts": _call_optional_client_method(client, "get_workouts", limit=10),
        "devices": _call_optional_client_method(client, "get_devices"),
        "badges": _call_optional_client_method(client, "get_earned_badges"),
        "blood_pressure": _call_optional_client_method(client, "fetch_blood_pressure_data"),
        "menstrual": _call_optional_client_method(client, "fetch_menstrual_data"),
    }

    names = list(tasks.keys())
    results = await asyncio.gather(*tasks.values())
    bundle = {name: result for name, result in zip(names, results)}

    devices_data = _source_payload(bundle, "devices")
    primary_device = None
    if isinstance(devices_data, list):
        primary_device = next((item for item in devices_data if isinstance(item, dict) and item.get("primary")), None)
        if primary_device is None:
            primary_device = next((item for item in devices_data if isinstance(item, dict)), None)

    device_id = None
    if isinstance(primary_device, dict):
        device_id = (
            primary_device.get("deviceId")
            or primary_device.get("unitId")
            or primary_device.get("id")
            or primary_device.get("deviceTypePk")
        )

    if device_id is not None:
        bundle["device_settings"] = await _call_optional_client_method(client, "get_device_settings", device_id)
    else:
        bundle["device_settings"] = {"available": False, "error": "device_id_unavailable"}

    return bundle


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
    return _load_browser_tokens(browser_session_id) is not None


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    await _cleanup_pending_auths()
    browser_session_id, needs_cookie = _ensure_browser_session_id(request)
    if _load_browser_tokens(browser_session_id) is not None:
        return RedirectResponse(url="/dashboard", status_code=303)

    response = templates.TemplateResponse(
        request=request,
        name="login.html",
        context={},
    )
    if needs_cookie:
        _set_browser_cookie(request, response, browser_session_id)
    return response


@app.head("/")
def index_head():
    return Response(status_code=200)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/logo.png")
def logo_png():
    return FileResponse(LOGO_PATH)


@app.head("/logo.png")
def logo_png_head():
    return Response(status_code=200)


@app.get("/favicon.ico")
def favicon():
    return FileResponse(LOGO_PATH)


@app.head("/favicon.ico")
def favicon_head():
    return Response(status_code=200)


@app.get("/apple-touch-icon.png")
def apple_touch_icon():
    return FileResponse(LOGO_PATH)


@app.head("/apple-touch-icon.png")
def apple_touch_icon_head():
    return Response(status_code=200)


@app.get("/icon-192.png")
def icon_192():
    return FileResponse(LOGO_PATH)


@app.head("/icon-192.png")
def icon_192_head():
    return Response(status_code=200)


@app.get("/icon-512.png")
def icon_512():
    return FileResponse(LOGO_PATH)


@app.head("/icon-512.png")
def icon_512_head():
    return Response(status_code=200)


@app.get("/site.webmanifest")
def site_webmanifest():
    return JSONResponse(
        {
            "name": "CharlieChat",
            "short_name": "CharlieChat",
            "description": "Garmin data, explained in plain language.",
            "start_url": "/",
            "scope": "/",
            "display": "standalone",
            "background_color": "#05070b",
            "theme_color": "#63a8ff",
            "icons": [
                {
                    "src": "/icon-192.png",
                    "sizes": "192x192",
                    "type": "image/png",
                    "purpose": "any maskable",
                },
                {
                    "src": "/icon-512.png",
                    "sizes": "512x512",
                    "type": "image/png",
                    "purpose": "any maskable",
                },
            ],
        }
    )


@app.head("/site.webmanifest")
def site_webmanifest_head():
    return Response(status_code=200)


@app.head("/healthz")
def healthz_head():
    return Response(status_code=200)


@app.get("/api/session")
async def session_status(request: Request):
    await _cleanup_pending_auths()
    browser_session_id = _browser_session_id(request)
    stored_tokens = _load_browser_tokens(browser_session_id)
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
    stored_tokens = _load_browser_tokens(browser_session_id)
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "email": stored_tokens.email if stored_tokens else "",
        },
    )


@app.get("/api/shortcuts")
async def shortcuts(request: Request):
    today = date.today()
    stored_tokens = _stored_tokens_for_request(request)

    async def fetch_shortcuts(client: GarminClient) -> Any:
        full_context_data, trend_data = await _fetch_runtime_context(
            client,
            stored_tokens.email if stored_tokens else None,
            today,
        )
        history_context = _build_history_context(stored_tokens.email if stored_tokens else None, today)
        notifications = {"active": [], "history": []}
        if stored_tokens is not None:
            _save_metric_snapshot(stored_tokens.email, _build_daily_snapshot(full_context_data, today))
            history_context = _build_history_context(stored_tokens.email, today)
            _save_daily_notifications(
                stored_tokens.email,
                today,
                _build_daily_notifications(full_context_data, trend_data, history_context, today),
            )
            notifications = _load_daily_notifications(stored_tokens.email)
        return {
            "as_of": today.isoformat(),
            "shortcuts": _summarize_shortcuts(full_context_data, trend_data, history_context=history_context),
            "history": history_context,
            "notifications": notifications,
        }

    return await _with_client(fetch_shortcuts, request=request)


@app.post("/api/notifications/{notification_id}/dismiss")
async def dismiss_notification(notification_id: str, request: Request):
    stored_tokens = _stored_tokens_for_request(request)
    if stored_tokens is None:
        raise HTTPException(status_code=401, detail="Connect Garmin before dismissing notifications.")

    _dismiss_daily_notification(stored_tokens.email, notification_id)
    return {
        "ok": True,
        "notifications": _load_daily_notifications(stored_tokens.email),
    }


@app.post("/api/chat")
async def chat(request_payload: GarminChatRequest, request: Request):
    today = date.today()
    question = request_payload.question.strip()
    stored_tokens = _stored_tokens_for_request(request)

    if not question:
        raise HTTPException(status_code=400, detail="Question must not be empty.")

    async def answer_question(client: GarminClient) -> Any:
        full_context_data, trend_data = await _fetch_runtime_context(
            client,
            stored_tokens.email if stored_tokens else None,
            today,
        )
        history_context = _build_history_context(stored_tokens.email if stored_tokens else None, today)
        if stored_tokens is not None:
            _save_metric_snapshot(stored_tokens.email, _build_daily_snapshot(full_context_data, today))
            history_context = _build_history_context(stored_tokens.email, today)
        heuristic_response = _build_chat_answer(
            question,
            full_context_data,
            trend_data,
            history_context=history_context,
        )
        ollama_answer = None
        question_language = _question_language(question)
        if _should_try_ollama(question):
            ollama_answer = await _ask_ollama(question, full_context_data, trend_data, history_context=history_context)
        if ollama_answer and _ollama_language_matches(ollama_answer, question_language):
            heuristic_response["answer"] = ollama_answer
            heuristic_response["mode"] = "ollama"
        else:
            heuristic_response["mode"] = "heuristic"
        return {
            "as_of": today.isoformat(),
            "response": heuristic_response,
            "history": history_context,
        }

    return await _with_client(answer_question, request=request)


@app.post("/api/history/sync")
async def sync_history(payload: GarminHistorySyncRequest, request: Request):
    stored_tokens = _stored_tokens_for_request(request)
    if stored_tokens is None:
        raise HTTPException(status_code=401, detail="Connect Garmin before syncing history.")

    today = date.today()
    requested_days = max(7, min(60, payload.days))
    offset_days = max(0, min(365, payload.offset_days))
    end_date = today - timedelta(days=offset_days)
    start_date = end_date - timedelta(days=requested_days - 1)
    existing_dates = {
        snapshot.get("calendar_date")
        for snapshot in _load_metric_snapshots(stored_tokens.email, start_date, end_date)
    }
    target_dates = [
        target_day
        for offset in range(requested_days)
        for target_day in [start_date + timedelta(days=offset)]
        if target_day.isoformat() not in existing_dates or target_day == end_date
    ]

    async def perform_sync(client: GarminClient) -> Any:
        saved = 0
        failed: list[str] = []
        for target_day in target_dates:
            try:
                bundle = await _fetch_metric_snapshot_bundle(client, target_day)
                _save_metric_snapshot(
                    stored_tokens.email,
                    _build_daily_snapshot(bundle, target_day),
                )
                saved += 1
            except Exception as exc:
                logger.warning("Failed to sync metric snapshot for %s: %s", target_day, type(exc).__name__)
                failed.append(f"{target_day.isoformat()}:{type(exc).__name__}")
            await asyncio.sleep(0.05)

        history_context = _build_history_context(stored_tokens.email, today)
        return {
            "status": "ok",
            "requested_days": requested_days,
            "offset_days": offset_days,
            "saved_days": saved,
            "failed_days": failed[:20],
            "batch_start": start_date.isoformat(),
            "batch_end": end_date.isoformat(),
            "history": history_context,
        }

    return await _with_client(perform_sync, request=request)


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
                _set_browser_cookie(request, response, browser_session_id)
            return response

        oauth1_token, oauth2_token = _extract_garth_tokens(login_result)
        _save_browser_tokens(
            browser_session_id,
            StoredTokens(
                email=payload.email,
                oauth1_token=oauth1_token,
                oauth2_token=oauth2_token,
                connected_at=_now(),
            ),
        )
        response = JSONResponse({"status": "connected", "email": payload.email})
        if needs_cookie:
            _set_browser_cookie(request, response, browser_session_id)
        return response
    except Exception as exc:
        response = getattr(exc, "response", None)
        status_code = _response_status_code(response) if response is not None else None
        response_text = _response_text(response) if response is not None else ""

        if status_code == 429:
            retry_after = _garmin_retry_after_seconds(response)
            raise HTTPException(
                status_code=429,
                detail="Garmin is rate limiting authentication attempts. Wait before trying again.",
                headers={"Retry-After": str(retry_after)},
            ) from exc

        if status_code is not None:
            detail = f"Garmin authentication failed: HTTP {status_code}"
            if response_text:
                detail = f"{detail} - {response_text[:200]}"
            raise HTTPException(status_code=401, detail=detail) from exc

        if type(exc).__name__ in {"GarminConnectAuthenticationError", "GarthHTTPError", "GarthException"}:
            message = str(exc).strip()
            detail = "Garmin authentication failed. Check your email and password."
            if message:
                detail = f"Garmin authentication failed: {message[:200]}"
            raise HTTPException(status_code=401, detail=detail) from exc

        logger.exception("Garmin sign-in failed")
        raise HTTPException(
            status_code=502,
            detail=f"Garmin sign-in failed: {type(exc).__name__} - {str(exc)[:200] or 'Unknown error'}",
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
                garth_resume_login,
                pending.mfa_state,
                payload.code,
            )

        oauth1_token, oauth2_token = _extract_garth_tokens(result)

        _save_browser_tokens(
            browser_session_id,
            StoredTokens(
                email=pending.email,
                oauth1_token=oauth1_token,
                oauth2_token=oauth2_token,
                connected_at=_now(),
            ),
        )
        await _close_pending_auth(payload.pending_id)
        response = JSONResponse({"status": "connected", "email": pending.email})
        if needs_cookie:
            _set_browser_cookie(request, response, browser_session_id)
        return response
    except HTTPException:
        raise
    except Exception as exc:
        response = getattr(exc, "response", None)
        status_code = _response_status_code(response) if response is not None else None
        response_text = _response_text(response) if response is not None else ""

        if status_code == 429:
            retry_after = _garmin_retry_after_seconds(response)
            raise HTTPException(
                status_code=429,
                detail="Garmin is rate limiting MFA attempts. Wait before trying again.",
                headers={"Retry-After": str(retry_after)},
            ) from exc

        if status_code is not None:
            detail = f"Garmin MFA completion failed: HTTP {status_code}"
            if response_text:
                detail = f"{detail} - {response_text[:200]}"
            raise HTTPException(status_code=502, detail=detail) from exc

        if type(exc).__name__ in {"GarminConnectAuthenticationError", "GarminMFACodeError", "GarminAuthError", "GarthException"}:
            message = str(exc).strip()
            detail = "The MFA code was not accepted."
            if message:
                detail = f"Garmin MFA completion failed: {message[:200]}"
            raise HTTPException(status_code=401, detail=detail) from exc

        logger.exception("Garmin MFA completion failed")
        raise HTTPException(
            status_code=502,
            detail=f"Garmin MFA completion failed: {type(exc).__name__} - {str(exc)[:200] or 'Unknown error'}",
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


@app.get("/trends")
async def trends(request: Request):
    today = date.today()

    async def fetch_trend_data(client: GarminClient) -> Any:
        return await _fetch_trend_windows(client, today)

    return await _with_client(fetch_trend_data, request=request)


@app.get("/context/full")
async def full_context(request: Request):
    today = date.today()

    async def fetch_full_context(client: GarminClient) -> Any:
        return {
            "as_of": today.isoformat(),
            "sources": await _fetch_full_context_bundle(client, today),
            "unsupported_targets": ["nutrition"],
        }

    return await _with_client(fetch_full_context, request=request)


@app.get("/chat-context")
async def chat_context(request: Request):
    today = date.today()

    async def fetch_chat_context(client: GarminClient) -> Any:
        full_context_data, trend_data = await asyncio.gather(
            _fetch_full_context_bundle(client, today),
            _fetch_trend_windows(client, today),
        )
        return {
            "as_of": today.isoformat(),
            "full_context": full_context_data,
            "historical_context": trend_data,
            "unsupported_targets": ["nutrition"],
        }

    return await _with_client(fetch_chat_context, request=request)


@app.get("/chat-brief")
async def chat_brief(request: Request):
    today = date.today()

    async def fetch_chat_brief(client: GarminClient) -> Any:
        full_context_data, trend_data = await asyncio.gather(
            _fetch_full_context_bundle(client, today),
            _fetch_trend_windows(client, today),
        )
        return {
            "as_of": today.isoformat(),
            "brief": _build_chat_brief(full_context_data, trend_data),
            "unsupported_targets": ["nutrition"],
        }

    return await _with_client(fetch_chat_brief, request=request)
