import asyncio
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Awaitable, Callable

import aiohttp
import garth
from aiogarmin import GarminAuth, GarminClient
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
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


def _save_browser_tokens(browser_session_id: str, stored_tokens: StoredTokens) -> None:
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
                    json.dumps(stored_tokens.oauth1_token),
                    json.dumps(stored_tokens.oauth2_token),
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
        oauth1_token=json.loads(row[1]),
        oauth2_token=json.loads(row[2]),
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


def _build_current_signals(bundle: dict[str, Any]) -> dict[str, Any]:
    summary_data = _source_payload(bundle, "summary")
    core_data = _source_payload(bundle, "core")
    body_data = _source_payload(bundle, "body")
    training_data = _source_payload(bundle, "training")

    return {
        "steps_today": _deep_find_first(summary_data or core_data, {"totalSteps", "steps", "dailySteps"}),
        "body_battery": _deep_find_first(core_data, {"bodyBattery", "bodyBatteryLevel", "bodyBatteryChargedValue"}),
        "stress_level": _deep_find_first(core_data, {"stressLevel", "stressQualifierText", "overallStressLevel"}),
        "resting_heart_rate": _deep_find_first(summary_data or core_data, {"restingHeartRate", "restingHR", "restingHeartRateValue"}),
        "sleep_score": _deep_find_first(core_data, {"sleepScore", "overallSleepScore"}),
        "sleep_minutes": _deep_find_first(core_data, {"sleepTimeMinutes", "sleepMinutes"}),
        "training_readiness": _deep_find_first(training_data, {"trainingReadiness", "trainingReadinessScore", "readinessScore"}),
        "training_status": _deep_find_first(training_data, {"trainingStatus", "trainingStatusLabel", "trainingStatusText"}),
        "hrv_status": _deep_find_first(training_data, {"hrvStatus", "hrvStatusText", "status"}),
        "hydration": _deep_find_first(body_data, {"hydration", "hydrationLiters", "hydrationML"}),
        "weight_kg": _deep_find_first(body_data, {"weightKg", "weight"}),
        "fitness_age": _deep_find_first(body_data, {"fitnessAge", "fitnessAgeValue"}),
    }


def _build_chat_brief(
    full_context_data: dict[str, Any],
    trend_data: dict[str, Any],
) -> dict[str, Any]:
    windows = trend_data["windows"]
    current_signals = _build_current_signals(full_context_data)
    inventory = _source_inventory(full_context_data)
    profile = _source_payload(full_context_data, "profile")

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
        "source_inventory": inventory,
        "observations": observations,
        "suggested_questions": suggested_questions,
    }


async def _fetch_trend_windows(client: GarminClient, today: date) -> dict[str, Any]:
    oldest_start = min(_window_start(today, days=days, months=months) for _, _, days, months in TREND_WINDOWS)
    activities_raw, steps_raw = await asyncio.gather(
        client.get_activities_by_date(oldest_start, today),
        client.get_daily_steps(oldest_start, today),
    )
    activities_data = _normalize_activities(activities_raw)
    steps_data = _normalize_steps(steps_raw)

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
        "windows": windows,
        "insights": _build_trend_insights(windows),
    }


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
        "core": _call_optional_client_method(client, "fetch_core_data", target_date=today),
        "body": _call_optional_client_method(client, "fetch_body_data", target_date=today),
        "activity": _call_optional_client_method(client, "fetch_activity_data"),
        "training": _call_optional_client_method(client, "fetch_training_data"),
        "goals": _call_optional_client_method(client, "fetch_goals_data"),
        "gear": _call_optional_client_method(client, "fetch_gear_data"),
        "blood_pressure": _call_optional_client_method(client, "fetch_blood_pressure_data"),
        "menstrual": _call_optional_client_method(client, "fetch_menstrual_data"),
    }

    names = list(tasks.keys())
    results = await asyncio.gather(*tasks.values())
    return {name: result for name, result in zip(names, results)}


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
