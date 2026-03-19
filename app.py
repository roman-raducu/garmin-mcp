from fastapi import FastAPI
import os
import asyncio
from aiogarmin import Garmin

app = FastAPI()

EMAIL = os.getenv("GARMIN_EMAIL")
PASSWORD = os.getenv("GARMIN_PASSWORD")

async def get_client():
    garmin = Garmin()
    await garmin.login(EMAIL, PASSWORD)
    return garmin

@app.get("/")
def root():
    return {"status": "ok", "message": "Garmin MCP running"}

@app.get("/today")
async def today():
    garmin = await get_client()
    data = await garmin.get_user_summary()
    return data

@app.get("/sleep")
async def sleep():
    garmin = await get_client()
    data = await garmin.get_sleep_data()
    return data

@app.get("/activities")
async def activities():
    garmin = await get_client()
    data = await garmin.get_activities(0, 5)
    return data
