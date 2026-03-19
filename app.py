from fastapi import FastAPI
import os
from aiogarmin import Client

app = FastAPI()

EMAIL = os.getenv("GARMIN_EMAIL")
PASSWORD = os.getenv("GARMIN_PASSWORD")

@app.get("/")
def root():
    return {"status": "ok", "message": "Garmin MCP running"}

@app.get("/today")
async def today():
    client = Client()
    await client.login(EMAIL, PASSWORD)

    summary = await client.get_user_summary()
    return summary

@app.get("/sleep")
async def sleep():
    client = Client()
    await client.login(EMAIL, PASSWORD)

    data = await client.get_sleep_data()
    return data

@app.get("/activities")
async def activities():
    client = Client()
    await client.login(EMAIL, PASSWORD)

    data = await client.get_activities(0, 5)
    return data
