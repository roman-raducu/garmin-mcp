from fastapi import FastAPI
from garminconnect import Garmin
import os

app = FastAPI()

EMAIL = os.getenv("GARMIN_EMAIL")
PASSWORD = os.getenv("GARMIN_PASSWORD")

def get_client():
    garmin = Garmin(EMAIL, PASSWORD)
    garmin.login()
    return garmin

@app.get("/")
def root():
    return {"status": "ok", "message": "Garmin MCP running"}

@app.get("/today")
def today():
    garmin = get_client()
    data = garmin.get_user_summary(date=None)
    return data

@app.get("/sleep")
def sleep():
    garmin = get_client()
    data = garmin.get_sleep_data(date=None)
    return data

@app.get("/activities")
def activities():
    garmin = get_client()
    data = garmin.get_activities(0, 5)
    return data
