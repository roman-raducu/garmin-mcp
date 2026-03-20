# garmin-mcp

## Garmin session persistence

Successful Garmin browser sessions are stored in a small SQLite database.

- Default path: `/tmp/garmin_state.db`
- Override with `GARMIN_STATE_DB_PATH`

If you want sessions to survive Render restarts or deploys, point `GARMIN_STATE_DB_PATH` at a persistent disk mount instead of `/tmp`.
