# AGENTS.md

## Project

`CharlieChat` is a Garmin-connected web app hosted on a Debian VPS and exposed at `https://garmin.raducu.co`.

Primary goal:
- turn Garmin data into a fast, app-like, natural-language experience
- support Romanian and English
- interpret data, not just dump raw payloads
- keep historical context persistent so Garmin is not queried repeatedly for the same windows

This file is the working product spec and development guardrail for future changes.

## Product Goals

The app should:
- let a user sign in with Garmin, including MFA when needed
- persist enough Garmin state to avoid repeated login and repeated historical fetches
- expose a clean dashboard with:
  - `Chat`
  - `Analytics`
  - notifications / daily overview
- answer questions about all meaningful Garmin metrics, not just a few headline signals
- support both current-state questions and wide historical/trend questions

The app should not:
- show raw JSON to end users
- expose technical API/library failure details in the main UI
- invent Garmin values that are not actually present
- show misleading or numerically broken interpretations

## Branding

App name:
- `CharlieChat`

Logo:
- use `templates/logo.png`
- same logo style as login
- no extra border/background framing around the logo in the header

Header branding:
- show only logo + `CharlieChat`
- do not show redundant `Dashboard` labels near the brand

## Login Screen Spec

Visual direction:
- dark UI
- blue accent derived from the logo
- no green/neon theme

Layout:
- desktop can have split layout
- mobile must center logo above the form
- no unnecessary vertical scroll if the form fits in the viewport

Copy:
- simple, natural, concise
- no marketing filler
- explain the app in max 2 lines

## Dashboard Information Architecture

The dashboard should behave like a modern web app, not a long static page.

Required top-level areas:
- `Chat`
- `Analytics`
- `Notifications`
- `Overview` / Garmin signals

Overview requirements:
- must expose all normalized current Garmin metrics that are meaningfully available, not just a subset such as steps, HRV, or body battery
- must include an explicit refresh control for current Garmin data
- must not depend on hidden gestures or logo clicks to open on mobile

Desktop:
- persistent main content area
- notifications open in a right-side overlay panel
- overview can remain visible on large screens

Mobile:
- must be intentionally designed, not a desktop layout squeezed down
- overview opens from a classic hamburger/menu icon
- notifications open from a bell icon
- header should use:
  - row 1: logo + app name + menu
  - row 2: current device chip + notifications
- sign out should live inside the mobile menu/drawer, not consume header space
- overlays/drawers must be scrollable and usable on small screens
- avoid elements that are inaccessible because of height/overflow issues

## Notifications / Daily Overview

Notifications are a core product feature.

Requirements:
- do not place daily overview as a permanent card inside the main sidebar
- show a notification bell near sign out
- show unread counter on the bell
- clicking the bell opens a right-side overlay panel
- panel shows:
  - unread notifications
  - history/log of prior daily overviews by date
- notifications must be dismissible
- dismissed notifications must remain in history
- notification dates must use Romanian display format: `DD-MM-YYYY`
- notification UI should feel like a standard right-side overlay panel, not a stack of heavy nested cards

Notification content requirements:
- must be insightful
- must explain what changed relative to baseline/history
- should surface things a user would not trivially infer from a single Garmin screen
- should be generated daily and persisted

Examples of good notification themes:
- sleep above/below 30-day baseline
- stress higher/lower than recent norm
- body battery stronger/weaker than typical
- resting heart rate elevated vs baseline
- broader daily overview synthesis

## Chat Requirements

The chat experience is the central interface.

Requirements:
- questions can be asked in Romanian or English
- answers must come back in the same language as the question
- no mixed-language responses
- avoid overly programmatic, list-dump style answers
- interpret signals in natural language
- combine current state + historical baseline + trend context
- be able to answer about all Garmin metrics that the app tracks
- when the user asks about a specific metric, answer that metric first and directly
- do not drift into Body Battery or generic recovery framing unless it is explicitly asked for or clearly needed as short supporting context
- questions about minima / maxima / `cea mai mică` / `cea mai mare` must return the actual saved historical value and date when available

Chat UI requirements:
- viewport-sized layout
- chat thread scrolls independently
- auto-scroll to the latest message
- input area remains accessible
- no redundant explanatory header text in the chat pane
- chat entry should be accessible from an obvious tab or menu item
- avoid filler copy above the conversation area

The chat should not:
- rely entirely on canned standard questions
- output raw error strings like `step_history_unavailable:GarminAPIError`
- claim certainty when a metric/history source is unavailable

LLM routing requirements:
- support local and hosted LLMs
- hosted providers may include `Groq`, `OpenRouter`, and `Hugging Face` when configured
- provider choice should be routed pragmatically based on prompt complexity and quota preservation
- always fall back safely if a provider is unavailable or times out
- same-language output remains mandatory regardless of provider

## Metric Coverage Requirements

The app must support interpretation for all relevant Garmin metrics available through the library and normalized snapshots, including where available:
- steps
- distance
- active calories
- sleep score
- sleep duration
- body battery
- stress
- resting heart rate
- training readiness
- training status
- acute/chronic load ratio
- VO2 max
- HRV
- hydration
- weight
- body fat
- fitness age
- endurance score
- hill score
- SpO2
- intensity minutes

When adding new behavior, prefer generic handling over one-off custom cases.

Data merge requirements:
- do not trust a single Garmin endpoint when another working endpoint can fill the same gap
- for current metrics, prefer fresher/raw endpoints over stale summary payloads when available
- for recent activities, merge list-style and range-style activity sources before deciding data is missing
- if one API is late or partial, merge from the others rather than leaving user-facing gaps

## Historical Data and Persistence

Historical data is required for:
- 7d / 30d / 90d windows
- 3 / 6 / 9 / 12 month understanding where possible
- analytics charts
- daily overview notifications
- broader contextual chat answers

Persistence requirements:
- once fetched, historical data should be saved locally
- avoid re-requesting the same Garmin periods unless refreshing current data or filling missing gaps
- current-day data can be refreshed more often
- trend/history data should come from local persistence whenever possible

## Numeric Correctness Rules

Very important:
- do not save or treat missing numeric values as real zeroes for metrics where zero is not a credible value
- analytics and chat must not produce nonsense averages such as a current VO2 max of `44.8` with a 7-day average of `6.4`

Rules:
- distinguish `missing` from `0`
- sanitize historical snapshots on read if older data was saved incorrectly
- do not average placeholder zeroes into baselines
- do not display a metric average if the underlying history is not numerically credible

Metrics especially sensitive to false-zero corruption:
- VO2 max
- HRV
- training readiness
- weight
- body fat
- fitness age
- endurance score
- hill score
- SpO2
- other optional Garmin metrics that are absent on some days/devices

## Device / Watch Chip Rules

Header device area should:
- show watch image/icon
- show connection/availability state
- show device name

If watch battery percentage is not reliably exposed by Garmin/library:
- do not display a fake or inferred battery value
- do not reserve excessive space for unavailable battery text
- prefer a compact device chip with icon + status + name
- if battery is unavailable, omit the battery text entirely rather than showing placeholders

Never guess battery percentage from unrelated numeric payload fields.

## Icons and UI Consistency

Use one coherent icon style across the app.

Requirements:
- menu, close, refresh, and bell icons should feel like the same set
- keep icon sizes consistent
- do not mix oversized controls beside smaller icons
- prefer one icon library consistently across the app shell

## Analytics Requirements

Analytics must be a first-class area, accessible from a tab or menu in the dashboard.

It should support:
- period switching such as `7d`, `30d`, `90d`, `12m`
- vertical scrolling on desktop and mobile so lower analytics cards are always reachable
- human-readable summaries for major metrics
- clear comparisons like current value vs window average vs 30-day baseline vs low/high
- charts only if they remain readable; avoid dense micro-sparklines that communicate little
- historical insights
- readable date formatting for Romanian users

Analytics should be powered from persisted local snapshots where possible, not live Garmin calls on each tab switch.

## Responsive / Mobile Best Practices

Every change must be evaluated for:
- small phones
- large phones
- tablets
- desktop

Mobile UX requirements:
- no hidden critical actions
- no dead zones caused by fixed panels and overflow mistakes
- drawers/overlays must fully open and close
- content inside drawers must scroll
- main content must remain usable while panels are closed
- touch targets should be comfortably tappable

Do not assume that because something works on desktop it works on mobile.

## Performance / Latency

Priorities:
- fast answers for common questions
- avoid unnecessary Ollama calls for simple metric/trend questions
- reuse persisted context aggressively where safe

If a local model is used:
- only use it where it adds real value
- keep fallback heuristic answers high quality
- always preserve language consistency

## Error Handling

User-facing messages must be human.

Good:
- explain that some historical Garmin data is temporarily incomplete

Bad:
- exposing raw strings like `step_history_unavailable:GarminAPIError`
- showing stack-ish or library-ish internal wording in primary UI

## Development Guardrails

When editing this project:
- prefer improving generic metric coverage over patching single metrics ad hoc
- keep the UI app-like and mobile-aware
- avoid reintroducing raw payload views
- preserve Romanian/English language symmetry
- preserve persistent historical storage and notifications
- verify numerical sanity for averages, baselines, and trend narratives

Before shipping:
- check `python3 -m py_compile app.py`
- test both desktop and mobile behavior
- confirm date formatting in UI
- confirm no obvious mixed-language responses
- confirm no fabricated device battery value is shown
