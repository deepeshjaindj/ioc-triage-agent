# IOC Triage Agent

A [Mastra](https://mastra.ai/) AI agent that triages an **IP address** indicator-of-compromise
(IOC) across multiple free threat-intelligence sources and returns a single, calibrated verdict.

## How it works

```
IP input ─▶ validate-ip ─▶ triage-ip ─▶ consolidation engine ─▶ concise verdict
              (gate)         (fan-out)      (weighted score)        (agent)
```

1. **Validate** — `validate-ip` confirms the string is a real IPv4/IPv6 address and
   classifies its scope. Private/loopback/reserved addresses are rejected (reputation
   lookups aren't meaningful for them); only public IPs proceed.
2. **Fan-out** — `triage-ip` queries all sources **in parallel**:
   | Source | Key required | Signal |
   |---|---|---|
   | AbuseIPDB | `ABUSEIPDB_API_KEY` | crowd-sourced abuse confidence (0–100) |
   | VirusTotal | `VIRUSTOTAL_API_KEY` | 70+ engine detections + reputation |
   | GreyNoise (Community) | `GREYNOISE_API_KEY` | internet-scan classification / RIOT |
   | AlienVault OTX | `OTX_API_KEY` | community threat "pulses" |
   | Shodan InternetDB | *none* | exposed ports, CVEs, risk tags |
3. **Consolidate** — every source is normalized onto a common **0–100 malicious
   score**, combined as a **reliability-weighted average**, and mapped to a verdict:
   `clean` < `low-risk` < `suspicious` < `malicious`.
4. **Confidence** reflects *coverage × agreement*: more independent sources that
   agree → higher confidence; a single source or contradicting sources → lower.

### Why it's robust
- **Graceful degradation** — a missing API key, timeout, or HTTP error never aborts
  the triage. That source is reported as skipped and only lowers confidence.
- **Per-source timeouts** via `AbortController` (12s) so one slow API can't hang the run.
- **Memory** — the agent keeps working memory of IPs already triaged this session, so
  follow-up questions don't trigger redundant lookups.

## Setup

The agent's reasoning runs on **Google Gemini** (free tier). Get a key at
[aistudio.google.com/apikey](https://aistudio.google.com/apikey) — this one is required:

```env
GOOGLE_GENERATIVE_AI_API_KEY=
```

Then add whichever threat-intel keys you have (all free; Shodan needs none). Missing
keys are skipped gracefully and only lower coverage/confidence:

```env
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
GREYNOISE_API_KEY=
OTX_API_KEY=
```

## Run

```shell
npm run dev
```

Open [http://localhost:4111](http://localhost:4111) for [Mastra Studio](https://mastra.ai/docs/studio/overview),
then chat with the **IOC Triage Agent**. Example prompts:

- `Triage 45.83.122.10`
- `Is 8.8.8.8 malicious?`
- `Check these: 1.2.3.4, 185.220.101.1`

You can also run the deterministic **`ioc-triage-workflow`** (validate → triage →
consolidate) for reproducible/batch use instead of conversational triage.

## Deploy to Netlify

Configured via [`@mastra/deployer-netlify`](https://www.npmjs.com/package/@mastra/deployer-netlify).
`npm run build` produces a Netlify Function under `.netlify/v1/` (routing/config is
generated automatically through Netlify's Frameworks API).

**1. Set environment variables in the Netlify dashboard** (Site settings → Environment
variables) — `.env` is git-ignored and is *not* deployed:

| Variable | Purpose |
|---|---|
| `GOOGLE_GENERATIVE_AI_API_KEY` + `GOOGLE_API_KEY` | LLM (required) |
| `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `GREYNOISE_API_KEY`, `OTX_API_KEY` | threat-intel sources |
| `DATABASE_URL` + `DATABASE_AUTH_TOKEN` | *(optional)* [Turso](https://turso.tech) libSQL for memory that persists across requests |
| `MASTRA_PLATFORM_ACCESS_TOKEN`, `MASTRA_PROJECT_ID` | *(optional)* observability |

**2. Deploy** — either:
- **Git integration (recommended):** push the repo and "Add new site → Import from Git"
  in Netlify. It runs `npm run build` (per `netlify.toml`) on every push.
- **CLI:** `npm i -g netlify-cli`, then `netlify deploy --build --prod`.

### Serverless notes
- Storage is environment-aware ([src/mastra/index.ts](src/mastra/index.ts)): on Netlify
  it uses libSQL (in-memory by default, or Turso if `DATABASE_URL` is set); locally it
  keeps the file-based DB + DuckDB observability store. **In-memory storage is stateless
  per cold start** — set Turso creds if you want conversation memory to persist.
- The Netlify deployer and DuckDB (a native module) are deliberately kept out of the
  deployed function to stay well under Netlify's 250 MB function limit.

## Code map

| Path | Responsibility |
|---|---|
| `src/mastra/lib/ip.ts` | IP validation + scope classification (pure) |
| `src/mastra/lib/providers.ts` | One adapter per source; normalizes API responses |
| `src/mastra/lib/consolidate.ts` | Weighted scoring + verdict + confidence |
| `src/mastra/tools/ip-validation-tool.ts` | `validate-ip` tool |
| `src/mastra/tools/ioc-triage-tool.ts` | `triage-ip` fan-out tool |
| `src/mastra/workflows/ioc-triage-workflow.ts` | Deterministic pipeline |
| `src/mastra/agents/ioc-triage-agent.ts` | The agent (memory + tools + instructions) |
| `src/mastra/scorers/ioc-triage-scorer.ts` | Eval scorers (tool use + verdict grounding) |

---

This project also retains the bootstrapped **Weather Agent** example. To learn more about
Mastra, see the [documentation](https://mastra.ai/docs/) and [course](https://mastra.ai/learn).
