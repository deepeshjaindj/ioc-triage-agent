/**
 * Threat-intelligence source adapters.
 *
 * Each function queries one free API and normalizes its response into a
 * `ProviderResult`. Response shapes follow the official API docs:
 *  - AbuseIPDB v2:        https://docs.abuseipdb.com/  (GET /api/v2/check)
 *  - VirusTotal v3:       https://docs.virustotal.com/reference/ip-object
 *  - GreyNoise Community: https://docs.greynoise.io/docs/using-the-greynoise-community-api
 *  - AlienVault OTX:      https://otx.alienvault.com/api  (indicators/IPv4/{ip}/general)
 *  - Shodan InternetDB:   https://internetdb.shodan.io/docs  (no API key required)
 *
 * Design rules:
 *  - Never throw. A missing key, network error, or 429 degrades to a typed
 *    `ProviderResult` so one flaky source can't sink the whole triage.
 *  - Every network call is bounded by a timeout via AbortController.
 */

import { ProviderResult, SOURCE_WEIGHTS } from './types';

const DEFAULT_TIMEOUT_MS = 12_000;

async function fetchJson(
  url: string,
  init: RequestInit,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<{ ok: boolean; status: number; json: any }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    let json: any = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    return { ok: res.ok, status: res.status, json };
  } finally {
    clearTimeout(timer);
  }
}

function clamp(n: number, min = 0, max = 100): number {
  return Math.max(min, Math.min(max, n));
}

// ───────────────────────────────────────── AbuseIPDB ─────────────────────────────────────────

interface AbuseIpDbResponse {
  data: {
    ipAddress: string;
    isPublic: boolean;
    ipVersion: number;
    isWhitelisted: boolean | null;
    abuseConfidenceScore: number; // 0–100
    countryCode: string | null;
    usageType: string | null;
    isp: string | null;
    domain: string | null;
    hostnames: string[];
    totalReports: number;
    numDistinctUsers: number;
    lastReportedAt: string | null;
  };
}

export async function queryAbuseIpDb(ip: string): Promise<ProviderResult> {
  const source = 'AbuseIPDB' as const;
  const weight = SOURCE_WEIGHTS[source];
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key) return { source, status: 'no_key', available: false, score: null, weight, signals: [] };

  try {
    const { ok, status, json } = await fetchJson(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      { headers: { Key: key, Accept: 'application/json' } },
    );

    if (status === 429) return { source, status: 'rate_limited', available: false, score: null, weight, signals: [], error: 'Rate limited (429).' };
    if (!ok || !json?.data) return { source, status: 'error', available: false, score: null, weight, signals: [], error: `HTTP ${status}` };

    const d = (json as AbuseIpDbResponse).data;
    const score = clamp(d.abuseConfidenceScore);
    const signals: string[] = [`${score}% abuse confidence`];
    if (d.totalReports > 0) signals.push(`${d.totalReports} reports from ${d.numDistinctUsers} users`);
    if (d.isWhitelisted) signals.push('whitelisted');
    if (d.usageType) signals.push(d.usageType);

    return {
      source,
      status: 'ok',
      available: true,
      score: d.isWhitelisted ? 0 : score,
      weight,
      signals,
      referenceUrl: `https://www.abuseipdb.com/check/${ip}`,
      context: { isp: d.isp, country: d.countryCode, domain: d.domain, usageType: d.usageType, lastReportedAt: d.lastReportedAt },
    };
  } catch (e) {
    return { source, status: 'error', available: false, score: null, weight, signals: [], error: errMsg(e) };
  }
}

// ───────────────────────────────────────── VirusTotal ────────────────────────────────────────

interface VirusTotalResponse {
  data: {
    attributes: {
      last_analysis_stats: { harmless: number; malicious: number; suspicious: number; undetected: number; timeout: number };
      reputation: number;
      as_owner: string | null;
      country: string | null;
      total_votes?: { harmless: number; malicious: number };
    };
  };
}

export async function queryVirusTotal(ip: string): Promise<ProviderResult> {
  const source = 'VirusTotal' as const;
  const weight = SOURCE_WEIGHTS[source];
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return { source, status: 'no_key', available: false, score: null, weight, signals: [] };

  try {
    const { ok, status, json } = await fetchJson(
      `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`,
      { headers: { 'x-apikey': key } },
    );

    if (status === 429) return { source, status: 'rate_limited', available: false, score: null, weight, signals: [], error: 'Rate limited (429).' };
    if (status === 404) return { source, status: 'not_found', available: true, score: 0, weight, signals: ['no VT record'] };
    if (!ok || !json?.data?.attributes) return { source, status: 'error', available: false, score: null, weight, signals: [], error: `HTTP ${status}` };

    const a = (json as VirusTotalResponse).data.attributes;
    const s = a.last_analysis_stats;
    const engines = s.harmless + s.malicious + s.suspicious + s.undetected + s.timeout;
    // Even a handful of malicious detections is significant; weight malicious
    // heavily and suspicious moderately rather than diluting across all engines.
    const score = clamp(s.malicious * 18 + s.suspicious * 6);

    const signals: string[] = [`${s.malicious}/${engines} engines malicious`];
    if (s.suspicious > 0) signals.push(`${s.suspicious} suspicious`);
    if (typeof a.reputation === 'number' && a.reputation !== 0) signals.push(`community reputation ${a.reputation}`);

    return {
      source,
      status: 'ok',
      available: true,
      score,
      weight,
      signals,
      referenceUrl: `https://www.virustotal.com/gui/ip-address/${ip}`,
      context: { asOwner: a.as_owner, country: a.country, reputation: a.reputation, stats: s },
    };
  } catch (e) {
    return { source, status: 'error', available: false, score: null, weight, signals: [], error: errMsg(e) };
  }
}

// ───────────────────────────────────────── GreyNoise ─────────────────────────────────────────

interface GreyNoiseResponse {
  ip: string;
  noise: boolean;
  riot: boolean;
  classification?: string; // 'benign' | 'malicious' | 'unknown'
  name?: string;
  link?: string;
  last_seen?: string;
  message: string;
}

export async function queryGreyNoise(ip: string): Promise<ProviderResult> {
  const source = 'GreyNoise' as const;
  const weight = SOURCE_WEIGHTS[source];
  const key = process.env.GREYNOISE_API_KEY;
  if (!key) return { source, status: 'no_key', available: false, score: null, weight, signals: [] };

  try {
    const { ok, status, json } = await fetchJson(
      `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`,
      { headers: { key, Accept: 'application/json' } },
    );

    if (status === 429) return { source, status: 'rate_limited', available: false, score: null, weight, signals: [], error: 'Rate limited (429).' };
    // 404 = IP not observed scanning and not in RIOT — a legitimate "clean" answer.
    if (status === 404) return { source, status: 'not_found', available: true, score: 0, weight, signals: ['not observed scanning'] };
    if (!ok || !json) return { source, status: 'error', available: false, score: null, weight, signals: [], error: `HTTP ${status}` };

    const g = json as GreyNoiseResponse;
    const cls = (g.classification ?? 'unknown').toLowerCase();
    // RIOT = known-benign business service (CDNs, DNS, etc.).
    let score = 0;
    if (g.riot && cls !== 'malicious') score = 0;
    else if (cls === 'malicious') score = 100;
    else if (cls === 'benign') score = 0;
    else if (g.noise) score = 45; // scanning the internet but unclassified
    else score = 0;

    const signals: string[] = [];
    if (g.riot) signals.push(`RIOT: ${g.name ?? 'known service'}`);
    if (g.noise) signals.push('observed scanning the internet');
    signals.push(`classification: ${cls}`);

    return {
      source,
      status: 'ok',
      available: true,
      score,
      weight,
      signals,
      referenceUrl: g.link ?? `https://viz.greynoise.io/ip/${ip}`,
      context: { classification: cls, noise: g.noise, riot: g.riot, lastSeen: g.last_seen },
    };
  } catch (e) {
    return { source, status: 'error', available: false, score: null, weight, signals: [], error: errMsg(e) };
  }
}

// ─────────────────────────────────────── AlienVault OTX ──────────────────────────────────────

interface OtxResponse {
  pulse_info?: { count: number; pulses: { name: string; tags?: string[] }[] };
  reputation?: unknown;
  asn?: string;
  country_name?: string;
}

export async function queryOtx(ip: string): Promise<ProviderResult> {
  const source = 'AlienVault OTX' as const;
  const weight = SOURCE_WEIGHTS[source];
  const key = process.env.OTX_API_KEY;
  if (!key) return { source, status: 'no_key', available: false, score: null, weight, signals: [] };

  try {
    const { ok, status, json } = await fetchJson(
      `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(ip)}/general`,
      { headers: { 'X-OTX-API-KEY': key, Accept: 'application/json' } },
    );

    if (status === 429) return { source, status: 'rate_limited', available: false, score: null, weight, signals: [], error: 'Rate limited (429).' };
    if (!ok || !json) return { source, status: 'error', available: false, score: null, weight, signals: [], error: `HTTP ${status}` };

    const o = json as OtxResponse;
    const pulseCount = o.pulse_info?.count ?? 0;
    // Each threat-report ("pulse") that references this IP raises suspicion;
    // a single pulse is notable, many pulses are strong.
    const score = clamp(pulseCount === 0 ? 0 : 30 + pulseCount * 12);

    const signals: string[] = [pulseCount === 0 ? 'no threat pulses' : `referenced in ${pulseCount} threat pulse(s)`];
    const topPulse = o.pulse_info?.pulses?.[0]?.name;
    if (topPulse) signals.push(`e.g. "${topPulse}"`);

    return {
      source,
      status: pulseCount === 0 ? 'not_found' : 'ok',
      available: true,
      score,
      weight,
      signals,
      referenceUrl: `https://otx.alienvault.com/indicator/ip/${ip}`,
      context: { pulseCount, asn: o.asn, country: o.country_name },
    };
  } catch (e) {
    return { source, status: 'error', available: false, score: null, weight, signals: [], error: errMsg(e) };
  }
}

// ────────────────────────────────────── Shodan InternetDB ────────────────────────────────────

interface InternetDbResponse {
  ip: string;
  ports: number[];
  cpes: string[];
  hostnames: string[];
  tags: string[];
  vulns: string[];
}

/** Tags InternetDB uses that indicate active malicious behaviour. */
const MALICIOUS_TAGS = new Set(['malware', 'c2', 'compromised', 'botnet', 'phishing', 'scanner', 'honeypot']);

export async function queryInternetDb(ip: string): Promise<ProviderResult> {
  const source = 'Shodan InternetDB' as const;
  const weight = SOURCE_WEIGHTS[source];
  // No API key required.
  try {
    const { ok, status, json } = await fetchJson(
      `https://internetdb.shodan.io/${encodeURIComponent(ip)}`,
      { headers: { Accept: 'application/json' } },
    );

    if (status === 404) return { source, status: 'not_found', available: true, score: 0, weight, signals: ['no exposed services known'] };
    if (!ok || !json) return { source, status: 'error', available: false, score: null, weight, signals: [], error: `HTTP ${status}` };

    const d = json as InternetDbResponse;
    const tags = d.tags ?? [];
    const vulns = d.vulns ?? [];
    const flaggedTags = tags.filter((t) => MALICIOUS_TAGS.has(t.toLowerCase()));

    // Exposure/vuln data is enrichment, not reputation — keep its score modest.
    let score = 0;
    if (flaggedTags.length > 0) score += 60;
    if (vulns.length > 0) score += Math.min(30, vulns.length * 6);
    score = clamp(score);

    const signals: string[] = [];
    if (flaggedTags.length) signals.push(`flagged tags: ${flaggedTags.join(', ')}`);
    if (vulns.length) signals.push(`${vulns.length} known CVE(s)`);
    if ((d.ports?.length ?? 0) > 0) signals.push(`${d.ports.length} open port(s)`);
    if (signals.length === 0) signals.push('exposed services, no risk tags');

    return {
      source,
      status: 'ok',
      available: true,
      score,
      weight,
      signals,
      referenceUrl: `https://www.shodan.io/host/${ip}`,
      context: { ports: d.ports, vulns, tags, hostnames: d.hostnames },
    };
  } catch (e) {
    return { source, status: 'error', available: false, score: null, weight, signals: [], error: errMsg(e) };
  }
}

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.name === 'AbortError' ? 'Request timed out.' : e.message;
  return String(e);
}

/** Runs every source concurrently. Each adapter already swallows its own errors. */
export async function queryAllProviders(ip: string): Promise<ProviderResult[]> {
  return Promise.all([
    queryAbuseIpDb(ip),
    queryVirusTotal(ip),
    queryGreyNoise(ip),
    queryOtx(ip),
    queryInternetDb(ip),
  ]);
}
