/**
 * Shared types for the IOC triage pipeline.
 *
 * Every threat-intelligence source is normalized into a common `ProviderResult`
 * so the consolidation engine can reason about heterogeneous APIs uniformly.
 */

export type ProviderName =
  | 'AbuseIPDB'
  | 'VirusTotal'
  | 'GreyNoise'
  | 'AlienVault OTX'
  | 'Shodan InternetDB';

/** What happened when we queried a source. */
export type ProviderStatus =
  | 'ok' // queried successfully, has data
  | 'not_found' // queried successfully, source has nothing on this IP
  | 'no_key' // skipped: API key not configured
  | 'error' // network/HTTP/parse failure
  | 'rate_limited'; // source returned 429

/** A source's normalized contribution to the verdict. */
export interface ProviderResult {
  source: ProviderName;
  status: ProviderStatus;
  /** True only when status === 'ok' or 'not_found' (i.e. the answer is trustworthy). */
  available: boolean;
  /**
   * Normalized malicious score 0–100 (0 = clean, 100 = certainly malicious).
   * null when the source produced no usable reputation signal.
   */
  score: number | null;
  /** Source reliability weight applied during consolidation. */
  weight: number;
  /** Short human-readable signals, e.g. "92% abuse confidence", "3/89 engines flagged". */
  signals: string[];
  /** Direct link to the source's report for analyst follow-up. */
  referenceUrl?: string;
  /** Error message when status === 'error' / 'rate_limited'. */
  error?: string;
  /** Enrichment context (ASN, ISP, country, ports, etc.) surfaced for the analyst. */
  context?: Record<string, unknown>;
}

export type Verdict = 'malicious' | 'suspicious' | 'low-risk' | 'clean' | 'unknown';

export interface ConsolidatedReport {
  ip: string;
  verdict: Verdict;
  /** Weighted, normalized 0–100 threat score across all available sources. */
  threatScore: number;
  /** 0–100 confidence in the verdict, driven by source coverage + agreement. */
  confidence: number;
  /** Count of sources that returned a trustworthy answer. */
  sourcesQueried: number;
  sourcesAvailable: number;
  /** One-line bottom line for the analyst. */
  summary: string;
  /** Notable cross-source signals worth calling out. */
  keySignals: string[];
  providers: ProviderResult[];
}

/** Per-source reliability weights used by the consolidation engine. */
export const SOURCE_WEIGHTS: Record<ProviderName, number> = {
  VirusTotal: 1.3, // 70+ engines aggregated
  AbuseIPDB: 1.1, // crowd-sourced abuse reports
  GreyNoise: 1.0, // internet-scan classification
  'AlienVault OTX': 0.8, // community threat pulses
  'Shodan InternetDB': 0.5, // exposure/vuln enrichment, weak reputation signal
};
