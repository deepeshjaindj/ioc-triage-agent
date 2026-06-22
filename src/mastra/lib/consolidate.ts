/**
 * Consolidation engine.
 *
 * Turns a set of normalized `ProviderResult`s into a single `ConsolidatedReport`:
 *  - threatScore: weighted average of each available source's 0–100 score,
 *    where weights reflect source reliability (see SOURCE_WEIGHTS).
 *  - verdict: threatScore mapped to bands (clean → malicious).
 *  - confidence: driven by how many sources answered AND how much they agree.
 *    Many sources that agree → high confidence. Few sources, or sources that
 *    disagree wildly → low confidence (verdict should be treated cautiously).
 */

import { ConsolidatedReport, ProviderResult, Verdict } from './types';

function bandToVerdict(score: number): Verdict {
  if (score >= 70) return 'malicious';
  if (score >= 40) return 'suspicious';
  if (score >= 15) return 'low-risk';
  return 'clean';
}

const VERDICT_BLURB: Record<Verdict, string> = {
  malicious: 'Malicious — strong consensus this IP is a threat. Recommend blocking and investigating related activity.',
  suspicious: 'Suspicious — multiple risk signals present. Treat with caution and corroborate before allowing.',
  'low-risk': 'Low risk — minor or isolated signals; likely benign but worth a glance in context.',
  clean: 'Clean — no meaningful threat signals across the queried sources.',
  unknown: 'Unknown — not enough source coverage to render a confident verdict.',
};

/** Population standard deviation of scores, used as a disagreement measure. */
function stdDev(values: number[]): number {
  if (values.length < 2) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
  return Math.sqrt(variance);
}

export function consolidate(ip: string, providers: ProviderResult[]): ConsolidatedReport {
  // A source counts toward the verdict only if it returned a trustworthy answer
  // (ok / not_found) AND produced a numeric score.
  const scored = providers.filter((p) => p.available && typeof p.score === 'number');
  const sourcesQueried = providers.length;
  const sourcesAvailable = scored.length;

  if (sourcesAvailable === 0) {
    return {
      ip,
      verdict: 'unknown',
      threatScore: 0,
      confidence: 0,
      sourcesQueried,
      sourcesAvailable,
      summary: noSourcesSummary(providers),
      keySignals: [],
      providers,
    };
  }

  const totalWeight = scored.reduce((sum, p) => sum + p.weight, 0);
  const weightedScore = scored.reduce((sum, p) => sum + (p.score as number) * p.weight, 0) / totalWeight;
  const threatScore = Math.round(weightedScore);
  const verdict = bandToVerdict(threatScore);

  // Confidence = coverage × agreement.
  //  - coverage rewards having more independent sources (saturating at 4).
  //    A single source can never reach high confidence — there's nothing to
  //    corroborate it against, so "perfect agreement" would be illusory.
  //  - agreement penalizes score dispersion (sources contradicting each other),
  //    with a floor so that many sources disagreeing still beats one lone source.
  const coverage = Math.min(1, sourcesAvailable / 4);
  const dispersion = stdDev(scored.map((p) => p.score as number)); // 0–~50
  const agreement = Math.max(0, 1 - dispersion / 50);
  const confidence = Math.round(100 * coverage * (0.5 + 0.5 * agreement));

  // Surface the strongest signals: any source scoring >= 40, highest first.
  const keySignals = [...scored]
    .filter((p) => (p.score as number) >= 40)
    .sort((a, b) => (b.score as number) - (a.score as number))
    .flatMap((p) => p.signals.map((s) => `${p.source}: ${s}`))
    .slice(0, 6);

  const skipped = providers.filter((p) => !p.available);
  const summary =
    `${VERDICT_BLURB[verdict]} ` +
    `(threat score ${threatScore}/100, ${confidence}% confidence from ${sourcesAvailable}/${sourcesQueried} source(s)` +
    (skipped.length ? `; ${skipped.map((p) => `${p.source}: ${p.status}`).join(', ')}` : '') +
    `).`;

  return { ip, verdict, threatScore, confidence, sourcesQueried, sourcesAvailable, summary, keySignals, providers };
}

function noSourcesSummary(providers: ProviderResult[]): string {
  const reasons = providers.map((p) => `${p.source}: ${p.status}${p.error ? ` (${p.error})` : ''}`).join(', ');
  return `No threat-intelligence source returned usable data. Configure API keys to enable lookups. Status — ${reasons}.`;
}
