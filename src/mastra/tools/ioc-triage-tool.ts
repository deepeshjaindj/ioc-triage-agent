import { createTool } from '@mastra/core/tools';
import { z } from 'zod';
import { validateIp } from '../lib/ip';
import { queryAllProviders } from '../lib/providers';
import { consolidate } from '../lib/consolidate';

const providerResultSchema = z.object({
  source: z.string(),
  status: z.enum(['ok', 'not_found', 'no_key', 'error', 'rate_limited']),
  available: z.boolean(),
  score: z.number().nullable(),
  weight: z.number(),
  signals: z.array(z.string()),
  referenceUrl: z.string().optional(),
  error: z.string().optional(),
  context: z.record(z.string(), z.unknown()).optional(),
});

const reportSchema = z.object({
  ip: z.string(),
  verdict: z.enum(['malicious', 'suspicious', 'low-risk', 'clean', 'unknown']),
  threatScore: z.number(),
  confidence: z.number(),
  sourcesQueried: z.number(),
  sourcesAvailable: z.number(),
  summary: z.string(),
  keySignals: z.array(z.string()),
  providers: z.array(providerResultSchema),
});

/**
 * Core triage tool: validates the IP, fans out to every configured threat-intel
 * source in parallel, and returns the consolidated, weighted verdict.
 * Sources without an API key (or that fail) degrade gracefully — they're
 * reported as skipped rather than aborting the triage.
 */
export const iocTriageTool = createTool({
  id: 'triage-ip',
  description:
    'Run a full reputation triage on a single IP address across multiple threat-intelligence sources ' +
    '(AbuseIPDB, VirusTotal, GreyNoise, AlienVault OTX, Shodan InternetDB) and return a consolidated, ' +
    'weighted verdict with a 0–100 threat score, confidence, and per-source breakdown. Validates the IP first.',
  inputSchema: z.object({
    ip: z.string().describe('A public IP address to triage, e.g. "45.83.122.10".'),
  }),
  outputSchema: z.object({
    validation: z.object({
      valid: z.boolean(),
      version: z.enum(['IPv4', 'IPv6']).nullable(),
      isPublic: z.boolean(),
      scope: z.string(),
      reason: z.string(),
    }),
    report: reportSchema.nullable(),
  }),
  execute: async (inputData) => {
    const v = validateIp(inputData.ip);
    const validation = { valid: v.valid, version: v.version, isPublic: v.isPublic, scope: v.scope, reason: v.reason };

    // Hard gate: never query external sources for invalid or non-public IPs.
    if (!v.valid || !v.isPublic) {
      return { validation, report: null };
    }

    const providers = await queryAllProviders(v.ip);
    const report = consolidate(v.ip, providers);
    return { validation, report };
  },
});
