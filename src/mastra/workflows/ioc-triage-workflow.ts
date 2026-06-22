import { createStep, createWorkflow } from '@mastra/core/workflows';
import { z } from 'zod';
import { validateIp } from '../lib/ip';
import { queryAllProviders } from '../lib/providers';
import { consolidate } from '../lib/consolidate';

/**
 * Deterministic triage pipeline: validate → fan-out + consolidate → narrate.
 * Use this when you want a reproducible, auditable run (e.g. batch jobs or
 * scheduled triage) rather than free-form agent conversation.
 */

const validationSchema = z.object({
  ip: z.string(),
  valid: z.boolean(),
  version: z.enum(['IPv4', 'IPv6']).nullable(),
  isPublic: z.boolean(),
  scope: z.string(),
  reason: z.string(),
});

const validateStep = createStep({
  id: 'validate-ip',
  description: 'Validate and classify the input IP; only public addresses proceed.',
  inputSchema: z.object({ ip: z.string().describe('The IP address to triage') }),
  outputSchema: validationSchema,
  execute: async ({ inputData }) => {
    if (!inputData) throw new Error('Input data not found');
    const v = validateIp(inputData.ip);
    return { ip: v.ip, valid: v.valid, version: v.version, isPublic: v.isPublic, scope: v.scope, reason: v.reason };
  },
});

const triageStep = createStep({
  id: 'triage-and-consolidate',
  description: 'Query all threat-intel sources in parallel and consolidate a verdict.',
  inputSchema: validationSchema,
  outputSchema: z.object({
    verdict: z.string(),
    threatScore: z.number(),
    confidence: z.number(),
    summary: z.string(),
    keySignals: z.array(z.string()),
    report: z.any().nullable(),
  }),
  execute: async ({ inputData }) => {
    if (!inputData) throw new Error('Validation result not found');

    if (!inputData.valid || !inputData.isPublic) {
      return {
        verdict: 'unknown',
        threatScore: 0,
        confidence: 0,
        summary: inputData.reason,
        keySignals: [],
        report: null,
      };
    }

    const providers = await queryAllProviders(inputData.ip);
    const report = consolidate(inputData.ip, providers);
    return {
      verdict: report.verdict,
      threatScore: report.threatScore,
      confidence: report.confidence,
      summary: report.summary,
      keySignals: report.keySignals,
      report,
    };
  },
});

const iocTriageWorkflow = createWorkflow({
  id: 'ioc-triage-workflow',
  inputSchema: z.object({ ip: z.string().describe('The IP address to triage') }),
  outputSchema: z.object({
    verdict: z.string(),
    threatScore: z.number(),
    confidence: z.number(),
    summary: z.string(),
    keySignals: z.array(z.string()),
    report: z.any().nullable(),
  }),
})
  .then(validateStep)
  .then(triageStep);

iocTriageWorkflow.commit();

export { iocTriageWorkflow };
