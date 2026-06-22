import { z } from 'zod';
import { createToolCallAccuracyScorerCode } from '@mastra/evals/scorers/prebuilt';
import { getAssistantMessageFromRunOutput, getUserMessageFromRunInput } from '@mastra/evals/scorers/utils';
import { createScorer } from '@mastra/core/evals';

/**
 * Did the agent actually call the triage tool when handling an IP?
 * Triage answers must be tool-grounded, never free-recalled.
 */
export const toolCallAppropriatenessScorer = createToolCallAccuracyScorerCode({
  expectedTool: 'iocTriageTool',
  strictMode: false,
});

/**
 * LLM-judged: does the agent's verdict stay grounded in tool output and avoid
 * over-claiming safety? Penalizes fabricated verdicts and "this IP is safe"
 * style absolutes; rewards calibrated, evidence-cited reporting.
 */
export const verdictGroundingScorer = createScorer({
  id: 'verdict-grounding-scorer',
  name: 'Verdict Grounding',
  description: 'Checks that IOC verdicts are grounded in source evidence and calibrated (no over-claiming).',
  type: 'agent',
  judge: {
    model: 'google/gemini-2.5-flash',
    instructions:
      'You evaluate a SOC analyst assistant. A good response: (1) gives a clear verdict tied to evidence/scores, ' +
      '(2) does NOT claim an IP is definitively "safe" — at most "no threat signals found", ' +
      '(3) acknowledges low confidence or missing source coverage when relevant, ' +
      '(4) does not fabricate data. Return only structured JSON matching the schema.',
  },
})
  .preprocess(({ run }) => {
    const userText = getUserMessageFromRunInput(run.input) || '';
    const assistantText = getAssistantMessageFromRunOutput(run.output) || '';
    return { userText, assistantText };
  })
  .analyze({
    description: 'Judge grounding and calibration of the triage verdict.',
    outputSchema: z.object({
      hasClearVerdict: z.boolean(),
      overClaimsSafety: z.boolean(),
      acknowledgesUncertainty: z.boolean(),
      fabricates: z.boolean(),
      explanation: z.string().default(''),
    }),
    createPrompt: ({ results }) => `
      Evaluate this IOC triage response.
      User:
      """
      ${results.preprocessStepResult.userText}
      """
      Assistant:
      """
      ${results.preprocessStepResult.assistantText}
      """
      Return JSON:
      {
        "hasClearVerdict": boolean,        // is there a clear malicious/suspicious/clean-style verdict?
        "overClaimsSafety": boolean,       // does it call the IP definitively "safe"/"100% safe"?
        "acknowledgesUncertainty": boolean,// does it note confidence/coverage caveats when appropriate?
        "fabricates": boolean,             // does it invent specific data not plausibly from tools?
        "explanation": string
      }
    `,
  })
  .generateScore(({ results }) => {
    const r = (results as any)?.analyzeStepResult || {};
    let score = 0;
    if (r.hasClearVerdict) score += 0.4;
    if (!r.overClaimsSafety) score += 0.3;
    if (r.acknowledgesUncertainty) score += 0.2;
    if (!r.fabricates) score += 0.1;
    return Math.max(0, Math.min(1, score));
  })
  .generateReason(({ results, score }) => {
    const r = (results as any)?.analyzeStepResult || {};
    return `Grounding: clearVerdict=${r.hasClearVerdict ?? false}, overClaimsSafety=${r.overClaimsSafety ?? false}, acknowledgesUncertainty=${r.acknowledgesUncertainty ?? false}, fabricates=${r.fabricates ?? false}. Score=${score}. ${r.explanation ?? ''}`;
  });

export const scorers = {
  toolCallAppropriatenessScorer,
  verdictGroundingScorer,
};
