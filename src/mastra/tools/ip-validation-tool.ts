import { createTool } from '@mastra/core/tools';
import { z } from 'zod';
import { validateIp } from '../lib/ip';

/**
 * Gate tool: the agent must validate an IP here before any reputation lookup.
 * Non-public addresses (private/loopback/etc.) are valid but flagged as not
 * meaningful for threat intelligence.
 */
export const ipValidationTool = createTool({
  id: 'validate-ip',
  description:
    'Validate whether a string is a syntactically correct IPv4/IPv6 address and classify its scope ' +
    '(public, private, loopback, reserved, etc.). Always call this before running a threat-intel lookup. ' +
    'Only public addresses should be sent to reputation sources.',
  inputSchema: z.object({
    ip: z.string().describe('The IP address to validate, e.g. "8.8.8.8" or "2001:4860:4860::8888".'),
  }),
  outputSchema: z.object({
    ip: z.string(),
    valid: z.boolean(),
    version: z.enum(['IPv4', 'IPv6']).nullable(),
    isPublic: z.boolean(),
    scope: z.enum(['public', 'private', 'loopback', 'link-local', 'reserved', 'multicast', 'unspecified', 'invalid']),
    reason: z.string(),
  }),
  execute: async (inputData) => {
    return validateIp(inputData.ip);
  },
});
