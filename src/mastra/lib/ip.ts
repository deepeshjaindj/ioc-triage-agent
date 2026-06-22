/**
 * IP address validation and classification helpers.
 *
 * Pure functions — no Mastra/network coupling — so they can be unit tested and
 * reused by tools, workflows, and the consolidation engine.
 */

export type IpVersion = 'IPv4' | 'IPv6';

export interface IpValidation {
  ip: string;
  valid: boolean;
  version: IpVersion | null;
  /** Public, routable address — the only kind worth sending to reputation sources. */
  isPublic: boolean;
  /** Private (RFC1918), loopback, link-local, reserved, multicast, etc. */
  scope:
    | 'public'
    | 'private'
    | 'loopback'
    | 'link-local'
    | 'reserved'
    | 'multicast'
    | 'unspecified'
    | 'invalid';
  reason: string;
}

const IPV4_OCTET = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

function isIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => IPV4_OCTET.test(p));
}

/**
 * Validates IPv6 including the common compressed (`::`) and IPv4-mapped
 * (`::ffff:1.2.3.4`) forms. Deliberately strict: at most one `::`.
 */
function isIpv6(ip: string): boolean {
  if (!ip.includes(':')) return false;
  // Zone index (e.g. fe80::1%eth0) — strip before validating.
  const addr = ip.split('%')[0];

  const doubleColon = addr.match(/::/g);
  if (doubleColon && doubleColon.length > 1) return false;

  // Split off a trailing embedded IPv4 (counts as 2 groups).
  const groups = addr.split(':');
  const last = groups[groups.length - 1];
  let embeddedIpv4Groups = 0;
  if (last.includes('.')) {
    if (!isIpv4(last)) return false;
    embeddedIpv4Groups = 2;
    groups.pop();
  }

  const hexGroup = /^[0-9a-fA-F]{1,4}$/;
  const nonEmpty = groups.filter((g) => g.length > 0);
  if (!nonEmpty.every((g) => hexGroup.test(g))) return false;

  const totalGroups = nonEmpty.length + embeddedIpv4Groups;
  if (addr.includes('::')) {
    // Compressed form: fewer than 8 groups, with `::` filling the gap.
    return totalGroups <= 7;
  }
  return totalGroups === 8;
}

function classifyIpv4(ip: string): IpValidation['scope'] {
  const o = ip.split('.').map(Number);
  if (o[0] === 0) return 'unspecified';
  if (o[0] === 10) return 'private';
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return 'private';
  if (o[0] === 192 && o[1] === 168) return 'private';
  if (o[0] === 169 && o[1] === 254) return 'link-local';
  if (o[0] === 127) return 'loopback';
  if (o[0] >= 224 && o[0] <= 239) return 'multicast';
  if (o[0] >= 240) return 'reserved';
  if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return 'private'; // CGNAT 100.64/10
  return 'public';
}

function classifyIpv6(ip: string): IpValidation['scope'] {
  const addr = ip.split('%')[0].toLowerCase();
  if (addr === '::' || addr === '::0') return 'unspecified';
  if (addr === '::1') return 'loopback';
  if (addr.startsWith('fe80')) return 'link-local';
  if (addr.startsWith('fc') || addr.startsWith('fd')) return 'private'; // ULA fc00::/7
  if (addr.startsWith('ff')) return 'multicast';
  // IPv4-mapped — classify by the embedded v4 address.
  const mapped = addr.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return classifyIpv4(mapped[1]);
  return 'public';
}

export function validateIp(input: string): IpValidation {
  const ip = (input ?? '').trim();

  if (!ip) {
    return { ip, valid: false, version: null, isPublic: false, scope: 'invalid', reason: 'Empty input.' };
  }

  let version: IpVersion | null = null;
  if (isIpv4(ip)) version = 'IPv4';
  else if (isIpv6(ip)) version = 'IPv6';

  if (!version) {
    return {
      ip,
      valid: false,
      version: null,
      isPublic: false,
      scope: 'invalid',
      reason: 'Not a syntactically valid IPv4 or IPv6 address.',
    };
  }

  const scope = version === 'IPv4' ? classifyIpv4(ip) : classifyIpv6(ip);
  const isPublic = scope === 'public';

  return {
    ip,
    valid: true,
    version,
    isPublic,
    scope,
    reason: isPublic
      ? `Valid public ${version} address.`
      : `Valid ${version} address but it is ${scope}; reputation lookups are not meaningful for non-public addresses.`,
  };
}
