/**
 * What may be typed into a setting that ends up in `.env`, a YAML file, a
 * Caddyfile or LiveKit's command line.
 *
 * Each of those reads the value raw. A space, a `;` or a `$` in an address
 * reached `sh -c` in LiveKit's entrypoint and compose's interpolation; a
 * port in it (`192.168.1.6:18000`) became `http://192.168.1.6:18000:18000` and
 * a LiveKit that would not start; a quote at the start of a free-text value
 * made compose read an unterminated string and swallow the lines after it.
 * So addresses are held to what an address is, and free text to what `.env`
 * can carry unquoted.
 */

/** A DNS name: labels of letters, digits and inner hyphens, dot-separated. */
const HOSTNAME =
  /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

const IPV4 =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

export function isHostname(value: string): boolean {
  return HOSTNAME.test(value);
}

export function isIpv4(value: string): boolean {
  return IPV4.test(value);
}

/** An IPv6 literal, without brackets. Loose, but never anything a shell or YAML reads specially. */
export function isIpv6(value: string): boolean {
  return value.includes(":") && /^[0-9A-Fa-f:.]+$/.test(value) && !value.includes(":::");
}

/** An address the console can be published on: an IP literal, nothing else. */
export function isBindAddress(value: string): boolean {
  return isIpv4(value) || isIpv6(value);
}

/**
 * Why [value] cannot go into `.env` as it is, or null. Control characters end
 * the line; a quote first starts a quoted value compose wants closed; a `#`
 * after a space starts a comment, so compose and the console would read two
 * different values.
 */
export function envTextProblem(label: string, value: string): string | null {
  // deno-lint-ignore no-control-regex
  if (/[\x00-\x1f\x7f]/.test(value)) {
    return `${label} cannot contain line breaks or other control characters.`;
  }
  if (/^["'`]/.test(value.trim())) {
    return `${label} cannot start with a quote mark.`;
  }
  if (/\s#/.test(value)) {
    return `${label} cannot contain a # after a space.`;
  }
  return null;
}

/** The shortest console password or backup passphrase accepted. */
export const MIN_SECRET_LENGTH = 8;
