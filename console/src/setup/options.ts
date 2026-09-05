/**
 * What an operator may choose, and what they get if they choose nothing.
 *
 * Three sources, in order: a `.env` they wrote by hand before ever starting
 * the console, the defaults below, and whatever they type into the setup page.
 * The file is entirely optional — it exists so that somebody deploying from a
 * script, or on a host where 80 and 443 are already taken, does not have to
 * come through a web page to say so.
 *
 * Ports are here rather than fixed in the compose file because the two hosts
 * most likely to run a Rift server are the two most likely to have something
 * on port 80 already: a VPS with another site, and a home machine.
 */
import { readEnvFile } from "../env_file.ts";

/** Every value setup writes, with the type the form needs to render it. */
export interface SetupOptions {
  domain: string;
  serverName: string;
  /** Blank means "generate one" — the common case. */
  consolePassword: string;
  /** The interface the console's own port binds to. */
  consoleBind: string;
  consolePort: number;
  httpPort: number;
  httpsPort: number;
  livekitTcpPort: number;
  livekitUdpPort: number;
}

/** What the form shows when nothing says otherwise. */
export const defaults: SetupOptions = {
  domain: "",
  serverName: "Rift",
  consolePassword: "",
  // Loopback, because this interface can replace any container on the host.
  consoleBind: "127.0.0.1",
  consolePort: 8080,
  httpPort: 80,
  httpsPort: 443,
  livekitTcpPort: 7881,
  livekitUdpPort: 7882,
};

/** One field, as the setup page draws it. */
export interface OptionField {
  key: keyof SetupOptions;
  label: string;
  hint?: string;
  kind: "text" | "number" | "password";
  /** Tucked behind "Advanced" — correct for almost everyone as it stands. */
  advanced: boolean;
}

/**
 * The form's shape, defined once and rendered from.
 *
 * Here rather than in the HTML so that the page, the defaults and the `.env`
 * keys cannot drift into disagreeing about what a field is called.
 */
export const fields: OptionField[] = [
  {
    key: "domain",
    label: "Domain",
    kind: "text",
    advanced: false,
    hint: "Must already point at this machine, with the HTTP and HTTPS ports " +
      "below reachable. A certificate is fetched automatically. Rift will not " +
      "work over plain HTTP: Android blocks it, so the server would be " +
      "invisible to every phone.",
  },
  { key: "serverName", label: "Server name", kind: "text", advanced: false },
  {
    key: "consolePassword",
    label: "Console password",
    kind: "password",
    advanced: false,
    hint: "Leave blank and one is generated for you, then shown once when " +
      "setup finishes.",
  },
  {
    key: "httpPort",
    label: "HTTP port",
    kind: "number",
    advanced: true,
    hint: "Where Let's Encrypt answers its challenge. Moving it off 80 means " +
      "something else must forward 80 here, or no certificate can be issued.",
  },
  { key: "httpsPort", label: "HTTPS port", kind: "number", advanced: true },
  {
    key: "livekitUdpPort",
    label: "Voice port (UDP)",
    kind: "number",
    advanced: true,
    hint: "Call audio goes straight to this port and cannot be proxied, so it " +
      "has to be open from the internet.",
  },
  {
    key: "livekitTcpPort",
    label: "Voice fallback (TCP)",
    kind: "number",
    advanced: true,
  },
  {
    key: "consolePort",
    label: "Console port",
    kind: "number",
    advanced: true,
    hint: "Changing this takes effect after the console restarts itself, " +
      "which it does at the end of setup.",
  },
  {
    key: "consoleBind",
    label: "Console interface",
    kind: "text",
    advanced: true,
    hint: "127.0.0.1 keeps the console off the network. It can start, stop " +
      "and replace every container on this host, so reach it over an SSH " +
      "tunnel rather than moving it to 0.0.0.0.",
  },
];

/** Read a port from [values], falling back to [fallback] if it is not one. */
function port(values: Record<string, string>, name: string, fallback: number): number {
  const parsed = Number(values[name]);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= 65535 ? parsed : fallback;
}

/**
 * The defaults, with anything a hand-written `.env` already says.
 *
 * Never carries a password across: `CONSOLE_PASSWORD` in an existing file is
 * honoured by [SetupOptions.consolePassword] being blank and setup keeping
 * what is there — see [runSetup]. Echoing it into a form field would put it on
 * screen for anybody walking past.
 */
export function optionsFromEnv(directory?: string): SetupOptions {
  const values = readEnvFile(directory);
  return {
    ...defaults,
    domain: values.RIFT_DOMAIN ?? defaults.domain,
    serverName: values.RIFT_SERVER_NAME ?? defaults.serverName,
    consolePassword: "",
    consoleBind: values.CONSOLE_BIND ?? defaults.consoleBind,
    consolePort: port(values, "CONSOLE_PORT", defaults.consolePort),
    httpPort: port(values, "HTTP_PORT", defaults.httpPort),
    httpsPort: port(values, "HTTPS_PORT", defaults.httpsPort),
    livekitTcpPort: port(values, "LIVEKIT_TCP_PORT", defaults.livekitTcpPort),
    livekitUdpPort: port(values, "LIVEKIT_UDP_PORT", defaults.livekitUdpPort),
  };
}

/** Whether a hand-written `.env` already supplies a console password. */
export function envHasPassword(directory?: string): boolean {
  const value = readEnvFile(directory).CONSOLE_PASSWORD;
  return value !== undefined && value.length > 0;
}

/** Complain about anything that would produce a stack that cannot start. */
export function problemsWith(options: SetupOptions): string[] {
  const problems: string[] = [];

  const domain = options.domain.trim();
  if (domain.length === 0) {
    problems.push("A domain is required — it is what the certificate is issued for.");
  } else if (/^https?:\/\//i.test(domain)) {
    problems.push("Enter the domain on its own, without http:// or https://.");
  } else if (domain.includes("/")) {
    problems.push("Enter the domain on its own, without a path.");
  }

  const ports: [string, number][] = [
    ["HTTP", options.httpPort],
    ["HTTPS", options.httpsPort],
    ["Voice (UDP)", options.livekitUdpPort],
    ["Voice (TCP)", options.livekitTcpPort],
    ["Console", options.consolePort],
  ];
  for (const [name, value] of ports) {
    if (!Number.isInteger(value) || value < 1 || value > 65535) {
      problems.push(`${name} port must be between 1 and 65535.`);
    }
  }

  // Two services on one port is a container that will not start, and the
  // failure arrives minutes later inside a compose log rather than here.
  const seen = new Map<number, string>();
  for (const [name, value] of ports) {
    // UDP and TCP are different stacks, so voice may legitimately share.
    if (name === "Voice (TCP)" && value === options.livekitUdpPort) continue;
    const other = seen.get(value);
    if (other) problems.push(`${other} and ${name} cannot both use port ${value}.`);
    seen.set(value, name);
  }

  return problems;
}
