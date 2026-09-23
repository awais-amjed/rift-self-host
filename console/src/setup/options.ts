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
  /**
   * A **disposable** stack on a LAN address, over plain HTTP.
   *
   * Not a mode a server graduates out of, and the console says so. A server's
   * address is part of every member's identity — the SIWS keypair is derived
   * from `(host, serverId)` — so changing it later makes every member a
   * stranger and every message sealed to them unreadable. A real server is
   * therefore named once, and the name is what moves when the machine does.
   *
   * It is also weaker than it looks: over HTTP nothing proves the address is
   * the address, and every SIWS message is the same constant string, so
   * anybody on the network can collect a signature that works on the real
   * thing. Fine for an afternoon on a trusted LAN; not fine for a server with
   * people on it.
   *
   * Phones cannot use it at all — Android has blocked cleartext since API 28.
   */
  localTesting: boolean;

  /** The LAN address clients reach, e.g. `192.168.1.6`. Local testing only. */
  localAddress: string;

  /** Where Kong is published in local testing — 8000 is usually taken. */
  localPort: number;

  /**
   * The operator already runs a reverse proxy, so this stack should not start
   * one of its own.
   *
   * Caddy here is a convenience, not a component: it holds a certificate and
   * routes two upstreams. Somebody who already terminates TLS for other things
   * on this machine has all of that, and starting a second proxy would mean
   * two processes competing for 80 and 443. So the stack keeps the domain —
   * every member's identity is derived from it, and TLS is still required —
   * and publishes its two upstreams on the loopback for the proxy to reach.
   */
  ownProxy: boolean;

  /**
   * Where Kong is published for that proxy, on 127.0.0.1.
   *
   * Loopback rather than every interface, because a published signalling port
   * on a public host is LiveKit and the API answering in the clear beside the
   * TLS that was meant to front them. A proxy in a container reaches
   * `kong:8000` on this stack's network instead and needs no published port at
   * all.
   */
  proxyPort: number;

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
  localTesting: false,
  localAddress: "",
  localPort: 18000,
  ownProxy: false,
  proxyPort: 8000,
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

/**
 * When a field applies at all.
 *
 * The two toggles are not preferences, they are three different stacks, and
 * most of this form belongs to only one of them: a local-testing stack has no
 * domain and no certificate, and neither it nor an operator's own proxy runs
 * Caddy, so the HTTP and HTTPS ports are nobody's. [problemsWith] has always
 * known that — it refuses the combinations and skips the ports it does not
 * own — but the form did not, so an operator filled in a domain, picked local
 * testing, and was told at submit that it had all been for nothing.
 */
export type AppliesWhen =
  /** A real server: a domain, and something terminating TLS for it. */
  | "domain"
  /** A throwaway stack on the LAN. */
  | "local"
  /** Only with the operator's own reverse proxy in front. */
  | "proxy"
  /** Only when this stack runs its own Caddy — neither of the above. */
  | "caddy";

/** One field, as the setup page draws it. */
export interface OptionField {
  key: keyof SetupOptions;
  label: string;
  hint?: string;
  kind: "text" | "number" | "password" | "toggle";
  /** Tucked behind "Advanced" — correct for almost everyone as it stands. */
  advanced: boolean;
  /** Absent means every stack has one. */
  only?: AppliesWhen;
}

/** Whether [field] applies to the stack [options] describes. */
export function applies(field: OptionField, options: SetupOptions): boolean {
  switch (field.only) {
    case undefined:
      return true;
    case "local":
      return options.localTesting;
    case "domain":
      return !options.localTesting;
    case "proxy":
      return !options.localTesting && options.ownProxy;
    case "caddy":
      return !options.localTesting && !options.ownProxy;
  }
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
    only: "domain",
    hint: "Must already point at this machine. Unless you bring your own " +
      "reverse proxy below, the HTTP and HTTPS ports must be reachable and a " +
      "certificate is fetched automatically. Rift will not work over plain " +
      "HTTP: Android blocks it, so the server would be invisible to every " +
      "phone.",
  },
  { key: "serverName", label: "Server name", kind: "text", advanced: false },
  {
    key: "localTesting",
    label: "Local testing only",
    kind: "toggle",
    advanced: false,
    hint: "A throwaway server on your LAN, over plain HTTP, with no domain and " +
      "no certificate. Phones cannot reach it, and it cannot be turned into a " +
      "real server later — a server's address is part of every member's " +
      "identity. Use it to try Rift, then build a real one.",
  },
  {
    key: "localAddress",
    label: "LAN address",
    kind: "text",
    advanced: false,
    only: "local",
    hint: "What clients will type, such as 192.168.1.6. Local testing only.",
  },
  {
    key: "localPort",
    label: "Local API port",
    kind: "number",
    advanced: true,
    only: "local",
    hint: "Where the API is published for local testing. 8000 is usually " +
      "already taken by something.",
  },
  {
    key: "ownProxy",
    label: "I have my own reverse proxy",
    kind: "toggle",
    advanced: false,
    only: "domain",
    hint: "Skips the built-in Caddy, for a machine that already terminates " +
      "TLS for something else. The stack publishes its two upstreams on " +
      "127.0.0.1 instead, and the dashboard shows the routes to point at " +
      "them. You still need the domain above — it is what your proxy serves, " +
      "and what every member's identity is derived from.",
  },
  {
    key: "proxyPort",
    label: "API port for your proxy",
    kind: "number",
    advanced: false,
    only: "proxy",
    hint: "Where Kong is published on 127.0.0.1 for your proxy to reach. " +
      "LiveKit's signalling goes to 127.0.0.1:7880 beside it.",
  },
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
    only: "caddy",
    hint: "Where Let's Encrypt answers its challenge. Moving it off 80 means " +
      "something else must forward 80 here, or no certificate can be issued.",
  },
  {
    key: "httpsPort",
    label: "HTTPS port",
    kind: "number",
    advanced: true,
    only: "caddy",
  },
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
    localTesting: values.RIFT_LOCAL_TESTING === "true",
    localAddress: values.RIFT_LOCAL_ADDRESS ?? defaults.localAddress,
    localPort: port(values, "RIFT_LOCAL_PORT", defaults.localPort),
    ownProxy: values.RIFT_OWN_PROXY === "true",
    proxyPort: port(values, "RIFT_PROXY_PORT", defaults.proxyPort),
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
  // Two ways of not running Caddy, and they do not compose: a local-testing
  // stack has no domain for a proxy to serve, and it publishes on the LAN
  // rather than the loopback so that other machines can reach it at all.
  if (options.localTesting && options.ownProxy) {
    problems.push(
      "Local testing already publishes the API directly, and has no domain " +
        "for a reverse proxy to serve. Pick one.",
    );
  }
  if (options.localTesting) {
    // A LAN address instead of a name. Deliberately not validated as a
    // hostname: the point of this mode is the addresses a name cannot be
    // issued for.
    if (options.localAddress.trim().length === 0) {
      problems.push(
        "Local testing needs the address clients will reach, such as 192.168.1.6.",
      );
    } else if (/^https?:\/\//i.test(options.localAddress)) {
      problems.push("Enter the address on its own, without http:// or https://.");
    }
  } else if (domain.length === 0) {
    problems.push("A domain is required — it is what the certificate is issued for.");
  } else if (/^https?:\/\//i.test(domain)) {
    problems.push("Enter the domain on its own, without http:// or https://.");
  } else if (domain.includes("/")) {
    problems.push("Enter the domain on its own, without a path.");
  }

  // 80 and 443 belong to whoever is terminating TLS. With an operator's own
  // proxy doing that, they are not this stack's to bind or to complain about.
  const ports: [string, number][] = [
    ...(options.ownProxy ? [] : [
      ["HTTP", options.httpPort] as [string, number],
      ["HTTPS", options.httpsPort] as [string, number],
    ]),
    ["Voice (UDP)", options.livekitUdpPort],
    ["Voice (TCP)", options.livekitTcpPort],
    ["Console", options.consolePort],
    ...(options.localTesting
      ? [["Local API", options.localPort] as [string, number]]
      : []),
    ...(options.ownProxy
      ? [
        ["Proxy API", options.proxyPort] as [string, number],
        // Published beside it, and fixed: it is LiveKit's own port, and the
        // routes the dashboard hands the operator name it.
        ["LiveKit signalling", 7880] as [string, number],
      ]
      : []),
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
