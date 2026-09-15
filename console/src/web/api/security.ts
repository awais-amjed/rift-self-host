/** The Security tab's endpoints: replacing secrets, and which ones it shows. */
import { setting } from "../../env_file.ts";
import { livekitUrl, publicUrl } from "../../servers.ts";
import { isRotationKind, rotate } from "../../rotation.ts";
import { type ApiRoutes, failure, json } from "../responses.ts";
import { isConfigured } from "../stack_state.ts";

export const securityRoutes: ApiRoutes = async (request, url, paths) => {
  if (url.pathname === "/api/rotate" && request.method === "POST") {
    if (!isConfigured()) {
      return json({
        error: "This stack has not been set up, so there is nothing to replace.",
      }, 409);
    }
    const { kind } = await request.json();
    if (!isRotationKind(kind)) {
      return json({ error: "Nothing by that name can be replaced." }, 400);
    }
    try {
      return json({ kind, rotatedAt: await rotate(kind, paths) });
    } catch (error) {
      return failure(`rotate ${kind}`, error);
    }
  }

  return null;
};

/** One row of the dashboard's credentials panel. */
interface VisibleSecret {
  name: string;
  value: string;
  /** Masked until the operator asks for it, and worth a warning when they do. */
  secret: boolean;
  /** Why it matters, shown beside a revealed value. */
  note?: string;
}

/**
 * What the dashboard is allowed to show.
 *
 * The service-role key is deliberately absent. Nothing an operator does by
 * hand needs it any more — the console makes the one call that did — and a
 * value on a page is a value in a screenshot.
 */
export function visibleSecrets(): VisibleSecret[] {
  const entries: (VisibleSecret | null)[] = [
    // The stack's own addresses, which the LAN switch deliberately does not
    // change: this panel is what the server *is*, and the local-testing panel
    // owns where it is temporarily pointed. Derived rather than written out as
    // `https://<domain>`, so a stack set up for local testing does not claim a
    // scheme and a name it has never had.
    { name: "Server URL", value: publicUrl(), secret: false },
    { name: "LiveKit URL", value: livekitUrl(), secret: false },
    // The publishable key, because that is what the server actually issues to
    // clients. Showing the legacy JWT beside it would invite somebody to paste
    // the one nothing hands out any more.
    //
    // Masked even though every member of the server holds a copy: it is handed
    // out per member by `resolve_invite`, not published, and it is the key that
    // reaches this server's API at all. A dashboard that draws it in plain text
    // by default puts it in every screenshot and every shared screen.
    keyRow(setting("SUPABASE_PUBLISHABLE_KEY")),
  ];
  return entries.filter((entry): entry is VisibleSecret => entry !== null);
}

function keyRow(value: string | undefined): VisibleSecret | null {
  if (!value) return null;
  return {
    name: "Publishable key",
    value,
    secret: true,
    note: "Anyone holding this can reach this server's API as an anonymous " +
      "caller. Members receive it automatically when they join — you never " +
      "need to send it to anybody, and it does not belong in a screenshot.",
  };
}
