/**
 * Redaction of key holders. Logs, util.inspect, error reporters and JSON
 * serializers all see a key holder only through redactedView, so key material
 * reaches them only if a holder puts it in publicFields.
 */

/** Marker printed in place of every secret */
export const REDACTED = "[REDACTED]";

/**
 * The one redacted view: publicFields are printed as given, and every name in
 * secretFields is printed as REDACTED. Each secret name must be the holder's real
 * field name: a name that matches no field hides nothing.
 */
export function redactedView(
  publicFields: Record<string, unknown>,
  secretFields: string[]
): Record<string, unknown> {
  const view: Record<string, unknown> = { ...publicFields };
  for (const name of secretFields) {
    view[name] = REDACTED;
  }
  return view;
}

/** The util.inspect form of a redacted view: the class name, then its JSON */
export function inspectRedacted(className: string, view: Record<string, unknown>): string {
  return `${className} ${JSON.stringify(view)}`;
}
