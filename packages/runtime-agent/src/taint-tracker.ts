/**
 * Taint Tracker — marks values originating from HTTP request objects
 * and tracks them through the application until they reach a dangerous sink.
 *
 * Approach: WeakMap-based taint labels on string values. When a tainted
 * value is passed to a dangerous function, a finding is reported.
 */

export interface TaintSource {
  type: "query" | "params" | "body" | "headers" | "cookie";
  key: string;
  location: string;
}

export interface TaintFinding {
  source: TaintSource;
  sink: string;
  sinkLocation: string;
  value: string;
  timestamp: number;
}

// Global taint registry — maps string references to their taint source
const taintMap = new WeakMap<object, TaintSource>();
const taintedStrings = new Map<string, TaintSource>();
const findings: TaintFinding[] = [];

let reportCallback: ((finding: TaintFinding) => void) | null = null;

export function setReportCallback(cb: (finding: TaintFinding) => void) {
  reportCallback = cb;
}

export function markTainted(value: string, source: TaintSource): string {
  // Store taint label for this string value
  taintedStrings.set(value, source);
  // Also store truncated/transformed versions
  if (value.length > 0) {
    taintedStrings.set(value.trim(), source);
    taintedStrings.set(value.toLowerCase(), source);
  }
  return value;
}

export function isTainted(value: unknown): TaintSource | null {
  if (typeof value !== "string") return null;
  return taintedStrings.get(value) || null;
}

export function reportSinkAccess(
  sink: string,
  args: unknown[],
  location: string,
): void {
  for (const arg of args) {
    const source = isTainted(arg);
    if (source) {
      const finding: TaintFinding = {
        source,
        sink,
        sinkLocation: location,
        value: typeof arg === "string" ? arg.slice(0, 200) : String(arg),
        timestamp: Date.now(),
      };
      findings.push(finding);
      reportCallback?.(finding);

      console.error(
        `\n[security-audit] TAINT FLOW DETECTED\n` +
          `  Source: ${source.type}.${source.key} (${source.location})\n` +
          `  Sink:   ${sink} (${location})\n` +
          `  Value:  ${finding.value.slice(0, 80)}...\n`,
      );
    }
  }
}

export function getFindings(): TaintFinding[] {
  return [...findings];
}

export function clearFindings(): void {
  findings.length = 0;
  taintedStrings.clear();
}
