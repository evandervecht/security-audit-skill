import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { URL } from "node:url";
import type { Finding } from "./types.js";

export interface LiveScanResult {
  url: string;
  findings: Finding[];
  checks: {
    headers: HeaderCheckResult;
    tls: TlsCheckResult;
    cors: CorsCheckResult;
    cookies: CookieCheckResult;
    redirects: RedirectCheckResult;
    errors: ErrorCheckResult;
  };
  duration: number;
}

interface HeaderCheckResult {
  present: Record<string, string>;
  missing: string[];
}

interface TlsCheckResult {
  version?: string;
  secure: boolean;
  issues: string[];
}

interface CorsCheckResult {
  allowOrigin?: string;
  allowCredentials?: boolean;
  issues: string[];
}

interface CookieCheckResult {
  cookies: Array<{
    name: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: string | null;
  }>;
  issues: string[];
}

interface RedirectCheckResult {
  tested: boolean;
  vulnerable: boolean;
  details?: string;
}

interface ErrorCheckResult {
  verbose: boolean;
  details?: string;
}

function makeRequest(
  url: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    followRedirects?: boolean;
  } = {},
): Promise<{
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  tlsVersion?: string;
}> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === "https:";
    const reqFn = isHttps ? httpsRequest : httpRequest;

    const req = reqFn(
      url,
      {
        method: options.method || "GET",
        headers: options.headers || {},
        timeout: 10000,
        rejectUnauthorized: true,
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk;
          // Limit response size
          if (body.length > 100000) {
            res.destroy();
          }
        });
        res.on("end", () => {
          const socket = res.socket as any;
          resolve({
            statusCode: res.statusCode || 0,
            headers: res.headers,
            body: body.slice(0, 50000),
            tlsVersion: socket?.getProtocol?.() || undefined,
          });
        });
      },
    );

    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timed out"));
    });
    req.end();
  });
}

const SECURITY_HEADERS = [
  { name: "strict-transport-security", label: "HSTS", severity: "error" as const },
  { name: "content-security-policy", label: "CSP", severity: "warning" as const },
  { name: "x-content-type-options", label: "X-Content-Type-Options", severity: "warning" as const },
  { name: "x-frame-options", label: "X-Frame-Options", severity: "warning" as const },
  { name: "referrer-policy", label: "Referrer-Policy", severity: "info" as const },
  { name: "permissions-policy", label: "Permissions-Policy", severity: "info" as const },
];

function checkHeaders(
  headers: Record<string, string | string[] | undefined>,
): { result: HeaderCheckResult; findings: Finding[] } {
  const present: Record<string, string> = {};
  const missing: string[] = [];
  const findings: Finding[] = [];

  for (const header of SECURITY_HEADERS) {
    const value = headers[header.name];
    if (value) {
      present[header.label] = Array.isArray(value) ? value.join(", ") : value;
    } else {
      missing.push(header.label);
      findings.push({
        checkpointId: `LIVE-HDR-${header.label.toUpperCase().replace(/[^A-Z]/g, "")}`,
        severity: header.severity,
        message: `Missing ${header.label} security header`,
        file: "HTTP Response",
        line: 0,
        column: 0,
        matchedText: "",
      });
    }
  }

  return { result: { present, missing }, findings };
}

function checkTls(
  url: string,
  tlsVersion?: string,
): { result: TlsCheckResult; findings: Finding[] } {
  const parsed = new URL(url);
  const findings: Finding[] = [];
  const issues: string[] = [];

  if (parsed.protocol === "http:") {
    issues.push("Not using HTTPS");
    findings.push({
      checkpointId: "LIVE-TLS-NOSSL",
      severity: "error",
      message: "Site served over HTTP without TLS encryption",
      file: "TLS Configuration",
      line: 0,
      column: 0,
      matchedText: url,
    });
    return { result: { secure: false, issues }, findings };
  }

  if (tlsVersion && !["TLSv1.2", "TLSv1.3"].includes(tlsVersion)) {
    issues.push(`Outdated TLS version: ${tlsVersion}`);
    findings.push({
      checkpointId: "LIVE-TLS-VERSION",
      severity: "error",
      message: `Outdated TLS version: ${tlsVersion} (require TLS 1.2+)`,
      file: "TLS Configuration",
      line: 0,
      column: 0,
      matchedText: tlsVersion,
    });
  }

  return {
    result: { version: tlsVersion, secure: issues.length === 0, issues },
    findings,
  };
}

function checkCors(
  headers: Record<string, string | string[] | undefined>,
): { result: CorsCheckResult; findings: Finding[] } {
  const findings: Finding[] = [];
  const issues: string[] = [];
  const allowOrigin = headers["access-control-allow-origin"];
  const allowCreds = headers["access-control-allow-credentials"];

  const originStr = Array.isArray(allowOrigin) ? allowOrigin[0] : allowOrigin;
  const credsStr = Array.isArray(allowCreds) ? allowCreds[0] : allowCreds;

  if (originStr === "*") {
    issues.push("CORS allows any origin (Access-Control-Allow-Origin: *)");
    findings.push({
      checkpointId: "LIVE-CORS-WILDCARD",
      severity: "warning",
      message: "CORS wildcard origin — any site can make cross-origin requests",
      file: "CORS Configuration",
      line: 0,
      column: 0,
      matchedText: "Access-Control-Allow-Origin: *",
    });
  }

  if (originStr === "*" && credsStr === "true") {
    issues.push("CORS wildcard with credentials — this is invalid per spec but some browsers may handle it insecurely");
    findings.push({
      checkpointId: "LIVE-CORS-CREDS",
      severity: "error",
      message: "CORS wildcard origin with credentials enabled",
      file: "CORS Configuration",
      line: 0,
      column: 0,
      matchedText: "Allow-Origin: * + Allow-Credentials: true",
    });
  }

  return {
    result: {
      allowOrigin: originStr || undefined,
      allowCredentials: credsStr === "true",
      issues,
    },
    findings,
  };
}

function checkCookies(
  headers: Record<string, string | string[] | undefined>,
): { result: CookieCheckResult; findings: Finding[] } {
  const findings: Finding[] = [];
  const issues: string[] = [];
  const cookies: CookieCheckResult["cookies"] = [];

  const setCookieHeaders = headers["set-cookie"];
  if (!setCookieHeaders) {
    return { result: { cookies: [], issues: [] }, findings };
  }

  const cookieValues = Array.isArray(setCookieHeaders)
    ? setCookieHeaders
    : [setCookieHeaders];

  for (const cookie of cookieValues) {
    const nameMatch = cookie.match(/^([^=]+)=/);
    const name = nameMatch?.[1] || "unknown";
    const lower = cookie.toLowerCase();

    const secure = lower.includes("secure");
    const httpOnly = lower.includes("httponly");
    const sameSiteMatch = lower.match(/samesite=(\w+)/);
    const sameSite = sameSiteMatch?.[1] || null;

    cookies.push({ name, secure, httpOnly, sameSite });

    if (!secure) {
      issues.push(`Cookie '${name}' missing Secure flag`);
      findings.push({
        checkpointId: "LIVE-COOKIE-SECURE",
        severity: "warning",
        message: `Cookie '${name}' missing Secure flag — can be sent over HTTP`,
        file: "Cookie Configuration",
        line: 0,
        column: 0,
        matchedText: cookie.slice(0, 80),
      });
    }

    if (!httpOnly) {
      issues.push(`Cookie '${name}' missing HttpOnly flag`);
      findings.push({
        checkpointId: "LIVE-COOKIE-HTTPONLY",
        severity: "warning",
        message: `Cookie '${name}' missing HttpOnly flag — accessible via JavaScript`,
        file: "Cookie Configuration",
        line: 0,
        column: 0,
        matchedText: cookie.slice(0, 80),
      });
    }

    if (!sameSite || sameSite === "none") {
      issues.push(`Cookie '${name}' has weak SameSite policy`);
      findings.push({
        checkpointId: "LIVE-COOKIE-SAMESITE",
        severity: "info",
        message: `Cookie '${name}' SameSite=${sameSite || "not set"} — consider Lax or Strict`,
        file: "Cookie Configuration",
        line: 0,
        column: 0,
        matchedText: cookie.slice(0, 80),
      });
    }
  }

  return { result: { cookies, issues }, findings };
}

async function checkRedirects(
  baseUrl: string,
): Promise<{ result: RedirectCheckResult; findings: Finding[] }> {
  const findings: Finding[] = [];

  // Test common redirect parameters
  const testPayloads = [
    { param: "redirect", value: "https://evil.com" },
    { param: "url", value: "https://evil.com" },
    { param: "next", value: "https://evil.com" },
    { param: "return", value: "https://evil.com" },
  ];

  for (const { param, value } of testPayloads) {
    try {
      const testUrl = `${baseUrl}?${param}=${encodeURIComponent(value)}`;
      const res = await makeRequest(testUrl);

      if (
        res.statusCode >= 300 &&
        res.statusCode < 400 &&
        res.headers.location
      ) {
        const location = Array.isArray(res.headers.location)
          ? res.headers.location[0]
          : res.headers.location;
        if (location?.includes("evil.com")) {
          findings.push({
            checkpointId: "LIVE-REDIRECT-OPEN",
            severity: "error",
            message: `Open redirect via '${param}' parameter — redirects to external domain`,
            file: "Redirect Configuration",
            line: 0,
            column: 0,
            matchedText: `${param}=${value} → ${location}`,
          });
          return {
            result: {
              tested: true,
              vulnerable: true,
              details: `Parameter '${param}' redirects to attacker-controlled URL`,
            },
            findings,
          };
        }
      }
    } catch {
      // Request failed — skip this test
    }
  }

  return { result: { tested: true, vulnerable: false }, findings };
}

async function checkErrors(
  baseUrl: string,
): Promise<{ result: ErrorCheckResult; findings: Finding[] }> {
  const findings: Finding[] = [];

  // Try to trigger an error page
  const errorUrls = [
    `${baseUrl}/nonexistent-path-${Date.now()}`,
    `${baseUrl}/%00`,
    `${baseUrl}/'`,
  ];

  for (const url of errorUrls) {
    try {
      const res = await makeRequest(url);

      // Check for stack traces and debug info
      const verbosePatterns = [
        /at\s+\w+\s+\([^)]*:\d+:\d+\)/, // Node.js stack trace
        /Traceback\s+\(most recent call last\)/, // Python traceback
        /Fatal error:.*in.*on line \d+/, // PHP fatal error
        /Exception in thread/, // Java exception
        /Stack Trace:/, // .NET stack trace
        /DEBUG\s*=\s*True/i, // Django debug
        /Laravel.*Exception/, // Laravel exception
      ];

      for (const pattern of verbosePatterns) {
        if (pattern.test(res.body)) {
          findings.push({
            checkpointId: "LIVE-ERROR-VERBOSE",
            severity: "error",
            message: "Verbose error page exposes stack trace or debug information",
            file: "Error Handling",
            line: 0,
            column: 0,
            matchedText: res.body.match(pattern)?.[0] || "stack trace detected",
          });
          return {
            result: { verbose: true, details: "Stack trace exposed in error response" },
            findings,
          };
        }
      }
    } catch {
      // Request failed — skip
    }
  }

  return { result: { verbose: false }, findings };
}

export async function scanLive(url: string): Promise<LiveScanResult> {
  const startTime = Date.now();
  const allFindings: Finding[] = [];

  // Normalize URL
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = `https://${url}`;
  }

  // Main request
  let response;
  try {
    response = await makeRequest(url);
  } catch (e) {
    return {
      url,
      findings: [
        {
          checkpointId: "LIVE-CONN-FAILED",
          severity: "error",
          message: `Failed to connect: ${e instanceof Error ? e.message : String(e)}`,
          file: "Connection",
          line: 0,
          column: 0,
          matchedText: url,
        },
      ],
      checks: {
        headers: { present: {}, missing: [] },
        tls: { secure: false, issues: ["Connection failed"] },
        cors: { issues: [] },
        cookies: { cookies: [], issues: [] },
        redirects: { tested: false, vulnerable: false },
        errors: { verbose: false },
      },
      duration: Date.now() - startTime,
    };
  }

  // Run all checks
  const { result: headers, findings: headerFindings } = checkHeaders(response.headers);
  allFindings.push(...headerFindings);

  const { result: tls, findings: tlsFindings } = checkTls(url, response.tlsVersion);
  allFindings.push(...tlsFindings);

  const { result: cors, findings: corsFindings } = checkCors(response.headers);
  allFindings.push(...corsFindings);

  const { result: cookies, findings: cookieFindings } = checkCookies(response.headers);
  allFindings.push(...cookieFindings);

  const { result: redirects, findings: redirectFindings } = await checkRedirects(url);
  allFindings.push(...redirectFindings);

  const { result: errors, findings: errorFindings } = await checkErrors(url);
  allFindings.push(...errorFindings);

  return {
    url,
    findings: allFindings,
    checks: { headers, tls, cors, cookies, redirects, errors },
    duration: Date.now() - startTime,
  };
}
