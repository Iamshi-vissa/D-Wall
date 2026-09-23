export type Verdict = "Safe" | "Suspicious" | "Dangerous";

export type NormalizedAnalysis = {
  verdict: Verdict;
  score: number;
  target: string;
  reasons: string[];
  redirectChain: string[];
  upi: {
    payee?: string;
    name?: string;
    amount?: string | number;
    currency?: string;
  } | null;
  source: "live" | "demo";
};

const API_URL = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(/\/$/, "");

function normalizeVerdict(value: unknown, score: number): Verdict {
  const candidate = String(value || "").toLowerCase();
  if (candidate.includes("danger") || score >= 71) return "Dangerous";
  if (candidate.includes("suspicious") || candidate.includes("warning") || score >= 31) return "Suspicious";
  return "Safe";
}

function normalizeReasons(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((reason) => {
      if (typeof reason === "string") return reason;
      if (reason && typeof reason === "object") {
        const item = reason as Record<string, unknown>;
        return String(item.message || item.description || item.title || "Security signal detected");
      }
      return String(reason);
    })
    .filter(Boolean);
}

function normalizeRedirects(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => {
      if (typeof entry === "string") return entry;
      if (entry && typeof entry === "object") {
        const item = entry as Record<string, unknown>;
        return String(item.url || item.target || item.location || "");
      }
      return "";
    })
    .filter(Boolean);
}

/**
 * Keeps UI contracts stable even if the FastAPI response uses snake_case or
 * slightly different field names. No payment data is persisted here.
 */
export function normalizeAnalysis(payload: Record<string, unknown>): NormalizedAnalysis {
  const rawScore = Number(payload.score ?? payload.risk_score ?? payload.riskScore ?? 0);
  const score = Math.min(100, Math.max(0, Number.isFinite(rawScore) ? rawScore : 0));
  const target = String(payload.target ?? payload.destination ?? payload.url ?? payload.link ?? "Unknown destination");
  const upiValue = payload.upi ?? payload.payment ?? payload.payment_payload ?? null;
  const upi = upiValue && typeof upiValue === "object" ? (upiValue as NormalizedAnalysis["upi"]) : null;

  return {
    verdict: normalizeVerdict(payload.verdict ?? payload.status ?? payload.result, score),
    score,
    target,
    reasons: normalizeReasons(payload.reasons ?? payload.flags ?? payload.signals),
    redirectChain: normalizeRedirects(payload.redirect_chain ?? payload.redirectChain ?? payload.redirects),
    upi,
    source: "live",
  };
}

async function postJson(path: string, body: Record<string, unknown>): Promise<NormalizedAnalysis> {
  const response = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`HTTP_${response.status}`);
  return normalizeAnalysis((await response.json()) as Record<string, unknown>);
}

export async function analyzeLink(input: string): Promise<NormalizedAnalysis> {
  return postJson("/analyze/link", { input, link: input });
}

export async function analyzeQR(file: File): Promise<NormalizedAnalysis> {
  const formData = new FormData();
  formData.append("file", file);
  const response = await fetch(`${API_URL}/analyze/qr`, { method: "POST", body: formData });
  if (!response.ok) throw new Error(`HTTP_${response.status}`);
  return normalizeAnalysis((await response.json()) as Record<string, unknown>);
}

export { API_URL };
