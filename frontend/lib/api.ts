export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_URL?.trim() || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

export const SCAN_STAGES = [
  "entity_extraction",
  "ml_analysis",
  "threat_intel",
  "ai_verdict",
] as const;

export type ScanStage = (typeof SCAN_STAGES)[number];

const riskLevels = ["LOW", "MEDIUM", "HIGH"] as const;
const scamTypes = [
  "unknown", "none", "phishing", "bank_kyc", "upi_fraud", "impersonation", "investment",
  "job", "delivery", "lottery", "tech_support", "malware", "other",
] as const;
const aiStatuses = ["completed", "unavailable", "skipped"] as const;
const aiReasons = [
  "missing_api_key", "quota_exceeded", "network_error", "provider_error",
  "invalid_response", "invalid_api_key", "no_input",
] as const;
const threatStatuses = ["hit", "clear", "unavailable", "skipped"] as const;

export type RiskLevel = (typeof riskLevels)[number];
export type ScamType = (typeof scamTypes)[number];

export interface Entities {
  urls: string[];
  phones: string[];
  emails: string[];
  upi_ids: string[];
  flags: string[];
}

export interface ThreatResult {
  provider: string;
  scope: "url" | "domain";
  indicator: string;
  status: "hit" | "clear" | "unavailable" | "skipped";
  domain_age_days: number | null;
}

export type AIStatus = (typeof aiStatuses)[number];
export type AIReason = (typeof aiReasons)[number];

export interface AIResult {
  status: AIStatus;
  reason?: AIReason | null;
  scam_type: ScamType;
  explanation: string;
  actions: string[];
  confidence: number | null;
}

export interface ScoreAdjustment {
  rule: string;
  delta: number;
}

export interface ScoreBreakdown {
  starting_score: number;
  adjustments: ScoreAdjustment[];
  final_score: number;
}

interface LocalResult {
  risk_score: number;
  risk_level: RiskLevel;
  score_breakdown: ScoreBreakdown;
  reasons: string[];
  positive_signals: string[];
  legitimate_probability: number;
}

export interface SmsResult extends LocalResult {
  ml_prediction: "PHISHING/SPAM" | "LEGITIMATE";
  model_variant: "sms_tfidf";
  phishing_probability: number;
}

export interface UrlResult extends LocalResult {
  url: string;
  hostname: string;
  scheme: "http" | "https" | "unknown";
  explicit_scheme: boolean;
  ml_prediction: "MALICIOUS" | "LEGITIMATE";
  model_variant: "url_tfidf_fallback";
  malicious_probability: number;
  features: Record<string, number>;
  recommendation: string;
}

export interface ScanResult {
  scan_id: string;
  created_at: string;
  risk_score: number;
  risk_level: RiskLevel;
  scam_type: ScamType;
  entities: Entities;
  ml: {
    sms: SmsResult | null;
    urls: UrlResult[];
    risk_score: number;
    risk_level: RiskLevel;
    score_breakdown: ScoreBreakdown;
  };
  threat_intel: ThreatResult[];
  ai: AIResult;
  score_breakdown: ScoreBreakdown;
  warning_card_png_base64: string | null;
}

export type StageProgress =
  | { event: "entity_extraction"; data: { url_count: number } }
  | { event: "ml_analysis"; data: { risk_score: number } }
  | { event: "threat_intel"; data: { checks: number; hits: number } }
  | { event: "ai_verdict"; data: { status: AIStatus; scam_type: ScamType; reason?: AIReason | null } };

const aiLimitations: Record<AIReason, string> = {
  missing_api_key: "Gemini’s API key is missing.",
  quota_exceeded: "Gemini’s request quota was reached.",
  network_error: "The scanner couldn’t reach Gemini.",
  provider_error: "Gemini returned an error.",
  invalid_response: "Gemini returned an unreadable result.",
  invalid_api_key: "Gemini rejected the configured API key.",
  no_input: "There was no text for Gemini to assess.",
};

export function describeAiLimitation(status: AIStatus, reason?: AIReason | null): string | null {
  if (status === "completed") return null;
  if (reason) return aiLimitations[reason];
  return status === "skipped" ? "AI classification was skipped." : "AI classification was unavailable.";
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly code?: string,
    public readonly retryAfter?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export const DEFAULT_SCREENSHOT_BYTES = 4 * 1024 * 1024;
export const MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024;
export const SCREENSHOT_ACCEPT = "image/png,image/jpeg,image/webp";

const screenshotMimeTypes = new Set(SCREENSHOT_ACCEPT.split(","));
const screenshotMimeByExtension: Record<string, string> = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  webp: "image/webp",
};

function screenshotMime(file: File): string | undefined {
  const extension = file.name.split(".").pop()?.toLowerCase() ?? "";
  return file.type || screenshotMimeByExtension[extension];
}

export function validateScreenshot(file: File | null): string | null {
  if (!file || file.size === 0) return "Choose a screenshot to scan.";
  if (!screenshotMimeTypes.has(screenshotMime(file) ?? "")) {
    return "Choose a PNG, JPEG, or WebP screenshot.";
  }
  if (file.size > MAX_SCREENSHOT_BYTES) return "Choose a screenshot up to 8 MiB.";
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item: unknown) => typeof item === "string");
}

function isChoice<T extends string>(value: unknown, choices: readonly T[]): value is T {
  return choices.some((choice) => choice === value);
}

function isOptionalAiReason(value: unknown): boolean {
  return value === undefined || value === null || isChoice(value, aiReasons);
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function isRiskScore(value: unknown): value is number {
  return isCount(value) && value <= 100;
}

function isProbability(value: unknown): value is number {
  return typeof value === "number" && value >= 0 && value <= 1;
}

function isScoreBreakdown(value: unknown): boolean {
  return (
    isRecord(value) &&
    isRiskScore(value.starting_score) &&
    isRiskScore(value.final_score) &&
    Array.isArray(value.adjustments) &&
    value.adjustments.every((item: unknown) =>
      isRecord(item) && typeof item.rule === "string" && Number.isInteger(item.delta),
    )
  );
}

function isLocalResult(value: unknown): value is Record<string, unknown> {
  return (
    isRecord(value) &&
    isRiskScore(value.risk_score) &&
    isChoice(value.risk_level, riskLevels) &&
    isScoreBreakdown(value.score_breakdown) &&
    isStringArray(value.reasons) &&
    isStringArray(value.positive_signals) &&
    isProbability(value.legitimate_probability)
  );
}

function isMlResult(value: unknown): boolean {
  return (
    isRecord(value) &&
    isRiskScore(value.risk_score) &&
    isChoice(value.risk_level, riskLevels) &&
    isScoreBreakdown(value.score_breakdown) &&
    (
      value.sms === null ||
      (
        isLocalResult(value.sms) &&
        isProbability(value.sms.phishing_probability) &&
        typeof value.sms.ml_prediction === "string" &&
        typeof value.sms.model_variant === "string"
      )
    ) &&
    Array.isArray(value.urls) &&
    value.urls.every((item: unknown) =>
      isLocalResult(item) &&
      isProbability(item.malicious_probability) &&
      typeof item.url === "string" &&
      typeof item.hostname === "string" &&
      typeof item.ml_prediction === "string" &&
      typeof item.model_variant === "string",
    )
  );
}

function isEntityResult(value: unknown): boolean {
  return (
    isRecord(value) &&
    ["urls", "phones", "emails", "upi_ids", "flags"].every((key) => isStringArray(value[key]))
  );
}

function isThreatResult(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.provider === "string" &&
    (value.scope === "url" || value.scope === "domain") &&
    typeof value.indicator === "string" &&
    isChoice(value.status, threatStatuses) &&
    (value.domain_age_days === null || isCount(value.domain_age_days))
  );
}

function parseVerdict(payload: unknown): ScanResult {
  if (
    !isRecord(payload) ||
    typeof payload.scan_id !== "string" ||
    typeof payload.created_at !== "string" ||
    !isRiskScore(payload.risk_score) ||
    !isChoice(payload.risk_level, riskLevels) ||
    !isChoice(payload.scam_type, scamTypes) ||
    !isEntityResult(payload.entities) ||
    !isMlResult(payload.ml) ||
    !Array.isArray(payload.threat_intel) ||
    !payload.threat_intel.every(isThreatResult) ||
    !isRecord(payload.ai) ||
    !isChoice(payload.ai.status, aiStatuses) ||
    !isOptionalAiReason(payload.ai.reason) ||
    !isChoice(payload.ai.scam_type, scamTypes) ||
    typeof payload.ai.explanation !== "string" ||
    !isStringArray(payload.ai.actions) ||
    !(payload.ai.confidence === null || isProbability(payload.ai.confidence)) ||
    !isScoreBreakdown(payload.score_breakdown) ||
    !(
      payload.warning_card_png_base64 === null ||
      (
        typeof payload.warning_card_png_base64 === "string" &&
        /^[A-Za-z0-9+/]+={0,2}$/.test(payload.warning_card_png_base64)
      )
    )
  ) {
    throw new ApiError("The scanner returned an incomplete verdict. Please try again.");
  }
  return payload as unknown as ScanResult;
}

const requestErrors = new Map<string, { status: number; message: string }>([
  ["duplicate_scan", {
    status: 409, message: "This exact input was scanned recently. Try a different input or wait before retrying this one.",
  }],
  ["rate_limited", {
    status: 429, message: "The scan limit has been reached. Wait before starting another scan.",
  }],
  ["scan_capacity", {
    status: 503, message: "The scanner is busy. Please try again in a moment.",
  }],
  ["scan_failed", { status: 500, message: "The scan ended before a verdict was ready." }],
  ["image_analysis_unavailable", {
    status: 503, message: "Screenshot analysis is unavailable. You can paste the text into Text / SMS.",
  }],
  ["gemini_missing_api_key", { status: 503, message: "Gemini’s API key is missing. Paste the screenshot text into Text / SMS." }],
  ["gemini_quota_exceeded", { status: 429, message: "Gemini’s request quota was reached. Paste the screenshot text into Text / SMS." }],
  ["gemini_network_error", { status: 503, message: "The scanner couldn’t reach Gemini. Try again or paste the text into Text / SMS." }],
  ["gemini_provider_error", { status: 502, message: "Gemini returned an error. Try again or paste the text into Text / SMS." }],
  ["gemini_invalid_response", { status: 502, message: "Gemini returned an unreadable result. Try again or paste the text into Text / SMS." }],
  ["gemini_invalid_api_key", { status: 503, message: "Gemini rejected the configured API key. Paste the screenshot text into Text / SMS." }],
]);

const statusErrors = new Map([
  [413, "This input exceeds the scanner’s size limit. Try a smaller screenshot or a shorter message."],
  [415, "The scanner couldn’t read this image. Use a valid PNG, JPEG, or WebP screenshot."],
  [422, "The scanner couldn’t validate this input. Check it and try again."],
  [503, "The scanner is temporarily unavailable. Please try again in a moment."],
]);

function getErrorCode(payload: unknown, status?: number): string | undefined {
  if (isRecord(payload) && typeof payload.code === "string") {
    const error = requestErrors.get(payload.code);
    if (error && (status === undefined || error.status === status)) return payload.code;
  }
  return status === 429 ? "rate_limited" : undefined;
}

async function postScan(path: string, options: RequestInit): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
    });
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new ApiError("Couldn’t connect to the scanner. Check your connection and try again.");
  }
  if (response.ok) return response;

  const payload: unknown = await response.json().catch(() => null);
  options.signal?.throwIfAborted();
  const code = getErrorCode(payload, response.status);
  const retryHeader = response.headers.get("Retry-After") ?? "";
  const seconds = /^\d+$/.test(retryHeader) ? Number(retryHeader) : undefined;
  throw new ApiError(
    (code && requestErrors.get(code)?.message) ||
      statusErrors.get(response.status) ||
      `The scan request failed (HTTP ${response.status}).`,
    response.status,
    code,
    Number.isSafeInteger(seconds) ? seconds : undefined,
  );
}

export async function scanScreenshot(
  file: File,
  redacted: boolean,
  signal?: AbortSignal,
): Promise<ScanResult> {
  const problem = validateScreenshot(file);
  if (problem) throw new ApiError(problem);
  if (!redacted) throw new ApiError("Confirm that sensitive personal details were removed.");

  const form = new FormData();
  const mime = screenshotMime(file);
  form.set("file", file.type ? file : file.slice(0, file.size, mime), file.name);
  form.set("redacted", "true");
  const response = await postScan("/api/v1/scan/image", {
    body: form,
    headers: { Accept: "application/json" },
    signal,
  });
  const payload: unknown = await response.json().catch(() => null);
  signal?.throwIfAborted();
  return parseVerdict(payload);
}

function isStageProgress(event: string, data: unknown): boolean {
  if (!isRecord(data)) return false;
  switch (event) {
    case "entity_extraction":
      return isCount(data.url_count);
    case "ml_analysis":
      return isRiskScore(data.risk_score);
    case "threat_intel":
      return isCount(data.checks) && isCount(data.hits) && data.hits <= data.checks;
    case "ai_verdict":
      return isChoice(data.status, aiStatuses) && isChoice(data.scam_type, scamTypes) && isOptionalAiReason(data.reason);
    default:
      return false;
  }
}

function decodeEvent(name: string, data: string, onProgress: (progress: StageProgress) => void) {
  if (!data || (name !== "complete" && name !== "error" && !SCAN_STAGES.some((stage) => stage === name))) {
    return null;
  }
  let payload: unknown;
  try {
    payload = JSON.parse(data);
  } catch {
    throw new ApiError("The scanner sent an unreadable update. Please try again.");
  }
  if (name === "complete") return parseVerdict(payload);
  if (name === "error") {
    const code = getErrorCode(payload);
    const message = (code && requestErrors.get(code)?.message) || "The scan ended before a verdict was ready.";
    throw new ApiError(message, undefined, code);
  }
  if (!isStageProgress(name, payload)) {
    throw new ApiError("The scanner sent an incomplete progress update. Please try again.");
  }
  onProgress({ event: name, data: payload } as StageProgress);
  return null;
}

async function readScanStream(
  body: ReadableStream<Uint8Array>,
  onProgress: (progress: StageProgress) => void,
): Promise<ScanResult> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let eventName = "message";
  let eventData: string[] = [];

  try {
    while (true) {
      const { value, done } = await reader.read();
      buffer += decoder.decode(value, { stream: !done });

      let lineEnd = buffer.search(/[\r\n]/);
      while (lineEnd !== -1) {
        if (!done && buffer[lineEnd] === "\r" && lineEnd === buffer.length - 1) break;
        const line = buffer.slice(0, lineEnd);
        const separatorLength = buffer.startsWith("\r\n", lineEnd) ? 2 : 1;
        buffer = buffer.slice(lineEnd + separatorLength);

        if (line === "") {
          const verdict = decodeEvent(eventName, eventData.join("\n"), onProgress);
          if (verdict) return verdict;
          eventName = "message";
          eventData = [];
        } else if (!line.startsWith(":")) {
          const colon = line.indexOf(":");
          const field = colon === -1 ? line : line.slice(0, colon);
          const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
          if (field === "event") eventName = value;
          if (field === "data") eventData.push(value);
        }

        lineEnd = buffer.search(/[\r\n]/);
      }
      if (done) throw new ApiError("The scan stream closed before a verdict was ready. Please try again.");
    }
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

export async function scanText(
  text: string,
  onProgress: (progress: StageProgress) => void,
  signal?: AbortSignal,
): Promise<ScanResult> {
  const response = await postScan("/api/v1/scan/stream", {
    body: JSON.stringify({ text }),
    headers: { Accept: "text/event-stream", "Content-Type": "application/json" },
    signal,
  });
  if (!response.body || !response.headers.get("Content-Type")?.toLowerCase().includes("text/event-stream")) {
    throw new ApiError("The scanner didn’t return a progress stream. Please try again.");
  }
  try {
    return await readScanStream(response.body, onProgress);
  } catch (error) {
    if (signal?.aborted || error instanceof ApiError) throw error;
    throw new ApiError("The connection was interrupted before the scan finished. Please try again.");
  }
}
