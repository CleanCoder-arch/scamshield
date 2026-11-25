"use client";

import {
  ArrowDownToLine, ArrowRight, BadgeIndianRupee, BrainCircuit, BriefcaseBusiness, Check,
  CircleAlert, FileImage, Fingerprint, ImagePlus, Link2, LoaderCircle, LockKeyhole,
  MessageSquareText, Radar, ScanLine, ShieldCheck, Siren, UploadCloud, X, type LucideIcon,
} from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import {
  ApiError, DEFAULT_SCREENSHOT_BYTES, SCAN_STAGES, SCREENSHOT_ACCEPT, describeAiLimitation,
  scanScreenshot, scanText, validateScreenshot, type ScanResult, type ScanStage, type StageProgress,
} from "@/lib/api";
import { MAX_TEXT_LENGTH, prepareText, SCAM_SAMPLES, type ScanMode } from "@/lib/scanner";
import { SafetyPanel, ScanResults } from "./scan-results";
import styles from "./scanner.module.css";

const modes: { id: ScanMode; label: string; icon: LucideIcon }[] = [
  { id: "text", label: "Text / SMS", icon: MessageSquareText },
  { id: "image", label: "Screenshot Upload", icon: ImagePlus },
  { id: "url", label: "URL Check", icon: Link2 },
  { id: "identity", label: "Phone / UPI Check", icon: Fingerprint },
];

const inputConfig = {
  text: {
    label: "Message or SMS",
    placeholder: "Paste the suspicious message here…",
    button: "Scan message",
    hint: "Omit passwords, OTPs, and account details.",
  },
  url: {
    label: "Website link",
    placeholder: "https://example.com/verify",
    button: "Check URL",
    hint: "Paste a full link or domain. ScamShield checks indicators without opening the link.",
  },
  identity: {
    label: "Indian mobile number or UPI ID",
    placeholder: "+91 or name@upi",
    button: "Check phone / UPI",
    hint: "This checks the submitted text for scam signals. It can’t verify an account holder.",
  },
} as const;

const progressSteps: Record<ScanStage, { label: string; description: string; icon: LucideIcon }> = {
  entity_extraction: { label: "Entity extraction", description: "Find links and payment details", icon: Fingerprint },
  ml_analysis: { label: "CyberGuard analysis", description: "Score local scam patterns", icon: ShieldCheck },
  threat_intel: { label: "Threat intelligence", description: "Check links against threat feeds", icon: Radar },
  ai_verdict: { label: "AI verdict", description: "Assess scam intent", icon: BrainCircuit },
};

const sampleIcons = [ShieldCheck, BadgeIndianRupee, Siren, BriefcaseBusiness];
type ScanPhase = "idle" | "running" | "complete" | "error" | "cancelled";
type Progress = Partial<Record<ScanStage, StageProgress>>;

function scanErrorMessage(problem: unknown): string {
  if (!(problem instanceof ApiError)) return "The scan couldn’t finish. Try again.";
  if (!problem.retryAfter || (problem.code !== "duplicate_scan" && problem.code !== "rate_limited")) {
    return problem.message;
  }
  const [seconds, label] = problem.retryAfter >= 3_600 ? [3_600, "hour"] as const
    : problem.retryAfter >= 60 ? [60, "minute"] as const
    : [1, "second"] as const;
  const amount = Math.ceil(problem.retryAfter / seconds);
  const wait = `${amount} ${label}${amount === 1 ? "" : "s"}`;
  if (problem.code === "duplicate_scan") {
    return `This exact input was scanned recently. Try a different input or retry this one in about ${wait}.`;
  }
  return `The scan limit has been reached. Try again in about ${wait}.`;
}

function progressFromResult(result: ScanResult): Progress {
  return {
    entity_extraction: { event: "entity_extraction", data: { url_count: result.entities.urls.length } },
    ml_analysis: { event: "ml_analysis", data: { risk_score: result.ml.risk_score } },
    threat_intel: {
      event: "threat_intel",
      data: {
        checks: result.threat_intel.length,
        hits: result.threat_intel.filter((finding) => finding.status === "hit").length,
      },
    },
    ai_verdict: { event: "ai_verdict", data: { status: result.ai.status, scam_type: result.ai.scam_type, reason: result.ai.reason } },
  };
}

function describeStep(step: StageProgress): string {
  switch (step.event) {
    case "entity_extraction":
      return `${step.data.url_count} ${step.data.url_count === 1 ? "link" : "links"} found`;
    case "ml_analysis":
      return `Local risk score ${step.data.risk_score}/100`;
    case "threat_intel":
      if (step.data.checks === 0) return "No link checks returned";
      return `${step.data.checks} ${step.data.checks === 1 ? "check" : "checks"} reported, ${step.data.hits} matches`;
    case "ai_verdict":
      return describeAiLimitation(step.data.status, step.data.reason) ?? "Scam indicators assessed";
  }
}

function ScanProgress({ phase, progress, image }: { phase: ScanPhase; progress: Progress; image: boolean }) {
  const active = phase === "running" && !image ? SCAN_STAGES.find((stage) => !progress[stage]) : undefined;
  const summary = image && phase === "running" ? "Reading screenshot and assessing risk"
    : active ? `Running ${progressSteps[active].label.toLowerCase()}`
    : phase === "running" ? "Preparing scan result"
    : phase === "complete" ? "Scan complete"
    : phase === "error" ? "Scan stopped"
    : phase === "cancelled" ? "Scan cancelled"
    : "Ready to scan";

  return (
    <section className={`${styles.surface} ${styles.progressPanel}`} aria-labelledby="progress-title">
      <header className={styles.progressHeader}>
        <span className={styles.sectionIcon}><Radar size={19} aria-hidden="true" /></span>
        <div>
          <h2 id="progress-title">Scan progress</h2>
          <p role="status" aria-live="polite">{summary}</p>
        </div>
      </header>
      <ol className={styles.timeline} aria-label="Pipeline stages">
        {SCAN_STAGES.map((key) => {
          const step = progressSteps[key];
          const event = progress[key];
          const limited = event?.event === "ai_verdict" && event.data.status !== "completed";
          const state = limited ? "limited" : event ? "done" : key === active ? "active" : "pending";
          const Icon = limited ? CircleAlert : event ? Check : key === active ? LoaderCircle : step.icon;
          return (
            <li key={key} className={styles.stage} data-state={state} aria-current={key === active ? "step" : undefined}>
              <span className={styles.stageIcon}><Icon size={16} aria-hidden="true" /></span>
              <div>
                <span className={styles.stageLabel}>{step.label}</span>
                <p>{event ? describeStep(event) : step.description}</p>
              </div>
              {state === "done" ? <span className="sr-only">Finished</span> : null}
            </li>
          );
        })}
      </ol>
      {image && phase === "running" ? <p className={styles.imageProgress}>Screenshot checks update when the result arrives.</p> : null}
    </section>
  );
}

export function Scanner() {
  const [mode, setMode] = useState<ScanMode>("text");
  const [drafts, setDrafts] = useState({ text: "", url: "", identity: "" });
  const [file, setFile] = useState<File | null>(null);
  const [redacted, setRedacted] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [progress, setProgress] = useState<Progress>({});
  const [error, setError] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);

  const requestRef = useRef<AbortController | null>(null);
  const tabRefs = useRef(new Map<ScanMode, HTMLButtonElement>());
  const messageRef = useRef<HTMLTextAreaElement | null>(null);
  const fileRef = useRef<HTMLInputElement | null>(null);
  const resultRef = useRef<HTMLDivElement | null>(null);

  const busy = phase === "running";
  const input = mode === "image" ? null : inputConfig[mode];
  const canSubmit = mode === "image" ? Boolean(file && redacted) : Boolean(drafts[mode].trim());

  useEffect(() => () => requestRef.current?.abort(), []);
  useEffect(() => {
    if (result && resultRef.current) {
      resultRef.current.focus({ preventScroll: true });
      resultRef.current.scrollIntoView({
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "instant" : "smooth",
        block: "start",
      });
    }
  }, [result]);

  function clearInputError() {
    setError("");
    if (phase === "error" || phase === "cancelled") {
      setPhase("idle");
      setProgress({});
    }
  }

  function editDraft(nextMode: Exclude<ScanMode, "image">, text: string) {
    setDrafts((current) => ({ ...current, [nextMode]: text }));
    clearInputError();
  }

  function switchMode(nextMode: ScanMode) {
    setMode(nextMode);
    clearInputError();
  }

  function moveTab(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const next = event.key === "ArrowRight" ? (index + 1) % modes.length
      : event.key === "ArrowLeft" ? (index + modes.length - 1) % modes.length
      : event.key === "Home" ? 0
      : event.key === "End" ? modes.length - 1
      : null;
    if (next === null) return;
    event.preventDefault();
    switchMode(modes[next].id);
    tabRefs.current.get(modes[next].id)?.focus();
  }

  function chooseFile(nextFile: File | null) {
    const problem = nextFile ? validateScreenshot(nextFile) : null;
    setFile(problem ? null : nextFile);
    setRedacted(false);
    clearInputError();
    if (problem) setError(problem);
    if (fileRef.current) fileRef.current.value = "";
  }

  function loadSample(text: string) {
    setMode("text");
    editDraft("text", text);
    requestAnimationFrame(() => messageRef.current?.focus());
  }

  function cancelScan() {
    requestRef.current?.abort();
    requestRef.current = null;
    setPhase("cancelled");
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (requestRef.current) return;
    let text = "";
    try {
      if (mode === "image") {
        if (!file || !redacted) throw new Error("Choose a screenshot and confirm that you removed sensitive details.");
      } else {
        text = prepareText(mode, drafts[mode]);
      }
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Check your input and try again.");
      return;
    }

    const controller = new AbortController();
    requestRef.current = controller;
    setPhase("running");
    setProgress({});
    setResult(null);
    setError("");

    try {
      const verdict = mode === "image" && file
        ? await scanScreenshot(file, redacted, controller.signal)
        : await scanText(text, (step) => {
          if (!controller.signal.aborted) setProgress((current) => ({ ...current, [step.event]: step }));
        }, controller.signal);
      if (controller.signal.aborted) return;
      setProgress(progressFromResult(verdict));
      setResult(verdict);
      setPhase("complete");
    } catch (problem) {
      if (controller.signal.aborted) return;
      setPhase("error");
      setError(scanErrorMessage(problem));
    } finally {
      if (requestRef.current === controller) requestRef.current = null;
    }
  }

  return (
    <>
      <div className={styles.workspace}>
        <section className={`${styles.surface} ${styles.scanner}`} aria-labelledby="new-scan-title">
          <header className={styles.scannerHeader}>
            <span className={styles.sectionIcon}><ScanLine size={21} aria-hidden="true" /></span>
            <div><h2 id="new-scan-title">New scan</h2><p>Choose what you want to check.</p></div>
          </header>

          <div className={styles.tabs} role="tablist" aria-label="Scan mode">
            {modes.map(({ id, label, icon: Icon }, index) => (
              <button
                key={id}
                type="button"
                role="tab"
                id={`mode-${id}`}
                aria-controls="scan-form"
                aria-selected={mode === id}
                tabIndex={mode === id ? 0 : -1}
                disabled={busy}
                ref={(node) => { if (node) tabRefs.current.set(id, node); else tabRefs.current.delete(id); }}
                onClick={() => switchMode(id)}
                onKeyDown={(event) => moveTab(event, index)}
              >
                <Icon size={16} aria-hidden="true" /><span>{label}</span>
              </button>
            ))}
          </div>

          <div id="scan-form" role="tabpanel" aria-labelledby={`mode-${mode}`}>
            <form className={styles.form} autoComplete="off" onSubmit={submit}>
              {mode === "image" ? (
                <div className={styles.field}>
                  <label className={styles.label} htmlFor="screenshot-input">Screenshot</label>
                  <label
                    className={styles.dropzone}
                    data-dragging={dragging}
                    data-disabled={busy}
                    htmlFor="screenshot-input"
                    onDragOver={(event) => { event.preventDefault(); if (!busy) setDragging(true); }}
                    onDragLeave={() => setDragging(false)}
                    onDrop={(event) => {
                      event.preventDefault();
                      setDragging(false);
                      if (!busy) chooseFile(event.dataTransfer.files[0] ?? null);
                    }}
                  >
                    <input
                      id="screenshot-input"
                      ref={fileRef}
                      className="sr-only"
                      type="file"
                      name="file"
                      accept={SCREENSHOT_ACCEPT}
                      disabled={busy}
                      aria-describedby="screenshot-types"
                      onChange={(event) => chooseFile(event.currentTarget.files?.[0] ?? null)}
                    />
                    <span className={styles.dropIcon}><UploadCloud size={24} aria-hidden="true" /></span>
                    <strong>{file ? "Choose a different screenshot" : "Click to upload or drag and drop"}</strong>
                    <span id="screenshot-types">PNG, JPEG, or WebP. Default upload limit {DEFAULT_SCREENSHOT_BYTES / 1024 ** 2} MB.</span>
                  </label>
                  {file ? (
                    <div className={styles.file}>
                      <FileImage size={18} aria-hidden="true" />
                      <span>{file.name}</span>
                      <button type="button" aria-label="Remove selected screenshot" disabled={busy} onClick={() => chooseFile(null)}>
                        <X size={17} aria-hidden="true" />
                      </button>
                    </div>
                  ) : null}
                  <label className={styles.confirm}>
                    <input name="redacted" type="checkbox" disabled={busy || !file} checked={redacted}
                      onChange={(event) => {
                        setRedacted(event.currentTarget.checked);
                        clearInputError();
                      }} />
                    <span>
                      <strong>I removed sensitive personal details from this screenshot.</strong>
                      <span>Cover names, phone numbers, account details, UPI IDs, and OTPs before sending the image to Gemini.</span>
                    </span>
                  </label>
                </div>
              ) : (
                <div className={styles.field}>
                  <label className={styles.label} htmlFor="scan-input">{input?.label}</label>
                  {mode === "text" ? (
                    <textarea id="scan-input" ref={messageRef} value={drafts.text} maxLength={MAX_TEXT_LENGTH} spellCheck={false}
                      placeholder={input?.placeholder} disabled={busy} aria-describedby="input-note"
                      onChange={(event) => editDraft("text", event.currentTarget.value)} />
                  ) : (
                    <input id="scan-input" type="text" autoComplete="off" autoCapitalize="none" spellCheck={false}
                      inputMode={mode === "url" ? "url" : "text"} maxLength={MAX_TEXT_LENGTH}
                      placeholder={input?.placeholder} value={drafts[mode]} disabled={busy} aria-describedby="input-note"
                      onChange={(event) => editDraft(mode, event.currentTarget.value)} />
                  )}
                  <div className={styles.inputMeta}>
                    <p id="input-note"><LockKeyhole size={13} aria-hidden="true" />{input?.hint}</p>
                    {mode === "text" ? <span aria-label={`${drafts.text.length} characters`}>{drafts.text.length.toLocaleString("en-IN")} / 8,000</span> : null}
                  </div>
                </div>
              )}

              {error ? <p className={styles.error} role="alert"><CircleAlert size={17} aria-hidden="true" />{error}</p> : null}
              <div className={styles.formActions}>
                <button className={styles.submit} type="submit" disabled={busy || !canSubmit}>
                  {busy ? <LoaderCircle className={styles.spinner} size={17} aria-hidden="true" /> : <ScanLine size={17} aria-hidden="true" />}
                  {busy ? "Scanning…" : input?.button ?? "Scan screenshot"}
                  {!busy ? <ArrowRight size={17} aria-hidden="true" /> : null}
                </button>
                {busy ? <button className={styles.cancel} type="button" onClick={cancelScan}>Cancel</button> : null}
              </div>
            </form>
          </div>

          <div className={styles.samples}>
            <p><ArrowDownToLine size={15} aria-hidden="true" /> Try a sample</p>
            <div className={styles.sampleList}>
              {SCAM_SAMPLES.map(({ label, text }, index) => {
                const Icon = sampleIcons[index];
                return (
                  <button key={label} type="button" disabled={busy} onClick={() => loadSample(text)}>
                    <Icon size={15} aria-hidden="true" />{label}
                  </button>
                );
              })}
            </div>
          </div>
        </section>

        <aside className={styles.sidebar} aria-label="Scan status and reporting">
          <ScanProgress phase={phase} progress={progress} image={mode === "image"} />
          <SafetyPanel />
        </aside>
      </div>
      {result ? (
        <div className={styles.resultRegion} ref={resultRef} tabIndex={-1} role="region" aria-label="Scan results">
          <ScanResults result={result} />
        </div>
      ) : null}
    </>
  );
}
