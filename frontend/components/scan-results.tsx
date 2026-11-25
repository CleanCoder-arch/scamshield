import Image from "next/image";
import {
  ArrowUpRight,
  ChevronDown,
  CircleAlert,
  Download,
  Fingerprint,
  ImageIcon,
  ListChecks,
  Phone,
  Radar,
  ShieldAlert,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";
import { describeAiLimitation, type RiskLevel, type ScanResult, type ScoreBreakdown, type ThreatResult } from "@/lib/api";

const PANEL = "rounded-2xl border border-stroke bg-surface";
const MUTED = "text-muted";
const ACCENT = "text-accent";
const MONO = "font-mono";
const SAFE_PORTAL = "https://cybercrime.gov.in/";

const riskTones: Record<RiskLevel, { title: string; color: string; fill: string; pill: string }> = {
  LOW: {
    title: "Low risk",
    color: ACCENT,
    fill: "bg-accent",
    pill: "border-emerald-400/30 bg-emerald-400/10",
  },
  MEDIUM: {
    title: "Medium risk",
    color: "text-amber-300",
    fill: "bg-amber-300",
    pill: "border-amber-300/30 bg-amber-300/10",
  },
  HIGH: {
    title: "High risk",
    color: "text-rose-300",
    fill: "bg-rose-400",
    pill: "border-rose-400/30 bg-rose-400/10",
  },
};

const scamNames: Record<string, string> = {
  unknown: "Unclassified",
  none: "No scam type detected",
  phishing: "Phishing",
  bank_kyc: "Bank KYC",
  upi_fraud: "UPI fraud",
  impersonation: "Impersonation",
  investment: "Investment fraud",
  job: "Job scam",
  delivery: "Delivery scam",
  lottery: "Lottery scam",
  tech_support: "Tech support scam",
  malware: "Malware",
  other: "Other scam",
};

const flagNames: Record<string, string> = {
  apk_link: "Android APK link",
  url_shortener: "Shortened URL",
  urgent_kyc: "Urgent KYC request",
};

const providerNames: Record<string, string> = {
  safe_browsing: "Google Safe Browsing",
  urlhaus: "URLhaus",
  phishtank: "PhishTank",
  virustotal: "VirusTotal",
  whois: "Domain registration (RDAP)",
};

const threatStatuses: Record<ThreatResult["status"], { label: string; color: string }> = {
  hit: { label: "Match found", color: "text-rose-300" },
  clear: { label: "No match", color: ACCENT },
  unavailable: { label: "Unavailable", color: "text-amber-300" },
  skipped: { label: "Skipped", color: MUTED },
};

function labelFor(labels: Record<string, string>, value: string): string {
  return Object.hasOwn(labels, value) ? labels[value] : value.replaceAll("_", " ");
}

function PanelHeading({ icon: Icon, children }: { icon: LucideIcon; children: ReactNode }) {
  return (
    <h3 className="mb-4 flex items-center gap-2.5 text-base font-semibold tracking-tight">
      <Icon className={ACCENT} size={17} aria-hidden="true" />
      {children}
    </h3>
  );
}

function ScoreItems({ breakdown, initialLabel }: { breakdown: ScoreBreakdown; initialLabel: string }) {
  return (
    <dl className="divide-y divide-stroke text-sm">
      <div className="flex items-baseline justify-between gap-4 py-2.5">
        <dt className={MUTED}>{initialLabel}</dt>
        <dd className={`${MONO} tabular-nums`}>{breakdown.starting_score}</dd>
      </div>
      {breakdown.adjustments.map(({ rule, delta }, index) => (
        <div key={`${rule}-${index}`} className="flex items-baseline justify-between gap-4 py-2.5">
          <dt className="min-w-0 [overflow-wrap:anywhere]">{rule}</dt>
          <dd className={`${MONO} shrink-0 tabular-nums ${delta > 0 ? "text-amber-300" : ACCENT}`}>
            {delta > 0 ? "+" : ""}{delta}
          </dd>
        </div>
      ))}
    </dl>
  );
}

type ModelResult = NonNullable<ScanResult["ml"]["sms"]> | ScanResult["ml"]["urls"][number];

function ModelEvidence({ model, title }: { model: ModelResult; title: string }) {
  const isUrl = "url" in model;
  const probability = isUrl ? model.malicious_probability : model.phishing_probability;
  const tone = riskTones[model.risk_level];
  return (
    <details className="group rounded-xl border border-stroke bg-panel">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 rounded-xl px-3 py-3 text-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent [&::-webkit-details-marker]:hidden">
        <span className="min-w-0 font-medium [overflow-wrap:anywhere]">{title}</span>
        <span className="flex shrink-0 items-center gap-2">
          <span className={`${tone.color} ${MONO} text-xs tabular-nums`}>{model.risk_score}/100</span>
          <ChevronDown size={15} className={`transition-transform group-open:rotate-180 ${MUTED}`} aria-hidden="true" />
        </span>
      </summary>
      <div className="border-t border-stroke px-3 pb-3 pt-2">
        <p className={`mb-1 text-xs leading-relaxed ${MUTED}`}>
          {isUrl ? "URL TF-IDF fallback" : "SMS TF-IDF"} · {model.ml_prediction} · {Math.round(probability * 100)}% {isUrl ? "malicious" : "phishing"} probability
        </p>
        <ScoreItems breakdown={model.score_breakdown} initialLabel="Starting score" />
        {model.positive_signals.length > 0 && (
          <ul className={`mt-2 space-y-1 text-xs leading-relaxed ${MUTED}`}>
            {model.positive_signals.map((item) => (
              <li key={item} className="flex items-start gap-2">
                <ShieldCheck className={`mt-0.5 shrink-0 ${ACCENT}`} size={13} aria-hidden="true" />
                {item}
              </li>
            ))}
          </ul>
        )}
      </div>
    </details>
  );
}

function DetectionEvidence({ result }: { result: ScanResult }) {
  const hasModels = result.ml.sms !== null || result.ml.urls.length > 0;
  return (
    <section className={`${PANEL} min-w-0 p-4 sm:p-5`} aria-label="Detection evidence">
      <PanelHeading icon={ListChecks}>Detection evidence</PanelHeading>
      <div className="mb-4">
        <ScoreItems breakdown={result.score_breakdown} initialLabel="Local detection score" />
      </div>
      {result.entities.flags.length > 0 && (
        <ul className="mb-4 flex flex-wrap gap-2">
          {result.entities.flags.map((flag) => (
            <li key={flag} className="rounded-md border border-amber-300/25 bg-amber-300/8 px-2 py-1 text-xs text-amber-200">
              {labelFor(flagNames, flag)}
            </li>
          ))}
        </ul>
      )}
      <div className="space-y-2">
        {result.ml.sms && <ModelEvidence model={result.ml.sms} title="Message model" />}
        {result.ml.urls.map((model, index) => (
          <ModelEvidence
            key={`${model.url}-${index}`}
            model={model}
            title={model.url}
          />
        ))}
        {!hasModels && <p className={`text-sm ${MUTED}`}>Local message and URL model checks were skipped.</p>}
      </div>
    </section>
  );
}

function ThreatEvidence({ checks, ai }: { checks: ThreatResult[]; ai: ScanResult["ai"] }) {
  const incomplete = checks.some(({ status }) => status === "unavailable" || status === "skipped");
  const aiLimitation = describeAiLimitation(ai.status, ai.reason);
  return (
    <section className={`${PANEL} min-w-0 p-4 sm:p-5`} aria-label="Threat intelligence">
      <PanelHeading icon={Radar}>Threat intelligence</PanelHeading>
      {checks.length === 0 ? (
        <p className={`text-sm leading-relaxed ${MUTED}`}>No eligible links were checked by external sources.</p>
      ) : (
        <ul className="divide-y divide-stroke">
          {checks.map((check, index) => {
            const status = threatStatuses[check.status];
            const age = check.domain_age_days;
            return (
              <li key={`${check.provider}-${check.indicator}-${index}`} className="flex items-start justify-between gap-3 py-2.5 first:pt-0">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{labelFor(providerNames, check.provider)}</p>
                  <p className={`${MONO} ${MUTED} mt-0.5 text-xs [overflow-wrap:anywhere]`}>{check.indicator}</p>
                </div>
                <span className={`${status.color} shrink-0 pt-0.5 text-xs font-medium`}>
                  {age === null ? status.label : `${age} ${age === 1 ? "day" : "days"} old`}
                </span>
              </li>
            );
          })}
        </ul>
      )}
      {checks.some(({ status }) => status === "clear") && (
        <p className={`mt-3 text-xs leading-relaxed ${MUTED}`}>A no-match result means the source had no matching record.</p>
      )}
      {(incomplete || aiLimitation) && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-amber-300/25 bg-amber-300/5 p-3 text-xs leading-relaxed text-amber-100">
          <CircleAlert size={15} className="mt-px shrink-0 text-amber-300" aria-hidden="true" />
          <div>
            <p className="font-semibold">Check coverage</p>
            <p>The verdict uses the checks that completed.</p>
            {aiLimitation && <p>{aiLimitation}</p>}
          </div>
        </div>
      )}
    </section>
  );
}

function ExtractedEntities({ entities }: { entities: ScanResult["entities"] }) {
  const groups = [
    { label: "URLs", values: entities.urls },
    { label: "Phone numbers", values: entities.phones },
    { label: "UPI IDs", values: entities.upi_ids },
    { label: "Email addresses", values: entities.emails },
  ].filter(({ values }) => values.length > 0);
  return (
    <section className={`${PANEL} min-w-0 p-4 sm:p-5`} aria-label="Extracted entities">
      <PanelHeading icon={Fingerprint}>Extracted entities</PanelHeading>
      {groups.length === 0 ? (
        <p className={`text-sm leading-relaxed ${MUTED}`}>No URLs, phone numbers, UPI IDs, or email addresses were identified.</p>
      ) : (
        <dl className="grid gap-4 sm:grid-cols-2">
          {groups.map(({ label, values }) => (
            <div key={label} className="min-w-0">
              <dt className={`mb-2 text-xs font-medium ${MUTED}`}>{label}</dt>
              <dd>
                <ul className="space-y-1.5">
                  {values.map((value, index) => (
                    <li key={`${value}-${index}`} className={`${MONO} rounded-lg border border-stroke bg-panel px-2.5 py-2 text-xs [overflow-wrap:anywhere]`}>{value}</li>
                  ))}
                </ul>
              </dd>
            </div>
          ))}
        </dl>
      )}
    </section>
  );
}

function WarningCard({ result }: { result: ScanResult }) {
  const png = result.warning_card_png_base64;
  if (result.risk_score < 40 || !png || png.length % 4 !== 0 || !/^iVBORw0KGgo[A-Za-z0-9+/]*={0,2}$/.test(png)) {
    return null;
  }
  const src = `data:image/png;base64,${png}`;
  return (
    <section className={`${PANEL} min-w-0 p-4 sm:p-5`} aria-label="Warning card">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 [&>h3]:mb-0">
        <PanelHeading icon={ImageIcon}>Warning card</PanelHeading>
        <a
          href={src}
          download="scamshield-warning.png"
          className={`inline-flex min-h-10 items-center gap-2 rounded-lg border border-stroke px-3 text-sm font-medium transition-colors hover:border-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${ACCENT}`}
        >
          <Download size={16} aria-hidden="true" />
          Download PNG
        </a>
      </div>
      <Image
        src={src}
        width={800}
        height={424}
        alt={`ScamShield warning card. ${riskTones[result.risk_level].title}, score ${result.risk_score} out of 100.`}
        className="mx-auto h-auto w-full max-w-[800px] rounded-xl border border-stroke"
        unoptimized
      />
    </section>
  );
}

export function SafetyPanel() {
  return (
    <section className={`${PANEL} border-amber-300/20 p-4 sm:p-5`} aria-label="Indian cybercrime help">
      <div className="mb-3 flex items-center gap-3">
        <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-amber-300/10 text-amber-300">
          <ShieldAlert size={17} aria-hidden="true" />
        </span>
        <h2 className="text-sm font-semibold">Report cybercrime</h2>
      </div>
      <p className={`text-sm leading-relaxed ${MUTED}`}>For financial cyber fraud in India, call the national helpline promptly or file a report online.</p>
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <a
          href="tel:1930"
          aria-label="Call the national cybercrime helpline at 1930"
          className={`${MONO} inline-flex min-h-10 items-center gap-2 rounded-lg border border-amber-300/30 bg-amber-300/8 px-3 text-sm font-semibold text-amber-200 transition-colors hover:bg-amber-300/15 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-300`}
        >
          <Phone size={14} aria-hidden="true" />
          1930
        </a>
        <a
          href={SAFE_PORTAL}
          target="_blank"
          rel="noopener noreferrer"
          className={`inline-flex min-h-10 items-center gap-1.5 rounded-lg px-2.5 text-xs font-medium hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${MUTED}`}
        >
          cybercrime.gov.in
          <ArrowUpRight size={14} aria-hidden="true" />
        </a>
      </div>
    </section>
  );
}

export function ScanResults({ result }: { result: ScanResult }) {
  const tone = riskTones[result.risk_level];
  const explanation = result.ai.explanation.trim() || "The score reflects the available checks. Review the evidence before acting on this message, link, or request.";
  return (
    <section id="scan-results" aria-labelledby="scan-result-title" className="space-y-4 scroll-mt-6 text-foreground">
      <div className={`${PANEL} grid gap-5 p-5 sm:grid-cols-[minmax(0,1fr)_minmax(9rem,0.46fr)] sm:items-center sm:p-6`}>
        <div className="min-w-0">
          <h2 id="scan-result-title" className="mb-3 flex items-center gap-2.5 text-sm font-semibold">
            <ShieldCheck className={ACCENT} size={18} aria-hidden="true" />
            Scan verdict
          </h2>
          <div className="flex flex-wrap items-center gap-3">
            <span className={`rounded-full border px-3 py-1 text-sm font-semibold ${tone.pill} ${tone.color}`}>{tone.title}</span>
            <span className={`text-sm ${MUTED}`}>{labelFor(scamNames, result.scam_type)}</span>
          </div>
          <p className={`mt-3 text-sm leading-relaxed [overflow-wrap:anywhere] ${MUTED}`}>{explanation}</p>
        </div>
        <div className="min-w-0">
          <div className="mb-2 flex items-baseline gap-2">
            <span className={`${MONO} ${tone.color} text-4xl font-semibold leading-none tabular-nums sm:text-5xl`}>{result.risk_score}</span>
            <span className={`${MONO} text-sm ${MUTED}`}>/ 100</span>
          </div>
          <div
            role="meter"
            aria-label="Risk score"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={result.risk_score}
            className="h-2 overflow-hidden rounded-full bg-panel"
          >
            <div className={`h-full rounded-full ${tone.fill}`} style={{ width: `${result.risk_score}%` }} />
          </div>
        </div>
      </div>

      {result.ai.actions.length > 0 && (
        <section className={`${PANEL} p-4 sm:p-5`} aria-label="Suggested next steps">
          <PanelHeading icon={ShieldCheck}>Suggested next steps</PanelHeading>
          <ul className={`list-disc space-y-2 pl-5 text-sm leading-relaxed marker:text-accent ${MUTED}`}>
            {result.ai.actions.map((action, index) => <li key={index} className="[overflow-wrap:anywhere]">{action}</li>)}
          </ul>
        </section>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <DetectionEvidence result={result} />
        <ThreatEvidence checks={result.threat_intel} ai={result.ai} />
      </div>
      <ExtractedEntities entities={result.entities} />
      <WarningCard result={result} />
    </section>
  );
}
