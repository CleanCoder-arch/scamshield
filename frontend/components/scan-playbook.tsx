import { ArrowUpRight, ListChecks, Phone, ShieldCheck } from "lucide-react";
import type { PlaybookGuidance } from "@/lib/api";

export function CybercrimeLinks() {
  return (
    <div className="mt-4 flex flex-wrap items-center gap-2">
      <a
        href="tel:1930"
        aria-label="Call the national cybercrime helpline at 1930"
        className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-amber-300/30 bg-amber-300/8 px-3 font-mono text-sm font-semibold text-amber-200 hover:bg-amber-300/15"
      >
        <Phone size={14} aria-hidden="true" />
        1930
      </a>
      <a
        href="https://cybercrime.gov.in/"
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex min-h-10 items-center gap-1.5 rounded-lg px-2.5 text-xs font-medium text-muted hover:underline"
      >
        cybercrime.gov.in
        <ArrowUpRight size={14} aria-hidden="true" />
      </a>
    </div>
  );
}

export function ScanPlaybook({ guidance }: { guidance: PlaybookGuidance }) {
  return (
    <section className="rounded-2xl border border-stroke bg-surface p-4 sm:p-5" aria-labelledby="playbook-heading">
      <h3 id="playbook-heading" className="mb-4 flex items-center gap-2.5 text-base font-semibold tracking-tight">
        <ShieldCheck size={18} className="text-accent" aria-hidden="true" />
        Safety playbook
      </h3>
      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-xl border border-stroke bg-panel p-4">
          <h4 className="mb-2.5 text-sm font-semibold">What to do now</h4>
          <ul className="space-y-2.5 text-sm leading-relaxed text-muted">
            {guidance.steps.map((step) => (
              <li key={step} className="flex items-start gap-2.5">
                <span className="mt-[0.55em] size-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true" />
                {step}
              </li>
            ))}
          </ul>
        </div>
        <div className="rounded-xl border border-amber-300/20 bg-amber-300/5 p-4">
          <h4 className="mb-2.5 flex items-center gap-2 text-sm font-semibold">
            <ListChecks size={15} className="text-amber-300" aria-hidden="true" />
            Reporting checklist
          </h4>
          <ol className="list-decimal space-y-2 pl-5 text-sm leading-relaxed text-muted marker:text-amber-300">
            {guidance.reporting_steps.map((step) => <li key={step}>{step}</li>)}
          </ol>
          <CybercrimeLinks />
        </div>
      </div>
    </section>
  );
}
