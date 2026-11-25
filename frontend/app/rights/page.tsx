import type { Metadata } from "next";
import {
  ArrowUpRight, BriefcaseBusiness, Fingerprint, Info, Landmark, Link2,
  LockKeyhole, Phone, Scale, ShieldCheck, Siren, Smartphone, type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: "Know Your Rights",
  description: "Recognise common cyber scams in India, act in the first hour, and learn how to report fraud and raise a grievance.",
};

const PORTAL = "https://cybercrime.gov.in/";
const sections = [
  ["scam-tactics", "Scam tactics"],
  ["legal-protections", "Legal protections"],
  ["first-hour", "First-hour checklist"],
  ["cyber-hygiene", "Cyber hygiene"],
] as const;

const tactics = [
  {
    title: "Digital arrest calls",
    icon: Siren,
    body: "Police, CBI and courts do not arrest people over voice or video calls or demand a “verification deposit” to clear a case. End the call and verify through a number you find independently on the agency’s official site.",
    source: ["MHA digital arrest advisory", "https://www.pib.gov.in/PressReleaseIframePage.aspx?PRID=2020570&lang=2&reg=48"],
  },
  {
    title: "UPI collect and PIN traps",
    icon: Smartphone,
    body: "A collect request asks you to pay. Entering your UPI PIN to approve it can debit your account. Receiving a refund or cashback requires neither a UPI PIN nor a QR code scan. Decline an unexpected request and check your transaction history in your UPI app.",
    source: ["NPCI fraud awareness", "https://www.npci.org.in/fraud-awareness"],
  },
  {
    title: "Fake KYC, parcel and utility links",
    icon: Link2,
    body: "A message may threaten bank suspension or a power cut, or claim a parcel is held until you pay. Leave its link unopened. Check the notice in the bank, courier or utility’s official app or website.",
    source: ["DoT warning on fake KYC and electricity messages", "https://www.pib.gov.in/PressReleasePage.aspx?PRID=2025970&lang=2&reg=48"],
  },
  {
    title: "Fake jobs and prepaid tasks",
    icon: BriefcaseBusiness,
    body: "High-pay job offers and small task payouts can lead to demands for registration or training fees, top-ups, or fees to unlock earnings. Check the employer’s official careers page and decline upfront payments for an offer.",
    source: ["I4C fake job advisory", "https://cybercrime.gov.in/Webform/theme/resources/advisories/ADVISORY%20TAU-ADV-004_Captcha%20Filling%20Fraud_08.04.2025.pdf"],
  },
] as const;

const firstHour = [
  {
    title: "End contact",
    body: "Hang up or stop replying. Refuse any verification, release or “tax” payment. Leave the supplied links and QR codes alone.",
  },
  {
    title: "Call 1930 and file online",
    body: "Call 1930 for financial cyber fraud and file or complete the report at cybercrime.gov.in. Save the acknowledgement ID and use it when following up.",
  },
  {
    title: "Contact your bank in parallel",
    body: "Use your bank or payment provider’s official fraud channel. Report the transactions, revoke compromised UPI mandates and ask the bank to block affected cards or net banking access.",
  },
  {
    title: "Preserve the original evidence",
    body: "Keep transaction IDs or UTR numbers, timestamps, amounts, receipts, screenshots, call logs, and links. Save links without opening them and share evidence privately with your bank or investigators.",
  },
];

const hygiene = [
  {
    title: "Keep credentials private",
    body: "Never share OTPs, PINs, CVVs or passwords with a caller or in a chat.",
  },
  {
    title: "Avoid unknown apps",
    body: "Never install an unknown .apk or a remote-access app at a caller’s request. Use official app stores.",
  },
  {
    title: "Verify numbers independently",
    body: "Open the official site or app yourself. Use the number listed there or printed on your bank card.",
  },
];

function SourceLink({ label, href }: { label: string; href: string }) {
  return (
    <a className="inline-flex items-center gap-1.5 text-xs font-semibold text-accent hover:underline"
      href={href} target="_blank" rel="noreferrer">
      {label} <ArrowUpRight size={13} className="shrink-0" aria-hidden="true" />
    </a>
  );
}

function InfoCard({ title, icon: Icon, children, sources }: {
  title: string;
  icon: LucideIcon;
  children: ReactNode;
  sources: ReadonlyArray<readonly [string, string]>;
}) {
  return (
    <article className="flex min-w-0 flex-col rounded-2xl border border-stroke bg-surface p-5 sm:p-6">
      <div className="mb-3 flex items-center gap-3">
        <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-accent/25 bg-accent/10 text-accent">
          <Icon size={18} aria-hidden="true" />
        </span>
        <h3 className="text-base font-bold tracking-tight text-foreground sm:text-lg">{title}</h3>
      </div>
      <div className="space-y-2.5 text-sm leading-relaxed text-muted">{children}</div>
      <div className="mt-auto flex flex-wrap gap-x-4 gap-y-2 pt-4">
        {sources.map(([label, href]) => <SourceLink key={href} label={label} href={href} />)}
      </div>
    </article>
  );
}

const sectionTitle = "mb-4 scroll-mt-6 text-2xl font-extrabold tracking-tight text-foreground sm:text-3xl";
const cardGrid = "grid gap-3 sm:grid-cols-2 sm:gap-4";

export default function RightsPage() {
  return (
    <div className="shell space-y-10 pb-12 pt-9 sm:space-y-12 sm:pb-16 sm:pt-12">
      <section className="grid items-end gap-6 border-b border-stroke pb-8 lg:grid-cols-[minmax(0,1fr)_21rem]" aria-labelledby="rights-title">
        <div>
          <h1 id="rights-title" className="text-[clamp(2.5rem,6vw,4.7rem)] leading-[1.06] font-extrabold tracking-[-0.065em]">
            Know Your <span className="text-accent">Rights</span>
          </h1>
          <p className="mt-4 max-w-2xl text-base leading-relaxed text-muted sm:text-lg">
            Recognise common scams in India, know what protections may apply, and act quickly if your money is at risk.
          </p>
        </div>
        <div className="min-w-0 rounded-2xl border border-accent/25 bg-surface bg-[radial-gradient(ellipse_at_top_left,#5af2c71c,transparent_75%)] p-5">
          <p className="flex items-center gap-2 font-bold"><Siren size={17} aria-hidden="true" className="text-accent" /> Lost money to a scam?</p>
          <p className="mt-2 text-sm leading-relaxed text-muted">Report it immediately and notify your bank.</p>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <a className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-accent px-3.5 text-sm font-extrabold text-[var(--accent-ink)] hover:brightness-110"
              href="tel:1930">
              <Phone size={15} aria-hidden="true" /> Call 1930
            </a>
            <SourceLink href={PORTAL} label="Report online" />
          </div>
        </div>
      </section>

      <nav className="flex flex-wrap gap-2.5" aria-label="On this page">
        {sections.map(([id, label]) => (
          <a key={id} href={`#${id}`}
            className="rounded-lg border border-stroke bg-panel px-3.5 py-2 text-sm font-semibold text-muted hover:border-accent/50 hover:text-accent">
            {label}
          </a>
        ))}
      </nav>

      <section aria-labelledby="scam-tactics">
        <h2 id="scam-tactics" className={sectionTitle}>Common Indian scam tactics</h2>
        <div className={cardGrid}>
          {tactics.map(({ title, icon, body, source }) => (
            <InfoCard key={title} title={title} icon={icon} sources={[source]}><p>{body}</p></InfoCard>
          ))}
        </div>
      </section>

      <section aria-labelledby="legal-protections">
        <h2 id="legal-protections" className={sectionTitle}>Your rights and legal protections in India</h2>
        <div className={cardGrid}>
          <InfoCard title="Financial fraud reporting and fund holds" icon={Landmark} sources={[
            ["MHA reporting system update", "https://www.pib.gov.in/PressReleasePage.aspx?PRID=2290377&lang=1&reg=22"],
          ]}>
            <p>Report financial cyber fraud promptly through 1930 and cybercrime.gov.in. The I4C reporting system helps banks and investigators trace payments and place temporary holds or liens on available funds after verification. Recovery depends on the case.</p>
          </InfoCard>
          <InfoCard title="RBI customer protection and complaints" icon={Scale} sources={[
            ["RBI liability directions", "https://www.rbi.org.in/scripts/BS_ViewMasDirections.aspx?id=13140"],
            ["RBI Ombudsman scheme", "https://www.rbi.org.in/commonman/english/scripts/FAQs.aspx?Id=3407"],
            ["RBI complaint portal", "https://cms.rbi.org.in/"],
          ]}>
            <p>Report an unauthorised debit to your bank immediately and keep the complaint reference. RBI rules can limit liability or reduce it to zero in eligible cases. Bank fault can qualify for zero liability, and prompt reporting matters for third-party breaches.</p>
            <p>Use the bank’s grievance process first. Escalate an eligible bank-service complaint to the RBI Ombudsman through its Complaint Management System if the reply is unsatisfactory or the applicable response window expires.</p>
          </InfoCard>
          <InfoCard title="Identity theft, impersonation and unauthorised access" icon={Fingerprint} sources={[
            ["Information Technology Act, 2000", "https://www.indiacode.nic.in/indiacode/handle/123456789/1999?locale=en"],
          ]}>
            <p>The IT Act addresses unauthorised computer access and related acts under Section 43, and makes specified acts criminal when done dishonestly or fraudulently under Section 66. Sections 66C and 66D cover identity theft and cheating by impersonation through a computer or communication device.</p>
          </InfoCard>
          <InfoCard title="If a chain freeze affects your account" icon={LockKeyhole} sources={[
            ["I4C grievance procedure (section 10)", "https://cdnbbsr.s3waas.gov.in/s3ec0277ee3bc58ce560b86c2b59363281/uploads/2026/04/2026042314.pdf#page=48"],
            ["NALSA legal aid", "https://nalsa.gov.in/faqs/"],
          ]}>
            <p>Ask your bank in writing what is restricted, the amount held, who directed it, and any complaint or order reference the bank can share. Keep statements and receipts showing why the payment was made.</p>
            <p>Ask the bank to forward your grievance to the investigating officer through the applicable I4C process. Request a review or a hold limited to the disputed amount where appropriate. If unresolved, ask about district or state review and seek legal aid for a police or court order.</p>
          </InfoCard>
        </div>
      </section>

      <section className="rounded-2xl border border-accent/25 bg-surface p-5 sm:p-7" aria-labelledby="first-hour">
        <h2 id="first-hour" className={sectionTitle}>First-hour golden window checklist</h2>
        <p className="max-w-2xl text-sm leading-relaxed text-muted">
          Act immediately, ideally within the first hour. Report the fraud even if more time has passed.
        </p>
        <ol className="mt-5 grid gap-3 sm:grid-cols-2">
          {firstHour.map(({ title, body }, index) => (
            <li key={title} className="flex min-w-0 gap-3.5 rounded-xl border border-stroke bg-panel p-4">
              <span className="grid size-7 shrink-0 place-items-center rounded-lg bg-accent/10 font-mono text-sm font-bold text-accent" aria-hidden="true">{index + 1}</span>
              <div>
                <h3 className="text-sm font-bold">{title}</h3>
                <p className="mt-1 text-sm leading-relaxed text-muted">{body}</p>
              </div>
            </li>
          ))}
        </ol>
        <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2">
          <SourceLink href={PORTAL} label="File on cybercrime.gov.in" />
          <SourceLink href="https://cybercrime.gov.in/webform/FAQ.aspx" label="Reporting and evidence FAQ" />
        </div>
      </section>

      <section aria-labelledby="cyber-hygiene">
        <h2 id="cyber-hygiene" className={sectionTitle}>Everyday cyber hygiene</h2>
        <ul className="grid gap-3 md:grid-cols-3">
          {hygiene.map(({ title, body }) => (
            <li key={title} className="rounded-xl border border-stroke bg-surface p-4">
              <h3 className="flex items-start gap-2.5 text-sm font-bold"><ShieldCheck size={16} className="mt-px shrink-0 text-accent" aria-hidden="true" />{title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted">{body}</p>
            </li>
          ))}
        </ul>
        <p className="mt-5 flex gap-2.5 rounded-xl border border-stroke bg-panel p-4 text-sm leading-relaxed text-muted">
          <Info className="mt-0.5 shrink-0 text-accent" size={16} aria-hidden="true" />
          <span>This page provides general public awareness only. For advice about a specific case, consult a qualified legal professional.</span>
        </p>
      </section>
    </div>
  );
}
