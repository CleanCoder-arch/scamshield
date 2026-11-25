import type { Metadata } from "next";
import Link from "next/link";
import { ArrowUpRight, ShieldCheck } from "lucide-react";
import "@fontsource-variable/manrope";
import "./globals.css";
import { SiteNav } from "@/components/site-nav";

export const metadata: Metadata = {
  title: { default: "ScamShield | Scam & Phishing Scanner", template: "%s | ScamShield" },
  description: "Check suspicious messages, screenshots, links, and payment details for scam indicators.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en-IN">
      <body>
        <a className="skip-link" href="#main-content">Skip to content</a>
        <header className="site-header">
          <div className="shell site-header-inner">
            <Link className="wordmark" href="/" aria-label="ScamShield home">
              <span className="brand-mark"><ShieldCheck size={21} strokeWidth={2.15} aria-hidden="true" /></span>
              Scam<span>Shield</span>
            </Link>
            <SiteNav />
          </div>
        </header>
        <main id="main-content">{children}</main>
        <footer className="site-footer">
          <div className="shell site-footer-inner">
            <p><ShieldCheck size={16} aria-hidden="true" /> ScamShield</p>
            <a href="https://cybercrime.gov.in/" target="_blank" rel="noreferrer">
              National Cyber Crime Reporting Portal <ArrowUpRight size={14} aria-hidden="true" />
            </a>
          </div>
        </footer>
      </body>
    </html>
  );
}
