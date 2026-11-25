"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ArrowUpRight, CodeXml, ScanLine } from "lucide-react";

export function SiteNav() {
  const path = usePathname();

  return (
    <nav className="site-nav" aria-label="Main navigation">
      <Link href="/" aria-current={path === "/" ? "page" : undefined}>
        <ScanLine size={16} aria-hidden="true" /> Scanner
      </Link>
      <Link href="/developers" aria-current={path === "/developers" ? "page" : undefined}>
        <CodeXml size={17} aria-hidden="true" /> Developer API
      </Link>
      <a className="nav-report" href="https://cybercrime.gov.in/" target="_blank" rel="noreferrer">
        Report a scam <ArrowUpRight size={15} aria-hidden="true" />
      </a>
    </nav>
  );
}
