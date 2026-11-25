"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ArrowUpRight, Scale, ScanLine } from "lucide-react";

export function SiteNav() {
  const path = usePathname();

  return (
    <nav className="site-nav" aria-label="Main navigation">
      <Link href="/" aria-current={path === "/" ? "page" : undefined}>
        <ScanLine size={16} aria-hidden="true" /> Scanner
      </Link>
      <Link href="/rights" aria-current={path === "/rights" ? "page" : undefined}>
        <Scale size={17} aria-hidden="true" /> Know Your Rights
      </Link>
      <a className="nav-report" href="https://cybercrime.gov.in/" target="_blank" rel="noopener noreferrer">
        Report a scam <ArrowUpRight size={15} aria-hidden="true" />
      </a>
    </nav>
  );
}
