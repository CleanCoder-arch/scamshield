import { ShieldCheck } from "lucide-react";
import { Scanner } from "@/components/scanner";

export default function Home() {
  return (
    <div className="shell home">
      <section className="hero" aria-labelledby="scanner-title">
        <div className="hero-copy">
          <h1 id="scanner-title">Check before <span>you click.</span></h1>
          <p>Scan suspicious messages, links, screenshots, and payment details for signs of a scam.</p>
        </div>
        <div className="hero-art" aria-hidden="true">
          <div className="hero-grid" />
          <div className="radar-ring ring-outer" />
          <div className="radar-ring ring-middle" />
          <div className="radar-ring ring-inner" />
          <span className="radar-dot dot-a" />
          <span className="radar-dot dot-b" />
          <span className="radar-dot dot-c" />
          <div className="radar-shield"><ShieldCheck size={53} strokeWidth={1.35} /></div>
        </div>
      </section>
      <Scanner />
    </div>
  );
}
