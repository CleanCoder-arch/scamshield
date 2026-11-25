"use client";

import { ShieldCheck } from "lucide-react";
import { useEffect, useState, type CSSProperties } from "react";

const SESSION_KEY = "scamshield:launch-splash";
const HOLD_MS = 950;
const FADE_MS = 300;
const timing = {
  "--splash-hold": `${HOLD_MS}ms`,
  "--splash-fade": `${FADE_MS}ms`,
} as CSSProperties;

export function LaunchSplash() {
  const [phase, setPhase] = useState<"hidden" | "visible" | "leaving">("hidden");

  useEffect(() => {
    // Wait for a cancellable frame so a discarded Strict Mode effect never claims the session.
    const frame = window.requestAnimationFrame(() => {
      try {
        if (window.sessionStorage.getItem(SESSION_KEY)) return;
        window.sessionStorage.setItem(SESSION_KEY, "1");
      } catch {
        return;
      }

      if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        setPhase("visible");
      }
    });

    return () => window.cancelAnimationFrame(frame);
  }, []);

  useEffect(() => {
    if (phase === "hidden") return;

    if (phase === "leaving") {
      const timeout = window.setTimeout(() => setPhase("hidden"), FADE_MS);
      return () => window.clearTimeout(timeout);
    }

    const dismiss = () => setPhase("leaving");
    const timeout = window.setTimeout(dismiss, HOLD_MS);
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") dismiss();
    };
    window.addEventListener("keydown", handleKey);

    return () => {
      window.clearTimeout(timeout);
      window.removeEventListener("keydown", handleKey);
    };
  }, [phase]);

  if (phase === "hidden") return null;

  return (
    <button
      type="button"
      className="launch-splash"
      data-phase={phase}
      style={timing}
      aria-label="Dismiss opening animation"
      aria-hidden={phase === "leaving" || undefined}
      disabled={phase === "leaving"}
      onClick={() => setPhase("leaving")}
    >
      <span className="launch-splash-content" aria-hidden="true">
        <span className="launch-splash-radar">
          <span className="launch-splash-shield">
            <ShieldCheck size={38} strokeWidth={1.85} />
          </span>
          <span className="launch-splash-sweep" />
        </span>
        <span className="launch-splash-title">Scam<span>Shield</span></span>
        <span className="launch-splash-subtitle">Check before you click.</span>
        <span className="launch-splash-progress" />
        <span className="launch-splash-skip">Skip intro</span>
      </span>
    </button>
  );
}
