import { ShieldCheck } from "lucide-react";

export default function Loading() {
  return (
    <div
      className="grid min-h-[60svh] place-content-center justify-items-center gap-4 px-6 py-12"
      style={{ backgroundColor: "var(--background, #071018)" }}
      role="status"
    >
      <div className="relative grid size-16 place-items-center rounded-2xl border border-accent/25 bg-accent/10 text-accent">
        <span className="absolute -inset-2 rounded-[1.25rem] border border-accent/20 motion-safe:animate-pulse" aria-hidden="true" />
        <ShieldCheck size={30} strokeWidth={1.7} aria-hidden="true" />
      </div>
      <p className="text-sm font-semibold text-muted">Loading page…</p>
    </div>
  );
}
