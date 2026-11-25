export default function Loading() {
  return (
    <div
      className="min-h-[60svh]"
      style={{ backgroundColor: "var(--background, #071018)" }}
      role="status"
    >
      <span className="sr-only">Loading page…</span>
    </div>
  );
}
