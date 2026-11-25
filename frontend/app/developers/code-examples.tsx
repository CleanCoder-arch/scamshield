"use client";

import { Check, Copy } from "lucide-react";
import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import type { CodeExamples } from "./examples";
import styles from "./developers.module.css";

const languages = [
  { value: "curl", label: "cURL" },
  { value: "python", label: "Python" },
  { value: "javascript", label: "JavaScript" },
] as const;

export function RequestExamples({ samples, name }: { samples: CodeExamples; name: string }) {
  const [selected, setSelected] = useState(0);
  const [copy, setCopy] = useState<{ index: number; ok: boolean } | null>(null);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const id = useId();
  const current = languages[selected];
  const feedback = copy?.index === selected ? copy : null;

  useEffect(() => {
    if (!copy) return;
    const timer = window.setTimeout(() => setCopy(null), 2000);
    return () => window.clearTimeout(timer);
  }, [copy]);

  function moveTab(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    let next = index;
    switch (event.key) {
      case "ArrowRight": next = (index + 1) % languages.length; break;
      case "ArrowLeft": next = (index + languages.length - 1) % languages.length; break;
      case "Home": next = 0; break;
      case "End": next = languages.length - 1; break;
      default: return;
    }
    event.preventDefault();
    setSelected(next);
    tabs.current[next]?.focus();
  }

  async function copyExample() {
    try {
      await navigator.clipboard.writeText(samples[current.value]);
      setCopy({ index: selected, ok: true });
    } catch {
      setCopy({ index: selected, ok: false });
    }
  }

  return (
    <div className={styles.codePanel}>
      <div className={styles.codeHeader}>
        <div role="tablist" aria-label={name + " request language"} className={styles.codeTabs}>
          {languages.map((language, index) => (
            <button
              key={language.value}
              ref={(element) => { tabs.current[index] = element; }}
              type="button"
              role="tab"
              id={id + "-" + language.value}
              aria-controls={id + "-panel"}
              aria-selected={selected === index}
              tabIndex={selected === index ? 0 : -1}
              onClick={() => setSelected(index)}
              onKeyDown={(event) => moveTab(event, index)}
            >
              {language.label}
            </button>
          ))}
        </div>
        <button type="button" className={styles.copyButton} onClick={copyExample}>
          {feedback?.ok ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
          <span aria-live="polite">
            {feedback ? (feedback.ok ? "Copied" : "Select text to copy") : "Copy"}
          </span>
        </button>
      </div>
      <pre
        id={id + "-panel"}
        role="tabpanel"
        aria-labelledby={id + "-" + current.value}
        tabIndex={0}
        className={styles.codeBody}
      >
        <code>{samples[current.value]}</code>
      </pre>
    </div>
  );
}
