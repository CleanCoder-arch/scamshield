"use client";

import Image from "next/image";
import { Download, FileText, ImageIcon } from "lucide-react";
import { useState } from "react";
import type { PlaybookGuidance, RiskLevel } from "@/lib/api";

interface IncidentExportsProps {
  png: string | null;
  guidance?: PlaybookGuidance;
  createdAt: string;
  riskScore: number;
  riskLevel: RiskLevel;
}

const downloadClass = "inline-flex min-h-10 items-center gap-2 rounded-lg border border-stroke px-3 text-sm font-medium text-accent hover:border-accent";

function pngPreview(png: string | null, riskScore: number) {
  if (
    riskScore < 40 ||
    !png ||
    png.length < 32 ||
    png.length % 4 !== 0 ||
    !/^iVBORw0KGgo[A-Za-z0-9+/]*={0,2}$/.test(png)
  ) return null;

  const header = atob(png.slice(0, 32));
  if (header.length !== 24 || header.slice(12, 16) !== "IHDR") return null;
  const bytes = Uint8Array.from(header, (character) => character.charCodeAt(0));
  const view = new DataView(bytes.buffer);
  const width = view.getUint32(16);
  const height = view.getUint32(20);
  if (!width || !height) return null;
  return { src: `data:image/png;base64,${png}`, width, height };
}

export function IncidentExports({ png, guidance, createdAt, riskScore, riskLevel }: IncidentExportsProps) {
  const [preparing, setPreparing] = useState(false);
  const [error, setError] = useState("");
  const preview = pngPreview(png, riskScore);
  if (!preview && !guidance) return null;

  async function downloadPdf() {
    if (!guidance || preparing) return;
    setPreparing(true);
    setError("");
    try {
      const { downloadIncidentPdf } = await import("@/lib/incident-pdf");
      downloadIncidentPdf({ guidance, createdAt, riskScore, riskLevel });
    } catch {
      setError("Couldn’t prepare the PDF. Try downloading it again.");
    } finally {
      setPreparing(false);
    }
  }

  return (
    <section className="min-w-0 rounded-2xl border border-stroke bg-surface p-4 sm:p-5" aria-labelledby="incident-exports-heading">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 id="incident-exports-heading" className="flex items-center gap-2.5 text-base font-semibold tracking-tight">
          <ImageIcon size={17} className="text-accent" aria-hidden="true" />
          Incident exports
        </h3>
        <div className="flex flex-wrap items-center gap-2">
          {preview && (
            <a href={preview.src} download="scamshield-warning.png" className={downloadClass}>
              <Download size={16} aria-hidden="true" />
              Download PNG
            </a>
          )}
          {guidance && (
            <button type="button" onClick={downloadPdf} disabled={preparing} className={downloadClass}>
              <FileText size={16} aria-hidden="true" />
              {preparing ? "Preparing PDF…" : "Download PDF"}
            </button>
          )}
        </div>
      </div>
      {error && <p className="mt-3 text-sm text-rose-300" role="alert">{error}</p>}
      {preview && (
        <Image
          src={preview.src}
          width={preview.width}
          height={preview.height}
          alt={`ScamShield warning card. ${riskLevel.toLowerCase()} risk, score ${riskScore} out of 100.`}
          className="mx-auto mt-4 h-auto w-full max-w-[800px] rounded-xl border border-stroke"
          unoptimized
        />
      )}
    </section>
  );
}
