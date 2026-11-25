import assert from "node:assert/strict";
import { test } from "node:test";
import type { PlaybookGuidance } from "../lib/api";
import { buildIncidentPdf, type IncidentPdfInput } from "../lib/incident-pdf";

const guidance: PlaybookGuidance = {
  category_id: "upi_fraud",
  category_label: "UPI fraud",
  indicators: ["A payment request was detected."],
  steps: [
    "Open your payment app and decline unfamiliar requests.",
    "Contact your bank through its official support channel.",
  ],
  reporting_steps: [
    "Call the financial cyber fraud helpline promptly.",
    "Keep your transaction reference available for the official reporting form.",
  ],
};

const input: IncidentPdfInput = {
  createdAt: "2026-11-25T16:21:03+05:30",
  riskScore: 73,
  riskLevel: "HIGH",
  guidance,
};

test("renders a one-page report with the India time, verdict, curated steps and official contacts", () => {
  const document = buildIncidentPdf(input);
  const pdf = document.output();

  assert.match(pdf, /^%PDF-/);
  assert.equal(document.getNumberOfPages(), 1);
  for (const text of [
    "Incident & Safety Report",
    "25 Nov 2026, 16:21:03 IST",
    "73 / 100",
    "HIGH",
    "UPI fraud",
    ...guidance.steps,
    ...guidance.indicators,
    ...guidance.reporting_steps,
    "1930",
    "cybercrime.gov.in",
  ]) {
    assert.ok(pdf.includes(text), "PDF should contain " + text);
  }
  assert.ok(pdf.includes("/URI (tel:1930)"));
  assert.ok(pdf.includes("/URI (https://cybercrime.gov.in/)"));
});

test("drops raw scan text, AI prose, screenshot content, and extracted identifiers", () => {
  const secrets = {
    originalText: "Fixture private message",
    uploadedScreenshot: "TestPrivateScreenshotBytes",
    phone: "+91 98765 43210",
    upi: "fixture-user@upi",
    url: "https://fixture-private.example/path",
    aiProse: "Fixture model content",
    scanId: "fixture-private-scan-id",
  };
  const fullObject = {
    ...input,
    guidance: {
      ...guidance,
      rawInput: secrets.originalText,
      explanation: secrets.aiProse,
    },
    scan_id: secrets.scanId,
    text: secrets.originalText,
    image: secrets.uploadedScreenshot,
    ai: { explanation: secrets.aiProse },
    entities: {
      phones: [secrets.phone],
      upi_ids: [secrets.upi],
      urls: [secrets.url],
    },
  };
  const pdf = buildIncidentPdf(fullObject).output();

  for (const secret of Object.values(secrets)) {
    assert.ok(!pdf.includes(secret));
  }
});

test("keeps the reporting contacts on the same page with three long items in each section", () => {
  const longest =
    "Preserve relevant transaction references, original communications, dates, and confirmation notices. Keep the information available for the official form.";
  const document = buildIncidentPdf({
    ...input,
    guidance: {
      ...guidance,
      indicators: [longest, longest, longest],
      steps: [longest, longest, longest],
      reporting_steps: [longest, longest, longest],
    },
  });
  const pdf = document.output();
  const textY = [...pdf.matchAll(/^[\d.]+ ([\d.]+) Td$/gm)].map((position) => Number(position[1]));
  assert.equal(document.getNumberOfPages(), 1);
  assert.ok(textY.length > 10);
  assert.ok(Math.min(...textY) >= 30, "Text should stay above the bottom margin.");
  assert.ok(pdf.includes("https://cybercrime.gov.in/"));
});

test("rejects timestamps and scores that cannot represent a scan verdict", () => {
  assert.throws(() => buildIncidentPdf({ ...input, createdAt: "fixture raw input" }), /valid scan timestamp/);
  assert.throws(() => buildIncidentPdf({ ...input, riskScore: 105 }), /between 0 and 100/);
  assert.throws(() => buildIncidentPdf({ ...input, riskLevel: "LOW" }), /does not match/);
});
