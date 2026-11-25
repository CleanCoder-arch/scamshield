import assert from "node:assert/strict";
import { test } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { ScanPlaybook } from "../components/scan-playbook";
import { IncidentExports } from "../components/incident-exports";
import type { PlaybookGuidance } from "../lib/api";

const guidance: PlaybookGuidance = {
  category_id: "upi_fraud",
  category_label: "UPI fraud",
  indicators: ["Request to enter a UPI PIN to receive money"],
  steps: [
    "Approving a UPI collect request sends money. Decline unexpected requests.",
    "Receiving money does not require a UPI PIN or a QR code scan.",
  ],
  reporting_steps: [
    "If you lost money, call 1930 and contact your bank or payment provider immediately, ideally within the first hour.",
    "File at cybercrime.gov.in. Include the 1930 acknowledgement number if you received one.",
  ],
};

test("displays the supplied playbook with official reporting actions", () => {
  const html = renderToStaticMarkup(<ScanPlaybook guidance={guidance} />);
  for (const copy of [...guidance.steps, ...guidance.reporting_steps]) {
    assert.ok(html.includes(copy));
  }
  assert.match(html, /href="tel:1930"/);
  assert.match(html, /href="https:\/\/cybercrime\.gov\.in\/"/);
});

test("shows the PDF action beside a valid warning PNG", () => {
  const png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/Nq0AAAAASUVORK5CYII=";
  const html = renderToStaticMarkup(
    <IncidentExports
      png={png}
      guidance={guidance}
      createdAt="2026-11-25T10:00:00Z"
      riskScore={74}
      riskLevel="HIGH"
    />,
  );
  assert.match(html, /download="scamshield-warning\.png"/);
  assert.match(html, /Download PNG/);
  assert.match(html, /Download PDF/);
});

test("keeps PDF export available when a low-risk scan has no warning PNG", () => {
  const html = renderToStaticMarkup(
    <IncidentExports
      png={null}
      guidance={guidance}
      createdAt="2026-11-25T10:00:00Z"
      riskScore={12}
      riskLevel="LOW"
    />,
  );
  assert.doesNotMatch(html, /Download PNG/);
  assert.match(html, /Download PDF/);
});
