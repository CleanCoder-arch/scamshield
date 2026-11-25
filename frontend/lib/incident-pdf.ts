import { jsPDF } from "jspdf";
import type { PlaybookGuidance, RiskLevel } from "@/lib/api";

export interface IncidentPdfInput {
  createdAt: string;
  riskScore: number;
  riskLevel: RiskLevel;
  guidance: PlaybookGuidance;
}

type Color = [number, number, number];

const INK: Color = [14, 29, 49];
const MUTED: Color = [70, 91, 111];
const MINT: Color = [114, 243, 204];
const RISK_COLORS: Record<RiskLevel, Color> = {
  LOW: [22, 105, 80],
  MEDIUM: [138, 84, 16],
  HIGH: [153, 43, 61],
};

const MARGIN = 17;
const PAGE_WIDTH = 210;
const CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN;
const LINE_HEIGHT = 4.3;
const MAX_PLAYBOOK_ITEMS = 3;
const REPORT_PORTAL = "https://cybercrime.gov.in/";
const REPORT_NUMBER = "1930";

function drawSection(
  pdf: jsPDF,
  heading: string,
  items: readonly string[],
  top: number,
  checklist = false,
) {
  pdf.setFont("helvetica", "bold").setFontSize(12).setTextColor(...INK);
  pdf.text(heading, MARGIN, top);
  pdf.setFont("helvetica", "normal").setFontSize(10).setTextColor(...MUTED);

  let y = top + 6.6;
  items.slice(0, MAX_PLAYBOOK_ITEMS).forEach((item) => {
    const lines: string[] = pdf.splitTextToSize(item, CONTENT_WIDTH - 6);
    // The curated backend steps fit in three lines at this page width. Bound the
    // display line count so the reporting contacts remain on the first page.
    const visible = lines.slice(0, 3);

    if (checklist) {
      pdf.setDrawColor(...MUTED).setLineWidth(0.25).rect(MARGIN, y - 2.4, 2.6, 2.6);
    } else {
      pdf.setFillColor(...RISK_COLORS.LOW).circle(MARGIN + 1.2, y - 1.15, 0.65, "F");
    }

    pdf.text(visible, MARGIN + 6, y, { lineHeightFactor: 1.22 });
    y += visible.length * LINE_HEIGHT + 1.4;
  });
  return y + 5.5;
}

export function buildIncidentPdf({ createdAt, riskScore, riskLevel, guidance }: IncidentPdfInput): jsPDF {
  const scanDate = new Date(createdAt);
  if (Number.isNaN(scanDate.getTime())) throw new Error("A valid scan timestamp is required.");
  if (!Number.isInteger(riskScore) || riskScore < 0 || riskScore > 100) {
    throw new Error("Scan risk score must be between 0 and 100.");
  }
  const validLevel = riskScore >= 60 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW";
  if (riskLevel !== validLevel) throw new Error("Scan risk level does not match the risk score.");

  const pdf = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  pdf.setProperties({ title: "ScamShield Incident & Safety Report", author: "ScamShield" });
  pdf.setCreationDate(scanDate);
  pdf.setFillColor(...INK).rect(0, 0, PAGE_WIDTH, 42, "F");
  pdf.setFillColor(...MINT).rect(MARGIN, 12, 2, 2, "F");
  pdf.setFont("helvetica", "bold").setFontSize(10).setTextColor(...MINT);
  pdf.text("SCAMSHIELD", MARGIN + 4, 14);
  pdf.setFontSize(25).setTextColor(255, 255, 255);
  pdf.text("Incident & Safety Report", MARGIN, 31);

  pdf.setFillColor(244, 248, 251).roundedRect(MARGIN, 51, CONTENT_WIDTH, 27, 3, 3, "F");
  pdf.setFontSize(9).setTextColor(...MUTED);
  pdf.text("RISK SCORE", MARGIN + 5, 58.3);
  pdf.text("CATEGORY", MARGIN + 73, 58.3);
  pdf.setFontSize(22).setTextColor(...INK);
  const score = riskScore + " / 100";
  pdf.text(score, MARGIN + 5, 70);
  const levelX = MARGIN + 9 + pdf.getTextWidth(score);
  pdf.setFontSize(9).setTextColor(...RISK_COLORS[riskLevel]);
  pdf.text(riskLevel, levelX, 69.6);
  pdf.setFontSize(13).setTextColor(...INK);
  pdf.text(guidance.category_label, MARGIN + 73, 70, { maxWidth: CONTENT_WIDTH - 78 });

  const scanTime = new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "Asia/Kolkata",
    hourCycle: "h23",
  }).format(scanDate) + " IST";
  pdf.setFont("helvetica", "normal").setFontSize(9).setTextColor(...MUTED);
  pdf.text("Scan time  " + scanTime, MARGIN, 85.5);

  // These fields come from the backend's curated playbook guidance. Keep
  // evidence from scan entities, detector reasons and AI prose out of exports.
  let y = drawSection(
    pdf,
    "Evidence summary",
    guidance.indicators.length ? guidance.indicators : ["No specific indicator was recorded."],
    98,
  );
  y = drawSection(pdf, "What to do now", guidance.steps, y, true);
  y = drawSection(pdf, "Report cybercrime in India", guidance.reporting_steps, y, true);

  pdf.setDrawColor(214, 225, 232).setLineWidth(0.3).line(MARGIN, y - 2, PAGE_WIDTH - MARGIN, y - 2);
  pdf.setFont("helvetica", "bold").setFontSize(11).setTextColor(...RISK_COLORS.LOW);
  pdf.textWithLink(REPORT_NUMBER, MARGIN, y + 4, { url: "tel:" + REPORT_NUMBER });
  pdf.textWithLink("cybercrime.gov.in", MARGIN + 42, y + 4, { url: REPORT_PORTAL });
  pdf.setFont("helvetica", "normal").setFontSize(8).setTextColor(...MUTED);
  pdf.text("Financial cyber fraud helpline", MARGIN, y + 9);
  pdf.text("National Cyber Crime Reporting Portal", MARGIN + 42, y + 9);

  return pdf;
}

export function downloadIncidentPdf(input: IncidentPdfInput): void {
  buildIncidentPdf(input).save("scamshield-incident-report.pdf");
}
