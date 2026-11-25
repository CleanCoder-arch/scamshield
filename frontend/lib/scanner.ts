export const MAX_TEXT_LENGTH = 8_000;

export type ScanMode = "text" | "image" | "url" | "identity";

export const SCAM_SAMPLES = [
  {
    label: "Bank KYC",
    text: "URGENT: Your bank account will be suspended tonight. Complete your KYC at https://kyc-review.example/verify and confirm your OTP to restore access.",
  },
  {
    label: "UPI Collect",
    text: "Your ₹2,499 refund is ready. Approve the pending UPI collect request from demo-refund@sampleupi and enter your UPI PIN to receive the money.",
  },
  {
    label: "Digital Arrest",
    text: "This is the police cyber cell. A digital arrest order has been issued in your name. Stay on the video call and pay a verification deposit immediately.",
  },
  {
    label: "Fake Job",
    text: "Congratulations! You were selected for a remote data entry job paying ₹5,000 per day. Pay a ₹999 registration fee today to confirm your position.",
  },
] as const;

function prepareUrl(input: string): string {
  try {
    const explicit = /^https?:\/\//i.test(input);
    const address = explicit ? input.replace(/^https?:\/\//i, "") : input.replace(/^\/\//, "");
    if (/\s|\\/.test(input) || address.startsWith("/") || (
      /^[a-z][a-z\d+.-]*:\/\//i.test(input) && !explicit
    )) {
      throw new Error();
    }
    const parsed = new URL(explicit ? input : `http://${address}`);
    if (
      !parsed.hostname.includes(".") &&
      !parsed.hostname.startsWith("[") &&
      !(explicit && parsed.hostname === "localhost")
    ) {
      throw new Error();
    }
    return input;
  } catch {
    throw new Error("Enter a valid web URL or domain to check.");
  }
}

function prepareIdentity(input: string): string {
  const mobile = input.replace(/[\s().-]/g, "").match(/^(?:\+91|0091|91|0)?([6-9]\d{9})$/);
  if (mobile) return `+91${mobile[1]}`;
  if (/^[a-z\d][a-z\d._-]{0,127}@[a-z][a-z\d-]{1,63}$/i.test(input)) {
    // This identifies unfamiliar payment providers as UPI IDs during entity extraction.
    return `UPI ID: ${input}`;
  }
  throw new Error("Enter a valid Indian mobile number or UPI ID.");
}

export function prepareText(mode: Exclude<ScanMode, "image">, input: string): string {
  const text = input.trim();
  if (!text) throw new Error("Enter something to scan.");
  if (Array.from(text).length > MAX_TEXT_LENGTH) {
    throw new Error("Keep your input at 8,000 characters or fewer.");
  }
  if (mode === "url") return prepareUrl(text);
  if (mode === "identity") return prepareIdentity(text);
  return text;
}
