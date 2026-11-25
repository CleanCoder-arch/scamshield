export type CodeExamples = { curl: string; python: string; javascript: string };

const text = "Your library book is ready for collection.";
const streamText = "The library closes at 6 pm today.";
const shellQuote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";

export function examples(api: string) {
  const scan = api + "/api/v1/scan";
  const image = scan + "/image";
  const stream = scan + "/stream";
  const textBody = JSON.stringify({ text });
  const streamBody = JSON.stringify({ text: streamText });

  return {
    text: {
      curl: [
        "curl --fail-with-body " + shellQuote(scan) + " \\",
        "  -H 'Content-Type: application/json' \\",
        "  --data " + shellQuote(textBody),
      ].join("\n"),
      python: [
        "import requests",
        "",
        "response = requests.post(",
        "    " + JSON.stringify(scan) + ",",
        "    json=" + textBody + ",",
        "    timeout=30,",
        ")",
        "response.raise_for_status()",
        'print(response.json())',
      ].join("\n"),
      javascript: [
        "const response = await fetch(" + JSON.stringify(scan) + ", {",
        '  method: "POST",',
        '  headers: { "Content-Type": "application/json" },',
        "  body: JSON.stringify(" + textBody + "),",
        "});",
        'if (!response.ok) throw new Error("HTTP " + response.status);',
        "const verdict = await response.json();",
        "console.log(verdict);",
      ].join("\n"),
    },
    image: {
      curl: [
        "curl --fail-with-body " + shellQuote(image) + " \\",
        "  -F 'file=@redacted-screenshot.png;type=image/png' \\",
        "  -F 'redacted=true'",
      ].join("\n"),
      python: [
        "import requests",
        "",
        'with open("redacted-screenshot.png", "rb") as screenshot:',
        "    response = requests.post(",
        "        " + JSON.stringify(image) + ",",
        '        files={"file": ("redacted-screenshot.png", screenshot, "image/png")},',
        '        data={"redacted": "true"},',
        "        timeout=30,",
        "    )",
        "response.raise_for_status()",
        "print(response.json())",
      ].join("\n"),
      javascript: [
        "// screenshot is a File selected after the user confirms redaction.",
        "async function scanScreenshot(screenshot, redacted) {",
        '  if (!redacted) throw new Error("Confirm redaction first.");',
        "  const form = new FormData();",
        '  form.append("file", screenshot);',
        '  form.append("redacted", "true");',
        "  const response = await fetch(" + JSON.stringify(image) + ", {",
        '    method: "POST",',
        "    body: form,",
        "  });",
        '  if (!response.ok) throw new Error("HTTP " + response.status);',
        "  return await response.json();",
        "}",
      ].join("\n"),
    },
    stream: {
      curl: [
        "curl --no-buffer --fail-with-body " + shellQuote(stream) + " \\",
        "  -H 'Accept: text/event-stream' \\",
        "  -H 'Content-Type: application/json' \\",
        "  --data " + shellQuote(streamBody),
      ].join("\n"),
      python: [
        "import json",
        "import requests",
        "",
        "with requests.post(",
        "    " + JSON.stringify(stream) + ",",
        "    json=" + streamBody + ",",
        '    headers={"Accept": "text/event-stream"},',
        "    stream=True,",
        "    timeout=30,",
        ") as response:",
        "    response.raise_for_status()",
        '    event, data = "message", []',
        "    for line in response.iter_lines(chunk_size=1, decode_unicode=True):",
        '        if line.startswith("event:"):',
        "            event = line[6:].strip()",
        '        elif line.startswith("data:"):',
        '            data.append(line[5:].removeprefix(" "))',
        "        elif not line and data:",
        '            payload = json.loads("\\n".join(data))',
        '            if event == "error":',
        '                raise RuntimeError(payload["detail"])',
        "            print(event, payload)",
        '            if event == "complete":',
        "                break",
        '            event, data = "message", []',
        "    else:",
        '        raise RuntimeError("Stream ended before the final verdict.")',
      ].join("\n"),
      javascript: [
        "const response = await fetch(" + JSON.stringify(stream) + ", {",
        '  method: "POST",',
        '  headers: { "Content-Type": "application/json", Accept: "text/event-stream" },',
        "  body: JSON.stringify(" + streamBody + "),",
        "});",
        'if (!response.ok || !response.body) throw new Error("HTTP " + response.status);',
        "",
        "const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();",
        'let pending = "";',
        "readEvents: try {",
        "  while (true) {",
        "    const { value, done } = await reader.read();",
        '    if (done) throw new Error("Stream ended before the final verdict.");',
        "    pending += value;",
        "    const frames = pending.split(/\\r?\\n\\r?\\n/);",
        '    pending = frames.pop() ?? "";',
        "    for (const frame of frames) {",
        "      const lines = frame.split(/\\r?\\n/);",
        '      const event = lines.find(line => line.startsWith("event:"))?.slice(6).trim();',
        '      const data = lines.filter(line => line.startsWith("data:"))',
        '        .map(line => line.slice(5).replace(/^ /, "")).join("\\n");',
        "      if (!data) continue;",
        "      const payload = JSON.parse(data);",
        '      if (event === "error") throw new Error(payload.detail);',
        "      console.log(event, payload);",
        '      if (event === "complete") break readEvents;',
        "    }",
        "  }",
        "} finally {",
        "  await reader.cancel();",
        "  reader.releaseLock();",
        "}",
      ].join("\n"),
    },
  } satisfies Record<string, CodeExamples>;
}

const breakdown = { starting_score: 0, adjustments: [], final_score: 0 };

const verdict = {
  scan_id: "0860f2c6-1742-4af8-97c8-c3180031c4a7",
  created_at: "2026-11-24T10:00:00Z",
  risk_score: 0,
  risk_level: "LOW",
  scam_type: "unknown",
  entities: { urls: [], phones: [], emails: [], upi_ids: [], flags: [] },
  ml: {
    sms: {
      risk_score: 0,
      risk_level: "LOW",
      score_breakdown: breakdown,
      reasons: [],
      positive_signals: ["ML detector shows a relatively low phishing probability."],
      ml_prediction: "LEGITIMATE",
      model_variant: "sms_tfidf",
      legitimate_probability: 0.91,
      phishing_probability: 0.09,
    },
    urls: [],
    risk_score: 0,
    risk_level: "LOW",
    score_breakdown: breakdown,
  },
  threat_intel: [],
  ai: {
    status: "skipped", reason: "missing_api_key", scam_type: "unknown",
    explanation: "", actions: [], confidence: null,
  },
  score_breakdown: breakdown,
  guidance: {
    category_id: "low_risk",
    category_label: "Low-risk check",
    indicators: [],
    steps: [
      "Check the sender and the destination before you act.",
      "Use an official app or website for payments and account changes.",
    ],
    reporting_steps: [
      "If you lost money, call 1930 and contact your bank or payment provider immediately, ideally within the first hour.",
      "File at cybercrime.gov.in. Include the 1930 acknowledgement number if you received one.",
      "Keep screenshots, transaction references, and timestamps private for your bank or the authorities.",
    ],
  },
  warning_card_png_base64: null,
};

export const textResponse = JSON.stringify(verdict, null, 2);

export const imageResponse = JSON.stringify({
  ...verdict,
  scan_id: "573c5f3c-50e8-410d-af01-d50a4ce50b29",
  scam_type: "none",
  ai: {
    status: "completed",
    reason: null,
    scam_type: "none",
    explanation: "The screenshot shows a routine library notice.",
    actions: [],
    confidence: 0.92,
  },
}, null, 2);

export const streamResponse = [
  'event: entity_extraction\ndata: {"url_count":0}',
  'event: ml_analysis\ndata: {"risk_score":0}',
  'event: threat_intel\ndata: {"checks":0,"hits":0}',
  'event: ai_verdict\ndata: {"status":"skipped","reason":"missing_api_key","scam_type":"unknown"}',
  "event: complete\ndata: " + JSON.stringify({
    ...verdict,
    scan_id: "413345ef-888b-4f16-be4a-15baf2e8d11f",
  }),
].join("\n\n") + "\n\n";
