import type { Metadata } from "next";
import { ArrowUpRight, ChevronDown, FileJson, Radio, Terminal } from "lucide-react";
import { API_BASE_URL } from "../../lib/api";
import { RequestExamples } from "./code-examples";
import { examples, imageResponse, streamResponse, textResponse } from "./examples";
import styles from "./developers.module.css";

export const metadata: Metadata = {
  title: { absolute: "Developer API | ScamShield" },
  description: "Integrate ScamShield text, screenshot, and streaming scan endpoints.",
};

const sections = [
  {
    id: "scan",
    title: "Scan text",
    path: "/api/v1/scan",
    request: "application/json",
    response: "application/json",
    example: textResponse,
    command: "text",
  },
  {
    id: "image",
    title: "Scan a screenshot",
    path: "/api/v1/scan/image",
    request: "multipart/form-data",
    response: "application/json",
    example: imageResponse,
    command: "image",
  },
  {
    id: "stream",
    title: "Stream a text scan",
    path: "/api/v1/scan/stream",
    request: "application/json",
    response: "text/event-stream",
    example: streamResponse,
    command: "stream",
  },
] as const;

const errors = [
  [409, "This input was scanned recently. Retry after the delay in Retry-After."],
  [413, "The request body or screenshot exceeds a size limit."],
  [415, "The uploaded image type is unsupported or the bytes do not match it."],
  [422, "The text or multipart form failed validation."],
  [429, "The scanner rate limit or the Gemini quota was reached. Check the error code and Retry-After when present."],
  [502, "Gemini returned an upstream error or an unreadable screenshot result."],
  [503, "Scan capacity is busy, Gemini credentials need attention, or the server could not reach Gemini."],
] as const;

export default function DevelopersPage() {
  const requests = examples(API_BASE_URL);

  return (
    <div className={"shell " + styles.page}>
      <div className={styles.intro}>
        <div>
          <div className={styles.eyebrow}><Terminal size={15} aria-hidden="true" /> Developer API</div>
          <h1>API reference</h1>
          <p>Scan messages and screenshots, or stream a verdict as each check finishes.</p>
        </div>
        <div className={styles.baseUrl}>
          <span>API base URL</span>
          <code>{API_BASE_URL}</code>
        </div>
      </div>

      <div className={styles.layout}>
        <aside className={styles.sidebar}>
          <nav aria-label="On this page">
            <p>On this page</p>
            <ul>
              {sections.map((section) => (
                <li key={section.id}><a href={"#" + section.id}>{section.title}</a></li>
              ))}
              <li><a href="#errors">HTTP errors</a></li>
            </ul>
            <a className={styles.openapi} href={API_BASE_URL + "/docs"} target="_blank" rel="noreferrer">
              Interactive API schema <ArrowUpRight size={15} aria-hidden="true" />
            </a>
          </nav>
        </aside>

        <div className={styles.sections}>
          {sections.map(({ id, title, path, request, response, example, command }) => (
            <section key={id} id={id} className={styles.section} aria-labelledby={id + "-title"}>
              <div className={styles.sectionTitle}>
                <h2 id={id + "-title"}>{title}</h2>
                <div className={styles.route}><span>POST</span> <code>{path}</code></div>
              </div>
              {id === "scan" && (
                <p>Send a JSON object with <code>text</code> containing a message, URL, phone number, or UPI ID. The text must be between 1 and 8,000 characters after trimming.</p>
              )}
              {id === "image" && (
                <p>Remove sensitive personal details, then send one PNG, JPEG, or WebP screenshot as <code>file</code> and set <code>redacted=true</code>. The default upload limit is 4 MiB.</p>
              )}
              {id === "stream" && (
                <>
                  <p>Send the same JSON shape as a text scan and read the response stream incrementally. Each event has a name and a JSON <code>data</code> field.</p>
                  <ol className={styles.eventSteps} aria-label="Events in order">
                    {["entity_extraction", "ml_analysis", "threat_intel", "ai_verdict", "complete"].map((stage) => (
                      <li key={stage}><code>{stage}</code></li>
                    ))}
                  </ol>
                </>
              )}
              <h3 className={styles.panelHeading}>Request <code>{request}</code></h3>
              <RequestExamples name={title} samples={requests[command]} />
              <details className={styles.response}>
                <summary>
                  <span>{id === "stream" ? <Radio size={16} aria-hidden="true" /> : <FileJson size={16} aria-hidden="true" />}
                    Example response</span>
                  <code>200 · {response}</code>
                  <ChevronDown size={16} aria-hidden="true" className={styles.chevron} />
                </summary>
                <pre tabIndex={0} aria-label={title + " example response"}><code>{example}</code></pre>
              </details>
              {id === "stream" && (
                <p className={styles.note}>The <code>complete</code> event includes the full scan verdict. A scan failure after streaming starts arrives as an <code>error</code> event even though the initial response was HTTP 200.</p>
              )}
              {id !== "image" && (
                <p className={styles.note}>When Gemini can’t run, the verdict still includes local scan results. Check <code>ai.reason</code> for values such as <code>missing_api_key</code>, <code>quota_exceeded</code>, or <code>network_error</code>.</p>
              )}
            </section>
          ))}

          <section id="errors" className={styles.section} aria-labelledby="errors-title">
            <h2 id="errors-title">HTTP errors</h2>
            <p>Read <code>detail</code> for more information. Rate-limit and duplicate-scan responses can include a <code>Retry-After</code> header in seconds.</p>
            <dl className={styles.errorList}>
              {errors.map(([status, description]) => (
                <div key={status}><dt><code>{status}</code></dt><dd>{description}</dd></div>
              ))}
            </dl>
            <p>For browser requests, include your frontend origin in the API server’s <code>ALLOWED_ORIGINS</code> setting.</p>
          </section>
        </div>
      </div>
    </div>
  );
}
