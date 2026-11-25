import assert from "node:assert/strict";
import { test } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import RightsPage, { metadata } from "../app/rights/page";

test("Know Your Rights provides four sections with matching jump links", () => {
  const html = renderToStaticMarkup(<RightsPage />);
  assert.equal(metadata.title, "Know Your Rights");
  assert.match(html, /<h1[^>]*>Know Your <span[^>]*>Rights<\/span><\/h1>/);

  for (const id of ["scam-tactics", "legal-protections", "first-hour", "cyber-hygiene"]) {
    assert.ok(html.includes(`href="#${id}"`));
    assert.ok(html.includes(`aria-labelledby="${id}"`));
    assert.ok(html.includes(`<h2 id="${id}"`));
  }
  for (const heading of ["Digital arrest calls", "UPI collect and PIN traps", "Fake KYC, parcel and utility links", "Fake jobs and prepaid tasks"]) {
    assert.ok(html.includes(heading));
  }
  assert.match(html, /general public awareness only/);
});

test("the first-hour checklist shows the official reporting options and evidence steps", () => {
  const html = renderToStaticMarkup(<RightsPage />);
  assert.match(html, /href="tel:1930"/);
  assert.match(html, /href="https:\/\/cybercrime\.gov\.in\/"/);

  const checklist = html.match(/<section[^>]*aria-labelledby="first-hour"[^>]*>([\s\S]*?)<\/section>/)?.[1];
  assert.ok(checklist);
  assert.match(checklist, /<ol[\s>]/);
  assert.equal([...checklist.matchAll(/<li[\s>]/g)].length, 4);
  for (const detail of ["acknowledgement ID", "UPI mandates", "UTR numbers", "screenshots", "call logs"]) {
    assert.ok(checklist.includes(detail));
  }
});

test("links the liability and chain-freeze guidance to official grievance resources", () => {
  const html = renderToStaticMarkup(<RightsPage />);
  assert.match(html, /href="https:\/\/cms\.rbi\.org\.in\/"/);
  assert.match(html, /RBI rules can limit liability or reduce it to zero in eligible cases/);
  assert.match(html, /Recovery depends on the case/);
  assert.match(html, /Sections 66C and 66D/);
  assert.match(html, /I4C grievance procedure/);
  assert.match(html, /investigating officer/);
});
