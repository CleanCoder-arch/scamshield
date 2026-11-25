import assert from "node:assert/strict";
import { test } from "node:test";
import { PathnameContext } from "next/dist/shared/lib/hooks-client-context.shared-runtime";
import { renderToStaticMarkup } from "react-dom/server";
import { SiteNav } from "../components/site-nav";

function renderNav(path: string) {
  return renderToStaticMarkup(
    <PathnameContext.Provider value={path}>
      <SiteNav />
    </PathnameContext.Provider>,
  );
}

test("lists Scanner, Know Your Rights and Report a scam in the primary navigation", () => {
  const html = renderNav("/");
  assert.match(html, /<nav[^>]*aria-label="Main navigation"/);
  assert.match(html, /<a[^>]*href="\/"[^>]*>[\s\S]*?Scanner<\/a>/);
  assert.match(html, /<a[^>]*href="\/rights"[^>]*>[\s\S]*?Know Your Rights<\/a>/);
  assert.match(
    html,
    /<a[^>]*href="https:\/\/cybercrime\.gov\.in\/"[^>]*target="_blank"[^>]*rel="noopener noreferrer"[^>]*>Report a scam/,
  );
  assert.doesNotMatch(html, /Developer API|href="\/developers"/);
});

test("marks only the current primary route for assistive technology", () => {
  for (const path of ["/", "/rights"]) {
    const links = [...renderNav(path).matchAll(/<a\b[^>]*aria-current="page"[^>]*>/g)];
    assert.equal(links.length, 1);
    assert.ok(links[0][0].includes(`href="${path}"`));
  }
  assert.doesNotMatch(renderNav("/developers"), /aria-current/);
});
