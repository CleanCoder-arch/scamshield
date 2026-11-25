import assert from "node:assert/strict";
import { test, type TestContext } from "node:test";
import { Window as TestWindow } from "happy-dom";
import { act, StrictMode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { LaunchSplash } from "../components/launch-splash";

const sessionKey = "scamshield:launch-splash";

function installClock(window: Window) {
  let time = 0;
  let nextHandle = 0;
  const frames = new Map<number, FrameRequestCallback>();
  const timeouts = new Map<number, { run: () => void; deadline: number }>();

  window.requestAnimationFrame = (callback) => {
    frames.set(++nextHandle, callback);
    return nextHandle;
  };
  window.cancelAnimationFrame = (handle) => { frames.delete(handle); };
  window.setTimeout = (callback, delay = 0, ...args: unknown[]) => {
    if (typeof callback !== "function") throw new TypeError("Expected a timer callback.");
    timeouts.set(++nextHandle, { run: () => callback(...args), deadline: time + delay });
    return nextHandle;
  };
  window.clearTimeout = (handle) => { if (handle !== undefined) timeouts.delete(handle); };

  return {
    pendingFrames: () => frames.size,
    pendingTimeouts: () => timeouts.size,
    nextFrame: () => act(async () => {
      for (const handle of [...frames.keys()]) {
        const callback = frames.get(handle);
        frames.delete(handle);
        callback?.(time);
      }
    }),
    advance: (milliseconds: number) => act(async () => {
      const target = time + milliseconds;
      while (timeouts.size) {
        const [handle, task] = [...timeouts].sort(([, left], [, right]) => left.deadline - right.deadline)[0];
        if (task.deadline > target) break;
        timeouts.delete(handle);
        time = task.deadline;
        task.run();
      }
      time = target;
    }),
  };
}

async function setup(t: TestContext, reducedMotion = false) {
  const browser = new TestWindow({
    url: "https://scamshield.test/",
    settings: { enableJavaScriptEvaluation: false, disableJavaScriptFileLoading: true },
  });
  const window = browser as unknown as Window;
  const { document } = window;
  const matchMedia = window.matchMedia.bind(window);
  window.matchMedia = (query) => {
    const matches = query === "(prefers-reduced-motion: reduce)" && reducedMotion;
    return Object.defineProperty(matchMedia(query), "matches", { value: matches });
  };
  const clock = installClock(window);
  const overrides = { window, document, navigator: window.navigator, IS_REACT_ACT_ENVIRONMENT: true };
  const originals = Object.keys(overrides).map((name) =>
    [name, Object.getOwnPropertyDescriptor(globalThis, name)] as const,
  );
  for (const [name, value] of Object.entries(overrides)) {
    Object.defineProperty(globalThis, name, { configurable: true, value });
  }

  async function closeBrowser() {
    for (const [name, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else Reflect.deleteProperty(globalThis, name);
    }
    await browser.happyDOM.close();
  }

  const container = document.createElement("div");
  document.body.append(container);
  const root = await import("react-dom/client")
    .then(({ createRoot }) => createRoot(container))
    .catch(async (error: unknown) => {
      await closeBrowser();
      throw error;
    });
  t.after(async () => {
    try {
      await act(async () => { root.unmount(); });
    } finally {
      await closeBrowser();
    }
  });

  return {
    ...clock,
    storage: window.sessionStorage,
    splash: () => container.querySelector<HTMLElement>(".launch-splash"),
    render: (pathname = "/") => act(async () => {
      root.render(
        <StrictMode>
          <LaunchSplash />
          <main key={pathname}>{pathname}</main>
        </StrictMode>,
      );
    }),
    remove: () => act(async () => { root.render(null); }),
  };
}

test("renders no splash in the server response", () => {
  assert.equal(renderToStaticMarkup(<LaunchSplash />), "");
});

test("checks the first session after a frame and removes the splash after its hold and fade", async (t) => {
  const page = await setup(t);
  await page.render();
  assert.equal(page.splash(), null);
  assert.equal(page.storage.getItem(sessionKey), null);
  assert.equal(page.pendingFrames(), 1);

  await page.nextFrame();
  assert.notEqual(page.storage.getItem(sessionKey), null);
  const splash = page.splash();
  assert.ok(splash);
  assert.equal(splash.dataset.phase, "visible");
  assert.equal(splash.tagName, "DIV");
  assert.equal(splash.getAttribute("aria-hidden"), "true");
  assert.equal(splash.querySelector('button, [role="button"], a, [tabindex]'), null);
  assert.doesNotMatch(splash.textContent ?? "", /skip intro/i);
  assert.equal(page.pendingTimeouts(), 1);

  await page.advance(949);
  assert.equal(page.splash()?.dataset.phase, "visible");
  await page.advance(1);
  assert.equal(page.splash()?.dataset.phase, "leaving");
  assert.equal(page.pendingTimeouts(), 1);

  await page.advance(299);
  assert.equal(page.splash()?.dataset.phase, "leaving");
  await page.advance(1);
  assert.equal(page.splash(), null);
  assert.equal(page.pendingTimeouts(), 0);
});

test("changing route content leaves the splash timer alone and does not replay it", async (t) => {
  const page = await setup(t);
  await page.render();
  await page.nextFrame();
  const splash = page.splash();
  assert.ok(splash);

  await page.advance(500);
  await page.render("/rights");
  assert.equal(page.splash(), splash);
  assert.equal(page.pendingFrames(), 0);
  await page.advance(450);
  assert.equal(page.splash()?.dataset.phase, "leaving");
  await page.advance(300);
  assert.equal(page.splash(), null);

  await page.render("/");
  assert.equal(page.splash(), null);
  assert.equal(page.pendingFrames(), 0);
  assert.equal(page.pendingTimeouts(), 0);
});

test("a fresh mount in the same session skips the splash", async (t) => {
  const page = await setup(t);
  await page.render();
  await page.nextFrame();
  assert.equal(page.splash()?.dataset.phase, "visible");

  await page.remove();
  await page.render("/rights");
  await page.nextFrame();
  assert.equal(page.splash(), null);
  assert.equal(page.pendingTimeouts(), 0);
});

test("records a reduced-motion session without mounting or scheduling the splash", async (t) => {
  const page = await setup(t, true);
  await page.render();
  await page.nextFrame();
  assert.notEqual(page.storage.getItem(sessionKey), null);
  assert.equal(page.splash(), null);
  assert.equal(page.pendingTimeouts(), 0);
});

test("cancels pending frame and timeout work when the component unmounts", async (t) => {
  const page = await setup(t);
  await page.render();
  assert.equal(page.pendingFrames(), 1);
  await page.remove();
  assert.equal(page.pendingFrames(), 0);
  assert.equal(page.storage.getItem(sessionKey), null);

  await page.render();
  await page.nextFrame();
  assert.equal(page.splash()?.dataset.phase, "visible");
  assert.equal(page.pendingTimeouts(), 1);
  await page.remove();
  assert.equal(page.pendingTimeouts(), 0);
});
