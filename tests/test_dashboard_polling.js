const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  startIndependentPolling,
} = require("../triagewall/dashboard/static/polling.js");

test("starts SPC without waiting for the main dashboard request", () => {
  const calls = [];
  const timers = [];

  startIndependentPolling({
    loadMain: () => {
      calls.push("main");
      return new Promise(() => {});
    },
    loadSpc: () => calls.push("spc"),
    setTimer: (callback, delay) => timers.push({ callback, delay }),
  });

  assert.deepEqual(calls, ["spc", "main"]);
  assert.equal(timers.length, 2);
  assert.deepEqual(timers.map(({ delay }) => delay), [30_000, 30_000]);
});

test("keeps SPC polling when the main dashboard request fails", async () => {
  let mainCalls = 0;
  let spcCalls = 0;
  const errors = [];
  const timers = [];

  startIndependentPolling({
    loadMain: () => {
      mainCalls += 1;
      return Promise.reject(new Error("verdicts unavailable"));
    },
    loadSpc: () => {
      spcCalls += 1;
    },
    setTimer: (callback) => timers.push(callback),
    onError: (error) => errors.push(error.message),
  });

  await Promise.resolve();
  assert.equal(mainCalls, 1);
  assert.equal(spcCalls, 1);
  assert.deepEqual(errors, ["verdicts unavailable"]);

  timers.forEach((callback) => callback());
  await Promise.resolve();
  assert.equal(mainCalls, 2);
  assert.equal(spcCalls, 2);
  assert.deepEqual(errors, ["verdicts unavailable", "verdicts unavailable"]);
});

test("dashboard wires SPC outside the verdict-loading function", () => {
  const indexPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "index.html",
  );
  const html = fs.readFileSync(indexPath, "utf8");
  const loadStart = html.indexOf("async function load() {");
  const loadEnd = html.indexOf("function renderHero", loadStart);

  assert.notEqual(loadStart, -1);
  assert.notEqual(loadEnd, -1);
  assert.doesNotMatch(html.slice(loadStart, loadEnd), /loadSpc\s*\(/);
  assert.match(html, /<script src="\/static\/polling\.js"><\/script>/);
  assert.match(
    html,
    /startIndependentPolling\(\{ loadMain: load, loadSpc \}\);/,
  );
});
