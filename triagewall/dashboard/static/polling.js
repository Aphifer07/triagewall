(function (root, factory) {
  const api = factory();
  root.startIndependentPolling = api.startIndependentPolling;
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  function startIndependentPolling({
    loadMain,
    loadSpc,
    setTimer = setInterval,
    intervalMs = 30_000,
    onError = (error) => console.error("Dashboard polling failed", error),
  }) {
    const run = (task) => {
      try {
        const result = task();
        if (result && typeof result.catch === "function") {
          result.catch(onError);
        }
      } catch (error) {
        onError(error);
      }
    };

    // Start and schedule each data source separately so a slow or failed
    // verdict request cannot delay the fast SPC panel.
    run(loadSpc);
    run(loadMain);
    setTimer(() => run(loadSpc), intervalMs);
    setTimer(() => run(loadMain), intervalMs);
  }

  return { startIndependentPolling };
});
