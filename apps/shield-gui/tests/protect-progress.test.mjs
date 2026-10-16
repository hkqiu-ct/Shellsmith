import assert from "node:assert/strict";
import { after, test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

const server = await createServer({ server: { middlewareMode: true }, appType: "custom" });
after(() => server.close());
const { ProtectProgressPanel } = await server.ssrLoadModule("/src/components/app/protect-progress-panel.tsx");

test("APK、AAB、签名共享进度组件显示真实终态及失败步骤", () => {
  for (const currentStep of ["ProcessDex", "SignApk"]) {
    for (const [state, label] of [["idle", "就绪"], ["running", "执行中"], ["failed", "失败"], ["done", "完成"]]) {
      const html = renderToStaticMarkup(createElement(ProtectProgressPanel, {
        locale: "zh", state, currentStep, steps: ["CheckTools", currentStep, "Cleanup"],
        showProgress: state !== "idle", startedAt: 1000, finishedAt: 86000,
      }));
      assert.match(html, new RegExp(`<h2[^>]*>${label}</h2>`));
      if (state === "failed") {
        assert.match(html, /aria-label="失败"/);
        assert.match(html, /1m 25s/);
        assert.doesNotMatch(html, /animate-spin|执行中/);
      }
      if (state === "done") assert.match(html, /100%/);
    }
  }
});
