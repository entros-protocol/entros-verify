/**
 * Vitest global setup.
 *
 * 1. Registers jest-dom matchers (toBeInTheDocument, toHaveClass, etc.)
 *    against vitest's expect.
 * 2. Polyfills crypto.randomUUID for jsdom builds that don't ship it.
 */

import "@testing-library/jest-dom/vitest";

if (typeof crypto !== "undefined" && typeof crypto.randomUUID !== "function") {
  Object.defineProperty(crypto, "randomUUID", {
    value: () =>
      "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        const v = c === "x" ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      }),
    configurable: true,
  });
}
