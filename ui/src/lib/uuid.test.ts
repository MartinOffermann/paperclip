import { afterEach, describe, expect, it, vi } from "vitest";
import { createUuid } from "./uuid";

describe("createUuid", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("creates a UUID on plain HTTP when crypto.randomUUID is unavailable", () => {
    const getRandomValues = vi.fn((bytes: Uint8Array) => {
      bytes.fill(0);
      return bytes;
    });
    vi.stubGlobal("crypto", { getRandomValues } as unknown as Crypto);

    expect(createUuid()).toBe("00000000-0000-4000-8000-000000000000");
    expect(getRandomValues).toHaveBeenCalledOnce();
  });
});
