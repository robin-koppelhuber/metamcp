import { describe, expect, it } from "vitest";

import { isEndpointAllowedForKey } from "./api-key-scope";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";

describe("isEndpointAllowedForKey", () => {
  it("lets an unrestricted key open every endpoint", () => {
    const scope = { scope_restricted: false, allowed_endpoint_uuids: [] };
    expect(isEndpointAllowedForKey(scope, A)).toBe(true);
    expect(isEndpointAllowedForKey(scope, B)).toBe(true);
  });

  it("ignores a stale list on an unrestricted key", () => {
    const scope = { scope_restricted: false, allowed_endpoint_uuids: [A] };
    expect(isEndpointAllowedForKey(scope, B)).toBe(true);
  });

  it("lets a restricted key open only the listed endpoints", () => {
    const scope = { scope_restricted: true, allowed_endpoint_uuids: [A] };
    expect(isEndpointAllowedForKey(scope, A)).toBe(true);
    expect(isEndpointAllowedForKey(scope, B)).toBe(false);
  });

  it("lets a restricted key open several listed endpoints", () => {
    const scope = { scope_restricted: true, allowed_endpoint_uuids: [A, B] };
    expect(isEndpointAllowedForKey(scope, A)).toBe(true);
    expect(isEndpointAllowedForKey(scope, B)).toBe(true);
  });

  it("opens nothing for a restricted key with an empty list (all its endpoints were deleted)", () => {
    const scope = { scope_restricted: true, allowed_endpoint_uuids: [] };
    expect(isEndpointAllowedForKey(scope, A)).toBe(false);
    expect(isEndpointAllowedForKey(scope, B)).toBe(false);
  });
});
