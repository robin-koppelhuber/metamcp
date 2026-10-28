/**
 * Endpoint scoping of API keys.
 *
 * A key is either unrestricted (the default, behaviour unchanged) or restricted to an explicit list of endpoints.
 * "Restricted" is an explicit flag and not inferred from the list being non-empty: a restricted key whose last
 * listed endpoint was deleted therefore opens nothing instead of silently opening everything.
 */
export interface ApiKeyScope {
  scope_restricted: boolean;
  allowed_endpoint_uuids: string[];
}

export function isEndpointAllowedForKey(
  scope: ApiKeyScope,
  endpointUuid: string,
): boolean {
  if (!scope.scope_restricted) {
    return true;
  }
  return scope.allowed_endpoint_uuids.includes(endpointUuid);
}
