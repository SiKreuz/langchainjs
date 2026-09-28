import { IssuerMismatchError, OAuthError } from "@modelcontextprotocol/client";
import { MCPClientError } from "./utils/errors.js";
import { ConnectionManager } from "./connection.js";
import { mergeHeaders } from "./utils/misc.js";
import {
  assertCallbackState,
  discoveryStateHint,
  knownCallbackErrorCode,
} from "./utils/oauth.js";
import {
  HTTPConnectionSchema,
  StdioConnectionSchema,
  callbackParamsSchema,
  finishAuthOptionsSchema,
  oAuthClientProviderSchema,
  type HTTPConnection,
  type FinishAuthOptions,
} from "./types.js";

/**
 * Complete an OAuth authorization-code redirect for an HTTP or SSE server.
 *
 * Pass the same connection object you would put under `servers.<name>`, plus
 * the callback URL's query (`new URL(callbackUrl).searchParams`). The SDK
 * validates `iss` (RFC 9207) before redeeming the code and saves tokens
 * through the provider. Nothing connects here and no state is kept between
 * the redirect and this call, so the callback may arrive in another request
 * or process; the next discovery or tool call connects. The route that
 * handles the callback doesn't need an `MCPAdapter` at all — only a provider
 * that reads and writes the same storage as the one on the adapter's server
 * config.
 *
 * @throws {ZodError} if `callbackParams` is not a `URLSearchParams`, or
 * `options` doesn't match `FinishAuthOptions`.
 * @throws {MCPClientError} for a stdio or otherwise invalid server, a
 * provider that is not an `OAuthClientProvider`, a `state` mismatch, an
 * `error=` callback, or a failed exchange (the SDK error is the `cause`; it
 * may carry callback text, so don't display it).
 */
export async function finishAuth(
  server: HTTPConnection,
  callbackParams: URLSearchParams,
  options?: FinishAuthOptions
): Promise<void> {
  const params = callbackParamsSchema.parse(callbackParams);
  const { expectedState } = finishAuthOptionsSchema.parse(options ?? {});

  const resolved = HTTPConnectionSchema.safeParse(server);
  if (!resolved.success) {
    if (StdioConnectionSchema.safeParse(server).success)
      throw new MCPClientError(
        "finishAuth requires an HTTP or SSE server; this configuration uses stdio"
      );

    throw new MCPClientError(
      "finishAuth received an invalid HTTP or SSE server configuration",
      undefined,
      { cause: resolved.error }
    );
  }

  const connection = resolved.data;
  // Messages below print only the origin: the full URL can carry
  // credentials or secrets in its userinfo, path or query.
  const origin = new URL(connection.url).origin;

  const provider = oAuthClientProviderSchema.safeParse(connection.authProvider);
  if (!provider.success)
    throw new MCPClientError(
      `finishAuth requires an OAuthClientProvider for ${origin}`
    );

  if (expectedState !== undefined)
    assertCallbackState(params, expectedState, origin);

  try {
    await new ConnectionManager().finishAuth(
      { ...connection, headers: mergeHeaders(undefined, connection.headers) },
      params
    );
  } catch (error) {
    // On the "authorization_response" kind (RFC 9207) the error carries the
    // callback's `iss`, which an attacker controls in a mix-up, as they do the
    // callback's error fields; the SDK says not to display them. The
    // "metadata" kind (RFC 8414 §3.3) means the authorization server's
    // metadata names a different issuer than the URL it was fetched from.
    // Each kind gets its own fixed message, and neither echoes a received value.
    if (IssuerMismatchError.isInstance(error)) {
      if (error.kind === "authorization_response")
        throw new MCPClientError(
          `OAuth authorization for ${origin} failed: the callback's issuer does not match the authorization server (RFC 9207), so the code was not redeemed.`,
          undefined,
          { cause: error }
        );

      throw new MCPClientError(
        `OAuth authorization for ${origin} failed: the authorization server's metadata issuer does not match the URL it was fetched from (RFC 8414).`,
        undefined,
        { cause: error }
      );
    }

    // With no `code`, the SDK builds this OAuthError from the callback's own
    // error fields once `iss` passes (unchecked when the server doesn't
    // advertise RFC 9207). Echo only a standard `error` code.
    if (!params.get("code") && OAuthError.isInstance(error)) {
      const code = knownCallbackErrorCode(params);
      throw new MCPClientError(
        `OAuth authorization for ${origin} failed: the callback reported ${code ? `"${code}"` : "an error"}, so no code was redeemed.`,
        undefined,
        { cause: error }
      );
    }

    throw new MCPClientError(
      `OAuth authorization for ${origin} failed: ${error}.${discoveryStateHint(provider.data)}`,
      undefined,
      { cause: error }
    );
  }
}
