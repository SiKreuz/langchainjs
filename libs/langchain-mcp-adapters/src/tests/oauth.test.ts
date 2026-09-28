import { afterEach, describe, expect, it, vi } from "vitest";
import { z, ZodError } from "zod";
import {
  IssuerMismatchError,
  OAuthError,
  SSEClientTransport,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import {
  MCPAdapter,
  MCPClientError,
  UnauthorizedError,
  finishAuth,
  type MCPAdapterConfig,
  type SSEConnection,
  type StreamableHTTPConnection,
} from "../index.js";
import { ConnectionManager } from "../connection.js";
import { getHttpErrorCode, isAuthenticationError } from "../utils/errors.js";
import {
  startOAuthFixture,
  type OAuthFixture,
  type OAuthFixtureOptions,
} from "./fixtures/oauth-server.js";
import {
  authorizeInBrowser,
  createTestOAuthProvider,
} from "./fixtures/oauth-client.js";

const cleanup: Array<() => Promise<unknown>> = [];

afterEach(async () => {
  for (const step of cleanup.splice(0).reverse()) await step();
});

async function fixture(options?: OAuthFixtureOptions): Promise<OAuthFixture> {
  const started = await startOAuthFixture(options);
  cleanup.push(() => started.close());
  return started;
}

function adapter(config: MCPAdapterConfig) {
  const created = new MCPAdapter(config);
  cleanup.push(() => created.close());
  return created;
}

const toolNames = (tools: ReadonlyArray<{ name: string }>) =>
  tools.map((tool) => tool.name);

const hasWhoami = (tools: ReadonlyArray<{ name: string }>) =>
  toolNames(tools).some((name) => name.endsWith("whoami"));

/** Await a rejection that must be an MCPClientError, and return it. */
async function failure(promise: Promise<unknown>): Promise<MCPClientError> {
  const error = await promise.then(
    () => undefined,
    (reason: unknown) => reason
  );
  if (!MCPClientError.isInstance(error))
    throw new Error(`expected MCPClientError, got ${String(error)}`);
  return error;
}

describe("OAuth fixture", () => {
  it("advertises RFC 9207 support and challenges unauthenticated MCP requests", async () => {
    const server = await fixture();
    const metadata = z
      .object({ authorization_response_iss_parameter_supported: z.boolean() })
      .parse(
        await (
          await fetch(`${server.base}/.well-known/oauth-authorization-server`)
        ).json()
      );
    expect(metadata.authorization_response_iss_parameter_supported).toBe(true);

    const challenge = await fetch(server.mcpUrl, { method: "POST" });
    expect(challenge.status).toBe(401);
    expect(challenge.headers.get("www-authenticate")).toContain(
      "resource_metadata="
    );
  });

  it("serves tools to a valid bearer token", async () => {
    const server = await fixture();
    const token = server.mintAccessToken();
    const tools = await adapter({
      servers: {
        svc: {
          transport: "http",
          url: server.mcpUrl,
          headers: { Authorization: `Bearer ${token}` },
        },
      },
    }).listTools();
    expect(hasWhoami(tools)).toBe(true);
  });
});

describe("token providers", () => {
  it("connects with { token }", async () => {
    const server = await fixture();
    const token = server.mintAccessToken();
    const tools = await adapter({
      servers: {
        svc: {
          transport: "http",
          url: server.mcpUrl,
          authProvider: { token: async () => token },
        },
      },
    }).listTools();

    expect(hasWhoami(tools)).toBe(true);
    const sent = server.requests
      .filter((request) => request.path === "/mcp")
      .map((request) => request.authorization);
    expect(new Set(sent)).toEqual(new Set([`Bearer ${token}`]));
  });

  it("refreshes through onUnauthorized and retries once", async () => {
    const server = await fixture();
    let current = "stale";
    const onUnauthorized = vi.fn(async () => {
      current = server.mintAccessToken();
    });
    const tools = await adapter({
      servers: {
        svc: {
          transport: "http",
          url: server.mcpUrl,
          authProvider: { token: async () => current, onUnauthorized },
        },
      },
    }).listTools();

    expect(hasWhoami(tools)).toBe(true);
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["an empty object", {}],
    ["a non-callable token", { token: "abc" }],
    [
      "a non-callable onUnauthorized",
      { token: async () => "t", onUnauthorized: 1 },
    ],
    ["null", null],
    ["a string", "token"],
  ])("rejects %s at construction", (_label, authProvider) => {
    expect(
      () =>
        new MCPAdapter({
          servers: {
            svc: {
              transport: "http",
              url: "http://127.0.0.1:1/mcp",
              authProvider: authProvider as never,
            },
          },
        })
    ).toThrow(ZodError);
  });
});

describe("auth failure labeling", () => {
  it("labels a provider flow on HTTP and keeps UnauthorizedError as the cause", async () => {
    const server = await fixture();
    const error = await failure(
      adapter({
        servers: {
          svc: {
            transport: "http",
            url: server.mcpUrl,
            authProvider: createTestOAuthProvider(),
          },
        },
      }).listTools()
    );
    expect(error.message).toMatch(
      /^Authentication failed for HTTP server "svc"/
    );
    expect(error.cause).toBeInstanceOf(UnauthorizedError);
  });

  it("labels a provider flow on SSE", async () => {
    const server = await fixture();
    const error = await failure(
      adapter({
        servers: {
          svc: {
            transport: "sse",
            url: server.sseUrl,
            authProvider: createTestOAuthProvider(),
          },
        },
      }).listTools()
    );
    expect(error.message).toMatch(
      /^Authentication failed for SSE server "svc"/
    );
    expect(error.cause).toBeInstanceOf(UnauthorizedError);
  });

  it("labels a 401 without a provider, with the HTTP status on the cause", async () => {
    const server = await fixture();
    const error = await failure(
      adapter({
        servers: { svc: { transport: "http", url: server.mcpUrl } },
      }).listTools()
    );
    expect(error.message).toMatch(
      /^Authentication failed for HTTP server "svc"/
    );
    expect(getHttpErrorCode(error.cause)).toBe(401);
  });

  it("never falls back to SSE from a legacy-mode provider flow", async () => {
    const server = await fixture();
    const error = await failure(
      adapter({
        servers: {
          svc: {
            transport: "http",
            mode: "legacy",
            url: server.mcpUrl,
            authProvider: createTestOAuthProvider(),
          },
        },
      }).listTools()
    );
    expect(error.cause).toBeInstanceOf(UnauthorizedError);
    expect(server.requests.some((request) => request.path === "/sse")).toBe(
      false
    );
  });

  it("keeps a throwing token() as the cause and does not call it an auth failure", async () => {
    const server = await fixture();
    const error = await failure(
      adapter({
        servers: {
          svc: {
            transport: "http",
            url: server.mcpUrl,
            authProvider: {
              token: async () => {
                throw new Error("vault unavailable");
              },
            },
          },
        },
      }).listTools()
    );
    expect(error.message).not.toMatch(/^Authentication failed/);
    expect(error.cause).toBeInstanceOf(Error);
    expect((error.cause as Error).message).toBe("vault unavailable");
  });
});

describe("auth failures stay retryable", () => {
  function tokenAdapter(
    server: OAuthFixture,
    token: () => string,
    onConnectionError:
      | "ignore"
      | ((params: { serverName: string; error: unknown }) => void)
  ) {
    return adapter({
      onConnectionError,
      servers: {
        svc: {
          transport: "http",
          url: server.mcpUrl,
          authProvider: { token: async () => token() },
        },
      },
    });
  }

  it("retries an auth-failed server under onConnectionError: ignore", async () => {
    const server = await fixture();
    let token = "not-yet-valid";
    const mcp = tokenAdapter(server, () => token, "ignore");

    expect(await mcp.listTools()).toEqual([]);
    token = server.mintAccessToken();
    expect(hasWhoami(await mcp.listTools())).toBe(true);
  });

  it("reports each auth failure to the handler and retries", async () => {
    const server = await fixture();
    let token = "not-yet-valid";
    const onConnectionError = vi.fn();
    const mcp = tokenAdapter(server, () => token, onConnectionError);

    expect(await mcp.listTools()).toEqual([]);
    expect(onConnectionError).toHaveBeenCalledTimes(1);
    expect(
      isAuthenticationError(onConnectionError.mock.calls[0][0].error)
    ).toBe(true);

    token = server.mintAccessToken();
    expect(hasWhoami(await mcp.listTools())).toBe(true);
    expect(onConnectionError).toHaveBeenCalledTimes(1);
  });

  it("labels a 401 that survives onUnauthorized as an authentication failure, and keeps retrying", async () => {
    const server = await fixture();
    const onUnauthorized = vi.fn();
    const onConnectionError = vi.fn();
    const mcp = adapter({
      onConnectionError,
      servers: {
        svc: {
          transport: "http",
          url: server.mcpUrl,
          authProvider: { token: async () => "bad", onUnauthorized },
        },
      },
    });

    await mcp.listTools();
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
    const [{ error }] = onConnectionError.mock.calls[0];
    expect(MCPClientError.isInstance(error)).toBe(true);
    expect((error as MCPClientError).message).toMatch(/^Authentication failed/);
    expect(getHttpErrorCode((error as MCPClientError).cause)).toBe(401);
    expect(isAuthenticationError(error)).toBe(true);

    await mcp.listTools();
    expect(onUnauthorized).toHaveBeenCalledTimes(2);
    expect(onConnectionError).toHaveBeenCalledTimes(2);
  });

  it("retries a legacy-mode server whose HTTP→SSE fallback also 401s", async () => {
    const server = await fixture();
    const onConnectionError = vi.fn();
    const mcp = adapter({
      onConnectionError,
      servers: {
        svc: {
          transport: "http",
          mode: "legacy",
          automaticSSEFallback: true,
          url: server.mcpUrl,
        },
      },
    });

    expect(await mcp.listTools()).toEqual([]);
    expect(onConnectionError).toHaveBeenCalledTimes(1);
    expect(server.requests.some((request) => request.path === "/sse")).toBe(
      true
    );

    const [{ error }] = onConnectionError.mock.calls[0];
    expect(MCPClientError.isInstance(error)).toBe(true);
    expect(MCPClientError.isInstance((error as MCPClientError).cause)).toBe(
      true
    );
    expect(isAuthenticationError(error)).toBe(true);

    expect(await mcp.listTools()).toEqual([]);
    expect(onConnectionError).toHaveBeenCalledTimes(2);
  });

  it("keeps an unreachable server blocked", async () => {
    const onConnectionError = vi.fn();
    const mcp = adapter({
      onConnectionError,
      servers: { down: { transport: "http", url: "http://127.0.0.1:1/mcp" } },
    });
    await mcp.listTools();
    await mcp.listTools();
    expect(onConnectionError).toHaveBeenCalledTimes(1);
  });

  it("keeps a throwing token provider blocked", async () => {
    const server = await fixture();
    const onConnectionError = vi.fn();
    const mcp = adapter({
      onConnectionError,
      servers: {
        svc: {
          transport: "http",
          url: server.mcpUrl,
          authProvider: {
            token: async () => {
              throw new Error("vault unavailable");
            },
          },
        },
      },
    });
    await mcp.listTools();
    await mcp.listTools();
    expect(onConnectionError).toHaveBeenCalledTimes(1);
  });
});

/** Start a login: the first discovery fails and hands out one authorization URL. */
async function pendingLogin(
  options: {
    iss?: OAuthFixtureOptions["iss"];
    state?: string;
    persistDiscovery?: boolean;
    transport?: "http" | "sse";
    /** Which field spells out an SSE server; ignored for HTTP. */
    sseSpelling?: "transport" | "type";
  } = {}
) {
  const server = await fixture({ iss: options.iss });
  const provider = createTestOAuthProvider({
    state: options.state,
    persistDiscovery: options.persistDiscovery,
  });
  const transport = options.transport ?? "http";
  const sseSpelling = options.sseSpelling ?? "transport";
  // A widened `transport` variable does not narrow the discriminated
  // union below, so each branch is written with its literal directly.
  const serverConfig =
    transport === "sse"
      ? sseSpelling === "type"
        ? ({
            type: "sse",
            url: server.sseUrl,
            authProvider: provider,
          } satisfies SSEConnection)
        : ({
            transport: "sse",
            url: server.sseUrl,
            authProvider: provider,
          } satisfies SSEConnection)
      : ({
          transport: "http",
          url: server.mcpUrl,
          authProvider: provider,
        } satisfies StreamableHTTPConnection);
  const mcp = adapter({ servers: { svc: serverConfig } });
  const error = await failure(mcp.listTools());
  expect(error.cause).toBeInstanceOf(UnauthorizedError);
  expect(provider.redirects).toHaveLength(1);
  const callback = await authorizeInBrowser(provider.redirects[0]);
  return { server, provider, mcp, serverConfig, callback };
}

describe("finishAuth", () => {
  it.each([false, true])(
    "completes a redirect login (persisted discovery: %s)",
    async (persistDiscovery) => {
      const { server, mcp, serverConfig, callback } = await pendingLogin({
        persistDiscovery,
      });
      await finishAuth(serverConfig, callback);
      expect(hasWhoami(await mcp.listTools())).toBe(true);
      expect(server.stats.exchanges).toBe(1);
    }
  );

  it.each(["transport", "type"] as const)(
    "completes the exchange for an SSE server (spelled via %s)",
    async (sseSpelling) => {
      const { server, provider, serverConfig, callback } = await pendingLogin({
        transport: "sse",
        sseSpelling,
      });
      const close = vi.spyOn(SSEClientTransport.prototype, "close");
      try {
        await finishAuth(serverConfig, callback);
        expect(close).toHaveBeenCalledTimes(1);
      } finally {
        close.mockRestore();
      }
      expect(provider.stored.tokens?.access_token).toBeDefined();
      expect(server.stats.exchanges).toBe(1);
    }
  );

  it("rejects a tampered iss before redeeming the code, without echoing callback text", async () => {
    const { server, provider, serverConfig, callback } = await pendingLogin();
    callback.set("iss", "http://attacker.invalid/");
    callback.set("error_description", "attacker-text");
    const error = await failure(finishAuth(serverConfig, callback));
    expect(error.cause).toBeInstanceOf(IssuerMismatchError);
    expect(error.message).toContain(
      "the callback's issuer does not match the authorization server (RFC 9207)"
    );
    expect(error.message).not.toContain("attacker-text");
    expect(error.message).not.toContain("attacker.invalid");
    expect(server.stats.exchanges).toBe(0);
    expect(provider.stored.tokens).toBeUndefined();
  });

  it("gives an authorization-server metadata mismatch its own message", async () => {
    // A "metadata" mismatch concerns the authorization server's own metadata
    // document, not the callback, so it must not reuse the callback message.
    // Synthesized via a spy: the fixture's metadata always matches its URL.
    const { serverConfig, callback } = await pendingLogin();
    const mismatch = new IssuerMismatchError(
      "metadata",
      "https://as.example",
      "https://mismatched.example"
    );
    const spy = vi
      .spyOn(ConnectionManager.prototype, "finishAuth")
      .mockRejectedValueOnce(mismatch);
    try {
      const error = await failure(finishAuth(serverConfig, callback));
      expect(spy.mock.calls[0][0].authProvider).toBe(serverConfig.authProvider);
      expect(error.cause).toBe(mismatch);
      expect(error.message).toContain(
        "the authorization server's metadata issuer does not match the URL it was fetched from (RFC 8414)"
      );
      expect(error.message).not.toContain("callback's issuer");
    } finally {
      spy.mockRestore();
    }
  });

  it("rejects a callback without iss when the server advertises it", async () => {
    const { server, serverConfig, callback } = await pendingLogin({
      iss: "omitted",
    });
    expect(callback.has("iss")).toBe(false);
    const error = await failure(finishAuth(serverConfig, callback));
    expect(error.cause).toBeInstanceOf(IssuerMismatchError);
    expect(error.message).toContain(
      "the callback's issuer does not match the authorization server (RFC 9207)"
    );
    expect(server.stats.exchanges).toBe(0);
  });

  it("accepts a callback without iss when the server does not send it", async () => {
    const { server, serverConfig, callback } = await pendingLogin({
      iss: "unsupported",
    });
    await finishAuth(serverConfig, callback);
    expect(server.stats.exchanges).toBe(1);
  });

  it("surfaces an error= callback as OAuthError", async () => {
    const { serverConfig, callback } = await pendingLogin();
    const denied = new URLSearchParams({
      error: "access_denied",
      error_description: "user declined",
      iss: callback.get("iss") ?? "",
    });
    const error = await failure(finishAuth(serverConfig, denied));
    expect(error.cause).toBeInstanceOf(OAuthError);
    expect(error.message).toContain("access_denied");
    expect(error.message).not.toContain("user declined");
  });

  it("drops error_description/error_uri from an access_denied callback when the server doesn't support iss", async () => {
    const { serverConfig } = await pendingLogin({ iss: "unsupported" });
    const denied = new URLSearchParams({
      error: "access_denied",
      error_description: "you were phished by attacker.invalid",
      error_uri: "https://distinct-uri-marker.example/explain",
    });
    const error = await failure(finishAuth(serverConfig, denied));
    expect(error.cause).toBeInstanceOf(OAuthError);
    expect(error.message).toContain("access_denied");
    expect(error.message).not.toContain("attacker.invalid");
    expect(error.message).not.toContain("phished");
    expect(error.message).not.toContain("distinct-uri-marker");
  });

  it("does not echo a non-allowlisted error code", async () => {
    const { serverConfig } = await pendingLogin({ iss: "unsupported" });
    const code = "evil<script>alert(1)</script>";
    const denied = new URLSearchParams({ error: code });
    const error = await failure(finishAuth(serverConfig, denied));
    expect(error.cause).toBeInstanceOf(OAuthError);
    expect(error.message).not.toContain(code);
  });

  it("does not treat a CRLF-suffixed near-miss as the standard code", async () => {
    const { serverConfig } = await pendingLogin({ iss: "unsupported" });
    const denied = new URLSearchParams({ error: "access_denied\r\nX: y" });
    const error = await failure(finishAuth(serverConfig, denied));
    expect(error.cause).toBeInstanceOf(OAuthError);
    expect(error.message).toContain("an error");
    expect(error.message).not.toContain("access_denied");
  });

  it("keeps an unverifiable error= callback on the generic path", async () => {
    const serverConfig = {
      transport: "http",
      url: "http://127.0.0.1:9/mcp",
      authProvider: createTestOAuthProvider(),
    } satisfies StreamableHTTPConnection;
    const error = await failure(
      finishAuth(serverConfig, new URLSearchParams({ error: "access_denied" }))
    );
    expect(error.cause).toBeInstanceOf(UnauthorizedError);
    expect(error.message).not.toContain("access_denied");
    expect(error.message).toContain("saveDiscoveryState");
  });

  it("reports a failed exchange when the callback carries both code and error", async () => {
    const { serverConfig, callback } = await pendingLogin();
    callback.set("code", "bogus");
    callback.set("error", "access_denied");
    const error = await failure(finishAuth(serverConfig, callback));
    expect(error.cause).toBeInstanceOf(OAuthError);
    expect(error.message).not.toContain("access_denied");
    expect(error.message).toContain("saveDiscoveryState");
  });

  it("rejects a stdio server and a token-only provider", async () => {
    const params = new URLSearchParams({ code: "c" });
    const stdioError = await failure(
      finishAuth(
        { transport: "stdio", command: "node", args: ["-e", ""] } as never,
        params
      )
    );
    expect(stdioError.message).toMatch(
      /^finishAuth requires an HTTP or SSE server; this configuration uses stdio/
    );

    // Anchored: the SDK's own message also names OAuthClientProvider.
    const tokenError = await failure(
      finishAuth(
        {
          transport: "http",
          url: "http://127.0.0.1:9/mcp",
          authProvider: { token: async () => "t" },
        },
        params
      )
    );
    expect(tokenError.message).toMatch(
      /^finishAuth requires an OAuthClientProvider/
    );
  });

  it("rejects an otherwise invalid server configuration", async () => {
    const params = new URLSearchParams({ code: "c" });
    const error = await failure(
      finishAuth({ url: "not a url" } as never, params)
    );
    expect(error.message).toMatch(
      /^finishAuth received an invalid HTTP or SSE server configuration/
    );
    expect(error.cause).toBeInstanceOf(ZodError);
  });

  it.each([
    ["a state mismatch", false],
    ["SDK error text that quotes it", true],
  ])(
    "keeps the server URL's secrets out of %s",
    async (_label, sdkQuotesUrl) => {
      const secretUrl = "https://user:pw@host/mcp/SECRETPATH?api_key=SECRETQ";
      const spy = vi.spyOn(ConnectionManager.prototype, "finishAuth");
      if (sdkQuotesUrl)
        spy.mockRejectedValueOnce(
          new Error(`Protected resource does not match expected ${secretUrl}`)
        );
      try {
        const error = await failure(
          finishAuth(
            { url: secretUrl, authProvider: createTestOAuthProvider() },
            new URLSearchParams({ code: "c", state: "actual" }),
            sdkQuotesUrl ? undefined : { expectedState: "expected" }
          )
        );
        expect(error.message).toContain("https://host");
        for (const secret of ["user:pw", "SECRETPATH", "SECRETQ"])
          expect(error.message).not.toContain(secret);
      } finally {
        spy.mockRestore();
      }
    }
  );

  it("completes a per-user provider's login via finishAuth", async () => {
    const server = await fixture();
    const provider = createTestOAuthProvider();
    const serverConfig = {
      transport: "http",
      url: server.mcpUrl,
      authProvider: { token: async () => "not-valid" },
    } satisfies StreamableHTTPConnection;
    const mcp = adapter({ servers: { svc: serverConfig } });
    await failure(mcp.listToolsets({ authProvider: provider }));
    await finishAuth(
      { ...serverConfig, authProvider: provider },
      await authorizeInBrowser(provider.redirects[0])
    );
    expect(
      hasWhoami((await mcp.listToolsets({ authProvider: provider })).svc)
    ).toBe(true);
  });

  it("sends no MCP request and closes the transport it creates", async () => {
    const { server, serverConfig, callback } = await pendingLogin();
    const before = server.requests.filter(
      (request) => request.path === "/mcp"
    ).length;
    const close = vi.spyOn(StreamableHTTPClientTransport.prototype, "close");
    try {
      await finishAuth(serverConfig, callback);
      expect(close).toHaveBeenCalledTimes(1);
    } finally {
      close.mockRestore();
    }
    expect(
      server.requests.filter((request) => request.path === "/mcp")
    ).toHaveLength(before);
  });

  it("requires URLSearchParams", async () => {
    const { serverConfig, callback } = await pendingLogin();
    await expect(
      finishAuth(
        serverConfig,
        `http://127.0.0.1:9/callback?${callback}` as never
      )
    ).rejects.toThrow(/URLSearchParams/);
  });

  describe("expectedState", () => {
    it("accepts the matching state", async () => {
      const { server, serverConfig, callback } = await pendingLogin({
        state: "s-1",
      });
      expect(callback.get("state")).toBe("s-1");
      await finishAuth(serverConfig, callback, { expectedState: "s-1" });
      expect(server.stats.exchanges).toBe(1);
    });

    it.each([
      ["missing", (params: URLSearchParams) => params.delete("state")],
      ["repeated", (params: URLSearchParams) => params.append("state", "s-1")],
      ["different", (params: URLSearchParams) => params.set("state", "s-2")],
    ])(
      "rejects a %s state before redeeming the code",
      async (_label, mutate) => {
        const { server, serverConfig, callback } = await pendingLogin({
          state: "s-1",
        });
        mutate(callback);
        const error = await failure(
          finishAuth(serverConfig, callback, { expectedState: "s-1" })
        );
        expect(error.message).toMatch(/state/);
        expect(server.stats.exchanges).toBe(0);
      }
    );

    it("defers to the SDK when omitted", async () => {
      const { server, serverConfig, callback } = await pendingLogin({
        state: "s-1",
      });
      callback.set("state", "tampered");
      await finishAuth(serverConfig, callback);
      expect(server.stats.exchanges).toBe(1);
    });

    it("rejects an empty expectedState up front", async () => {
      const { server, serverConfig, callback } = await pendingLogin({
        state: "s-1",
      });
      await expect(
        finishAuth(serverConfig, callback, { expectedState: "" })
      ).rejects.toThrow(/expectedState/);
      expect(server.stats.exchanges).toBe(0);
    });
  });

  it.each([
    [false, true],
    [true, false],
  ])(
    "hints at discovery state when a callback fails (persisted: %s)",
    async (persistDiscovery, hinted) => {
      const { serverConfig, callback } = await pendingLogin({
        persistDiscovery,
      });
      callback.set("code", "bogus");
      const error = await failure(finishAuth(serverConfig, callback));
      expect(error.cause).toBeDefined();
      expect(error.message.includes("saveDiscoveryState")).toBe(hinted);
    }
  );
});

describe("OAuth behavior on SDK 2.1", () => {
  it("lets the provider's token win over a stale configured Authorization after login", async () => {
    const server = await fixture();
    const provider = createTestOAuthProvider();
    const serverConfig = {
      transport: "http",
      url: server.mcpUrl,
      headers: { Authorization: "Bearer stale" },
      authProvider: provider,
    } satisfies StreamableHTTPConnection;
    const mcp = adapter({ servers: { svc: serverConfig } });
    await failure(mcp.listTools());
    await finishAuth(
      serverConfig,
      await authorizeInBrowser(provider.redirects[0])
    );

    expect(hasWhoami(await mcp.listTools())).toBe(true);
    expect(provider.redirects).toHaveLength(1);
    const sent = server.requests
      .filter((request) => request.path === "/mcp")
      .map((request) => request.authorization);
    expect(sent[0]).toBe("Bearer stale");
    expect(sent.at(-1)).toBe(`Bearer ${provider.stored.tokens?.access_token}`);
  });

  it("gives a per-call provider precedence over a configured Authorization", async () => {
    const server = await fixture();
    const token = server.mintAccessToken();
    const mcp = adapter({
      servers: {
        svc: {
          transport: "http",
          url: server.mcpUrl,
          headers: { Authorization: "Bearer stale" },
        },
      },
    });
    await mcp.listToolsets({ authProvider: { token: async () => token } });
    const sent = server.requests
      .filter((request) => request.path === "/mcp")
      .map((request) => request.authorization);
    expect(new Set(sent)).toEqual(new Set([`Bearer ${token}`]));
  });

  it("refreshes an expired access token without a new redirect", async () => {
    const { server, provider, mcp, serverConfig, callback } =
      await pendingLogin();
    await finishAuth(serverConfig, callback);
    const [tool] = (await mcp.listTools()).filter((t) =>
      t.name.endsWith("whoami")
    );

    server.expireAccessTokens();
    expect(JSON.stringify(await tool.invoke({}))).toContain("authorized");
    expect(server.stats.refreshes).toBe(1);
    expect(provider.redirects).toHaveLength(1);
  });

  it("keeps one connection per per-call provider", async () => {
    const server = await fixture();
    const [a, b] = [server.mintAccessToken(), server.mintAccessToken()];
    const providerA = { token: async () => a };
    const providerB = { token: async () => b };
    const mcp = adapter({
      servers: { svc: { transport: "http", url: server.mcpUrl } },
    });
    await mcp.listToolsets({ authProvider: providerA });
    await mcp.listToolsets({ authProvider: providerB });
    const sent = new Set(
      server.requests
        .filter((request) => request.path === "/mcp")
        .map((request) => request.authorization)
    );
    expect(sent).toEqual(new Set([`Bearer ${a}`, `Bearer ${b}`]));

    const clientA = await mcp.getClient("svc", { authProvider: providerA });
    const clientB = await mcp.getClient("svc", { authProvider: providerB });
    expect(clientA).toBeDefined();
    expect(clientB).toBeDefined();
    expect(clientA).not.toBe(clientB);
  });

  it("keeps the last spelling when one config repeats Authorization", async () => {
    const server = await fixture();
    await failure(
      adapter({
        servers: {
          svc: {
            transport: "http",
            url: server.mcpUrl,
            headers: { authorization: "Bearer a", Authorization: "Bearer b" },
          },
        },
      }).listTools()
    );
    expect(
      server.requests.find((request) => request.path === "/mcp")?.authorization
    ).toBe("Bearer b");
  });

  it("keeps the last spelling on the finishAuth leg too", async () => {
    const server = await fixture();
    const provider = createTestOAuthProvider();
    const serverConfig = {
      transport: "http",
      url: server.mcpUrl,
      headers: { authorization: "Bearer a", Authorization: "Bearer b" },
      authProvider: provider,
    } satisfies StreamableHTTPConnection;
    const mcp = adapter({ servers: { svc: serverConfig } });
    await failure(mcp.listTools());

    // Visible only because the SDK forwards configured headers to the
    // authorization server too; if that stops, the recorded set empties.
    const before = server.requests.length;
    await finishAuth(
      serverConfig,
      await authorizeInBrowser(provider.redirects[0])
    );
    const finishAuthSpellings = new Set(
      server.requests
        .slice(before)
        .map((request) => request.authorization)
        .filter((value) => value !== undefined)
    );
    expect(finishAuthSpellings).toEqual(new Set(["Bearer b"]));
  });

  // Upstream #2510: the SDK cannot complete a mid-session redirect itself. A
  // stateless finishAuth lets the live connection pick up the new tokens.
  it("characterization: a login that lapses mid-session completes through finishAuth", async () => {
    const { server, provider, mcp, serverConfig, callback } =
      await pendingLogin();
    await finishAuth(serverConfig, callback);
    const [tool] = (await mcp.listTools()).filter((t) =>
      t.name.endsWith("whoami")
    );

    server.revokeAll();
    await expect(tool.invoke({})).rejects.toThrow(/UnauthorizedError/);
    expect(provider.redirects).toHaveLength(2);

    await finishAuth(
      serverConfig,
      await authorizeInBrowser(provider.redirects[1])
    );
    expect(JSON.stringify(await tool.invoke({}))).toContain("authorized");
  });

  // Documented limitation (§4.5): rediscovering while a login is pending
  // starts a second redirect and replaces the PKCE verifier.
  it("characterization: rediscovering during a pending login invalidates the first callback", async () => {
    const { server, provider, mcp, serverConfig, callback } =
      await pendingLogin();
    await failure(mcp.listTools());
    expect(provider.redirects).toHaveLength(2);

    await failure(finishAuth(serverConfig, callback));
    expect(server.stats.exchanges).toBe(0);
  });

  // The SDK's auth() treats invalid_grant on the code leg the same as a
  // rejected refresh and invalidates stored tokens, so a replayed callback
  // logs the user out right after a successful login. Applications must
  // make the callback single-use themselves; see the README.
  it("characterization: replaying a used callback rejects and discards the stored tokens", async () => {
    const { provider, mcp, serverConfig, callback } = await pendingLogin();
    await finishAuth(serverConfig, callback);
    expect(provider.stored.tokens).toBeDefined();

    await failure(finishAuth(serverConfig, callback));
    expect(provider.stored.tokens).toBeUndefined();

    const redirectsBefore = provider.redirects.length;
    await failure(mcp.listTools());
    expect(provider.redirects).toHaveLength(redirectsBefore + 1);
  });

  // SSE's connect path retries after every onUnauthorized with no cap, so only
  // a throwing handler ends it; the README tells token providers to throw.
  it("characterization: over SSE, onUnauthorized runs on every rejected reconnect", async () => {
    const server = await fixture();
    let calls = 0;
    const mcp = adapter({
      servers: {
        svc: {
          transport: "sse",
          url: server.sseUrl,
          authProvider: {
            token: async () => "bad",
            onUnauthorized: async () => {
              calls += 1;
              if (calls === 3) throw new Error("no newer token");
            },
          },
        },
      },
    });
    await failure(mcp.listTools());
    expect(calls).toBe(3);
  });
});
