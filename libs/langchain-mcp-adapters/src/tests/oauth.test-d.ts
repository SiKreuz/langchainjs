import { expectTypeOf, test } from "vitest";
import {
  MCPAdapter,
  UnauthorizedError,
  finishAuth,
  type AuthProvider,
  type FinishAuthOptions,
  type SSEConnection,
  type StreamableHTTPConnection,
} from "../index.js";

test("authProvider accepts both SDK provider shapes", () => {
  expectTypeOf<{
    token: () => Promise<string>;
  }>().toExtend<AuthProvider>();

  new MCPAdapter({
    servers: {
      a: {
        transport: "http",
        url: "http://127.0.0.1/mcp",
        authProvider: { token: async () => "t" },
      },
    },
  });
});

test("finishAuth takes a server config, the callback query, and optional FinishAuthOptions", () => {
  expectTypeOf<Parameters<typeof finishAuth>[0]>().toEqualTypeOf<
    StreamableHTTPConnection | SSEConnection
  >();
  expectTypeOf<
    Parameters<typeof finishAuth>[1]
  >().toEqualTypeOf<URLSearchParams>();
  expectTypeOf<typeof finishAuth>().returns.toEqualTypeOf<Promise<void>>();
  expectTypeOf<FinishAuthOptions>().toEqualTypeOf<{
    expectedState?: string;
  }>();

  const server = { transport: "http", url: "http://127.0.0.1/mcp" } as const;
  // @ts-expect-error finishAuth's callback query must be URLSearchParams, not a string.
  finishAuth(server, "http://127.0.0.1/callback?code=1");
});

test("UnauthorizedError is the exported auth check", () => {
  expectTypeOf(UnauthorizedError.isInstance).toBeFunction();
});
