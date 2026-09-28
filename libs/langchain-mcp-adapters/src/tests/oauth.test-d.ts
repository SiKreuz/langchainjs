import { expectTypeOf, test } from "vitest";
import {
  MCPAdapter,
  UnauthorizedError,
  type AuthProvider,
  type FinishAuthOptions,
  type OAuthClientProvider,
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

test("finishAuth takes the callback query and optional FinishAuthOptions", () => {
  expectTypeOf<MCPAdapter["finishAuth"]>()
    .parameter(1)
    .toEqualTypeOf<URLSearchParams>();
  expectTypeOf<MCPAdapter["finishAuth"]>().returns.toEqualTypeOf<
    Promise<void>
  >();
  expectTypeOf<FinishAuthOptions>().toExtend<{
    authProvider?: OAuthClientProvider;
    expectedState?: string;
  }>();
});

test("finishAuth rejects a non-URLSearchParams callback and a token-only authProvider", () => {
  const mcp = new MCPAdapter({
    servers: { a: { transport: "http", url: "http://127.0.0.1/mcp" } },
  });

  // @ts-expect-error finishAuth's callback query must be URLSearchParams, not a string.
  mcp.finishAuth("a", "http://127.0.0.1/callback?code=1");

  // @ts-expect-error a token-only AuthProvider is not an OAuthClientProvider.
  const bad: FinishAuthOptions["authProvider"] = { token: async () => "x" };
  mcp.finishAuth("a", new URLSearchParams(), { authProvider: bad });
  expectTypeOf(bad).toEqualTypeOf<FinishAuthOptions["authProvider"]>();
});

test("UnauthorizedError is the exported auth check", () => {
  expectTypeOf(UnauthorizedError.isInstance).toBeFunction();
});
