import { TrustlessProxyConfig } from "./types.js";

const DEFAULT_LISTEN_HOST = "127.0.0.1";
const DEFAULT_LISTEN_PORT = 9090;

function parsePort(value: string | undefined): number {
  if (!value || !value.trim()) {
    return DEFAULT_LISTEN_PORT;
  }

  const port = Number.parseInt(value, 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error("TRUSTLESS_PROXY_LISTEN_PORT must be an integer from 1 to 65535");
  }

  return port;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): TrustlessProxyConfig {
  return {
    listenHost: env.TRUSTLESS_PROXY_LISTEN_HOST?.trim() || DEFAULT_LISTEN_HOST,
    listenPort: parsePort(env.TRUSTLESS_PROXY_LISTEN_PORT),
    remoteGatewayUrl: requiredEnvFrom(env, "TRUSTLESS_PROXY_REMOTE_GATEWAY_URL"),
    chainRpcUrl: requiredEnvFrom(env, "TRUSTLESS_PROXY_CHAIN_RPC_URL"),
    localAccount: requiredEnvFrom(env, "TRUSTLESS_PROXY_LOCAL_ACCOUNT"),
    keystorePath: requiredEnvFrom(env, "TRUSTLESS_PROXY_KEYSTORE_PATH")
  };
}

function requiredEnvFrom(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) {
    throw new Error(`missing required environment variable: ${name}`);
  }

  return value;
}
