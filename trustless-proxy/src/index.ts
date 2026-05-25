import { loadConfig } from "./config.js";
import { createUnimplementedTrustlessRecipientKeyring } from "./keyring.js";

export async function main(): Promise<void> {
  const config = loadConfig();
  const keyring = createUnimplementedTrustlessRecipientKeyring();

  console.log(
    JSON.stringify({
      component: "trustless-local-proxy",
      status: "scaffolded",
      listenHost: config.listenHost,
      listenPort: config.listenPort,
      remoteGatewayUrl: config.remoteGatewayUrl,
      chainRpcUrl: config.chainRpcUrl,
      localAccount: config.localAccount,
      keystorePath: config.keystorePath,
      keyringName: keyring.keyringName
    })
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  });
}

export * from "./config.js";
export * from "./keyring.js";
export * from "./types.js";
