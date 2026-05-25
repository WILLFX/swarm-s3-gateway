export type Hex32 = string;
export type SubstrateAccountId = string;

export type TrustlessBucketType = "trustless-private";

export interface TrustlessProxyConfig {
  readonly listenHost: string;
  readonly listenPort: number;
  readonly remoteGatewayUrl: string;
  readonly chainRpcUrl: string;
  readonly localAccount: SubstrateAccountId;
  readonly keystorePath: string;
}

export interface RecipientEncryptionKey {
  readonly account: SubstrateAccountId;
  readonly publicKey: string;
  readonly keyType: string;
  readonly keyVersion: number;
  readonly enabled: boolean;
}

export interface RecipientEnvelopeContext {
  readonly bucketId: Hex32;
  readonly objectKeyId: Hex32;
  readonly policyVersion: number;
  readonly recipients: readonly RecipientEncryptionKey[];
}

export interface TrustlessPutPlan {
  readonly bucket: string;
  readonly key: string;
  readonly bucketType: TrustlessBucketType;
  readonly ciphertextOnly: true;
  readonly envelopeContext: RecipientEnvelopeContext;
}

export interface TrustlessGetPlan {
  readonly bucket: string;
  readonly key: string;
  readonly bucketType: TrustlessBucketType;
  readonly decryptLocally: true;
}
