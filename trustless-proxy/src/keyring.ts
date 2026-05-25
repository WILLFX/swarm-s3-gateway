import { RecipientEnvelopeContext } from "./types.js";

/**
 * Placeholder boundary for the custom aws-esdk keyring.
 *
 * The implementation must wrap aws-esdk data keys to recipient public encryption keys
 * fetched from the identity contract. It must never send plaintext data keys or the
 * local private encryption key to the remote gateway.
 */
export interface TrustlessRecipientKeyring {
  readonly keyringName: "trustless-recipient-keyring";

  encryptWithRecipientEnvelopes(
    plaintext: Uint8Array,
    context: RecipientEnvelopeContext
  ): Promise<Uint8Array>;

  decryptWithLocalRecipientKey(
    ciphertext: Uint8Array,
    context: RecipientEnvelopeContext
  ): Promise<Uint8Array>;
}

export function createUnimplementedTrustlessRecipientKeyring(): TrustlessRecipientKeyring {
  return {
    keyringName: "trustless-recipient-keyring",

    async encryptWithRecipientEnvelopes(): Promise<Uint8Array> {
      throw new Error("trustless recipient aws-esdk keyring encryption is not implemented yet");
    },

    async decryptWithLocalRecipientKey(): Promise<Uint8Array> {
      throw new Error("trustless recipient aws-esdk keyring decryption is not implemented yet");
    }
  };
}
