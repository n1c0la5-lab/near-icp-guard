// Checks a signed transaction from the guard before it goes to NEAR.
//
// `preview_transfer` is a query: one replica answers it, so its bytes are only
// a hint. What counts is the signed transaction in the *update* response of
// `sign_transfer`. This module checks exactly those bytes:
//   1. the unsigned part equals what NEAR's own library (@near-js/transactions)
//      builds for the same input, byte for byte;
//   2. it is followed by exactly one ed25519 signature (type 0 + 64 bytes);
//   3. that signature verifies against the canister's public key over
//      sha256(unsigned) — what NEAR checks;
//   4. the returned tx hash is base58(sha256(unsigned)).
// Any mismatch throws.

import { createHash, createPublicKey, verify } from "node:crypto";
import { actionCreators, createTransaction, encodeTransaction } from "@near-js/transactions";
import { PublicKey } from "@near-js/crypto";
import bs58 from "bs58";

// DER prefix of an ed25519 SubjectPublicKeyInfo; the 32 raw key bytes follow.
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

/** Unsigned transaction bytes as @near-js/transactions builds them. */
export function referenceBytes({ accountId, publicKey, receiver, nonce, yocto, blockHash }) {
  return Buffer.from(
    encodeTransaction(
      createTransaction(
        accountId,
        PublicKey.fromString(publicKey),
        receiver,
        BigInt(nonce),
        [actionCreators.transfer(BigInt(yocto))],
        bs58.decode(blockHash),
      ),
    ),
  );
}

/** Throws unless `signedTxBase64` is `reference` + a valid signature by `publicKey`. */
export function verifySigned({ signedTxBase64, reference, publicKey, txHash }) {
  const signed = Buffer.from(signedTxBase64, "base64");
  if (signed.toString("base64") !== signedTxBase64) throw new Error("signed_tx_base64 is not canonical base64");
  if (signed.length !== reference.length + 65) {
    throw new Error(`signed tx has ${signed.length} bytes, expected ${reference.length} + 65`);
  }
  const unsigned = signed.subarray(0, reference.length);
  if (!unsigned.equals(reference)) {
    throw new Error(`signed tx differs from @near-js/transactions\n signed:  ${unsigned.toString("hex")}\n near-js: ${reference.toString("hex")}`);
  }
  if (signed[reference.length] !== 0) throw new Error("signature type is not ed25519");
  const signature = signed.subarray(reference.length + 1);
  const hash = createHash("sha256").update(unsigned).digest();
  const key = createPublicKey({
    key: Buffer.concat([SPKI_ED25519, Buffer.from(PublicKey.fromString(publicKey).data)]),
    format: "der",
    type: "spki",
  });
  if (!verify(null, hash, key, signature)) throw new Error("signature does not verify over sha256(unsigned tx)");
  if (txHash !== bs58.encode(hash)) throw new Error(`tx_hash ${txHash} is not base58(sha256(unsigned tx))`);
}
