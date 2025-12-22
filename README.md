# Aegis

**Aegis** is a storage-agnostic, Post-Quantum Cryptography (PQC) ready End-to-End (E2E) encryption library.

It combines ML-KEM (Kyber-like KEM) for key agreement and modern symmetric primitives (ChaCha20-Poly1305, Blake3) to provide secure 1:1 sessions and scalable client-side group encryption.

This README gives an overview, a compact API reference, and clear sample usage for common flows.

---

## Features

- Storage-agnostic: you supply the storage adapter (AsyncStorage, LocalStorage, SQLite, in-memory, etc.).
- Post-quantum KEM for initial key agreement (ML-KEM 768).
- Symmetric ratchets for forward secrecy (ChaCha20-Poly1305 + Blake3).
- Sender-key based group messaging for O(1) broadcast encryption.
- Minimal runtime dependencies.

---

## Installation

```/dev/null/install.md#L1-6
# Using npm
npm install @immahq/aegis

# or with yarn
yarn add @immahq/aegis
```

---

## Quick Start (essential flows)

### 1) Implement a Storage Adapter

Aegis requires a minimal async key-value storage adapter:

```/dev/null/storage.example.ts#L1-14
// StorageAdapter
const myStorage: StorageAdapter = {
  async setItem(key: string, value: string) {
    await db.save(key, value);
  },
  async getItem(key: string) {
    return await db.get(key);
  },
  async removeItem(key: string) {
    await db.delete(key);
  },
};

Aegis.init({ storage: myStorage });
```

> Security note: The adapter will persist secret material (e.g., private keys and chain keys). In production use secure storage (Keychain, Keystore, secure enclave).

---

### 2) Identity (PQC keys & pre-keys)

```/dev/null/identity.example.ts#L1-12
// Create and persist an identity (KEM + signature keys + prekeys)
const myIdentity = await createIdentity("alice_user_id", "email", "alice@example.com");
// Identity is persisted to your StorageAdapter
```

You can export/import a backup bundle:

```/dev/null/identity-backup.example.ts#L1-8
const backup = await exportIdentity("strong-password");
// Later...
const restored = await importIdentity(backup, "strong-password");
```

> Note: `exportIdentity()` now returns a password-encrypted backup (base64-encoded JSON envelope with fields `salt`, `nonce`, and `ciphertext`) using a Blake3-based KDF + ChaCha20-Poly1305. For production use, prefer a slow, memory-hard KDF such as Argon2 or scrypt and ensure backup integrity before restoring.
 
Server note: If you manage One-Time PreKeys on the server, use `getAndConsumePublicKeyBundle()` to hand out a bundle while marking the OTPK as consumed so it cannot be reused. The `getPublicKeyBundle()` response also includes the identity signing key as `sigPublicKey`, which can be used to verify Signed PreKey signatures.

---

### 3) Establish a 1:1 Session (Initiator / Recipient)

Initiator (Alice):

```/dev/null/session-init.example.ts#L1-12
// Alice fetches Bob's public bundle from your server
const bobBundle = await getPublicKeyBundle(); // { identityKey, signedPreKey, oneTimePreKey?, userId }
const initData = await initializeSession("session_alice_bob", bobBundle);
// send initData.ciphertexts to Bob via your server
```

Recipient (Bob):

```/dev/null/session-accept.example.ts#L1-12
// Bob receives ciphertexts; he uses his private keys to accept session
await acceptSession("session_alice_bob", initData.ciphertexts, {
  identitySecret: bobIdentity.kem.secretKey,
  signedPreKeySecret: bobIdentity.signedPreKey!.keyPair.secretKey,
  oneTimePreKeySecret: bobIdentity.oneTimePreKeys.find(k => k.id === bobBundle.oneTimePreKey!.id)?.keyPair.secretKey, // optional
});
```

---

### 4) Encrypt & Decrypt Messages

```/dev/null/messages.example.ts#L1-12
// Alice
const encrypted = await encryptMessage("session_alice_bob", "Hello Bob!");

// Bob receives
const plaintext = await decryptMessage(encrypted);
```

- `encryptMessage` returns an object `{ sessionId, ciphertext, nonce, messageNumber, timestamp }`.
- `decryptMessage` expects that object and returns the plaintext string.

---

### 5) Group Messaging (Sender Keys)

- Each group member has a `SenderKey` (chain key).
- The sender privately distributes a `SenderKeyDistributionMessage` to group members (via 1:1 session). Members store the chain key and can O(1) decrypt sender broadcasts.

Example flow:

```/dev/null/group.example.ts#L1-24
// Alice creates/loads group
const aliceGroup = await getGroupSession("group_chat");

// Alice creates a distribution message and sends it to Bob (via secure 1:1)
const distMsg = aliceGroup.createDistributionMessage("alice_user_id");
// Alice encrypts distMsg using 1:1 session to Bob and sends it

// Bob receives and processes the distribution message (after decrypting the 1:1 transport)
const bobGroup = await getGroupSession("group_chat");
await bobGroup.processDistributionMessage(decodedDistMsg);

// Alice broadcasts to group (one encryption)
const groupCipher = await aliceGroup.encrypt("Hello Group!", "alice_user_id");

// Bob decrypts
const plaintext = await bobGroup.decrypt(groupCipher);
```

---

## API Reference

High-level exported functions:

- `Aegis.init({ storage: StorageAdapter })` — initialize with your storage adapter.
- `Aegis.getStorage()` — access the configured storage adapter.

Identity management:

- `createIdentity(userId, authMethod, identifier): Promise<UserIdentity>`
- `loadIdentity(): Promise<UserIdentity | null>`
- `saveIdentity(identity): Promise<void>`
- `deleteIdentity(): Promise<void>`
- `exportIdentity(password): Promise<string>`
- `importIdentity(backupData, password): Promise<UserIdentity>`
- `getPublicKeyBundle(): Promise<{ identityKey, signedPreKey, oneTimePreKey?, userId }>` — used by initiators to form session handshakes.

Session (1:1):

- `initializeSession(sessionId, recipientBundle): Promise<{ sessionId, ciphertexts }>`
- `acceptSession(sessionId, ciphertexts, keys): Promise<void>`
- `encryptMessage(sessionId, plaintext): Promise<EncryptedMessage>`
- `decryptMessage(encryptedMsg): Promise<string>`
- `getSessionInfo(sessionId): Promise<{createdAt, lastUsed, messagesSent} | null>`
- `deleteSession(sessionId): Promise<void>`

Group:

- `getGroupSession(groupId): Promise<GroupSession>`
  - `GroupSession.createDistributionMessage(senderId)`
  - `GroupSession.processDistributionMessage(payload)`
  - `GroupSession.encrypt(plaintext, myUserId)`
  - `GroupSession.decrypt(senderKeyMessage)`

Types:
- `StorageAdapter` - `{ setItem(key,value):Promise<void>, getItem(key):Promise<string|null>, removeItem(key):Promise<void> }`
- `UserIdentity`, `PQKeyPair`, `SenderKeyMessage`, etc. are exported in the package typings.

---

## Testing, Example & Scripts

- Run tests:
```/dev/null/test-run.md#L1-2
npm test
```

- Run the sample usage (demo):
```/dev/null/sample-run.md#L1-2
npm run sample
```
The `examples/usage.ts` demonstrates the full flow (identity creation, session handshake, 1:1 messaging, group distribution). See `examples/usage.ts` for a working reference.

---

## Practical Notes & Current Limitations

- Signed pre-key signatures: currently the signed-pre-key "signature" is a placeholder; **signature verification is not fully implemented**. Do not rely on this for authenticating key bundles in production until signature verification is implemented.
- One-Time Pre-Keys (OTPKs) are returned by `getPublicKeyBundle()`. In production deployments, the server should ensure an OTPK, once used, is marked as consumed so it cannot be reused.
- `exportIdentity()` returns a base64 JSON bundle (not encrypted) in the current version — this **must be replaced** with password-based encryption (e.g., Argon2 + ChaCha20-Poly1305) before using backups in production.
- Concurrency: encryption/decryption in a single process are serialized per-session to avoid state races. If your app uses multiple processes/instances that may mutate the same session state, you must implement a cross-process lock.
- The symmetric ratchet implemented is a hash-based ratchet derived from shared secrets (it provides forward secrecy for message sequences). It is not a full Signal-style Double Ratchet (no periodic Diffie-Hellman ratchet in this version).

---

## Security & Threat Model

- Aegis focuses on client-side E2E. Server responsibilities include safe distribution of public bundles and one-time pre-key consumption.
- Use secure persistent storage (Keychain, Keystore), TLS for server APIs, and strong password-based encryption for any identity backups.
- Before production use, audit cryptography choices and perform a security review (this project aims to be a foundation, not a complete audited product).

---

## Contribution & Roadmap

- Contributions are welcome — open issues/PRs for:
  - Proper signature generation and verification for signed pre-keys
  - Secure identity export/import with proper cryptography
  - Full Double Ratchet implementation (DH ratchet)
  - OTPK lifecycle management utilities and server-side example
  - Cross-process locking for session state/storage

---

## License

MIT

---
