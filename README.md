# **Aegis** – Storage-Agnostic, Post-Quantum Cryptography (PQC) Ready E2E Encryption Library

**Aegis** is a lightweight, storage-agnostic library for client-side End-to-End (E2E) encryption, designed for future security. It combines the NIST-standardized ML-KEM 768 algorithm for quantum-resistant key agreement with high-performance symmetric cryptography (ChaCha20-Poly1305, Blake3) to provide secure 1:1 sessions and scalable group messaging.

---
## **Core Features**

- **Post-Quantum Ready**: Uses **ML-KEM 768 (formerly Kyber)** for initial key encapsulation, aligning with NIST standards.
- **Storage-Agnostic**: You provide a simple key-value storage adapter (e.g., AsyncStorage, LocalStorage, SQLite).
- **Modern Cryptography**: Symmetric ratchets for forward secrecy and Sender Keys for O(1) group encryption.
- **Minimal Dependencies**: Relies on robust, well-audited libraries like `@noble/curves` and `@noble/hashes`.

---
## **Installation**

Install the library using npm or yarn.
```bash
npm install @immahq/aegis
# or
yarn add @immahq/aegis
```

---
## **Quick Start**

### **1. Implement a Storage Adapter**
Aegis requires a minimal async storage adapter to persist keys and session state.
```typescript
import { StorageAdapter } from '@immahq/aegis';

const myStorage: StorageAdapter = {
  async setItem(key: string, value: string) { /* Save to secure storage */ },
  async getItem(key: string): Promise<string | null> { /* Retrieve from storage */ },
  async removeItem(key: string) { /* Delete from storage */ },
};

// Initialize the library before any other operation
import { Aegis } from '@immahq/aegis';
Aegis.init({ storage: myStorage });
```
> **Security Note**: The adapter will store secret key material. In production, always use platform-secured storage (e.g., iOS Keychain, Android Keystore, or a securely encrypted database).

### **2. Create a User Identity**
A user identity consists of a post-quantum KEM key pair, a signing key pair, and pre-keys for session establishment.
```typescript
import { createIdentity } from '@immahq/aegis';

// This creates and automatically saves the identity to your storage
const myIdentity = await createIdentity(
  "alice_user_id",
  "email",
  "alice@example.com"
);
```

### **3. Establish a 1:1 Encrypted Session**
#### **Initiator (Alice)**
```typescript
import { initializeSession } from '@immahq/aegis';

// 1. Fetch recipient's public bundle from your server
const bobBundle = await getPublicKeyBundle(); // { identityKey, signedPreKey, oneTimePreKey?, userId }

// 2. Initialize a session. This performs the ML-KEM key encapsulation.
const initData = await initializeSession("session_alice_bob", bobBundle);

// 3. Send `initData.ciphertexts` to Bob via your server
```

#### **Recipient (Bob)**
```typescript
import { acceptSession } from '@immahq/aegis';
import { loadIdentity } from '@immahq/aegis';

// 1. Load local identity to access secret keys
const bobIdentity = await loadIdentity();
if (!bobIdentity) throw new Error("Identity not found");

// 2. Accept the session using the received ciphertexts and secret keys
await acceptSession("session_alice_bob", initData.ciphertexts, {
  identitySecret: bobIdentity.kem.secretKey,
  signedPreKeySecret: bobIdentity.signedPreKey!.keyPair.secretKey,
  // Include if an OTPK was used:
  oneTimePreKeySecret: bobIdentity.oneTimePreKeys.find(k => k.id === bobBundle.oneTimePreKey!.id)?.keyPair.secretKey,
});
```

### **4. Exchange Messages**
#### **Encrypt a Message**
```typescript
import { encryptMessage } from '@immahq/aegis';

const encryptedMessage = await encryptMessage(
  "session_alice_bob",
  "Hello, Bob! This is a secret."
);
// encryptedMessage = { sessionId, ciphertext, nonce, messageNumber, timestamp, ... }
```

#### **Decrypt a Message**
```typescript
import { decryptMessage } from '@immahq/aegis';

// Assume `receivedMsg` is the object received over the network
const plaintext = await decryptMessage(receivedMsg);
console.log(plaintext); // "Hello, Bob! This is a secret."
```

### **5. Group Messaging with Sender Keys**
Aegis uses the Sender Key protocol for efficient group messaging, where each member encrypts a message once for the entire group.

#### **Create a Group and Distribute Keys**
```typescript
import { getGroupSession } from '@immahq/aegis';

// Alice creates/loads a group session
const aliceGroup = await getGroupSession("family_chat_2025");

// Create a distribution message for Bob
const distMsgForBob = aliceGroup.createDistributionMessage("alice_user_id");

// CRITICAL: Send `distMsgForBob` to Bob via your existing SECURE 1:1 session.
// e.g., await encryptMessage("session_alice_bob", JSON.stringify(distMsgForBob));
```

#### **Process a Received Distribution Message**
```typescript
// Bob loads the same group session
const bobGroup = await getGroupSession("family_chat_2025");

// First, decrypt the 1:1 message from Alice to get the distribution payload
// const distributionPayload = JSON.parse(await decryptMessage(encryptedDistMsg));

// Then, process it to store Alice's sender key
await bobGroup.processDistributionMessage(distributionPayload);
```

#### **Broadcast and Decrypt Group Messages**
```typescript
// Alice encrypts a message for the entire group (O(1) operation)
const groupCiphertext = await aliceGroup.encrypt("Dinner at 8 PM!", "alice_user_id");

// Send `groupCiphertext` to all group members via your server

// Bob decrypts the group message using the stored sender key
const groupPlaintext = await bobGroup.decrypt(groupCiphertext);
console.log(groupPlaintext); // "Dinner at 8 PM!"
```

---
## **API Reference**

### **Core & Configuration**
- **`Aegis.init(config: { storage: StorageAdapter })`**: Initializes the library. Must be called first.
- **`Aegis.getStorage(): StorageAdapter`**: Returns the configured storage adapter.

### **Identity Management**
- **`createIdentity(userId, authMethod, identifier): Promise<UserIdentity>`**
- **`loadIdentity(): Promise<UserIdentity | null>`**
- **`saveIdentity(identity): Promise<void>`**
- **`deleteIdentity(): Promise<void>`**
- **`exportIdentity(password): Promise<string>`**
- **`importIdentity(backupData, password): Promise<UserIdentity>`**
- **`getPublicKeyBundle()`**: Returns `{ identityKey, signedPreKey, oneTimePreKey?, userId, sigPublicKey }`
- **`getAndConsumePublicKeyBundle()`**: Returns a bundle and removes the used OTPK from storage.

### **1:1 Sessions**
- **`initializeSession(sessionId, recipientBundle): Promise<SessionInitData>`**
- **`acceptSession(sessionId, ciphertexts, secretKeys): Promise<void>`**
- **`encryptMessage(sessionId, plaintext): Promise<EncryptedMessage>`**
- **`decryptMessage(encryptedMsg): Promise<string>`**
- **`deleteSession(sessionId): Promise<void>`**
- **`getSessionInfo(sessionId): Promise<{createdAt, lastUsed, messagesSent} | null>`**

### **Group Sessions**
- **`getGroupSession(groupId): Promise<GroupSession>`**
  - **`GroupSession.createDistributionMessage(senderId): SenderKeyDistributionMessage`**
  - **`GroupSession.processDistributionMessage(payload): Promise<void>`**
  - **`GroupSession.encrypt(plaintext, senderId): Promise<SenderKeyMessage>`**
  - **`GroupSession.decrypt(msg): Promise<string>`**

---
## **Testing and Examples**

- **Run Tests**: `npm test`
- **Run Sample Flow**: `npm run sample`
  - This executes `examples/usage.ts`, demonstrating a complete flow: identity creation, session handshake, 1:1 messaging, and group setup.

---
## **Security Model & Best Practices**

### **Cryptographic Foundation**
Aegis is built on a hybrid model:
1.  **Key Agreement**: **ML-KEM 768 (Kyber)** provides quantum-resistant key encapsulation. This algorithm is now a finalized NIST standard (FIPS 203).
2.  **Data Encryption**: **ChaCha20-Poly1305** is used for fast, authenticated encryption of message contents.
3.  **Key Derivation & Hashing**: **Blake3** is used for key derivation and hashing, providing high speed and security.

### **Critical Implementation Notes**
⚠️ **These points are essential for production security:**
- **Signed Pre-Key Signatures**: The library includes a signature field for signed pre-keys, but **signature verification during session initialization must be implemented by the application** until a future library version provides it.
- **One-Time Pre-Keys (OTPKs)**: The `getPublicKeyBundle()` function returns an OTPK. Your server **must** track used OTPKs and ensure they are never reused. Use `getAndConsumePublicKeyBundle()` as a reference for client-side management.
- **Identity Backups**: The `exportIdentity()` function now uses a **memory-hard scrypt Key Derivation Function (KDF)** followed by ChaCha20-Poly1305 encryption. Ensure backups are stored securely.
- **Concurrency**: Operations for a single session are serialized. If your application uses multiple processes/workers that might access the same session, you must implement cross-process locking for the storage adapter.
- **Storage Security**: The storage adapter you provide holds all secret keys. **You are responsible for its security.** Use platform-backed secure storage.

---
## **Contributing & Roadmap**

We welcome contributions. Priority areas include:
- Full implementation of signed pre-key verification.
- Utilities for server-side OTPK lifecycle management.
- Enhanced examples for cross-platform secure storage.

---
## **License**

MIT
