# **Aegis** 
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/68e739263f9740b3be6693e795d17d0a)](https://app.codacy.com/gh/imma-hq/aegis/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)![git workflow](https://github.com/imma-hq/aegis/actions/workflows/ci.yml/badge.svg?branch=main)
![NPM Version](https://img.shields.io/npm/v/@immahq/aegis)

**Aegis** is a lightweight, storage-agnostic library for client-side End-to-End (E2E) encryption, designed for future security. It combines the NIST-standardized ML-KEM 768 algorithm for quantum-resistant key agreement with high-performance symmetric cryptography (ChaCha20-Poly1305, Blake3) to provide secure 1:1 sessions and scalable group messaging.

---


## **Core Features**

- **Post-Quantum Ready**: Uses **ML-KEM 768** for initial key encapsulation, aligning with NIST standards.
- **Storage-Agnostic**: You provide a simple key-value storage adapter (e.g., AsyncStorage, LocalStorage, SQLite, SecureStore).
- **Modern Cryptography**: Symmetric ratchets for forward secrecy and Sender Keys for O(1) group encryption.
- **Enhanced Security**: Implements proper group key encryption, pre-key signature verification, and secure group membership protocols.
- **Minimal Dependencies**: Relies on robust, well-audited libraries like `@noble/curves` and `@noble/hashes`.

---

## **Installation**

Install the library using npm, yarn, or pnpm.

```bash
npm install @immahq/aegis
# or
yarn add @immahq/aegis
```
For React Native, you may need a
[polyfill for getRandomValues](https://github.com/LinusU/react-native-get-random-values).

---

## **Quick Start**

### **1. Implement a Storage Adapter**

Aegis requires a minimal async storage adapter to persist keys and session state.

```typescript
import { StorageAdapter, Identity, Session } from "@immahq/aegis";

const myStorage: StorageAdapter = {
  async saveIdentity(identity: Identity) {
    /* Save to secure storage (e.g., JSON.stringify(identity)) */
  },
  async getIdentity(): Promise<Identity | null> {
    /* Retrieve and parse from storage */
    return null;
  },
  async deleteIdentity() {
    /* Delete from storage */
  },
  async saveSession(sessionId: string, session: Session) {
    /* Save session state */
  },
  async getSession(sessionId: string): Promise<Session | null> {
    /* Retrieve session state */
    return null;
  },
  async deleteSession(sessionId: string) {
    /* Delete specific session */
  },
  async listSessions(): Promise<string[]> {
    /* Return list of all session IDs */
    return [];
  },
  async deleteAllSessions() {
    /* Clear all sessions */
  },
};

// Initialize the library before any other operation
import { E2EE } from "@immahq/aegis";
const aegis = new E2EE(myStorage);
```

> **Security Note**: The adapter will store secret key material. In production, always use platform-secured storage (e.g., iOS Keychain, Android Keystore, or a securely encrypted database).

### **2. Create a User Identity**

A user identity consists of a post-quantum KEM key pair, a signing key pair, and pre-keys for session establishment.

```typescript
// This creates and automatically saves the identity to your storage
const { identity, publicBundle } = await aegis.createIdentity();
console.log("Your Public Bundle:", publicBundle);
```

### **3. Establish a 1:1 Encrypted Session**

#### **Initiator (Alice)**

```typescript
// 1. Fetch recipient's public bundle from your server
const bobBundle = await getPublicKeyBundle();

// 2. Create a session. This performs the ML-KEM key encapsulation.
const { sessionId, ciphertext, confirmationMac } = await aegis.createSession(
  bobBundle
);

// 3. Send `ciphertext` and `confirmationMac` to Bob via your server
```

#### **Recipient (Bob)**

```typescript
// 1. Create the session as a responder using the received ciphertext
const { sessionId, confirmationMac, isValid } =
  await aegis.createResponderSession(
    aliceBundle,
    receivedCiphertext,
    receivedConfirmationMac
  );

if (isValid) {
  console.log("Session established and verified!");
}
```

### **4. Exchange Messages**

#### **Encrypt a Message**

```typescript
const encryptedMessage = await aegis.encryptMessage(
  sessionId,
  "Hello, Bob! This is a secret."
);
```

#### **Decrypt a Message**

```typescript
const plaintext = await aegis.decryptMessage(sessionId, encryptedMessage);
console.log(plaintext); // "Hello, Bob! This is a secret."
```

### **5. Group Messaging with Enhanced Security**

Aegis uses the Sender Key protocol for efficient group messaging, where each member encrypts a message once for the entire group. With enhanced security features, group keys are now properly encrypted with member public keys and pre-key signatures are verified.

#### **Create a Group with Secure Key Distribution**

```typescript
import { Aegis, MemoryStorage } from "@immahq/aegis";

// Initialize Aegis with your storage adapter
const aegis = new Aegis(new MemoryStorage());

// Prepare member public keys
const memberKemPublicKeys = new Map<string, Uint8Array>();
memberKemPublicKeys.set(aliceUserId, aliceKem);
// ... add other members ...

const memberDsaPublicKeys = new Map<string, Uint8Array>();
memberDsaPublicKeys.set(aliceUserId, aliceDsa);
// ... add other members ...

// Alice creates a group
const group = await aegis.createGroup(
  "family_chat_2025",
  [aliceUserId, bobUserId, charlieUserId],
  memberKemPublicKeys,
  memberDsaPublicKeys
);
```

#### **Broadcast and Decrypt Group Messages**

```typescript
// Alice encrypts a message for the entire group
const groupCiphertext = await aegis.encryptGroupMessage(
  "family_chat_2025",
  "Dinner at 8 PM!"
);

// Bob decrypts the group message
const groupPlaintext = await aegis.decryptGroupMessage(
  "family_chat_2025",
  groupCiphertext
);
console.log(new TextDecoder().decode(groupPlaintext)); // "Dinner at 8 PM!"
```

---

## **API Reference**

### **Core & Configuration**

### **Identity Management**

- **`aegis.createIdentity(): Promise<{ identity, publicBundle }>`**
- **`aegis.getIdentity(): Promise<Identity>`**
- **`aegis.getPublicBundle(): Promise<PublicBundle>`**
- **`aegis.rotateIdentity(): Promise<{ identity, publicBundle }>`**

### **1:1 Sessions**

- **`aegis.createSession(peerBundle): Promise<{ sessionId, ciphertext, confirmationMac }>`**
- **`aegis.createResponderSession(peerBundle, ciphertext, initiatorMac?): Promise<{ sessionId, confirmationMac, isValid }>`**
- **`aegis.confirmSession(sessionId, responderMac): Promise<boolean>`**
- **`aegis.encryptMessage(sessionId, plaintext): Promise<EncryptedMessage>`**
- **`aegis.decryptMessage(sessionId, encryptedMsg): Promise<Uint8Array>`**
- **`aegis.triggerRatchet(sessionId): Promise<void>`**

### **Group Sessions**

- **`aegis.createGroup(name, members, kemKeys, dsaKeys): Promise<Group>`**
- **`aegis.addGroupMember(groupId, userId, session, userPublicKey): Promise<void>`**
- **`aegis.removeGroupMember(groupId, userId): Promise<void>`**
- **`aegis.updateGroupKey(groupId): Promise<void>`**
- **`aegis.encryptGroupMessage(groupId, message): Promise<GroupMessage>`**
- **`aegis.decryptGroupMessage(groupId, encryptedMsg): Promise<Uint8Array>`**
- **`aegis.getGroup(groupId): Promise<Group | null>`**

---

## **Testing and Examples**

- **Run Sample Flow**: `npm run sample`
  - This executes `examples/usage.ts`, demonstrating a complete flow: identity creation, session handshake, 1:1 messaging, and group setup.

---

## **Security Model & Best Practices**

### **Cryptographic Foundation**

Aegis is built on a hybrid model:

1.  **Key Agreement**: **ML-KEM 768** provides quantum-resistant key encapsulation. This algorithm is now a finalized NIST standard (FIPS 203).
2.  **Data Encryption**: **ChaCha20-Poly1305** is used for fast, authenticated encryption of message contents.
3.  **Key Derivation & Hashing**: **Blake3** is used for key derivation and hashing, providing high speed and security.

### **Critical Implementation Notes**

⚠️ **These points are essential for production security:**

- **Signed Pre-Key Signatures**: The library verifies pre-key signatures during session initialization. This provides protection against active man-in-the-middle attacks during session establishment.
- **One-Time Pre-Keys (OTPKs)**: The `getPublicBundle()` function returns a pre-key. Your server should track used keys and ensure they are rotated.
- **Group Key Encryption**: Group shared keys are properly encrypted using ML-KEM with each member's public key, ensuring that only authorized group members can access the group key.
- **Storage Security**: The storage adapter you provide holds all secret keys. **You are responsible for its security.** Use platform-backed secure storage.

---

## **Contributing & Roadmap**

We welcome contributions. Priority areas include:

- Enhanced utilities for server-side OTPK lifecycle management.
- Improved examples for cross-platform secure storage.
- Advanced group management features (admin roles, permissions, etc.).
- Performance optimizations for large group messaging.

---

## **License**

MIT
