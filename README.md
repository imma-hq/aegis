# Aegis

**Aegis** is a storage-agnostic, Post-Quantum Cryptography (PQC) ready End-to-End (E2E) encryption library for TypeScript/JavaScript applications.

It provides robust security for messaging applications by combining modern classic cryptography (ChaCha20-Poly1305, Blake3) with next-generation post-quantum key encapsulation (ML-KEM 768) to protect against future threats.

## Features

- **Storage Agnostic**: You provide the storage backend (SQLite, AsyncStorage, LocalStorage, In-Memory, etc.). Aegis handles the encryption.
- **Post-Quantum Ready**: Uses **ML-KEM 768** for initial key exchange, protecting past sessions from future quantum decryption (Harvest Now, Decrypt Later).
- **Forward Secrecy**: Implements a Double Ratchet algorithm using **ChaCha20-Poly1305** and **Blake3** to ensure that a compromised session key cannot decrypt past messages.
- **Group Messaging**: Supports client-side fan-out encryption for secure group chats.
- **Secure Identity**: Manages cryptographically secure user identities with signature and encryption keys.
- **No External Dependencies for Storage**: Zero hard dependencies on specific databases or React Native.

## Installation

```bash
npm install @immahq/aegis
# or
yarn add @immahq/aegis
```

## Quick Start

### 1. Implement a Storage Adapter

Aegis needs to persist keys and session state but doesn't dictate how. You must implement the `StorageAdapter` interface.

```typescript
import { Aegis, StorageAdapter } from "@immahq/aegis";

// Example using a simple in-memory Map (for testing)
// In production, use AsyncStorage, SQLite, or similar.
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

// Initialize the library with your adapter
Aegis.init({ storage: myStorage });
```

### 2. Create an Identity

Each user needs an identity consisting of KEM (Key Encapsulation) and Signing keys.

```typescript
import { createIdentity } from "@immahq/aegis";

const myIdentity = await createIdentity(
  "alice_user_id",
  "email",
  "alice@example.com"
);
// Identity is automatically saved to your storage adapter.
```

### 3. Establish a session (1:1)

To chat with another user, you must perform an initial secure handshake.

**Initiator (Alice):**

```typescript
import { initializeSession } from "@immahq/aegis";

// 1. Fetch Bob's public key (from your server)
const bobPublicKey = ...;

// 2. Initialize session locally
const sessionData = await initializeSession("session_id_123", bobPublicKey);

// 3. Send `sessionData.kemCiphertext` to Bob via your server.
```

**Recipient (Bob):**

```typescript
import { acceptSession } from "@immahq/aegis";

// 1. Receive ciphertext from Alice
const kemCiphertext = ...;

// 2. Accept session using your secret key
await acceptSession("session_id_123", kemCiphertext, myIdentity.kem.secretKey);
```

### 4. Send Encryption Messages

Once the session is established, both parties can send and receive encrypted messages.

```typescript
import { encryptMessage, decryptMessage } from "@immahq/aegis";

// Sending (Encryption)
const encryptedMsg = await encryptMessage("session_id_123", "Hello World!");
// Send `encryptedMsg` JSON to the recipient.

// Receiving (Decryption)
const plaintext = await decryptMessage(receivedEncryptedMsg);
console.log(plaintext); // "Hello World!"
```

### 5. Group Messaging

Aegis supports group messaging via "client-side fan-out". This means the sender encrypts the message individually for every group member using their respective 1:1 sessions.

```typescript
import { sendGroupMessage } from "@immahq/aegis";

// Map of UserID -> SessionID
const participants = {
  bob_id: "session_alice_bob",
  charlie_id: "session_alice_charlie",
};

const bundle = await sendGroupMessage(
  "group_id_1",
  participants,
  "Hello Team!"
);

// `bundle` contains a map of encrypted messages:
// bundle.messages["bob_id"] -> encrypted for Bob
// bundle.messages["charlie_id"] -> encrypted for Charlie
```

## License

MIT
