import { Aegis } from "../src/config"; // Using source files for example
import {
  getPublicKeyBundle,
  createIdentity,
  exportIdentity,
  importIdentity,
  getAndConsumePublicKeyBundle,
  deleteIdentity,
  loadIdentity,
} from "../src/pqc";
import {
  initializeSession,
  acceptSession,
  encryptMessage,
  decryptMessage,
} from "../src/session";
import { getGroupSession } from "../src/group";

// Mock Storage Adapter (In-Memory)
class MockStorage {
  private store: Map<string, string> = new Map();
  async getItem(key: string) {
    return this.store.get(key) || null;
  }
  async setItem(key: string, value: string) {
    this.store.set(key, value);
  }
  async removeItem(key: string) {
    this.store.delete(key);
  }
  async clear() {
    this.store.clear();
  }
}

async function runExample() {
  console.log(
    "=== Aegis: Secure Messaging Demo (PQC X3DH + Sender Keys) ===\n",
  );

  // 1. Initialize Library
  const aliceStorage = new MockStorage();
  const bobStorage = new MockStorage();

  // We need to switch context for each user since current implementation
  // is a singleton `Aegis.init`. In a real app, strict separation or
  // instance-based architecture would be used.
  // Helper to switch context:
  const asAlice = () => Aegis.init({ storage: aliceStorage });
  const asBob = () => Aegis.init({ storage: bobStorage });

  // 2. Identity Creation (Bob)
  asBob();
  const bobIdentity: any = await createIdentity(
    "bob_123",
    "email",
    "bob@example.com",
  );
  const bobBundle = await getPublicKeyBundle(); // Bob publishes this to server
  console.log(
    "Bob Identity Created. EK Public:",
    bobBundle.identityKey.substring(0, 10) + "...",
  );

  // Server-side: consume an OTPK (if you want server-managed consumption)
  const serverConsumedBundle = await getAndConsumePublicKeyBundle();
  console.log(
    "Server consumed OTPK id:",
    serverConsumedBundle.oneTimePreKey?.id ?? "none",
  );

  // Export and import (backup/restore) demo for Bob
  const backup = await exportIdentity("demo-password");
  console.log("Backup created (truncated):", backup.substring(0, 40) + "...");

  // Simulate deleting and restoring Bob's identity from backup
  await deleteIdentity();
  console.log("Bob identity deleted. Restoring from backup...");
  await importIdentity(backup, "demo-password");
  const restored = await loadIdentity();
  console.log("Restored identity for:", restored?.userId);

  // 3. Session Establish (Alice -> Bob)
  asAlice();
  await createIdentity("alice_456", "phone", "+15550000");
  console.log("Alice Identity Created.");

  const sessionInit = await initializeSession("session_a_b", bobBundle);
  console.log("Alice initialized session. Sending bundle...");

  // 4. Accept Session (Bob)
  asBob();
  // Bob fetches his own keys to decrypt (demo-only, in a real app you'd read from secure storage)
  const bobKeys = {
    identitySecret: bobIdentity.kem.secretKey,
    signedPreKeySecret: bobIdentity.signedPreKey!.keyPair.secretKey, // ! bang for demo
    oneTimePreKeySecret: bobBundle.oneTimePreKey
      ? bobIdentity.oneTimePreKeys.find(
          (k: any) => k.id === bobBundle.oneTimePreKey!.id,
        )?.keyPair.secretKey
      : undefined,
  };
  await acceptSession("session_a_b", sessionInit.ciphertexts, bobKeys);

  // 5. 1:1 Messaging
  asAlice();
  const msg1 = await encryptMessage("session_a_b", "Hello Bob, this is Alice!");
  console.log("Alice Sent (1:1):", msg1.ciphertext.substring(0, 10) + "...");

  asBob();
  const plain1 = await decryptMessage(msg1);
  console.log("Bob Received (1:1):", plain1);

  // 6. Group Messaging (Sender Keys)
  console.log("\n--- Group Messaging (Sender Keys) ---");
  const groupId = "group_cool_people";

  // Alice initializes group
  asAlice();
  const aliceGroup = await getGroupSession(groupId);
  // Create distribution message for Bob
  const distMsg = aliceGroup.createDistributionMessage("alice_456");

  // Alice sends this dist session via 1:1 to Bob
  const encryptedDist = await encryptMessage(
    "session_a_b",
    JSON.stringify(distMsg),
  );

  // Bob receives and processes
  asBob();
  const decryptedDistStr = await decryptMessage(encryptedDist);
  const receivedDistMsg = JSON.parse(decryptedDistStr);
  const bobGroup = await getGroupSession(groupId);
  await bobGroup.processDistributionMessage(receivedDistMsg);

  // Alice broadcasts to group
  asAlice();
  const groupCipher = await aliceGroup.encrypt(
    "Hello Group! Scaling to millions!",
    "alice_456",
  );
  console.log(
    "Alice Broadcast:",
    groupCipher.cipherText.substring(0, 10) + "...",
  );

  // Bob reads broadcast
  asBob();
  const groupPlain = await bobGroup.decrypt(groupCipher);
  console.log("Bob Read Group Msg:", groupPlain);

  console.log("\n=== Demo Complete ===");
}

runExample().catch(console.error);
