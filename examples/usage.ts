import {
  Aegis,
  createIdentity,
  getPublicKeyBundle,
  initializeSession,
  acceptSession,
  encryptMessage,
  decryptMessage,
  sendGroupMessage,
  StorageAdapter,
} from "../dist/";

// 1. Implement In-Memory Storage Adapter for testing/examples
const memoryStorage = new Map<string, string>();

const mockStorage: StorageAdapter = {
  async setItem(key: string, value: string) {
    memoryStorage.set(key, value);
  },
  async getItem(key: string) {
    return memoryStorage.get(key) || null;
  },
  async removeItem(key: string) {
    memoryStorage.delete(key);
  },
};

// Initialize Aegis
Aegis.init({ storage: mockStorage });

async function main() {
  console.log("=== Aegis E2E Encryption Example ===\n");

  // 1. Create Identities
  console.log("1. Creating Identities...");
  const alice = await createIdentity("alice", "email", "alice@example.com");
  const bob = await createIdentity("bob", "email", "bob@example.com");
  const charlie = await createIdentity(
    "charlie",
    "email",
    "charlie@example.com"
  );

  // 2. Setup 1:1 Session (Alice -> Bob)
  console.log("\n2. Establishing 1:1 Session (Alice -> Bob)...");

  // Bob publishes his public keys
  const bobBundle = await getPublicKeyBundle();

  // Alice initiates session (Alice's view)
  const aliceSessionId = "session_alice_to_bob";
  const initData = await initializeSession(aliceSessionId, bob.kem.publicKey);

  // Bob accepts session (Bob's view)
  const bobSessionId = "session_bob_from_alice";
  await acceptSession(bobSessionId, initData.kemCiphertext, bob.kem.secretKey);

  // 3. 1:1 Messaging
  console.log("\n3. Testing 1:1 Messaging...");
  const msg1 = "Hello Bob, this is Alice!";
  console.log(`Alice sends: "${msg1}"`);

  const encrypted1 = await encryptMessage(aliceSessionId, msg1);
  console.log(`Encrypted: ${encrypted1.ciphertext.substring(0, 20)}...`);

  // Bob decrypts (must use his local session ID)
  // We simulate transport layer delivering message to "Bob's Session"
  const decrypted1 = await decryptMessage({
    ...encrypted1,
    sessionId: bobSessionId,
  });
  console.log(`Bob receives: "${decrypted1}"`);

  // 4. Setup Session (Alice -> Charlie) for Group
  console.log("\n4. Establishing Session (Alice -> Charlie) for Group...");
  const aliceToCharlieId = "session_alice_charlie";
  const charlieToAliceId = "session_charlie_alice";

  const initDataAC = await initializeSession(
    aliceToCharlieId,
    charlie.kem.publicKey
  );

  await acceptSession(
    charlieToAliceId,
    initDataAC.kemCiphertext,
    charlie.kem.secretKey
  );

  // 5. Group Messaging (Alice -> [Bob, Charlie])
  console.log("\n5. Testing Group Messaging (Fan-out)...");
  const groupMsg = "Hello Team! Secure update here.";
  const groupId = "group_1";

  const participants = {
    [bob.userId]: aliceSessionId,
    [charlie.userId]: aliceToCharlieId,
  };

  console.log(`Alice broadcasts to group ${groupId}: "${groupMsg}"`);
  const bundle = await sendGroupMessage(groupId, participants, groupMsg);

  // Bob decrypts his copy
  const bobCopy = bundle.messages[bob.userId];
  if (bobCopy) {
    const bobDecrypted = await decryptMessage({
      ...bobCopy,
      sessionId: bobSessionId,
    });
    console.log(`Bob receives group msg: "${bobDecrypted}"`);
  }

  // Charlie decrypts his copy
  const charlieCopy = bundle.messages[charlie.userId];
  if (charlieCopy) {
    const charlieDecrypted = await decryptMessage({
      ...charlieCopy,
      sessionId: charlieToAliceId,
    });
    console.log(`Charlie receives group msg: "${charlieDecrypted}"`);
  }
}

main().catch(console.error);
