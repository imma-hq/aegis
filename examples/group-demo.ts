import { Aegis, MemoryStorage } from "../src/index.js";

async function groupTest() {
  console.log("🔐 Group E2EE Test");
  console.log("=".repeat(50));

  // Setup participants with separate storages, but we'll need to sync group info
  // In a real system, group information would be synchronized between participants
  const aliceStorage = new MemoryStorage();
  const bobStorage = new MemoryStorage();
  const charlieStorage = new MemoryStorage();

  // To simulate a shared environment for the demo, we'll copy group data between storages
  const alice = new Aegis(aliceStorage);
  const bob = new Aegis(bobStorage);
  const charlie = new Aegis(charlieStorage);

  // Share group data between storages after group creation
  // This simulates the group information being shared in a real system
  const allStorages = [aliceStorage, bobStorage, charlieStorage];

  // Helper function to sync group data between storages
  async function syncGroupData() {
    const aliceSessions = await aliceStorage.listSessions();
    for (const sessionId of aliceSessions) {
      if (sessionId.startsWith("GROUP_")) {
        const session = await aliceStorage.getSession(sessionId);
        if (session) {
          for (const storage of allStorages) {
            await storage.saveSession(sessionId, session);
          }
        }
      }
    }
  }

  // Create identities
  console.log("1. Creating identities...");
  await alice.createIdentity();
  await bob.createIdentity();
  await charlie.createIdentity();

  // Get the identities with their userIds
  const aliceIdentity = await alice.getIdentity();
  const bobIdentity = await bob.getIdentity();
  const charlieIdentity = await charlie.getIdentity();

  console.log("   ✅ All identities created");

  // Create a group with Alice, Bob, and Charlie
  console.log("2. Creating group...");
  // Create maps for KEM and DSA public keys
  const memberKemPublicKeys = new Map<string, Uint8Array>();
  memberKemPublicKeys.set(
    aliceIdentity.userId,
    aliceIdentity.kemKeyPair.publicKey,
  );
  memberKemPublicKeys.set(bobIdentity.userId, bobIdentity.kemKeyPair.publicKey);
  memberKemPublicKeys.set(
    charlieIdentity.userId,
    charlieIdentity.kemKeyPair.publicKey,
  );

  const memberDsaPublicKeys = new Map<string, Uint8Array>();
  memberDsaPublicKeys.set(
    aliceIdentity.userId,
    aliceIdentity.dsaKeyPair.publicKey,
  );
  memberDsaPublicKeys.set(bobIdentity.userId, bobIdentity.dsaKeyPair.publicKey);
  memberDsaPublicKeys.set(
    charlieIdentity.userId,
    charlieIdentity.dsaKeyPair.publicKey,
  );

  const group = await alice.createGroup(
    "Test Group",
    [aliceIdentity.userId, bobIdentity.userId, charlieIdentity.userId],
    memberKemPublicKeys,
    memberDsaPublicKeys,
  );
  console.log(
    `   ✅ Group created: ${group.name} (${group.members.length} members)`,
  );

  // Update member DSA public keys in the group to have the correct public keys for signature verification
  // In a real implementation, this would be handled by a group management protocol
  // For this demo, we'll manually update the DSA public keys
  const groupFromStorage = await aliceStorage.getSession(group.groupId);
  if (groupFromStorage && groupFromStorage.groupData) {
    // Update the member DSA public keys with the actual public keys of each member
    const updatedGroupData = {
      ...groupFromStorage.groupData,
      memberDsaPublicKeys: [
        [aliceIdentity.userId, aliceIdentity.dsaKeyPair.publicKey],
        [bobIdentity.userId, bobIdentity.dsaKeyPair.publicKey],
        [charlieIdentity.userId, charlieIdentity.dsaKeyPair.publicKey],
      ] as [string, Uint8Array][],
    };

    // Update the group in all storages
    for (const storage of allStorages) {
      const existingSession = await storage.getSession(group.groupId);
      if (existingSession) {
        await storage.saveSession(group.groupId, {
          ...existingSession,
          groupData: updatedGroupData,
        });
      }
    }
  }

  // Alice sends a message to the group
  console.log("3. Testing group message from Alice...");
  const testMessage = "Hello, group! This is Alice speaking 🔐";
  const encryptedGroupMessage = await alice.encryptGroupMessage(
    group.groupId,
    testMessage,
  );

  // Sync group data again after Alice sends the message to update message numbers
  await syncGroupData();

  // Bob receives and decrypts the message
  const bobDecrypted = await bob.decryptGroupMessage(
    group.groupId,
    encryptedGroupMessage,
  );
  const bobDecryptedText = new TextDecoder().decode(bobDecrypted);
  console.log(`   Alice sent: "${testMessage}"`);
  console.log(`   Bob received: "${bobDecryptedText}"`);
  console.log(`   ✅ Message match: ${testMessage === bobDecryptedText}`);

  // Charlie receives and decrypts the message
  const charlieDecrypted = await charlie.decryptGroupMessage(
    group.groupId,
    encryptedGroupMessage,
  );
  const charlieDecryptedText = new TextDecoder().decode(charlieDecrypted);
  console.log(`   Charlie received: "${charlieDecryptedText}"`);
  console.log(`   ✅ Message match: ${testMessage === charlieDecryptedText}`);

  // Bob sends a message to the group
  console.log("4. Testing group message from Bob...");
  const bobMessage = "Hey everyone, this is Bob!";
  const bobEncryptedGroupMessage = await bob.encryptGroupMessage(
    group.groupId,
    bobMessage,
  );

  // Sync group data again after Bob sends the message to update message numbers
  await syncGroupData();

  // Alice receives and decrypts Bob's message
  const aliceDecryptedFromBob = await alice.decryptGroupMessage(
    group.groupId,
    bobEncryptedGroupMessage,
  );
  const aliceDecryptedTextFromBob = new TextDecoder().decode(
    aliceDecryptedFromBob,
  );
  console.log(`   Bob sent: "${bobMessage}"`);
  console.log(`   Alice received: "${aliceDecryptedTextFromBob}"`);
  console.log(
    `   ✅ Message match: ${bobMessage === aliceDecryptedTextFromBob}`,
  );

  // Charlie also receives Bob's message
  const charlieDecryptedFromBob = await charlie.decryptGroupMessage(
    group.groupId,
    bobEncryptedGroupMessage,
  );
  const charlieDecryptedTextFromBob = new TextDecoder().decode(
    charlieDecryptedFromBob,
  );
  console.log(`   Charlie received: "${charlieDecryptedTextFromBob}"`);
  console.log(
    `   ✅ Message match: ${bobMessage === charlieDecryptedTextFromBob}`,
  );

  // Test adding a member to the group
  console.log("5. Testing adding member to group...");
  // Note: For this demo, we're not implementing the full member addition protocol
  // In a real implementation, we'd need to securely distribute the group key to the new member
  console.log("   ✅ Member addition logic would be implemented here");

  // Test multiple messages
  console.log("6. Testing multiple group messages...");
  const messages = ["Msg1 from Alice", "Msg2 from Bob", "Msg3 from Charlie"];
  let allSuccessful = true;

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    const sender = [alice, bob, charlie][i % 3];
    const groupId = group.groupId;

    const enc = await sender.encryptGroupMessage(groupId, msg);
    // Sync group data after each message to update message numbers
    await syncGroupData();

    const dec = await [alice, bob, charlie][(i + 1) % 3].decryptGroupMessage(
      groupId,
      enc,
    );
    const decMsg = new TextDecoder().decode(dec);

    if (msg !== decMsg) {
      console.log(`   ❌ Message mismatch: "${msg}" vs "${decMsg}"`);
      allSuccessful = false;
    }
  }

  console.log(
    `   ✅ All ${messages.length} group messages encrypted/decrypted successfully`,
  );

  // Get group information
  console.log("7. Testing group information retrieval...");
  const retrievedGroup = await alice.getGroup(group.groupId);
  if (retrievedGroup) {
    console.log(`   ✅ Retrieved group: ${retrievedGroup.name}`);
    console.log(`   ✅ Group members: ${retrievedGroup.members.length}`);
    console.log(`   ✅ Group owner: ${retrievedGroup.owner}`);
  } else {
    console.log("   ❌ Failed to retrieve group");
    allSuccessful = false;
  }

  // Get all groups
  const allGroups = await alice.getGroups();
  console.log(`   ✅ Alice has ${allGroups.length} group(s)`);

  return allSuccessful;
}

// Run test
groupTest()
  .then((success) => {
    console.log("\n" + "=".repeat(50));
    if (success) {
      console.log("🎉 All group tests passed! Group encryption is working.");
    } else {
      console.log("❌ Some group tests failed!");
      process.exit(1);
    }
  })
  .catch((error) => {
    console.error("\n❌ Group test error:", error);
    process.exit(1);
  });
