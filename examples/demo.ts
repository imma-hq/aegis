import { Aegis, MemoryStorage } from "../dist"; // import { Aegis, MemoryStorage } from "@immahq/aegis";

async function quickTest() {
  console.log("🔍 Quick E2EE & Replay Protection Test");
  console.log("=".repeat(50));

  // Setup
  const alice = new Aegis(new MemoryStorage());
  const bob = new Aegis(new MemoryStorage());

  // Create identities
  console.log("1. Creating identities...");
  const aliceIdentity = await alice.createIdentity("alice-user-123");
  const bobIdentity = await bob.createIdentity("bob-user-456");
  console.log("   ✅ Identities created");

  // Establish session
  console.log("2. Establishing session...");
  const aliceSession = await alice.createSession(bobIdentity.publicBundle);
  const bobSession = await bob.createResponderSession(
    aliceIdentity.publicBundle,
    aliceSession.ciphertext,
    aliceSession.confirmationMac,
  );

  await alice.confirmSession(
    aliceSession.sessionId,
    bobSession.confirmationMac,
  );
  console.log("   ✅ Session established with key confirmation");

  // Test normal message flow
  console.log("3. Testing normal message flow...");
  const testMessage =
    "Any sufficiently advanced technology is indistinguishable from magic ✨. - Arthur C. Clarke";
  const encrypted = await alice.encryptMessage(
    aliceSession.sessionId,
    testMessage,
  );
  const decrypted = await bob.decryptMessage(bobSession.sessionId, encrypted);

  const decryptedText = new TextDecoder().decode(decrypted.plaintext);
  console.log(`   Original: "${testMessage}"`);
  console.log(`   Decrypted: "${decryptedText}"`);
  console.log(`   ✅ Messages match: ${testMessage === decryptedText}`);

  // Test replay protection
  console.log("4. Testing replay protection...");
  try {
    await bob.decryptMessage(bobSession.sessionId, encrypted);
    console.log("   ❌ FAIL: Replay should have been blocked");
    return false;
  } catch (error: any) {
    if (
      error.message.includes("Duplicate") ||
      error.message.includes("replay")
    ) {
      console.log("   ✅ PASS: Replay correctly blocked");
      console.log(`   Error: ${error.message}`);
    } else {
      console.log("   ❌ FAIL: Wrong error type");
      console.log(`   Error: ${error.message}`);
      return false;
    }
  }

  // Test multiple messages
  console.log("5. Testing multiple messages...");
  const messages = ["Msg1", "Msg2", "Msg3"];
  let allSuccessful = true;

  for (const msg of messages) {
    const enc = await alice.encryptMessage(aliceSession.sessionId, msg);
    const dec = await bob.decryptMessage(bobSession.sessionId, enc);
    const decMsg = new TextDecoder().decode(dec.plaintext);

    if (msg !== decMsg) {
      console.log(`   ❌ Message mismatch: "${msg}" vs "${decMsg}"`);
      allSuccessful = false;
    }
  }

  console.log(
    `   ✅ All ${messages.length} messages encrypted/decrypted successfully`,
  );

  // Check replay protection status
  console.log("6. Checking replay protection status...");
  const status = await bob.getReplayProtectionStatus(bobSession.sessionId);
  console.log(`   Stored message IDs: ${status.storedMessageIds}`);
  console.log(
    `   Expected: ${messages.length + 1} (including first test message)`,
  );

  if (status.storedMessageIds === messages.length + 1) {
    console.log("   ✅ Correct number of messages tracked");
  } else {
    console.log(
      `   ❌ Incorrect count: expected ${messages.length + 1}, got ${status.storedMessageIds}`,
    );
    allSuccessful = false;
  }

  // Test key rotation
  console.log("7. Testing key rotation...");
  const originalIdentity = await alice.getIdentity();
  console.log(
    `   Original identity userId: ${originalIdentity.userId.substring(0, 16)}...`,
  );

  // Test rotating with a new userId to ensure the identity changes
  const _rotatedResult = await alice.rotateIdentity("alice-user-123-rotated");
  const newIdentity = await alice.getIdentity();
  console.log(
    `   New identity userId: ${newIdentity.userId.substring(0, 16)}...`,
  );

  if (originalIdentity.userId !== newIdentity.userId) {
    console.log("   ✅ Identity successfully rotated with new userId");

    // Test that we can still create a new session with the rotated identity
    const bobPublicBundle = await bob.getPublicBundle();
    const newAliceSession = await alice.createSession(bobPublicBundle);
    const newBobSession = await bob.createResponderSession(
      await alice.getPublicBundle(),
      newAliceSession.ciphertext,
      newAliceSession.confirmationMac,
    );

    await alice.confirmSession(
      newAliceSession.sessionId,
      newBobSession.confirmationMac,
    );

    // Test message encryption/decryption with new keys
    const newTestMessage = "Message after key rotation";
    const newEncrypted = await alice.encryptMessage(
      newAliceSession.sessionId,
      newTestMessage,
    );
    const newDecrypted = await bob.decryptMessage(
      newBobSession.sessionId,
      newEncrypted,
    );
    const newDecryptedText = new TextDecoder().decode(newDecrypted.plaintext);

    if (newTestMessage === newDecryptedText) {
      console.log("   ✅ New session with rotated keys works correctly");
    } else {
      console.log("   ❌ New session with rotated keys failed");
      allSuccessful = false;
    }
  } else {
    console.log("   ❌ Identity rotation failed - userIds are the same");
    allSuccessful = false;
  }

  return allSuccessful;
}

// Run test
quickTest()
  .then((success) => {
    console.log(`\n${"=".repeat(50)}`);
    if (success) {
      console.log("🎉 All tests passed! Replay protection is working.");
    } else {
      console.log("❌ Some tests failed!");
    }
  })
  .catch((error) => {
    console.error("\n❌ Test error:", error);
  });
