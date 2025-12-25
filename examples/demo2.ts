// src/minimal-test.ts
import { E2EE, MemoryStorage } from "../dist/index.js";

async function minimalTest() {
  const alice = new E2EE(new MemoryStorage());
  const bob = new E2EE(new MemoryStorage());

  // Setup
  const aliceId = await alice.createIdentity();
  const bobId = await bob.createIdentity();

  // Session
  const aliceSession = await alice.createSession(bobId.publicBundle);
  const bobSession = await bob.createResponderSession(
    aliceId.publicBundle,
    aliceSession.ciphertext,
    aliceSession.confirmationMac,
  );

  await alice.confirmSession(
    aliceSession.sessionId,
    bobSession.confirmationMac,
  );

  // Test
  const msg = "Test";
  const enc = await alice.encryptMessage(aliceSession.sessionId, msg);
  const dec1 = await bob.decryptMessage(bobSession.sessionId, enc);
  const text1 = new TextDecoder().decode(dec1.plaintext);

  // Try replay
  try {
    await bob.decryptMessage(bobSession.sessionId, enc);
    return false; // Should not reach here
  } catch {
    return text1 === msg;
  }
}

minimalTest().then((success) => {
  console.log(success ? "✅ Replay protection works!" : "❌ Failed");
  process.exit(success ? 0 : 1);
});
