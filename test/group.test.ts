import { describe, it, expect, beforeEach } from "vitest";
import { sendGroupMessage, decryptGroupMessage } from "../src/group";
import { initializeSession, acceptSession } from "../src/session";
import { createIdentity } from "../src/pqc";
import { Aegis } from "../src/config";
import { MockStorage } from "./setup";

describe("Group Messaging", () => {
  let aliceStorage: MockStorage;
  let bobStorage: MockStorage;
  let charlieStorage: MockStorage;

  beforeEach(() => {
    aliceStorage = new MockStorage();
    bobStorage = new MockStorage();
    charlieStorage = new MockStorage();
  });

  async function asUser<T>(
    userStorage: MockStorage,
    fn: () => Promise<T>
  ): Promise<T> {
    Aegis.init({ storage: userStorage });
    return fn();
  }

  it("should broadcast a message to multiple recipients", async () => {
    // 1. Identities
    const aliceId = await asUser(aliceStorage, () =>
      createIdentity("alice", "email", "alice@test.com")
    );
    const bobId = await asUser(bobStorage, () =>
      createIdentity("bob", "email", "bob@test.com")
    );
    const charlieId = await asUser(charlieStorage, () =>
      createIdentity("charlie", "email", "charlie@test.com")
    );

    // 2. Establish Sessions
    // Alice -> Bob
    const sidAB = "session_ab";
    const initAB = await asUser(aliceStorage, () =>
      initializeSession(sidAB, bobId.kem.publicKey)
    );
    await asUser(bobStorage, () =>
      acceptSession(sidAB, initAB.kemCiphertext, bobId.kem.secretKey)
    );

    // Alice -> Charlie
    const sidAC = "session_ac";
    const initAC = await asUser(aliceStorage, () =>
      initializeSession(sidAC, charlieId.kem.publicKey)
    );
    await asUser(charlieStorage, () =>
      acceptSession(sidAC, initAC.kemCiphertext, charlieId.kem.secretKey)
    );

    // 3. Send Group Message
    const groupId = "group_1";
    const plaintext = "Hello Team";
    const participants = {
      [bobId.userId]: sidAB,
      [charlieId.userId]: sidAC,
    };

    const bundle = await asUser(aliceStorage, () =>
      sendGroupMessage(groupId, participants, plaintext)
    );

    expect(bundle.groupId).toBe(groupId);
    expect(bundle.messages[bobId.userId]).toBeDefined();
    expect(bundle.messages[charlieId.userId]).toBeDefined();

    // 4. Decrypt
    // Bob receives
    const decBob = await asUser(bobStorage, () =>
      decryptGroupMessage(bundle.messages[bobId.userId])
    );
    expect(decBob).toBe(plaintext);

    // Charlie receives
    const decCharlie = await asUser(charlieStorage, () =>
      decryptGroupMessage(bundle.messages[charlieId.userId])
    );
    expect(decCharlie).toBe(plaintext);
  });
});
