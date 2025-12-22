import { describe, it, expect, beforeEach } from "vitest";
import { GroupSession } from "../src/group";
import {
  initializeSession,
  acceptSession,
  encryptMessage,
  decryptMessage,
} from "../src/session";
import { createIdentity, getPublicKeyBundle } from "../src/pqc";
import { Aegis } from "../src/config";
import { MockStorage } from "./setup";

describe("Sender Key Group Messaging", () => {
  let aliceStorage: MockStorage;
  let bobStorage: MockStorage;

  beforeEach(() => {
    aliceStorage = new MockStorage();
    bobStorage = new MockStorage();
  });

  async function asUser<T>(
    userStorage: MockStorage,
    fn: () => Promise<T>,
  ): Promise<T> {
    Aegis.init({ storage: userStorage });
    return fn();
  }

  it("should distribute sender keys and exchange messages", async () => {
    // 1. Identities
    const aliceId = await asUser(aliceStorage, () =>
      createIdentity("alice", "email", "alice@test.com"),
    );
    const bobId = await asUser(bobStorage, () =>
      createIdentity("bob", "email", "bob@test.com"),
    );

    // 2. Establish 1:1 Session (for Key Distribution)
    const sidAB = "session_ab";
    const bobBundle = await asUser(bobStorage, () => getPublicKeyBundle());

    const initAB = await asUser(aliceStorage, () =>
      initializeSession(sidAB, bobBundle),
    );

    const bobKeys = {
      identitySecret: bobId.kem.secretKey,
      signedPreKeySecret: bobId.signedPreKey!.keyPair.secretKey,
      oneTimePreKeySecret: bobId.oneTimePreKeys.find(
        (k) => k.id === bobBundle.oneTimePreKey!.id,
      )?.keyPair.secretKey,
    };
    await asUser(bobStorage, () =>
      acceptSession(sidAB, initAB.ciphertexts, bobKeys),
    );

    // 3. Alice creates group and distributes key
    const groupId = "group_alpha";
    const distMsg = await asUser(aliceStorage, async () => {
      const group = await GroupSession.get(groupId);
      return group.createDistributionMessage(aliceId.userId);
    });

    // Transport: Alice encrypts distMsg for Bob
    const encDist = await asUser(aliceStorage, () =>
      encryptMessage(sidAB, JSON.stringify(distMsg)),
    );

    // Transport: Bob receives and processes
    await asUser(bobStorage, async () => {
      const plainDist = await decryptMessage(encDist);
      const payload = JSON.parse(plainDist);
      const group = await GroupSession.get(groupId);
      await group.processDistributionMessage(payload);
    });

    // 4. Alice Broadcasts (Sender Key Encryption)
    const plaintext = "Hello Scalable World";
    const groupCipher = await asUser(aliceStorage, async () => {
      const group = await GroupSession.get(groupId);
      return group.encrypt(plaintext, aliceId.userId);
    });

    // 5. Bob Decrypts (using stored sender key)
    const bobDecrypted = await asUser(bobStorage, async () => {
      const group = await GroupSession.get(groupId);
      return group.decrypt(groupCipher);
    });

    expect(bobDecrypted).toBe(plaintext);
  });

  it("should throw when decrypting a group message without prior distribution", async () => {
    // 1. Identities
    const aliceId = await asUser(aliceStorage, () =>
      createIdentity("alice_nodist", "email", "alice_nodist@test.com"),
    );
    const bobId = await asUser(bobStorage, () =>
      createIdentity("bob_nodist", "email", "bob_nodist@test.com"),
    );

    // Alice encrypts a group message but does not distribute sender key to Bob
    const groupId = "group_no_dist";
    const groupCipher = await asUser(aliceStorage, async () => {
      const group = await GroupSession.get(groupId);
      return group.encrypt("Message without distribution", aliceId.userId);
    });

    // Bob attempts to read the group message without having received a distribution message
    await expect(
      asUser(bobStorage, async () => {
        const group = await GroupSession.get(groupId);
        await group.decrypt(groupCipher);
      }),
    ).rejects.toThrow(/No sender key found for/);
  });
});
