import { describe, it, expect, beforeEach } from "vitest";
import { Aegis, StorageAdapter } from "../src/index";

// Simulate a more realistic storage implementation for benchmarking
class SimulatedStorage implements StorageAdapter {
  private identity: any = null;
  private sessions = new Map<string, any>();

  async saveIdentity(identity: any): Promise<void> {
    // Simulate I/O delay for mobile/desktop storage
    await new Promise((resolve) => setTimeout(resolve, 0.1)); // 0.1ms delay
    this.identity = identity;
  }

  async getIdentity(): Promise<any> {
    // Simulate I/O delay for mobile/desktop storage
    await new Promise((resolve) => setTimeout(resolve, 0.1)); // 0.1ms delay
    return this.identity;
  }

  async deleteIdentity(): Promise<void> {
    // Simulate I/O delay for mobile/desktop storage
    await new Promise((resolve) => setTimeout(resolve, 0.1)); // 0.1ms delay
    this.identity = null;
  }

  async saveSession(sessionId: string, session: any): Promise<void> {
    // Simulate I/O delay for mobile/desktop storage
    await new Promise((resolve) => setTimeout(resolve, 0.1)); // 0.1ms delay
    // Deep clone to avoid reference issues
    const sessionCopy: any = {
      ...session,
      skippedMessageKeys: new Map(session.skippedMessageKeys),
      receivedMessageIds: new Set(session.receivedMessageIds),
    };
    this.sessions.set(sessionId, sessionCopy);
  }

  async getSession(sessionId: string): Promise<any> {
    // Simulate I/O delay for mobile/desktop storage
    await new Promise((resolve) => setTimeout(resolve, 0.1)); // 0.1ms delay
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    // Return a deep clone
    return {
      ...session,
      skippedMessageKeys: new Map(session.skippedMessageKeys),
      receivedMessageIds: new Set(session.receivedMessageIds),
    };
  }

  async deleteSession(sessionId: string): Promise<void> {
    // Simulate I/O delay for mobile/desktop storage
    await new Promise((resolve) => setTimeout(resolve, 0.1)); // 0.1ms delay
    this.sessions.delete(sessionId);
  }

  async listSessions(): Promise<string[]> {
    // Simulate I/O delay for mobile/desktop storage
    await new Promise((resolve) => setTimeout(resolve, 0.1)); // 0.1ms delay
    return Array.from(this.sessions.keys());
  }

  async deleteAllSessions(): Promise<void> {
    // Simulate I/O delay for mobile/desktop storage
    await new Promise((resolve) => setTimeout(resolve, 0.1)); // 0.1ms delay
    this.sessions.clear();
  }
}

describe("Mobile/Desktop Chat App Benchmark Tests", () => {
  it("should benchmark identity creation performance for mobile/desktop", async () => {
    const aegis = new Aegis(new SimulatedStorage());
    const iterations = 100; // More iterations for statistical significance
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      await aegis.createIdentity();
    }

    const end = performance.now();
    const totalDuration = end - start;
    const avgDuration = totalDuration / iterations;

    console.log(`\nMobile/Desktop Identity Creation Benchmark:`);
    console.log(`  Total time: ${totalDuration.toFixed(2)}ms`);
    console.log(`  Average time per identity: ${avgDuration.toFixed(2)}ms`);
    console.log(
      `  Operations per second: ${(iterations / (totalDuration / 1000)).toFixed(2)}`,
    );

    // Performance assertion - each identity creation should take less than 50ms on average for mobile/desktop
    expect(avgDuration).toBeLessThan(50);
  });

  it("should benchmark session creation performance for mobile/desktop", async () => {
    const alice = new Aegis(new SimulatedStorage());
    const bob = new Aegis(new SimulatedStorage());

    // Create identities first
    const aliceIdentity = await alice.createIdentity();
    const bobIdentity = await bob.createIdentity();

    const iterations = 50; // More iterations for statistical significance
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      // Create session with Bob's public bundle
      const aliceSession = await alice.createSession(bobIdentity.publicBundle);

      // Bob creates responder session
      const bobSession = await bob.createResponderSession(
        aliceIdentity.publicBundle,
        aliceSession.ciphertext,
        aliceSession.confirmationMac,
      );

      // Alice confirms session
      await alice.confirmSession(
        aliceSession.sessionId,
        bobSession.confirmationMac,
      );
    }

    const end = performance.now();
    const totalDuration = end - start;
    const avgDuration = totalDuration / iterations;

    console.log(`\nMobile/Desktop Session Creation Benchmark:`);
    console.log(`  Total time: ${totalDuration.toFixed(2)}ms`);
    console.log(`  Average time per session: ${avgDuration.toFixed(2)}ms`);
    console.log(
      `  Operations per second: ${(iterations / (totalDuration / 1000)).toFixed(2)}`,
    );

    // Performance assertion - each session creation should take less than 100ms on average for mobile/desktop
    expect(avgDuration).toBeLessThan(100);
  });

  it("should benchmark typical chat message encryption/decryption performance", async () => {
    const alice = new Aegis(new SimulatedStorage());
    const bob = new Aegis(new SimulatedStorage());

    // Set up a session
    const aliceIdentity = await alice.createIdentity();
    const bobIdentity = await bob.createIdentity();

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

    // Simulate typical chat message patterns
    const shortMessage = "Hi"; // Common short message
    const mediumMessage =
      "How are you doing today? I was wondering if we could meet up later."; // Medium message
    const longMessage =
      "This is a longer message that might contain more detailed information, thoughts, or a story. It represents the kind of message that users might send when they're having a more in-depth conversation. These types of messages are common in both mobile and desktop chat applications when users want to share more than just a quick response."; // Long message

    const iterations = 200; // More iterations for statistical significance
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      // Cycle through different message types to simulate real usage
      const messageIndex = i % 3;
      let message;
      switch (messageIndex) {
        case 0:
          message = shortMessage;
          break;
        case 1:
          message = mediumMessage;
          break;
        case 2:
          message = longMessage;
          break;
      }

      const encrypted = await alice.encryptMessage(
        aliceSession.sessionId,
        message,
      );
      await bob.decryptMessage(bobSession.sessionId, encrypted);
    }

    const end = performance.now();
    const totalDuration = end - start;
    const avgDuration = totalDuration / iterations;

    console.log(`\nMobile/Desktop Message Encryption/Decryption Benchmark:`);
    console.log(`  Total time: ${totalDuration.toFixed(2)}ms`);
    console.log(
      `  Average time per encrypt/decrypt cycle: ${avgDuration.toFixed(2)}ms`,
    );
    console.log(
      `  Operations per second: ${(iterations / (totalDuration / 1000)).toFixed(2)}`,
    );
    console.log(
      `  Throughput: ${((iterations * (shortMessage.length + mediumMessage.length + longMessage.length)) / 3 / (totalDuration / 1000) / 1024).toFixed(2)} KB/s`,
    );

    // Performance assertion - each encrypt/decrypt cycle should take less than 50ms on average for mobile/desktop
    expect(avgDuration).toBeLessThan(50);
  });

  it("should benchmark media message encryption/decryption performance", async () => {
    const alice = new Aegis(new SimulatedStorage());
    const bob = new Aegis(new SimulatedStorage());

    // Set up a session
    const aliceIdentity = await alice.createIdentity();
    const bobIdentity = await bob.createIdentity();

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

    // Simulate common media message sizes for mobile/desktop apps
    const smallMedia = new Uint8Array(10 * 1024); // 10KB - small image
    const mediumMedia = new Uint8Array(100 * 1024); // 100KB - medium image/video
    const largeMedia = new Uint8Array(1 * 1024 * 1024); // 1MB - larger media file

    for (let i = 0; i < smallMedia.length; i++) {
      smallMedia[i] = i % 256;
    }
    for (let i = 0; i < mediumMedia.length; i++) {
      mediumMedia[i] = i % 256;
    }
    for (let i = 0; i < largeMedia.length; i++) {
      largeMedia[i] = i % 256;
    }

    const iterations = 20; // Reduced iterations for larger data
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      // Cycle through different media sizes to simulate real usage
      const mediaIndex = i % 3;
      let media;
      switch (mediaIndex) {
        case 0:
          media = smallMedia;
          break;
        case 1:
          media = mediumMedia;
          break;
        case 2:
          media = largeMedia;
          break;
      }

      const encrypted = await alice.encryptMessage(
        aliceSession.sessionId,
        media,
      );
      await bob.decryptMessage(bobSession.sessionId, encrypted);
    }

    const end = performance.now();
    const totalDuration = end - start;
    const avgDuration = totalDuration / iterations;

    console.log(`\nMobile/Desktop Media Encryption/Decryption Benchmark:`);
    console.log(`  Total time: ${totalDuration.toFixed(2)}ms`);
    console.log(
      `  Average time per encrypt/decrypt cycle: ${avgDuration.toFixed(2)}ms`,
    );
    console.log(
      `  Operations per second: ${(iterations / (totalDuration / 1000)).toFixed(2)}`,
    );
    const avgSize =
      (smallMedia.length + mediumMedia.length + largeMedia.length) / 3;
    console.log(
      `  Throughput: ${((iterations * avgSize) / (totalDuration / 1000) / (1024 * 1024)).toFixed(2)} MB/s`,
    );

    // Performance assertion - each encrypt/decrypt cycle should take less than 500ms on average for mobile/desktop
    expect(avgDuration).toBeLessThan(500);
  });

  it("should benchmark ratchet performance during active chat sessions", async () => {
    const alice = new Aegis(new SimulatedStorage());
    const bob = new Aegis(new SimulatedStorage());

    // Set up a session
    const aliceIdentity = await alice.createIdentity();
    const bobIdentity = await bob.createIdentity();

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

    // First, establish the session properly by sending a few messages to ensure ratchet keys are exchanged
    for (let i = 0; i < 5; i++) {
      const msg = await alice.encryptMessage(
        aliceSession.sessionId,
        `establish ${i}`,
      );
      await bob.decryptMessage(bobSession.sessionId, msg);
      const reply = await bob.encryptMessage(
        bobSession.sessionId,
        `reply ${i}`,
      );
      await alice.decryptMessage(aliceSession.sessionId, reply);
    }

    const iterations = 10; // Number of ratchet operations
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      // Trigger ratchet on alice side (simulating periodic ratcheting in active chat)
      await alice.triggerRatchet(aliceSession.sessionId);

      // Send a message after ratchet
      const encrypted = await alice.encryptMessage(
        aliceSession.sessionId,
        `ratchet test ${i}`,
      );

      // Bob receives the ratchet message
      await bob.decryptMessage(bobSession.sessionId, encrypted);

      // Bob triggers his own ratchet (simulating bidirectional ratcheting)
      await bob.triggerRatchet(bobSession.sessionId);

      // Bob sends a message after ratchet
      const bobEncrypted = await bob.encryptMessage(
        bobSession.sessionId,
        `bob ratchet test ${i}`,
      );

      // Alice receives bob's ratchet message
      await alice.decryptMessage(aliceSession.sessionId, bobEncrypted);
    }

    const end = performance.now();
    // Calculate duration for the number of ratchet operations (2 per iteration)
    const totalRatchetOps = iterations * 2;
    const totalDuration = end - start;
    const avgDuration = totalDuration / totalRatchetOps;

    console.log(`\nMobile/Desktop Ratchet Performance During Active Chat:`);
    console.log(`  Total time: ${totalDuration.toFixed(2)}ms`);
    console.log(`  Total ratchet operations: ${totalRatchetOps}`);
    console.log(
      `  Average time per ratchet operation: ${avgDuration.toFixed(2)}ms`,
    );
    console.log(
      `  Operations per second: ${(totalRatchetOps / (totalDuration / 1000)).toFixed(2)}`,
    );

    // Performance assertion - each ratchet operation should take less than 200ms on average for mobile/desktop
    expect(avgDuration).toBeLessThan(200);
  });

  it("should benchmark group chat performance with typical group sizes", async () => {
    const aegis = new Aegis(new SimulatedStorage());
    const groupMembers = 8; // Typical group chat size (family, small team)
    const members = [];

    // Create multiple identities for the group
    for (let i = 0; i < groupMembers; i++) {
      const identityResult = await aegis.createIdentity();
      const identity = await aegis.getIdentity();
      members.push(identity);
    }

    const iterations = 10; // Number of group operations
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      // Create maps for KEM and DSA public keys
      const memberKemPublicKeys = new Map<string, Uint8Array>();
      const memberDsaPublicKeys = new Map<string, Uint8Array>();
      const memberIds: string[] = [];

      for (const member of members) {
        memberKemPublicKeys.set(member.userId, member.kemKeyPair.publicKey);
        memberDsaPublicKeys.set(member.userId, member.dsaKeyPair.publicKey);
        memberIds.push(member.userId);
      }

      // Create a group with typical number of members
      const group = await aegis.createGroup(
        `Chat Group ${i}`,
        memberIds,
        memberKemPublicKeys,
        memberDsaPublicKeys,
      );

      // Send a message to the group
      const encrypted = await aegis.encryptGroupMessage(
        group.groupId,
        `Group message ${i} for ${groupMembers} members`,
      );

      // Decrypt by the first member
      await aegis.decryptGroupMessage(group.groupId, encrypted);
    }

    const end = performance.now();
    const totalDuration = end - start;
    const avgDuration = totalDuration / iterations;

    console.log(
      `\nMobile/Desktop Group Chat Benchmark (${groupMembers} members):`,
    );
    console.log(`  Total time: ${totalDuration.toFixed(2)}ms`);
    console.log(
      `  Average time per group operation: ${avgDuration.toFixed(2)}ms`,
    );
    console.log(
      `  Operations per second: ${(iterations / (totalDuration / 1000)).toFixed(2)}`,
    );

    // Performance assertion - each group operation should take less than 1000ms on average for mobile/desktop
    expect(avgDuration).toBeLessThan(1000);
  });

  it("should benchmark concurrent chat sessions for mobile/desktop apps", async () => {
    const alice = new Aegis(new SimulatedStorage());
    const aliceIdentity = await alice.createIdentity();

    const bobInstances = [];
    const bobIdentities = [];
    const sessionCount = 10; // Typical number of concurrent chats for active users

    // Create multiple Bob instances representing different contacts
    for (let i = 0; i < sessionCount; i++) {
      const bob = new Aegis(new SimulatedStorage());
      const bobIdentity = await bob.createIdentity();
      bobInstances.push(bob);
      bobIdentities.push(bobIdentity);
    }

    const start = performance.now();

    // Create sessions concurrently (simulating multiple active chats)
    const sessionPromises = [];
    for (let i = 0; i < sessionCount; i++) {
      sessionPromises.push(
        (async () => {
          const aliceSession = await alice.createSession(
            bobIdentities[i].publicBundle,
          );
          const bobSession = await bobInstances[i].createResponderSession(
            aliceIdentity.publicBundle,
            aliceSession.ciphertext,
            aliceSession.confirmationMac,
          );
          await alice.confirmSession(
            aliceSession.sessionId,
            bobSession.confirmationMac,
          );
          return { aliceSession, bobSession };
        })(),
      );
    }

    const sessions = await Promise.all(sessionPromises);
    const end = performance.now();

    const totalDuration = end - start;

    console.log(
      `\nMobile/Desktop Concurrent Session Creation (${sessionCount} sessions):`,
    );
    console.log(`  Total time: ${totalDuration.toFixed(2)}ms`);
    console.log(
      `  Average time per session: ${(totalDuration / sessionCount).toFixed(2)}ms`,
    );

    // Performance assertion - all sessions should be created in reasonable time for mobile/desktop
    expect(totalDuration).toBeLessThan(10000); // 10 seconds for 10 sessions

    // Test sending messages across all sessions (simulating active multi-chat usage)
    const messageStart = performance.now();
    for (let i = 0; i < sessionCount; i++) {
      const encrypted = await alice.encryptMessage(
        sessions[i].aliceSession.sessionId,
        `Concurrent message to contact ${i}`,
      );
      await bobInstances[i].decryptMessage(
        sessions[i].bobSession.sessionId,
        encrypted,
      );
    }
    const messageEnd = performance.now();
    const messageDuration = messageEnd - messageStart;

    console.log(
      `  Message encryption/decryption across all sessions: ${messageDuration.toFixed(2)}ms`,
    );
    console.log(
      `  Average per session: ${(messageDuration / sessionCount).toFixed(2)}ms`,
    );

    // Performance assertion - all messages should be processed in reasonable time
    expect(messageDuration).toBeLessThan(5000); // 5 seconds for 10 sessions
  });

  it("should benchmark performance under sustained chat load", async () => {
    const alice = new Aegis(new SimulatedStorage());
    const bob = new Aegis(new SimulatedStorage());

    // Set up a session
    const aliceIdentity = await alice.createIdentity();
    const bobIdentity = await bob.createIdentity();

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

    // Simulate sustained chat activity over time
    const messageCount = 50; // Reduce count to focus on sustained performance
    const messageTypes = [
      "Short message",
      "This is a medium length message that contains more information than a short message.",
      "This is a longer message that might contain more detailed information, thoughts, or a story. It represents the kind of message that users might send when they're having a more in-depth conversation.",
      "Sustained message",
    ];

    const start = performance.now();

    for (let i = 0; i < messageCount; i++) {
      // Alternate between different message types
      const message = messageTypes[i % messageTypes.length];

      const encrypted = await alice.encryptMessage(
        aliceSession.sessionId,
        message,
      );
      await bob.decryptMessage(bobSession.sessionId, encrypted);

      // Simulate bidirectional chat
      const reply = await bob.encryptMessage(
        bobSession.sessionId,
        `Reply to message ${i}`,
      );
      await alice.decryptMessage(aliceSession.sessionId, reply);
    }

    const end = performance.now();
    const totalDuration = end - start;
    const avgDuration = totalDuration / (messageCount * 2); // 2 operations per iteration (send + reply)

    console.log(`\nMobile/Desktop Sustained Chat Load Benchmark:`);
    console.log(`  Total time: ${totalDuration.toFixed(2)}ms`);
    console.log(`  Total operations: ${messageCount * 2}`);
    console.log(`  Average time per operation: ${avgDuration.toFixed(2)}ms`);
    console.log(
      `  Operations per second: ${((messageCount * 2) / (totalDuration / 1000)).toFixed(2)}`,
    );

    // Performance assertion - sustained operations should remain efficient
    expect(avgDuration).toBeLessThan(50); // Less than 50ms per operation during sustained load
  });

  it("should benchmark performance with realistic mobile resource constraints", async () => {
    const alice = new Aegis(new SimulatedStorage());
    const bob = new Aegis(new SimulatedStorage());

    // Set up a session
    const aliceIdentity = await alice.createIdentity();
    const bobIdentity = await bob.createIdentity();

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

    // Simulate mobile chat with realistic message patterns and delays
    // representing network latency, battery saving, etc.
    const iterations = 100;
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      // Simulate variable message lengths
      const messageLength = Math.floor(Math.random() * 500) + 1; // 1-500 characters
      const message = "a".repeat(messageLength);

      const encrypted = await alice.encryptMessage(
        aliceSession.sessionId,
        message,
      );

      // Simulate mobile network delay
      await new Promise((resolve) => setTimeout(resolve, Math.random() * 10)); // 0-10ms network delay

      await bob.decryptMessage(bobSession.sessionId, encrypted);

      // Simulate user thinking time/battery saving in mobile apps
      if (i % 10 === 0) {
        // Every 10th message, simulate longer delay
        await new Promise((resolve) => setTimeout(resolve, 50)); // 50ms delay
      }
    }

    const end = performance.now();
    const totalDuration = end - start;
    const avgDuration = totalDuration / iterations;

    console.log(`\nMobile Chat with Resource Constraints Benchmark:`);
    console.log(`  Total time: ${totalDuration.toFixed(2)}ms`);
    console.log(`  Average time per operation: ${avgDuration.toFixed(2)}ms`);
    console.log(
      `  Operations per second: ${(iterations / (totalDuration / 1000)).toFixed(2)}`,
    );

    // Performance assertion - should still perform well under mobile constraints
    expect(avgDuration).toBeLessThan(60); // Less than 60ms per operation with mobile constraints
  });
});
