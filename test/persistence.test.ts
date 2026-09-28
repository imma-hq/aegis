import { describe, it, expect } from "vitest";
import { Aegis } from "../src/index";
import { ERRORS } from "../src/constants";
import type { Identity, Session, StorageAdapter } from "../src/types";

// A storage adapter that serializes everything to a plain object, so we can
// prove that identities and sessions survive a process restart (including the
// Uint8Array / Map / Set fields that a naive JSON round-trip would destroy).
class JsonStorage implements StorageAdapter {
  constructor(private backing: Record<string, string> = {}) {}

  private encode(value: unknown): string {
    return JSON.stringify(value, (_key, val) => {
      if (val instanceof Uint8Array) return { __t: "u8", d: Array.from(val) };
      if (val instanceof Map)
        return { __t: "map", d: Array.from(val.entries()) };
      if (val instanceof Set) return { __t: "set", d: Array.from(val) };
      return val;
    });
  }

  private decode<T>(text: string | undefined): T | null {
    if (text === undefined) return null;
    return JSON.parse(text, (_key, val) => {
      if (val && typeof val === "object" && "__t" in val) {
        if (val.__t === "u8") return new Uint8Array(val.d);
        if (val.__t === "map") return new Map(val.d);
        if (val.__t === "set") return new Set(val.d);
      }
      return val;
    }) as T;
  }

  async saveIdentity(identity: Identity): Promise<void> {
    this.backing.identity = this.encode(identity);
  }

  async getIdentity(): Promise<Identity | null> {
    return this.decode<Identity>(this.backing.identity);
  }

  async deleteIdentity(): Promise<void> {
    delete this.backing.identity;
  }

  async saveSession(sessionId: string, session: Session): Promise<void> {
    this.backing[`s:${sessionId}`] = this.encode(session);
  }

  async getSession(sessionId: string): Promise<Session | null> {
    return this.decode<Session>(this.backing[`s:${sessionId}`]);
  }

  async deleteSession(sessionId: string): Promise<void> {
    delete this.backing[`s:${sessionId}`];
  }

  async listSessions(): Promise<string[]> {
    return Object.keys(this.backing)
      .filter((key) => key.startsWith("s:"))
      .map((key) => key.slice(2));
  }

  async deleteAllSessions(): Promise<void> {
    for (const key of Object.keys(this.backing)) {
      if (key.startsWith("s:")) delete this.backing[key];
    }
  }
}

describe("Persistence across restart", () => {
  it("should continue a session after the process restarts", async () => {
    const aliceBacking: Record<string, string> = {};
    const bobBacking: Record<string, string> = {};

    // First "process"
    const alice1 = new Aegis(new JsonStorage(aliceBacking));
    const bob1 = new Aegis(new JsonStorage(bobBacking));

    const aliceIdentity = await alice1.createIdentity();
    const bobIdentity = await bob1.createIdentity();

    const aliceSession = await alice1.createSession(bobIdentity.publicBundle);
    const bobSession = await bob1.createResponderSession(
      aliceIdentity.publicBundle,
      aliceSession.ciphertext,
      aliceSession.confirmationMac,
    );
    await alice1.confirmSession(
      aliceSession.sessionId,
      bobSession.confirmationMac,
    );

    const before = await alice1.encryptMessage(
      aliceSession.sessionId,
      "before restart",
    );
    const beforePlain = await bob1.decryptMessage(bobSession.sessionId, before);
    expect(new TextDecoder().decode(beforePlain.plaintext)).toBe(
      "before restart",
    );

    // Restart: brand new Aegis instances over the same persisted backing stores
    const alice2 = new Aegis(new JsonStorage(aliceBacking));
    const bob2 = new Aegis(new JsonStorage(bobBacking));

    // Identity survived the restart
    const restoredIdentity = await alice2.getIdentity();
    expect(restoredIdentity.userId).toBe(aliceIdentity.identity.userId);

    // Session state survived: it still encrypts in both directions
    const after = await alice2.encryptMessage(
      aliceSession.sessionId,
      "after restart",
    );
    const afterPlain = await bob2.decryptMessage(bobSession.sessionId, after);
    expect(new TextDecoder().decode(afterPlain.plaintext)).toBe(
      "after restart",
    );

    const reply = await bob2.encryptMessage(
      bobSession.sessionId,
      "reply after restart",
    );
    const replyPlain = await alice2.decryptMessage(
      aliceSession.sessionId,
      reply,
    );
    expect(new TextDecoder().decode(replyPlain.plaintext)).toBe(
      "reply after restart",
    );
  });

  it("should preserve replay-protection state across a restart", async () => {
    const aliceBacking: Record<string, string> = {};
    const bobBacking: Record<string, string> = {};

    const alice1 = new Aegis(new JsonStorage(aliceBacking));
    const bob1 = new Aegis(new JsonStorage(bobBacking));

    const aliceIdentity = await alice1.createIdentity();
    const bobIdentity = await bob1.createIdentity();

    const aliceSession = await alice1.createSession(bobIdentity.publicBundle);
    const bobSession = await bob1.createResponderSession(
      aliceIdentity.publicBundle,
      aliceSession.ciphertext,
      aliceSession.confirmationMac,
    );
    await alice1.confirmSession(
      aliceSession.sessionId,
      bobSession.confirmationMac,
    );

    const message = await alice1.encryptMessage(
      aliceSession.sessionId,
      "only once",
    );
    await bob1.decryptMessage(bobSession.sessionId, message);

    // Restart bob, then replay the already-processed message
    const bob2 = new Aegis(new JsonStorage(bobBacking));
    await expect(
      bob2.decryptMessage(bobSession.sessionId, message),
    ).rejects.toThrow(ERRORS.DUPLICATE_MESSAGE);
  });
});
