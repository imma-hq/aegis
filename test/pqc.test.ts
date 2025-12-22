import { describe, it, expect, beforeEach } from "vitest";
import {
  createIdentity,
  loadIdentity,
  saveIdentity,
  deleteIdentity,
  getPublicKeyBundle,
  encapsulate,
  decapsulate,
} from "../src/pqc";
import { Aegis } from "../src/config";
import { MockStorage } from "./setup";
import { bytesToHex } from "../src/crypto";

describe("PQC / Identity", () => {
  let mockStorage: MockStorage;

  beforeEach(() => {
    mockStorage = new MockStorage();
    Aegis.init({ storage: mockStorage });
  });

  it("should create and save a new identity", async () => {
    const id = await createIdentity("user1", "email", "test@test.com");
    expect(id.userId).toBe("user1");
    expect(id.identifier).toBe("test@test.com");
    expect(id.kem.publicKey.length).toBeGreaterThan(0);
    expect(id.sig.publicKey.length).toBeGreaterThan(0);

    const loaded = await loadIdentity();
    expect(loaded).toBeTruthy();
    expect(loaded?.userId).toBe("user1");
    // Check key persistence
    expect(bytesToHex(loaded!.kem.secretKey)).toBe(
      bytesToHex(id.kem.secretKey)
    );
  });

  it("should delete identity", async () => {
    await createIdentity("user1", "email", "test@test.com");
    await deleteIdentity();
    const loaded = await loadIdentity();
    expect(loaded).toBeNull();
  });

  it("should provide public key bundle", async () => {
    const id = await createIdentity("user1", "email", "test@test.com");
    const bundle = await getPublicKeyBundle();

    // Bundle is base64
    expect(bundle.userId).toBe("user1");
    expect(bundle.kemPublicKey).toBeTruthy();
    expect(typeof bundle.kemPublicKey).toBe("string");
  });

  it("should perform KEM encapsulation/decapsulation correctly", async () => {
    const id = await createIdentity("alice", "email", "a@a.com");

    // Bob encapsulates to Alice
    const result = encapsulate(id.kem.publicKey);
    expect(result.sharedSecret).toHaveLength(32);
    expect(result.ciphertext).toBeTruthy();

    // Alice decapsulates
    const sharedSecret = decapsulate(result.ciphertext, id.kem.secretKey);

    expect(bytesToHex(sharedSecret)).toBe(bytesToHex(result.sharedSecret));
  });
});
