// src/index.ts
export { E2EE } from "./core";
export { MemoryStorage, IndexedDBStorage } from "./storage";
export { Logger } from "./logger";
export { KemRatchet } from "./ratchet";
export { SessionKeyExchange } from "./session";
export type {
  Identity,
  PublicBundle,
  Session,
  EncryptedMessage,
  StorageAdapter,
  PreKey,
  MessageHeader,
} from "./types";

// Core functions
export const createIdentity = async (storage: StorageAdapter) => {
  const e2ee = new E2EE(storage);
  return e2ee.createIdentity();
};

export const getPublicBundle = async (storage: StorageAdapter) => {
  const e2ee = new E2EE(storage);
  return e2ee.getPublicBundle();
};

export const createSession = async (
  storage: StorageAdapter,
  peerBundle: PublicBundle,
) => {
  const e2ee = new E2EE(storage);
  return e2ee.createSession(peerBundle);
};

export const createResponderSession = async (
  storage: StorageAdapter,
  peerBundle: PublicBundle,
  prekeyCiphertext: Uint8Array,
  initiatorConfirmationMac?: Uint8Array,
) => {
  const e2ee = new E2EE(storage);
  return e2ee.createResponderSession(
    peerBundle,
    prekeyCiphertext,
    initiatorConfirmationMac,
  );
};

export const confirmSession = async (
  storage: StorageAdapter,
  sessionId: string,
  responderConfirmationMac: Uint8Array,
) => {
  const e2ee = new E2EE(storage);
  return e2ee.confirmSession(sessionId, responderConfirmationMac);
};

export const encryptMessage = async (
  storage: StorageAdapter,
  sessionId: string,
  plaintext: string | Uint8Array,
) => {
  const e2ee = new E2EE(storage);
  return e2ee.encryptMessage(sessionId, plaintext);
};

export const decryptMessage = async (
  storage: StorageAdapter,
  sessionId: string,
  encrypted: EncryptedMessage,
) => {
  const e2ee = new E2EE(storage);
  return e2ee.decryptMessage(sessionId, encrypted);
};

export const rotateIdentity = async (storage: StorageAdapter) => {
  const e2ee = new E2EE(storage);
  return e2ee.rotateIdentity();
};

export const getSessions = async (storage: StorageAdapter) => {
  const e2ee = new E2EE(storage);
  return e2ee.getSessions();
};

export const getConfirmationMac = async (
  storage: StorageAdapter,
  sessionId: string,
) => {
  const e2ee = new E2EE(storage);
  return e2ee.getConfirmationMac(sessionId);
};

export const cleanupOldSessions = async (
  storage: StorageAdapter,
  maxAge?: number,
) => {
  const e2ee = new E2EE(storage);
  return e2ee.cleanupOldSessions(maxAge);
};

export const triggerRatchet = async (
  storage: StorageAdapter,
  sessionId: string,
) => {
  const e2ee = new E2EE(storage);
  return e2ee.triggerRatchet(sessionId);
};
