// src/index.ts
export { E2EE } from "./core";
export { MemoryStorage, IndexedDBStorage } from "./storage";
export { Logger } from "./logger";
export { KemRatchet } from "./ratchet";
export { SessionKeyExchange } from "./session";
// Core functions
export const createIdentity = async (storage) => {
    const e2ee = new E2EE(storage);
    return e2ee.createIdentity();
};
export const getPublicBundle = async (storage) => {
    const e2ee = new E2EE(storage);
    return e2ee.getPublicBundle();
};
export const createSession = async (storage, peerBundle) => {
    const e2ee = new E2EE(storage);
    return e2ee.createSession(peerBundle);
};
export const createResponderSession = async (storage, peerBundle, prekeyCiphertext, initiatorConfirmationMac) => {
    const e2ee = new E2EE(storage);
    return e2ee.createResponderSession(peerBundle, prekeyCiphertext, initiatorConfirmationMac);
};
export const confirmSession = async (storage, sessionId, responderConfirmationMac) => {
    const e2ee = new E2EE(storage);
    return e2ee.confirmSession(sessionId, responderConfirmationMac);
};
export const encryptMessage = async (storage, sessionId, plaintext) => {
    const e2ee = new E2EE(storage);
    return e2ee.encryptMessage(sessionId, plaintext);
};
export const decryptMessage = async (storage, sessionId, encrypted) => {
    const e2ee = new E2EE(storage);
    return e2ee.decryptMessage(sessionId, encrypted);
};
export const rotateIdentity = async (storage) => {
    const e2ee = new E2EE(storage);
    return e2ee.rotateIdentity();
};
export const getSessions = async (storage) => {
    const e2ee = new E2EE(storage);
    return e2ee.getSessions();
};
export const getConfirmationMac = async (storage, sessionId) => {
    const e2ee = new E2EE(storage);
    return e2ee.getConfirmationMac(sessionId);
};
export const cleanupOldSessions = async (storage, maxAge) => {
    const e2ee = new E2EE(storage);
    return e2ee.cleanupOldSessions(maxAge);
};
export const triggerRatchet = async (storage, sessionId) => {
    const e2ee = new E2EE(storage);
    return e2ee.triggerRatchet(sessionId);
};
