import { utf8ToBytes } from "@noble/hashes/utils.js";

export const CONTEXT_MSG_KEY = utf8ToBytes("msg_key");
export const CONTEXT_CHAIN_KEY = utf8ToBytes("chain_key");
export const CONTEXT_CONFIRMATION = utf8ToBytes("key_confirmation");
export const CONTEXT_CONFIRMATION_RESPONSE = utf8ToBytes(
  "key_confirmation_response",
);

// Session states
export const SESSION_STATES = {
  CREATED: "CREATED",
  KEY_CONFIRMED: "KEY_CONFIRMED",
  ACTIVE: "ACTIVE",
  RATCHET_PENDING: "RATCHET_PENDING",
  ERROR: "ERROR",
} as const;

// Error messages
export const ERRORS = {
  IDENTITY_NOT_FOUND: "Identity not found",
  SESSION_NOT_FOUND: "Session not found",
  INVALID_PREKEY_SIGNATURE: "Invalid prekey signature",
  INVALID_MESSAGE_SIGNATURE: "Invalid message signature",
  REPLAY_ATTACK: "Possible replay attack - message number too low",
  INVALID_PEER_BUNDLE: "Invalid peer bundle",
  MESSAGE_TOO_OLD: "Message is too old to process",
  SESSION_NOT_CONFIRMED: "Session keys not confirmed",
  INVALID_SESSION_STATE: "Invalid session state",
  RATCHET_CIPHERTEXT_MISSING: "KEM ratchet ciphertext missing",
  KEY_CONFIRMATION_FAILED: "Key confirmation failed",

  // Simple replay protection errors
  DUPLICATE_MESSAGE: "Duplicate message detected",
  MESSAGE_TOO_OLD_TIMESTAMP: "Message timestamp is too old",
} as const;

// KEM constants
export const ML_KEM768_PUBLIC_KEY_LENGTH = 1184;
export const ML_KEM768_SECRET_KEY_LENGTH = 2400;
export const ML_KEM768_CIPHERTEXT_LENGTH = 1088;

// Ratchet constants
export const RATCHET_AFTER_MESSAGES = 50;
export const MAX_SKIPPED_MESSAGES = 100;
export const KEY_CONFIRMATION_TIMEOUT = 30000; // 30 seconds

// Simple replay protection constants
export const REPLAY_WINDOW_SIZE = 100; // Accept messages up to 100 behind current
export const MAX_MESSAGE_AGE = 5 * 60 * 1000; // 5 minutes maximum message age
export const MAX_STORED_MESSAGE_IDS = 1000; // Store last 1000 message IDs
