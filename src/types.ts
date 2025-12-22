export interface PQKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export type AuthMethod = "phone" | "email";

export interface UserIdentity {
  kem: PQKeyPair;
  sig: PQKeyPair;
  userId: string;
  authMethod: AuthMethod;
  identifier: string;
  createdAt: number;
  version: string;
}

export interface TheirIdentity {
  kem: {
    publicKey: Uint8Array;
  };
  sig: {
    publicKey: Uint8Array;
  };
}

export interface ServerKeyBundle {
  kem_public_key: string;
  sig_public_key: string;
  signed_pre_key: string;
  signed_pre_key_signature: string;
  one_time_pre_keys: string[];
  device_id: string;
  device_fingerprint: string;
}

export interface EncryptedMessagePayload {
  session_id: string;
  ciphertext: string;
  nonce: string;
  signature: string;
  sequence: number;
  additional_data?: string;
}

export interface SessionInitiationRequest {
  their_user_id: string;
  their_device_id?: string;
  initiation_data: {
    session_id: string;
    ephemeral_public_key: string;
    ciphertext: string;
    signature: string;
    initiator_kem_public_key: string;
    initiator_sig_public_key: string;
  };
}

/**
 * Interface that must be implemented by the host application
 * to provide secure storage for keys and session data.
 */
export interface StorageAdapter {
  /**
   * Store a value securely.
   * On mobile, this should use EncryptedStorage or Keychain/Keystore.
   * On web, this might use IndexedDB with encryption.
   */
  setItem(key: string, value: string): Promise<void>;

  /**
   * Retrieve a value from secure storage.
   */
  getItem(key: string): Promise<string | null>;

  /**
   * Delete a value from secure storage.
   */
  removeItem(key: string): Promise<void>;
}
