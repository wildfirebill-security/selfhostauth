/**
 * Shared domain types: vault items and API contracts.
 * These are used by the server, desktop, mobile, and extension apps.
 */
import { TOTPParams } from "./totp.js";

export type VaultItemType = "totp" | "hotp";

/** A single authenticator entry (TOTP/HOTP). */
export interface VaultItem {
  /** Client-generated UUIDv4. */
  id: string;
  type: VaultItemType;
  /** Display name (e.g. "GitHub") */
  name: string;
  /** Issuer for otpauth URIs (e.g. "GitHub") */
  issuer?: string;
  /** Account / username / email */
  account?: string;
  /** TOTP parameters — secret is SERVER-ENCRYPTED (AES-256-GCM). */
  params: TOTPParams;
  /** Optional icon name/emoji */
  icon?: string;
  /** Optional user note (plain text) */
  note?: string;
  /** Unix ms timestamps (server-authoritative) */
  createdAt: number;
  updatedAt: number;
  /** Soft-delete marker for sync tombstoning */
  deletedAt?: number;
  /** Last client that modified this item */
  lastModifiedBy?: string;
}

/** Server-side encrypted wrapper for a vault item's secret. */
export interface EncryptedVaultItem extends Omit<VaultItem, "params"> {
  params: {
    /** AES-256-GCM encrypted JSON of TOTPParams */
    secret: string;
    algorithm: string;
    digits: number;
    period: number;
  };
}

export interface UserProfile {
  id: string;
  username: string;
  createdAt: number;
}

export interface AuthResponse {
  token: string;
  user: UserProfile;
}

export interface SyncPushRequest {
  /** Full client items with tombstones. Server merges by id+updatedAt. */
  items: VaultItem[];
  /** Client's current server revision (0 for initial push). */
  baseRevision: number;
}

export interface SyncPushResponse {
  /** New server revision after merge. */
  revision: number;
  /** Items the server accepted/changed (re-encrypted or overwritten). */
  conflicts: VaultItem[];
}

export interface SyncPullRequest {
  sinceRevision: number;
}

export interface SyncPullResponse {
  revision: number;
  /** Items changed since revision (encrypted params on the wire). */
  items: EncryptedVaultItem[];
  /** Items deleted since revision. */
  deleted: Array<{ id: string; deletedAt: number }>;
}

export interface ServerInfo {
  name: string;
  version: string;
  features: {
    sync: boolean;
    totpVerify: boolean;
    registration: boolean;
  };
}

export interface AccountTotpSetup {
  /** otpauth URI for the user's 2FA (already enabled after confirm). */
  uri: string;
  secret: string;
}

export interface ApiError {
  error: string;
  message: string;
  status: number;
}

export const API_VERSION = "v1";