/**
 * Typed HTTP client for the selfhostauth server.
 * Zero dependencies — uses global fetch (Node 18+, browsers, Electron).
 */
import {
  API_VERSION,
  AuthResponse,
  ServerInfo,
  SyncPullResponse,
  SyncPushRequest,
  SyncPushResponse,
  VaultItem,
  AccountTotpSetup,
} from "@selfhostauth/core";

export interface ClientOptions {
  baseUrl: string;
  token?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export class ApiClientError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
  ) {
    super(message);
    this.name = "ApiClientError";
  }
}

export class SelfhostAuthClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  token: string | null;

  constructor(options: ClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.token = options.token ?? null;
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.fetchImpl = options.fetchImpl ?? fetch.bind(globalThis);
  }

  private url(path: string): string {
    return `${this.baseUrl}/api/${API_VERSION}${path}`;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(this.url(path), {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await res.text();
      let json: unknown = null;
      if (text) {
        try {
          json = JSON.parse(text);
        } catch {
          /* non-JSON error body */
        }
      }
      if (!res.ok) {
        const err = (json as { error?: string; message?: string }) ?? {};
        throw new ApiClientError(
          err.message ?? `Request failed with status ${res.status}`,
          res.status,
          err.error,
        );
      }
      return json as T;
    } catch (e) {
      if (e instanceof ApiClientError) throw e;
      if (e instanceof Error && e.name === "AbortError") {
        throw new ApiClientError(`Request timed out after ${this.timeoutMs}ms`, 408, "timeout");
      }
      throw new ApiClientError(
        `Network error connecting to ${this.baseUrl}: ${e instanceof Error ? e.message : String(e)}`,
        0,
        "network",
      );
    } finally {
      clearTimeout(timer);
    }
  }

  // ---------------------------------------------------------------- auth

  async serverInfo(): Promise<ServerInfo> {
    return this.request<ServerInfo>("GET", "/info");
  }

  async register(username: string, password: string): Promise<AuthResponse> {
    const res = await this.request<AuthResponse>("POST", "/auth/register", { username, password });
    this.token = res.token;
    return res;
  }

  async login(username: string, password: string): Promise<AuthResponse> {
    const res = await this.request<AuthResponse>("POST", "/auth/login", { username, password });
    this.token = res.token;
    return res;
  }

  /** Begin 2FA enrollment (requires valid session). */
  async setupTotp2fa(): Promise<AccountTotpSetup> {
    return this.request<AccountTotpSetup>("POST", "/auth/2fa/setup");
  }

  /** Confirm 2FA enrollment with a code. */
  async confirmTotp2fa(code: string): Promise<{ enabled: boolean }> {
    return this.request<{ enabled: boolean }>("POST", "/auth/2fa/confirm", { code });
  }

  /** Login with 2FA code (adds `X-2fa-code` claim). */
  async login2fa(username: string, password: string, code: string): Promise<AuthResponse> {
    const res = await this.request<AuthResponse>("POST", "/auth/login", { username, password, totpCode: code });
    this.token = res.token;
    return res;
  }

  // ---------------------------------------------------------------- vault

  /** Full sync pull since a revision. */
  async pull(sinceRevision: number): Promise<SyncPullResponse> {
    return this.request<SyncPullResponse>("GET", `/sync/pull?since=${sinceRevision}`);
  }

  /** Push local items; server merges and returns conflicts/revision. */
  async push(req: SyncPushRequest): Promise<SyncPushResponse> {
    return this.request<SyncPushResponse>("POST", "/sync/push", req);
  }

  /** Add a single item. */
  async addItem(item: VaultItem): Promise<{ revision: number; item: VaultItem }> {
    return this.request("POST", "/vault/items", item);
  }

  /** Update a single item. */
  async updateItem(item: VaultItem): Promise<{ revision: number; item: VaultItem }> {
    return this.request("PUT", `/vault/items/${item.id}`, item);
  }

  /** Soft-delete a single item. */
  async deleteItem(id: string): Promise<{ revision: number }> {
    return this.request("DELETE", `/vault/items/${id}`);
  }

  /** Server-side TOTP validation (useful for testing / CI). */
  async verifyCode(id: string, code: string): Promise<{ valid: boolean }> {
    return this.request("POST", `/vault/items/${id}/verify`, { code });
  }
}