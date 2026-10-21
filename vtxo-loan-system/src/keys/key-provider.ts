/**
 * Key Provider System
 * 
 * Provides secure key derivation across multiple backends:
 * - Local: In-memory HD wallet for development
 * - Cloud: HSM/KMS integration for production
 * - Mock: Deterministic keys for testing
 */

import { Result, ok, err } from "neverthrow";
import * as bip39 from "bip39";
import BIP32Factory, { BIP32Interface } from "bip32";
import * as ecc from "tiny-secp256k1";
import { inspect } from "util";
import { inspectRedacted, redactedView } from "../redaction";

const bip32 = BIP32Factory(ecc);

/**
 * Key provider interface - all implementations must satisfy this
 */
export interface KeyProvider {
  /**
   * Derives a key at the given HD path
   * @param path - BIP32 path (e.g., "m/84'/0'/0'/0/0")
   * @returns Private key or error
   */
  deriveKey(path: string): Promise<Result<Buffer, Error>>;

  /**
   * Returns the type of key provider for logging
   */
  getProviderType(): string;
}

/**
 * Configuration for local key provider
 */
export interface LocalKeyConfig {
  type: "local";
  /** BIP39 mnemonic phrase */
  mnemonic: string;
}

/**
 * Configuration for cloud HSM provider
 */
export interface CloudKeyConfig {
  type: "cloud";
  /** Cloud provider (e.g., "gcp", "aws") */
  provider: "gcp" | "aws";
  /** Project or account ID */
  projectId: string;
  /** Secret identifier for mnemonic */
  secretId: string;
}

/**
 * Configuration for mock provider
 */
export interface MockKeyConfig {
  type: "mock";
  /** Optional seed for deterministic generation */
  seed?: string;
}

export type KeyProviderConfig = LocalKeyConfig | CloudKeyConfig | MockKeyConfig;

/**
 * Creates a key provider based on configuration
 */
export function createKeyProvider(config: KeyProviderConfig): KeyProvider {
  switch (config.type) {
    case "local":
      return new LocalKeyProvider(config.mnemonic);
    case "cloud":
      return new CloudKeyProvider(config);
    case "mock":
      return new MockKeyProvider(config.seed);
    default:
      throw new Error(`Unknown key provider type: ${(config as any).type}`);
  }
}

/**
 * Local key provider using in-memory HD wallet
 */
export class LocalKeyProvider implements KeyProvider {
  private root: BIP32Interface;

  constructor(mnemonic: string) {
    if (!bip39.validateMnemonic(mnemonic)) {
      throw new Error("Invalid BIP39 mnemonic");
    }

    const seed = bip39.mnemonicToSeedSync(mnemonic);
    this.root = bip32.fromSeed(seed);
  }

  async deriveKey(path: string): Promise<Result<Buffer, Error>> {
    try {
      const child = this.root.derivePath(path);
      
      if (!child.privateKey) {
        return err(new Error(`No private key at path ${path}`));
      }

      return ok(child.privateKey);
    } catch (e) {
      return err(e instanceof Error ? e : new Error(String(e)));
    }
  }

  getProviderType(): string {
    return "local";
  }

  toJSON(): Record<string, unknown> {
    return redactedView({ keyProvider: this.getProviderType() }, ["root"]);
  }

  [inspect.custom](): string {
    return inspectRedacted("LocalKeyProvider", this.toJSON());
  }
}

/**
 * Cloud HSM provider (GCP/AWS)
 */
export class CloudKeyProvider implements KeyProvider {
  private config: CloudKeyConfig;
  private cachedRoot?: BIP32Interface;

  constructor(config: CloudKeyConfig) {
    this.config = config;
  }

  async deriveKey(path: string): Promise<Result<Buffer, Error>> {
    try {
      // Lazy load root from cloud secret
      if (!this.cachedRoot) {
        const mnemonicResult = await this.fetchMnemonic();
        if (mnemonicResult.isErr()) {
          return err(mnemonicResult.error);
        }

        const seed = bip39.mnemonicToSeedSync(mnemonicResult.value);
        this.cachedRoot = bip32.fromSeed(seed);
      }

      const child = this.cachedRoot.derivePath(path);
      
      if (!child.privateKey) {
        return err(new Error(`No private key at path ${path}`));
      }

      return ok(child.privateKey);
    } catch (e) {
      return err(e instanceof Error ? e : new Error(String(e)));
    }
  }

  /**
   * Fetches mnemonic from cloud secret manager
   */
  private async fetchMnemonic(): Promise<Result<string, Error>> {
    try {
      if (this.config.provider === "gcp") {
        return await this.fetchFromGCP();
      } else if (this.config.provider === "aws") {
        return await this.fetchFromAWS();
      }
      return err(new Error(`Unsupported provider: ${this.config.provider}`));
    } catch (e) {
      return err(e instanceof Error ? e : new Error(String(e)));
    }
  }

  /**
   * Fetches secret from GCP Secret Manager
   */
  private async fetchFromGCP(): Promise<Result<string, Error>> {
    try {
      // Dynamically import GCP client to avoid dependency if not used
      const { SecretManagerServiceClient } = await import("@google-cloud/secret-manager");
      const client = new SecretManagerServiceClient();

      const secretName = `projects/${this.config.projectId}/secrets/${this.config.secretId}/versions/latest`;
      const [version] = await client.accessSecretVersion({ name: secretName });
      
      const mnemonic = version.payload?.data?.toString("utf8");
      if (!mnemonic) {
        return err(new Error("Empty mnemonic from GCP Secret Manager"));
      }

      return ok(mnemonic);
    } catch (e) {
      return err(
        e instanceof Error
          ? e
          : new Error(`GCP Secret Manager error: ${String(e)}`)
      );
    }
  }

  /**
   * Fetches secret from AWS Secrets Manager
   */
  private async fetchFromAWS(): Promise<Result<string, Error>> {
    try {
      // Dynamically import AWS SDK to avoid dependency if not used
      const { SecretsManagerClient, GetSecretValueCommand } = await import(
        "@aws-sdk/client-secrets-manager"
      );
      
      const client = new SecretsManagerClient({});
      const command = new GetSecretValueCommand({
        SecretId: this.config.secretId,
      });
      
      const response = await client.send(command);
      const mnemonic = response.SecretString;
      
      if (!mnemonic) {
        return err(new Error("Empty mnemonic from AWS Secrets Manager"));
      }

      return ok(mnemonic);
    } catch (e) {
      return err(
        e instanceof Error
          ? e
          : new Error(`AWS Secrets Manager error: ${String(e)}`)
      );
    }
  }

  getProviderType(): string {
    return `cloud-${this.config.provider}`;
  }

  toJSON(): Record<string, unknown> {
    return redactedView({ keyProvider: this.getProviderType() }, ["cachedRoot"]);
  }

  [inspect.custom](): string {
    return inspectRedacted("CloudKeyProvider", this.toJSON());
  }
}

/**
 * Mock key provider for testing
 * 
 * Uses a deterministic seed for reproducible key generation
 */
export class MockKeyProvider implements KeyProvider {
  private root: BIP32Interface;
  private seed: string;

  constructor(seed?: string) {
    // Use test mnemonic if no seed provided
    this.seed = seed || "test test test test test test test test test test test junk";
    
    const mnemonicSeed = bip39.mnemonicToSeedSync(this.seed);
    this.root = bip32.fromSeed(mnemonicSeed);
  }

  async deriveKey(path: string): Promise<Result<Buffer, Error>> {
    try {
      const child = this.root.derivePath(path);
      
      if (!child.privateKey) {
        return err(new Error(`No private key at path ${path}`));
      }

      return ok(child.privateKey);
    } catch (e) {
      return err(e instanceof Error ? e : new Error(String(e)));
    }
  }

  getProviderType(): string {
    return "mock";
  }

  toJSON(): Record<string, unknown> {
    return redactedView({ keyProvider: this.getProviderType() }, ["root", "seed"]);
  }

  [inspect.custom](): string {
    return inspectRedacted("MockKeyProvider", this.toJSON());
  }

  /**
   * Gets the seed being used (for test verification)
   */
  getSeed(): string {
    return this.seed;
  }
}

/**
 * Utility: Generate a new random mnemonic
 */
export function generateMnemonic(strength: 128 | 256 = 256): string {
  return bip39.generateMnemonic(strength);
}

/**
 * Utility: Validate a mnemonic phrase
 */
export function validateMnemonic(mnemonic: string): boolean {
  return bip39.validateMnemonic(mnemonic);
}
