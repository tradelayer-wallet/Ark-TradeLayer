/**
 * Event Witness System
 * 
 * Monitors external conditions and determines when to create attestations.
 * Supports multiple witness types for different data sources.
 */

/**
 * Result of a witness check
 */
export interface WitnessResult<T = unknown> {
  /** Whether the condition was met */
  conditionMet: boolean;
  /** The witnessed data */
  data: T;
  /** Timestamp of the check */
  timestamp: Date;
  /** Source of the data */
  source: string;
  /** Optional confidence score (0-1) */
  confidence?: number;
}

/**
 * Interface that all event witnesses must implement
 */
export interface EventWitness<T = unknown> {
  /**
   * Checks if the witness condition is satisfied
   */
  checkCondition(): Promise<WitnessResult<T>>;

  /**
   * Extracts the attestable outcome from witness data
   */
  extractOutcome(result: WitnessResult<T>): string | number;

  /**
   * Gets a human-readable description of this witness
   */
  getDescription(): string;
}

/**
 * Configuration for payment witness
 */
export interface PaymentWitnessConfig {
  /** Blockchain network (e.g., "ethereum", "bitcoin") */
  network: string;
  /** Expected recipient address */
  recipientAddress: string;
  /** Expected payment amount */
  expectedAmount: number;
  /** Asset/token identifier (e.g., "USDC", "BTC") */
  asset: string;
  /** Starting block for monitoring */
  fromBlock: number;
  /** Tolerance for amount matching (default 1%) */
  tolerance?: number;
}

/**
 * Payment witness - monitors blockchain for payment confirmation
 */
export class PaymentWitness implements EventWitness<PaymentData> {
  private config: PaymentWitnessConfig;
  private blockchainClient: BlockchainClient;

  constructor(config: PaymentWitnessConfig, client: BlockchainClient) {
    // A zero amount is met by an empty transfer list (totalReceived >= 0), so it
    // would report "paid" with no payment at all.
    if (!(Number.isFinite(config.expectedAmount) && config.expectedAmount > 0)) {
      throw new Error("PaymentWitness: expectedAmount must be a positive number");
    }
    this.config = config;
    this.blockchainClient = client;
  }

  async checkCondition(): Promise<WitnessResult<PaymentData>> {
    const transfers = await this.blockchainClient.getTransfers({
      network: this.config.network,
      toAddress: this.config.recipientAddress,
      asset: this.config.asset,
      fromBlock: this.config.fromBlock,
    });

    let totalReceived = 0;
    let matchingTransfer: Transfer | undefined;

    for (const transfer of transfers) {
      totalReceived += transfer.amount;

      // Check if this transfer matches the expected amount
      const tolerance = this.config.tolerance ?? 0.01;
      const difference = Math.abs(transfer.amount - this.config.expectedAmount);
      const percentDiff = difference / this.config.expectedAmount;

      if (percentDiff <= tolerance) {
        matchingTransfer = transfer;
        break;
      }
    }

    const conditionMet = !!matchingTransfer || totalReceived >= this.config.expectedAmount;

    return {
      conditionMet,
      data: {
        transfers,
        totalReceived,
        expectedAmount: this.config.expectedAmount,
        matchingTransfer,
      },
      timestamp: new Date(),
      source: `${this.config.network}-blockchain`,
      confidence: conditionMet ? 1.0 : 0.0,
    };
  }

  extractOutcome(result: WitnessResult<PaymentData>): string {
    return result.conditionMet ? "paid" : "unpaid";
  }

  getDescription(): string {
    return `Payment of ${this.config.expectedAmount} ${this.config.asset} to ${this.config.recipientAddress} on ${this.config.network}`;
  }
}

export interface PaymentData {
  transfers: Transfer[];
  totalReceived: number;
  expectedAmount: number;
  matchingTransfer?: Transfer;
}

export interface Transfer {
  from: string;
  to: string;
  amount: number;
  transactionHash: string;
  blockNumber: number;
  timestamp: Date;
}

/**
 * Configuration for threshold witness
 */
export interface ThresholdWitnessConfig {
  /** Asset symbol (e.g., "BTC", "ETH") */
  symbol: string;
  /** Threshold value */
  threshold: number;
  /** Direction: "above" or "below" */
  direction: "above" | "below";
  /** Quote currency (e.g., "USD") */
  currency?: string;
}

/**
 * Threshold witness - monitors if price/value crosses a threshold
 */
export class ThresholdWitness implements EventWitness<ThresholdData> {
  private config: ThresholdWitnessConfig;
  private priceClient: PriceClient;

  constructor(config: ThresholdWitnessConfig, client: PriceClient) {
    this.config = config;
    this.priceClient = client;
  }

  async checkCondition(): Promise<WitnessResult<ThresholdData>> {
    const priceData = await this.priceClient.getPrice(
      this.config.symbol,
      this.config.currency ?? "USD"
    );

    let conditionMet: boolean;
    if (this.config.direction === "above") {
      conditionMet = priceData.price >= this.config.threshold;
    } else {
      conditionMet = priceData.price <= this.config.threshold;
    }

    return {
      conditionMet,
      data: {
        currentPrice: priceData.price,
        threshold: this.config.threshold,
        direction: this.config.direction,
        priceData,
      },
      timestamp: new Date(),
      source: priceData.source,
      confidence: 1.0, // Price feeds are generally reliable
    };
  }

  extractOutcome(result: WitnessResult<ThresholdData>): string {
    return result.conditionMet ? "hit" : "miss";
  }

  getDescription(): string {
    return `${this.config.symbol} price ${this.config.direction} ${this.config.threshold} ${this.config.currency}`;
  }
}

export interface ThresholdData {
  currentPrice: number;
  threshold: number;
  direction: "above" | "below";
  priceData: PriceData;
}

export interface PriceData {
  symbol: string;
  price: number;
  currency: string;
  timestamp: Date;
  source: string;
}

/**
 * Configuration for time-based witness
 */
export interface TimeWitnessConfig {
  /** Target timestamp (Unix epoch seconds) */
  targetTime: number;
  /** Type of time check */
  type: "before" | "after" | "exact";
}

/**
 * Time witness - triggers based on time conditions
 */
export class TimeWitness implements EventWitness<TimeData> {
  private config: TimeWitnessConfig;

  constructor(config: TimeWitnessConfig) {
    this.config = config;
  }

  async checkCondition(): Promise<WitnessResult<TimeData>> {
    const currentTime = Math.floor(Date.now() / 1000);
    
    let conditionMet: boolean;
    switch (this.config.type) {
      case "before":
        conditionMet = currentTime < this.config.targetTime;
        break;
      case "after":
        conditionMet = currentTime >= this.config.targetTime;
        break;
      case "exact":
        // Within 60 seconds of target
        conditionMet = Math.abs(currentTime - this.config.targetTime) <= 60;
        break;
    }

    return {
      conditionMet,
      data: {
        currentTime,
        targetTime: this.config.targetTime,
        type: this.config.type,
      },
      timestamp: new Date(),
      source: "system-clock",
      confidence: 1.0,
    };
  }

  extractOutcome(result: WitnessResult<TimeData>): string {
    return result.conditionMet ? "triggered" : "pending";
  }

  getDescription(): string {
    const targetDate = new Date(this.config.targetTime * 1000);
    return `Time ${this.config.type} ${targetDate.toISOString()}`;
  }
}

export interface TimeData {
  currentTime: number;
  targetTime: number;
  type: "before" | "after" | "exact";
}

/**
 * Composite witness - combines multiple witnesses with AND/OR logic
 */
export class CompositeWitness implements EventWitness<CompositeData> {
  private witnesses: EventWitness[];
  private logic: "and" | "or";

  constructor(witnesses: EventWitness[], logic: "and" | "or" = "and") {
    // Over no members, AND is vacuously satisfied: an empty composite would
    // report "satisfied" without any evidence.
    if (witnesses.length === 0) {
      throw new Error("CompositeWitness needs at least one witness");
    }
    this.witnesses = witnesses;
    this.logic = logic;
  }

  async checkCondition(): Promise<WitnessResult<CompositeData>> {
    const results = await Promise.all(
      this.witnesses.map((w) => w.checkCondition())
    );

    let conditionMet: boolean;
    if (this.logic === "and") {
      conditionMet = results.every((r) => r.conditionMet);
    } else {
      conditionMet = results.some((r) => r.conditionMet);
    }

    // Calculate combined confidence (average)
    const avgConfidence =
      results.reduce((sum, r) => sum + (r.confidence ?? 1), 0) / results.length;

    return {
      conditionMet,
      data: {
        results,
        logic: this.logic,
      },
      timestamp: new Date(),
      source: "composite",
      confidence: avgConfidence,
    };
  }

  extractOutcome(result: WitnessResult<CompositeData>): string {
    return result.conditionMet ? "satisfied" : "unsatisfied";
  }

  getDescription(): string {
    const descriptions = this.witnesses.map((w) => w.getDescription());
    return descriptions.join(` ${this.logic.toUpperCase()} `);
  }
}

export interface CompositeData {
  results: WitnessResult[];
  logic: "and" | "or";
}

/**
 * Blockchain client interface for payment witness
 */
export interface BlockchainClient {
  getTransfers(params: {
    network: string;
    toAddress: string;
    asset: string;
    fromBlock: number;
  }): Promise<Transfer[]>;
}

/**
 * Price client interface for threshold witness
 */
export interface PriceClient {
  getPrice(symbol: string, currency: string): Promise<PriceData>;
}
