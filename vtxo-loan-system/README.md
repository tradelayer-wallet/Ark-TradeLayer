# VTXO Loan Contract System

A Bitcoin-native loan platform using **VTXOs** (Virtual Transaction Outputs), **DLCs** (Discreet Log Contracts), and cryptographic **oracles** for trustless lending.

## 🎯 Overview

This system enables peer-to-peer Bitcoin loans with the following properties:

- **Bitcoin-Native**: All settlements occur on Bitcoin (no wrapped tokens or bridges)
- **Privacy-Preserving**: DLC execution reveals minimal information on-chain
- **Instant Finality**: Cooperative paths settle immediately via Ark ASP
- **Non-Custodial**: Users maintain full control with unilateral exit options
- **Oracle-Verified**: External conditions (payments, prices) attested cryptographically

## 🏗️ Architecture

### Components

1. **Attestation Engine**: Creates and verifies cryptographic oracle signatures
2. **Event Witnesses**: Monitors real-world conditions (payments, prices, time)
3. **VTXO Contracts**: Arkade Script templates for various loan types
4. **Key Management**: Secure HD wallet with cloud HSM support
5. **Settlement Coordinator**: Manages cooperative and unilateral paths

### Loan Flow

```
┌─────────────┐
│  1. Request │  Borrower creates loan request
└──────┬──────┘
       │
┌──────▼────────┐
│ 2. Announce   │  Oracle pre-commits to future events
│    Events     │  (payment confirmation, price feeds)
└──────┬────────┘
       │
┌──────▼────────┐
│ 3. Create     │  Parties construct VTXO with:
│    VTXO       │  - Cooperative path (instant w/ server)
│               │  - Unilateral path (timelock exit)
└──────┬────────┘
       │
┌──────▼────────┐
│ 4. Fund       │  Lender provides principal
│    Contract   │  Borrower provides collateral (if applicable)
└──────┬────────┘
       │
┌──────▼────────┐
│ 5. Monitor    │  Event witnesses check conditions:
│    Conditions │  - Has borrower repaid?
│               │  - Is collateral value safe?
└──────┬────────┘
       │
┌──────▼────────┐
│ 6. Attest     │  Oracle signs observed outcomes
│               │  (payment received, price level, etc.)
└──────┬────────┘
       │
┌──────▼────────┐
│ 7. Settle     │  Parties use attestation to:
│               │  - Unlock conditional payments
│               │  - Execute winning outcome
│               │  - Close VTXO
└───────────────┘
```

## 🚀 Quick Start

### Prerequisites

```bash
# Install Node.js 18+
node --version

# Install MongoDB
mongod --version

# Install Redis
redis-server --version
```

### Installation

```bash
# Clone repository
git clone <repository-url>
cd vtxo-loan-system

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your settings
```

### Configuration

Create a `.env` file:

```bash
# Network
NETWORK=regtest
ORACLE_MODE=development

# Key Management
KEY_PROVIDER=local
MNEMONIC="your twelve word mnemonic phrase here"

# Database
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=vtxo-loans

# Redis
REDIS_HOST=127.0.0.1
REDIS_PORT=6379

# External Data (optional for development)
# COINGECKO_API_KEY=your-api-key
# ALCHEMY_API_KEY=your-api-key

# API
PUBLIC_API_PORT=3000
INTERNAL_API_PORT=3001
API_AUTH_KEY=dev-key-insecure

# Monitoring
LOG_LEVEL=info
```

### Running

```bash
# Development mode with hot reload
npm run dev

# Production mode
npm run build
npm start

# Run tests
npm test
```

## 📚 Usage Examples

### Example 1: Create a Collateralized Loan

```typescript
import { AttestationEngine } from "./src/attestation/attestation-engine";
import { PaymentWitness } from "./src/witness/event-witness";
import { loadConfig, getBitcoinNetwork } from "./src/config/system-config";
import { createKeyProvider } from "./src/keys/key-provider";

// Load configuration
const config = loadConfig();
const network = getBitcoinNetwork(config.network);

// Initialize attestation engine
const keyProvider = createKeyProvider(config.keys);
const engine = new AttestationEngine({
  network,
  keyProvider,
  usedNonceRegistryPath: config.usedNonceRegistryPath,
  usedNonceRegistryInit: config.usedNonceRegistryInit,
});
await engine.initialize();

// Create event announcement for payment verification
const paymentEvent = await engine.createAnnouncement(
  "loan-001-payment",
  {
    type: AttestationType.BINARY,
    outcomes: ["paid", "unpaid"],
  },
  Math.floor(Date.now() / 1000) + 86400 * 30 // 30 days
);

// Create event announcement for price monitoring
const priceEvent = await engine.createAnnouncement(
  "loan-001-btc-price",
  {
    type: AttestationType.NUMERIC,
    base: 2,
    numDigits: 18,
    unit: "USD",
    precision: 0,
    signed: false,
  },
  Math.floor(Date.now() / 1000) + 86400 * 30
);

// Set up payment witness
const paymentWitness = new PaymentWitness(
  {
    network: "ethereum",
    recipientAddress: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    expectedAmount: 10000, // 10,000 USDC
    asset: "USDC",
    fromBlock: 18000000,
  },
  blockchainClient
);

// Monitor for payment
const witnessResult = await paymentWitness.checkCondition();
if (witnessResult.conditionMet) {
  // Create attestation
  const attestation = await engine.attestBinary(paymentEvent, true);
  
  console.log("Payment confirmed and attested!");
  console.log("Attestation:", attestation);
}
```

### Example 2: Monitor Price Threshold

```typescript
import { ThresholdWitness } from "./src/witness/event-witness";

// Create threshold witness for liquidation monitoring
const thresholdWitness = new ThresholdWitness(
  {
    symbol: "BTC",
    threshold: 50000,
    direction: "below",
    currency: "USD",
  },
  priceClient
);

// Check if liquidation threshold hit
const result = await thresholdWitness.checkCondition();

if (result.conditionMet) {
  console.log(`BTC dropped below $50,000! Current: $${result.data.currentPrice}`);
  
  // Create attestation to trigger liquidation
  const attestation = await engine.attestBinary(priceEvent, true);
  
  // Lender can now use this attestation to claim collateral
}
```

### Example 3: Deploy VTXO Loan Contract

```typescript
import { VtxoFactory } from "./src/vtxo/vtxo-factory";
import { readFileSync } from "fs";

// Load Arkade contract template
const contractTemplate = readFileSync(
  "./contracts/CollateralizedLoan.ark",
  "utf8"
);

// Create VTXO instance
const vtxoFactory = new VtxoFactory(config);
const vtxo = await vtxoFactory.createLoanVtxo({
  lenderPubkey: lenderKey,
  borrowerPubkey: borrowerKey,
  serverPubkey: aspServerKey,
  oraclePubkey: engine.getPublicKey(),
  principalAmount: 100000000, // 1 BTC in satoshis
  collateralAmount: 150000000, // 1.5 BTC collateral
  maturityTime: Math.floor(Date.now() / 1000) + 86400 * 90, // 90 days
  exitDelay: 1008, // 1 week exit delay
  paymentEventId: paymentEvent.eventId,
  priceEventId: priceEvent.eventId,
});

console.log("VTXO Created!");
console.log("Locking Script:", vtxo.lockingScript);
console.log("Funding Address:", vtxo.fundingAddress);
```

### Example 4: Cooperative Settlement

```typescript
import { SettlementCoordinator } from "./src/dlc/settlement-coordinator";

// Initialize settlement coordinator
const coordinator = new SettlementCoordinator(config);

// Get attestation for repayment
const repaymentAttestation = await AttestationRecordModel.findOne({
  eventId: "loan-001-payment",
});

if (!repaymentAttestation) {
  throw new Error("Repayment not confirmed");
}

// Execute cooperative settlement
const settlement = await coordinator.settleCooperative({
  loanId: "loan-001",
  attestation: repaymentAttestation,
  lenderSignature: lenderSig,
  borrowerSignature: borrowerSig,
  serverSignature: serverSig,
});

console.log("Loan settled cooperatively!");
console.log("Settlement TX:", settlement.txid);
```

## 🔐 Security Considerations

### Key Management

**Development**: Use `local` provider with a development mnemonic
**Production**: Use `gcp` or `aws` provider with HSM-backed secret storage

```bash
# Production configuration
KEY_PROVIDER=gcp
CLOUD_PROJECT_ID=my-gcp-project
CLOUD_SECRET_ID=oracle-master-key
```

### Nonce Security

The system uses **deterministic nonce derivation** to prevent nonce reuse:

```
eventIdHash = sha256(utf8(eventId))                  // printable-ASCII event ids
index       = H_tag("DLC/oracle/nonce-index/v1", lenpfx(eventIdHash) || be32(i)) mod 2^31
nonce_key   = BIP32(m/585'/coin'/0'/0'/index')
k           = nonce_key + H_tag("DLC/oracle/nonce-tweak/v1", lenpfx(R_base) || lenpfx(eventIdHash))
```

- Each event has unique nonces
- Nonces are reproducible for signing
- The derivation-index hash and the nonce tweak use **separate domain tags**
- A **used-nonce registry** (`src/attestation/used-nonce-registry.ts`) is the
  fail-closed backstop: single-writer for the process lifetime, durable
  append-only history with a digest chain, and refusal to run on an
  in-memory-only registry outside development. Reusing a `k` across two
  messages leaks the oracle key (`x = (s1 - s2) / (e1 - e2)`), so a second
  writer or a deleted/truncated history is fatal at startup, never a warning.
  The registry is never created implicitly: a missing registry refuses to
  start. Set `USED_NONCE_REGISTRY_INIT=1` for the first start of a signer only,
  then unset it. The first creation also writes a marker, `<registry>.created`.
  While the marker exists, a missing registry is refused even with the flag:
  restore the registry from backup, and do not re-init. To move an existing
  registry, move its file and its `.anchor` together to `USED_NONCE_REGISTRY_PATH`
  with the same names; moving the file alone is refused.

### Oracle Trust

This system uses a **single oracle** for simplicity. For production:

1. **Use multi-oracle federations**: Require M-of-N oracle attestations
2. **Reputation systems**: Track oracle honesty over time
3. **Threshold schemes**: No single oracle can unlock funds alone

### VTXO Security

- **Timelock safety**: Ensure exit delays are sufficient for chain monitoring
- **Server availability**: Have fallback ASPs or increase exit delays
- **Fee bumping**: Reserve funds for fee escalation during unilateral exits

## 🧪 Testing

```bash
# Run all tests
npm test

# Run specific test suite
npm test -- attestation-engine

# Run with coverage
npm test -- --coverage

# Run integration tests
npm run test:integration
```

### Test Structure

```
tests/
├── unit/
│   ├── attestation-engine.test.ts
│   ├── event-witness.test.ts
│   ├── key-provider.test.ts
│   └── bitcoin-primitives.test.ts
├── integration/
│   ├── loan-flow.test.ts
│   ├── settlement.test.ts
│   └── oracle-coordination.test.ts
└── fixtures/
    ├── test-vectors.json
    └── sample-contracts.ts
```

## 📊 API Reference

### Attestation Engine

```typescript
class AttestationEngine {
  async initialize(): Promise<void>
  async createAnnouncement(
    eventId: string,
    descriptor: EventDescriptor,
    maturityTime: number
  ): Promise<EventAnnouncement>
  async attestNumeric(
    announcement: EventAnnouncement,
    value: number
  ): Promise<EventAttestation>
  async attestBinary(
    announcement: EventAnnouncement,
    outcome: boolean
  ): Promise<EventAttestation>
  async attestEnum(
    announcement: EventAnnouncement,
    outcomeIndex: number
  ): Promise<EventAttestation>
  verifyAttestation(
    announcement: EventAnnouncement,
    attestation: EventAttestation
  ): boolean
}
```

### Event Witnesses

```typescript
interface EventWitness<T> {
  checkCondition(): Promise<WitnessResult<T>>
  extractOutcome(result: WitnessResult<T>): string | number
  getDescription(): string
}

class PaymentWitness implements EventWitness<PaymentData>
class ThresholdWitness implements EventWitness<ThresholdData>
class TimeWitness implements EventWitness<TimeData>
class CompositeWitness implements EventWitness<CompositeData>
```

### Key Providers

```typescript
interface KeyProvider {
  deriveKey(path: string): Promise<Result<Buffer, Error>>
  getProviderType(): string
}

class LocalKeyProvider implements KeyProvider
class CloudKeyProvider implements KeyProvider
class MockKeyProvider implements KeyProvider
```

## 🛠️ Development

### Project Structure

```
vtxo-loan-system/
├── src/
│   ├── attestation/       # Oracle attestation logic
│   ├── witness/           # External condition monitoring
│   ├── crypto/            # Bitcoin primitives
│   ├── keys/              # Key management
│   ├── vtxo/              # VTXO construction
│   ├── dlc/               # DLC integration
│   ├── storage/           # Database schemas
│   ├── config/            # Configuration
│   └── api/               # REST API
├── contracts/             # Arkade Script templates
├── tests/                 # Test suites
├── docs/                  # Additional documentation
└── scripts/               # Utility scripts
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- **Ark Protocol**: VTXO design and specifications
- **node-dlc**: DLC implementation and messaging
- **Arkade**: Smart contract language and tooling
- **Bitcoin community**: Schnorr signatures, Taproot, and covenant research

## 📞 Support

- Documentation: See `/docs` folder
- Issues: GitHub issue tracker
- Community: [Discord/Telegram/etc.]

## 🗺️ Roadmap

- [x] Core attestation engine
- [x] VTXO contract templates
- [x] Payment and price witnesses
- [x] Basic key management
- [ ] Multi-oracle federation support
- [ ] Reputation tracking system
- [ ] Advanced covenant patterns
- [ ] Lightning Network integration
- [ ] Mobile SDK
- [ ] Web interface
