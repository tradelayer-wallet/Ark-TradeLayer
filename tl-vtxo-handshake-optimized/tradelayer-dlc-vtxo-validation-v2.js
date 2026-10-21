/**
 * DLC/VTXO Validation for TradeLayer (Updated to Handshake Spec v0.1)
 * 
 * This uses the cleaner approach from the Ark-TradeLayer handshake spec:
 * - Template allowlist for canonicity
 * - Simple deposit recognition (taprootOutputKey matching)
 * - Exit validation (script-path spend verification)
 */

const TxUtils = require('./txUtils.js');
const PropertyList = require('./property.js');
const TallyMap = require('./tally.js');
const { ArkTradeLayerBridge } = require('./arkTradeLayerHandshake.js');

// Singleton bridge instance
const arkBridge = new ArkTradeLayerBridge();

/**
 * Initialize default Ark templates
 */
function initializeDefaultTemplates() {
  // Example template for a standard Ark VTXO
  const standardArkTemplate = {
    version: 1,
    network: 'bitcoin-mainnet',
    
    // These would be provided by the ASP
    internalKey: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    
    leafScripts: [
      // Leaf 0: Batch settlement (User + Server cooperative)
      '20<user_pk>ac20<server_pk>ac',
      
      // Leaf 1: User exit (User + CSV)
      '20<user_pk>ac02f003b2', // <user_pk> CHECKSIGVERIFY 1008 CSV
      
      // Leaf 2: ASP forfeit (Server + CSV)
      '20<server_pk>ac02d007b2' // <server_pk> CHECKSIGVERIFY 2000 CSV
    ],
    
    leafVersions: [0xc0, 0xc0, 0xc0],
    
    leafRoles: ['batch-settle', 'user-exit', 'asp-forfeit'],
    
    timeouts: {
      userExitCsv: 1008,  // ~1 week
      aspForfeitCsv: 2000 // ~2 weeks
    },
    
    semantics: {
      batchSettle: 'Cooperative spend by user and server',
      userExit: 'Unilateral user exit after CSV timeout',
      aspForfeit: 'Server claims funds if user misbehaves'
    },
    
    // These are computed from above
    merkleRoot: '0000000000000000000000000000000000000000000000000000000000000000', // Placeholder
    taprootOutputKey: '0000000000000000000000000000000000000000000000000000000000000000' // Placeholder
  };

  // In production, compute real merkleRoot and taprootOutputKey
  // Then register with ASP identity
  try {
    const templateId = arkBridge.registerTemplate(
      standardArkTemplate,
      'ark.example.com' // ASP identity
    );
    console.log('[Init] Registered standard Ark template:', templateId);
  } catch (error) {
    console.warn('[Init] Could not register template:', error.message);
  }
}

// Initialize on module load
initializeDefaultTemplates();

/**
 * Extended DLC/VTXO Validation using Handshake Spec
 */
const DLCVTXOValidation = {
  
  /**
   * Validates DLC/VTXO token minting (ARK_WRAP_MINT transaction)
   * 
   * From spec:
   * "User posts ARK_WRAP_MINT TL transaction with:
   *  - templateId
   *  - aspId
   *  - deposit txid:vout
   *  - valueSats
   *  - userVtxoId
   *  - userArkProofHash
   * 
   * TL consensus checks templateId allowlist + onchain UTXO validity."
   */
  validateDLCVTXOMint: async (sender, params, txid) => {
    // Reject-then-validate (H6): fail closed unless every check passes.
    params.valid = false;
    params.reason = 'Validation incomplete';

    console.log('[DLC/VTXO] Validating ARK_WRAP_MINT:', params);

    try {
      // 1. Verify this is a DLC/VTXO token type
      if (params.type !== 'dlc-vtxo' && params.type !== 'ark-vtxo') {
        params.reason = 'Not a DLC/VTXO or ARK-VTXO token type';
        return params;
      }

      // 2. Validate the mint amount before any comparison/arithmetic (H6)
      const valueSats = params.initialAmount;
      if (!Number.isSafeInteger(valueSats) || valueSats <= 0) {
        params.reason = 'Invalid mint amount: must be a positive safe integer (satoshis)';
        return params;
      }

      // 3. Validate using Ark bridge
      const validation = await arkBridge.validateMint({
        templateId: params.templateId,
        aspId: params.aspId,
        depositTxid: params.fundingTxid || params.depositTxid,
        depositVout: params.fundingVout || params.depositVout,
        valueSats: valueSats
      });

      if (!validation.valid) {
        params.reason = validation.reason || validation.error;
        return params;
      }

      console.log('[DLC/VTXO] Mint validation successful');

      // 4. Store additional metadata
      params.commitment = validation.commitment;
      params.taprootOutputKey = validation.commitment.taprootOutputKey;

      params.valid = true;
      params.reason = '';
      return params;

    } catch (error) {
      console.error('[DLC/VTXO] Mint validation error:', error);
      params.valid = false;
      params.reason = `Validation error: ${error.message}`;
      return params;
    }
  },

  /**
   * Validates DLC/VTXO token burning (redemption via exit spend)
   * 
   * From spec:
   * "Exit spends appear as Taproot scriptpath spends. TL protocol parses:
   *  - leaf script
   *  - control block
   *  - merkle path
   *  - checks taprootOutputKey reconstructed from leaf matches templateId
   * 
   * TL marks redeem as complete."
   */
  validateDLCVTXOBurn: async (sender, params, txid) => {
    // Reject-then-validate (H6): fail closed unless every check passes.
    params.valid = false;
    params.reason = 'Validation incomplete';

    console.log('[DLC/VTXO] Validating burn/redeem:', params);

    try {
      // 1. Validate the burn amount before any comparison/arithmetic (H6)
      const burnAmount = params.amount;
      if (!Number.isSafeInteger(burnAmount) || burnAmount <= 0) {
        params.reason = 'Invalid burn amount: must be a positive safe integer (satoshis)';
        return params;
      }

      // 2. Verify user has sufficient balance
      const balance = await TallyMap.getTally(sender, params.propertyId);
      const available = balance ? balance.available : 0;
      if (!Number.isSafeInteger(available) || available < burnAmount) {
        params.reason = `Insufficient balance (have: ${balance?.available || 0}, need: ${burnAmount})`;
        return params;
      }

      // 3. Get token metadata
      const tokenData = await PropertyList.getPropertyData(params.propertyId);
      if (!tokenData || (tokenData.type !== 'dlc-vtxo' && tokenData.type !== 'ark-vtxo')) {
        params.reason = 'Token is not DLC/VTXO or ARK-VTXO type';
        return params;
      }

      // 4. Verify redemption transaction is provided
      if (!params.redemptionTxid && !params.redeemTxid) {
        params.reason = 'Redemption transaction required';
        return params;
      }

      const redeemTxid = params.redemptionTxid || params.redeemTxid;

      // 5. Validate using Ark bridge
      const validation = await arkBridge.validateBurn({
        templateId: tokenData.templateId,
        aspId: tokenData.aspId,
        depositTxid: tokenData.fundingTxid || tokenData.depositTxid,
        depositVout: tokenData.fundingVout || tokenData.depositVout,
        redeemTxid: redeemTxid
      });

      if (!validation.valid) {
        params.reason = validation.reason || validation.error;
        return params;
      }

      console.log('[DLC/VTXO] Burn validation successful');

      // 6. Verify released value matches burn amount
      const FEE_TOLERANCE = 10000; // 10,000 sats tolerance for fees
      const releasedValue = validation.releasedValue;
      if (!Number.isSafeInteger(releasedValue) || releasedValue < (burnAmount - FEE_TOLERANCE)) {
        params.reason = `Released value (${releasedValue}) less than burn amount (${burnAmount})`;
        return params;
      }

      params.valid = true;
      params.reason = '';
      return params;

    } catch (error) {
      console.error('[DLC/VTXO] Burn validation error:', error);
      params.valid = false;
      params.reason = `Validation error: ${error.message}`;
      return params;
    }
  },

  /**
   * Gets the Ark bridge instance
   */
  getArkBridge: () => arkBridge,

  /**
   * Registers a new template (governance action)
   */
  registerTemplate: (template, aspId) => {
    return arkBridge.registerTemplate(template, aspId);
  },

  /**
   * Checks if a template is allowed
   */
  isTemplateAllowed: (templateId, aspId) => {
    return arkBridge.templateRegistry.isAllowed(templateId, aspId);
  }
};

module.exports = {
  DLCVTXOValidation,
  arkBridge
};
