# 🔍 World Cup Inu (WINU) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 5 |
| **Audit Date** | 2026-06-09T13:30:57.350Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0x2a1ba3483917f5adbc3820fb41e9cada7524bc6b` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | World Cup Inu |
| **Symbol** | WINU |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Tue, 09 Jun 2026 13:30:57 GMT

### Summary

This is a standard `ERC20` tax token (`WorldCup Inu`, 9 decimals, fixed supply) with buy/sell taxes routed to a `marketingWallet` via auto-swap on `PancakeRouter`. It has owner-controlled parameters (tax rates up to 10%, AMM pair flags, fee/tx exemptions) and trading gate plus optional anti-whale limits (currently disabled on-chain). Overall, the code is simple and non-upgradeable, but centralized control and launch fairness concerns exist. Overall Risk: MEDIUM – Owner can change taxes/exemptions and trade pre-launch; no upgrade proxy or minting backdoors found.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 3% (max 10%) | ⚠️ Moderate |
| Sell Tax | 3% (max 10%) | ⚠️ Moderate |
| Max Transaction | None (limits disabled on-chain) | ✅ No restriction |
| Contract Type | Standard (non-upgradeable) | Info |
| Ownership | Active (`owner()` nonzero) | ⚠️ Centralized |
| Pause Function | No full pause; trading gate only | ✅ No hard pause |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Low | No reentrancy/mint backdoors; basic ERC20 with taxes |
| Centralization | Medium | Owner controls taxes, exemptions, AMM flags, trading enable |
| Code Quality | Medium | Custom `Address`/`SafeERC20`; minor deviations from OZ |
| Exploit Likelihood | Low | Typical tax-token surface; no external protocol integrations |
| **Overall Risk Score** | **89/100** | No crit/high vulns; centralized controls and MEV exposure lower score |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn address used to permanently remove tokens |
| `FEE_DENOMINATOR()` | `10000` | Basis points denominator for tax math (10000 = 100%) |
| `MAX_LIMIT()` | `200` | 2% minimum cap for maxTx/maxWallet thresholds |
| `MAX_TAX()` | `1000` | Maximum per-side tax = 10% |
| `PANCAKE_ROUTER()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router on BSC mainnet |
| `TOTAL_SUPPLY()` | `1000000000000000000` | Total supply units (1e9 tokens with 9 decimals) |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | WBNB address used as base pair |
| `buyTax()` | `300` | 3% buy tax (300/10000) |
| `decimals()` | `9` | Token uses 9 decimals |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | Router used for swaps and LP pair creation |
| `limitsEnabled()` | `false` | Anti-whale limits currently disabled |
| `lpPair()` | `0x31f29CE4368001d9EfE65A5E2F35335A3A382544` | Pancake pair address for WINU/WBNB |
| `marketingWallet()` | `0x049C425281F8d455185F1BD7C84CCE22f0D3Bdf5` | Receives BNB from tax swaps and withdrawals |
| `maxTxAmount()` | `1000000000000000000` | Set to full supply (limit ineffective) |
| `maxWalletAmount()` | `1000000000000000000` | Set to full supply (limit ineffective) |
| `name()` | `World Cup Inu` | Contract name identifier |
| `owner()` | `0x57969346cc1879071E3C1b2f8d6c3523E9CA329D` | Address with admin privileges |
| `sellTax()` | `300` | 3% sell tax (300/10000) |
| `swapEnabled()` | `true` | Automatic tax swapping currently enabled |
| `swapTokensAtAmount()` | `2500000000000000` | Auto-swap threshold = 0.25% supply |
| `symbol()` | `WINU` | Contract symbol |
| `totalSupply()` | `1000000000000000000` | Total tokens ever created |
| `tradingEnabled()` | `true` | Public trading is enabled |

### Findings Summary

| Severity | Count | Key Items |
|---------|-------|-----------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 2 | Pre-launch trading by privileged addresses; Zero-slippage swaps (MEV exposure) |
| Low | 4 | Non-standard `Address.functionCall`; Ignored BNB transfer failure; AMM flagging risk; Anti-whale removable |

### Critical Findings

None.

### High Findings

None.

### Medium Findings

---

#### 🟡 [M-1] Privileged addresses can trade before `tradingEnabled` (launch fairness risk)

**Description:**
The `tradingEnabled` gate only applies when both `from` and `to` are not fee-exempt. `owner`, `marketingWallet`, `address(this)`, and `DEAD` are fee-exempt from deployment, allowing them to trade before the public launch.

```solidity
function _transfer(address from, address to, uint256 amount) internal override {
    ...
    if (!exemptFromFees[from] && !exemptFromFees[to]) {
        require(tradingEnabled, "Trading is not enabled");
    }
    ...
}
```

**Impact:**
Owner/marketing can buy/sell/add-liquidity/snipe before public trading, potentially impacting price discovery and fairness.

**Location:**
`WorldCupInu._transfer()`

**💡 Recommendation:**
> **Action Required:**
> 1. Introduce a dedicated `launched` flag requiring `from == owner()` and `to == lpPair` during initial liquidity only.
> 2. Optionally remove fee-exempt status for privileged addresses until trading is enabled.
> - Alternative: Add an allowlist for initial liquidity providers only.

---

#### 🟡 [M-2] `amountOutMin = 0` in swaps exposes tax swaps to MEV and poor rates

**Description:**
`swapTokensForBNB` passes `amountOutMin` as `0`, enabling sandwiches and extreme slippage during `swapBack()` and `manualSwap()`.

```solidity
function swapTokensForBNB(uint256 tokenAmount) private {
    ...
    dexRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        0, // amountOutMin = 0
        path,
        address(this),
        block.timestamp
    );
}
```

**Impact:**
Collected taxes may be swapped at unfavorable prices, diminishing marketing funds and harming holders.

**Location:**
`WorldCupInu.swapTokensForBNB()`

**💡 Recommendation:**
> **Action Required:**
> 1. Add router slippage protection by computing a conservative `amountOutMin` from TWAP/Oracle or reserve check.
> 2. Split swaps into smaller chunks beyond the existing 5x cap to reduce impact.
> - Alternative: Allow owner to configure a minimum out bps parameter.

---

### Low Findings

---

#### 🟢 [L-1] Custom `Address.functionCall` omits `isContract` check

**Description:**
The helper does not verify that the `target` has code, unlike OpenZeppelin. While used only via `SafeERC20.safeTransfer`, this can mask misconfiguration in generic usage.

```solidity
library Address {
    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.call(data);
        if (success) { return returndata; }
        if (returndata.length > 0) { assembly { ... } }
        revert(errorMessage);
    }
}
```

**Impact:**
Calling an EOA could return success with empty data; in other contexts this may silently no-op.

**Location:**
`Address.functionCall()`, used in `SafeERC20.safeTransfer()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Add `require(Address.isContract(target), "call to non-contract")` prior to low-level calls.
> 2. Prefer importing unmodified OpenZeppelin `Address` and `SafeERC20`.

---

#### 🟢 [L-2] Ignoring failure when sending BNB to `marketingWallet` in `swapBack`

**Description:**
If `marketingWallet` rejects funds, the call’s failure is ignored and only the event reflects zero sent; funds remain in the contract.

```solidity
(bool success, ) = payable(marketingWallet).call{value: newBalance}("");
emit TaxesSwapped(tokenAmount, success ? newBalance : 0);
```

**Impact:**
Temporary inability to forward BNB; requires `withdrawStuckBNB()` to recover.

**Location:**
`WorldCupInu.swapBack()`

**💡 Recommendation:**
> **Action Required:**
> 1. Consider reverting on failed transfer, or
> 2. Add a retry mechanism or a fallback recipient.
> - Alternative: Document operational runbook to call `withdrawStuckBNB()` when needed.

---

#### 🟢 [L-3] Owner can arbitrarily flag addresses as AMM pairs (unexpected taxation routes)

**Description:**
`setAMMPair()` lets the owner mark any address as an AMM pair (excluding the main pair). Transfers to/from such addresses will be considered buys/sells and taxed.

```solidity
function setAMMPair(address pair, bool value) external onlyOwner {
    require(pair != address(0), "Zero address");
    require(pair != lpPair, "Main pair cannot be removed");
    isAMMPair[pair] = value;
    emit AMMPairUpdated(pair, value);
}
```

**Impact:**
Unexpected taxes on transfers to designated addresses or custom routers, potentially affecting integrations and user expectations.

**Location:**
`WorldCupInu.setAMMPair()`

**💡 Recommendation:**
> **Action Required:**
> 1. Restrict AMM list changes post-launch, or
> 2. Make AMM curation transparent via timelock/multisig.
> - Alternative: Hardcode only known AMMs if feasible.

---

#### 🟢 [L-4] Anti-whale protections can be fully removed by owner

**Description:**
`limitsEnabled` can be disabled, and `maxTxAmount`/`maxWalletAmount` can be set to any value ≥ 2% supply. On-chain, both are set to full supply and `limitsEnabled=false`.

```solidity
function updateMaxTxAmount(uint256 newAmount) external onlyOwner {
    require(newAmount >= (TOTAL_SUPPLY * MAX_LIMIT) / FEE_DENOMINATOR, "Cannot set below 2%");
    ...
}
```

**Impact:**
No effective anti-whale/anti-bot protections; large holders can accumulate/transact without constraint.

**Location:**
`WorldCupInu.updateMaxTxAmount()`, `updateMaxWalletAmount()`, `setLimitsEnabled()`

**💡 Recommendation:**
> **Action Required:**
> 1. If anti-whale is desired, enforce sensible upper bounds and keep `limitsEnabled=true` during early trading.
> 2. Communicate operational settings publicly.

---

### Good Practices

- Fixed supply minted once; no external mint/burn functions (supply cannot be increased).
- Non-upgradeable; no proxy or delegatecall patterns detected.
- Taxes capped at 10% per side; cannot exceed set maximums.
- Main LP pair cannot be unset as AMM (`lpPair` protected).
- `rescueTokens()` prevents rescuing this token, LP token, or any AMM pair token.
- Ownership renunciation is standard (`address(0)`) with no restore/backdoor variables.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard (tax token) | Low (no upgrade risk) |
| Upgrade Control | None (immutable code) | Low |
| Ownership Status | Active (not renounced) | Medium (centralized control) |
| Owner Address | 0x57969346cc1879071E3C1b2f8d6c3523E9CA329D | Current admin |
| Total Supply | 1,000,000,000 tokens (9 decimals) | Low |
| Buy Tax | 3% (max 10%) | Medium (owner adjustable) |
| Sell Tax | 3% (max 10%) | Medium (owner adjustable) |
| Max Transaction | Disabled effectively (limits off; set to full supply) | Low (no restriction) |

- Fees: Collected on AMM buys/sells only. Tokens are accrued to the contract, swapped for BNB, and forwarded to `marketingWallet`. Swap threshold is 0.25% supply; swaps capped to 5x threshold per trigger to limit impact.
- Controls: Owner can adjust taxes up to 10% per side, toggle swap/limits, set fee/tx exemptions, and curate AMM pairs (cannot unset main pair). `marketingWallet` is owner-changeable and exempt from fees/tx limits.
- Current posture (on-chain): `tradingEnabled=true`; `limitsEnabled=false`; `maxTxAmount` and `maxWalletAmount` are full supply (no anti-whale), `swapEnabled=true`, taxes at 3%/3%.
- Rug risk: No mint/burn backdoors or upgradeability. Centralization risk persists through adjustable taxes and exemptions; funds from taxes go to `marketingWallet`, which can withdraw BNB. Ownership renunciation, if performed, would be proper (no restore backdoor observed).

Ownership Renunciation Verification:
- Owner is currently nonzero (active). No `previousOwner`, `restoreOwner`, `emergencyRecover`, or modifier side-doors observed. If renounced, ownership appears properly renounceable without backdoors.

---

## ⚠️ Important Disclaimer

> **This is an AI-generated audit and should NOT be considered as professional security advice.**

This automated analysis:
- ✅ Provides quick security insights using advanced AI models
- ❌ May contain errors or miss critical vulnerabilities
- ❌ Cannot replace professional security audits
- ❌ Should not be used as the sole basis for investment decisions

**Always conduct thorough manual audits by qualified security professionals before:**
- Deploying smart contracts to production
- Investing significant funds
- Making critical security decisions

---

<sub>Generated by CheesePad AI Token Audit System</sub>
