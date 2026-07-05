# 🔍 The Binance Bull (BULLBNB) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-07-05T15:00:03.668Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xdc3d4cd63f4bd26e2fbdd577b69fc9ff17dcfd75` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | The Binance Bull |
| **Symbol** | BULLBNB |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Sun, 05 Jul 2026 15:00:03 GMT

### Summary

This is a standard `ERC20` token with minimal tax logic: fixed `1%` buy and `1%` sell fees applied only on AMM pairs, auto-swapped to BNB and forwarded to a `taxWallet`. Owner can exclude addresses from fees, add additional AMM pairs, and adjust the swap threshold within bounded limits. Primary risks are centralized controls and a permanent, undocumented `deployer`-only function that can withdraw the contract’s BNB (including accrued tax) at any time. Overall Risk: HIGH - Centralized controls over fees/pairs and a deployer-only BNB sweep can adversely impact holders and tax distribution.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 1% | ✅ Low |
| Sell Tax | 1% | ✅ Low |
| Max Transaction | None | ✅ No limit |
| Contract Type | Standard | Info |
| Ownership | Active (Owner present) | ⚠️ Centralized |
| Pause Function | No | ✅ No restrictions |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | Swap uses `amountOutMin=0`, but fee logic conservative and guarded by `_inSwap`. |
| Centralization | High | Owner controls fee exclusions, AMM pairs, swap threshold; deployer can withdraw BNB. |
| Code Quality | Low | Clean, minimal, OZ v5.x; clear invariants and try/catch wrappers. |
| Exploit Likelihood | Medium | No critical reentrancy/overflow vectors; centralized parameters can be abused. |
| **Overall Risk Score** | **87/100** | 0 critical, 1 high, 2 medium, 2 low |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `BUY_TAX()` | `1` | 1% buy fee on purchases from AMM pairs |
| `SELL_TAX()` | `1` | 1% sell fee on sales to AMM pairs |
| `TOTAL_SUPPLY()` | `1000000000000000000000000000` | Total tokens minted at deployment |
| `decimals()` | `18` | Display precision for token amounts |
| `name()` | `The Binance Bull` | Contract name identifier |
| `owner()` | `0xbA482dD4393B28388c6886e220e63D7c91633A27` | Address with owner-only admin rights |
| `pair()` | `0x75E9F8767Ebf4539c620AdDD5ACd25BE74804bF0` | Primary PancakeSwap trading pair |
| `router()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap v2 router used for swaps |
| `swapThreshold()` | `200000000000000000000000` | Token balance that triggers tax swap |
| `symbol()` | `BULLBNB` | Token ticker symbol |
| `taxWallet()` | `0x3779B90F1a7F87D7982B055bf4Ac9fD2c41BC488` | Recipient of BNB from fees |
| `totalSupply()` | `1000000000000000000000000000` | Current total supply (no burns) |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 0 | — |
| High | 1 | Deployer-only BNB withdrawal can divert tax proceeds |
| Medium | 2 | Owner-controlled AMM pair designation; Adjustable swap threshold enables large dumps |
| Low | 2 | `amountOutMin=0` exposes swaps to MEV; Single EOA holds immutable BNB-withdrawal role |

### Critical Findings

None.

### High Findings

---

#### 🟠 [H-1] Permanent deployer-only BNB withdrawal can divert tax proceeds

**Description:**
The contract includes a `deployer`-only function `clearStuckBNB()` that can withdraw the entire BNB balance from the token contract at any time. Since sell-tax is swapped to BNB and temporarily held by the contract before forwarding to `taxWallet`, any BNB that remains (e.g., after a failed forward) can be unilaterally redirected by the `deployer` instead of the designated `taxWallet`. This role persists even if `owner()` is later renounced.

```solidity
address private deployer;

// set once in constructor and immutable thereafter
deployer = payable(_msgSender());

function clearStuckBNB() external {
    require(_msgSender() == deployer);
    require(address(this).balance > 0, "Token: no BNB to clear");
    payable(msg.sender).transfer(address(this).balance);
}
```

**Impact:**
- Tax revenue (BNB) can be diverted away from `taxWallet` without owner consent or community visibility beyond a raw transfer.
- Undermines stated tokenomics: holders expect BNB collected from tax to flow to `taxWallet`.
- Persists post-renunciation (if any), creating a hidden centralized lever over treasury flows.

**Location:**
`clearStuckBNB()` and `deployer` variable in `TheBinanceBull` contract.

**💡 Recommendation:**
> **Action Required:**
> 1. Remove or restrict `clearStuckBNB()`; if a recovery path is needed, make it `onlyOwner` and emit an event with reason/amount.
> 2. Alternatively, restrict to send only to `taxWallet` and emit `RecoveredBNB(amount)`.
> 3. Add a timelock or multisig for any treasury-moving function.
> 4. Disclose this role prominently if retained.

---

### Medium Findings

---

#### 🟡 [M-1] Owner can arbitrarily mark addresses as AMM pairs, taxing and triggering swaps on normal transfers

**Description:**
The owner can mark any address as an AMM pair via `setAMMPair()`. Pair addresses control when fees apply (buy/sell detection) and when `_swapBack()` executes. Misuse or error could cause wallet-to-wallet transfers to be treated as buys/sells (charging fees and triggering swaps), altering user expectations and potentially causing unexpected sell pressure.

```solidity
function setAMMPair(address pairAddress, bool isPair_) external onlyOwner {
    require(pairAddress != pair, "BULLBNB: primary pair is fixed");
    isAMMPair[pairAddress] = isPair_;
    emit AMMPairUpdated(pairAddress, isPair_);
}

// Fee detection and swap trigger
if (isAMMPair[to] && takeFee) {
    _swapBack();
}
if (isAMMPair[from]) {
    fee = (amount * BUY_TAX) / 100;
} else if (isAMMPair[to]) {
    fee = (amount * SELL_TAX) / 100;
}
```

**Impact:**
- Owner can tax transfers to/from arbitrary addresses by labeling them as pairs.
- Can unintentionally or intentionally trigger `_swapBack()`, creating unexpected sell pressure.

**Location:**
`setAMMPair()`; fee and swap logic in `_update()`.

**💡 Recommendation:**
> **Action Required:**
> - Restrict `setAMMPair()` to known factory-created pairs (validate via factory).
> - Emit events and maintain a public list; consider time delays for changes.
> - Optionally hardcode or whitelist legitimate DEX factories to prevent abuse.

---

#### 🟡 [M-2] Adjustable swap threshold allows up to 5% supply swaps per transaction (sell pressure risk)

**Description:**
`swapThreshold` can be set up to `TOTAL_SUPPLY / 200` (0.5%). The actual per-tx swap cap is `swapThreshold * 10`, allowing swaps up to 5% of total supply in a single `_swapBack()` when threshold is maxed.

```solidity
function setSwapThreshold(uint256 newThreshold) external onlyOwner {
    require(
        newThreshold >= TOTAL_SUPPLY / 100000 && newThreshold <= TOTAL_SUPPLY / 200,
        "BULLBNB: threshold out of bounds"
    );
    swapThreshold = newThreshold;
    emit SwapThresholdUpdated(newThreshold);
}

uint256 maxSwap = swapThreshold * 10; // up to 5% if threshold = 0.5%
```

**Impact:**
- Large, owner-configurable swaps can cause significant price impact and slippage, harming holders.
- Increases MEV/sandwich attack surface on swaps due to predictable large sells.

**Location:**
`setSwapThreshold()` and `_swapBack()`.

**💡 Recommendation:**
> **Action Required:**
> - Reduce the upper bound or remove the `* 10` amplification; cap per-tx swaps to ≤0.2% supply.
> - Optionally use a time-weighted or incremental swap strategy to smooth sell pressure.

---

### Low Findings

---

#### 🟢 [L-1] `amountOutMin=0` in swap enables MEV/front-running and poor execution

**Description:**
Swapping collected fees uses `amountOutMin=0`. Although wrapped in `try/catch` and intended not to affect user transfers, it exposes tax swaps to slippage and MEV, potentially realizing poor rates and extra price impact.

```solidity
try router.swapExactTokensForETHSupportingFeeOnTransferTokens(
    amount, 0, path, address(this), block.timestamp
) { ... } catch {}
```

**Impact:**
- Reduced BNB proceeds for `taxWallet`.
- Increased price impact for holders during swaps.

**Location:**
`_swapBack()`.

**💡 Recommendation:**
> **Action Required:**
> - Use a reasonable `amountOutMin` via an on-chain oracle, TWAP, or configurable slippage parameter.
> - Introduce a max gas price or cool-down to reduce MEV exposure.

---

#### 🟢 [L-2] Single EOA `deployer` role is immutable; risk of stuck funds if keys lost

**Description:**
The `deployer` role is set once and cannot be changed. If keys are lost or compromised, it may cause permanent loss of recovery pathway (or unauthorized withdrawal) for stuck BNB, independent of `owner()`.

```solidity
address private deployer;
// no function to change deployer
```

**Impact:**
- Availability risk: stuck BNB if `deployer` is inaccessible.
- Security risk: if compromised, unauthorized BNB drain until mitigated externally.

**Location:**
`deployer` variable and `clearStuckBNB()`.

**💡 Recommendation:**
> **Action Required:**
> - Replace `deployer` EOA with a multisig and allow one-time migration to a new multisig.
> - If not needed, remove the pathway and rely on `onlyOwner` rescues to a known `taxWallet`.

---

### Good Practices

- Uses unmodified OpenZeppelin `ERC20`, `Ownable`, and `SafeERC20` v5.x; no tampering detected in math or access control.
- Taxes hardcoded and minimal (1%/1%); cannot be raised.
- Fees applied only on recognized AMM pairs; plain transfers untaxed.
- Swap wrapped in `try/catch`; user transfers succeed even if swap or forwarding fails.
- Reentrancy exposure mitigated with `_inSwap` to avoid nested fee logic during swaps.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard `ERC20` | Low (no proxy) |
| Upgrade Control | None (no proxy) | Low |
| Ownership Status | Active (not renounced) | High (centralized controls) |
| Owner Address | 0xbA482dD4393B28388c6886e220e63D7c91633A27 | Current owner |
| Total Supply | 1,000,000,000 BULLBNB (18 decimals) | Low |
| Buy Tax | 1% | Low |
| Sell Tax | 1% | Low |
| Max Transaction | None | Low |

Detailed analysis:
- Fees: Fixed `1%` buy/sell on AMM trades; cannot be changed, but owner can exclude addresses from fees (including pairs), effectively zeroing fees for selected flows.
- Swap mechanics: On sells (when `to` is an AMM pair), contract attempts to swap accrued fee-tokens to BNB and forward to `taxWallet`. If swap or forward fails, BNB remains in contract and is retried. However, the `deployer` can withdraw this BNB at any time via `clearStuckBNB()`, diverging from the stated tax destination.
- Centralization levers: Owner can designate additional AMM pairs and adjust `swapThreshold` (bounded 0.001%–0.5% of supply, with an effective per-tx cap up to 5% due to `* 10` multiplier), enabling significant sell pressure. These are trust assumptions rather than code exploits.

Balanced assessment: While upgradeability is not present (positive), centralized controls (owner and a separate `deployer` role) introduce trust requirements. The largest risk is treasury diversion through the deployer’s BNB sweep and large, owner-configured swap sizes that can negatively impact price.

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
