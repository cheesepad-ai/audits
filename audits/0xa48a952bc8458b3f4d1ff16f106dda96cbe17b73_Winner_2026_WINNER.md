# 🔍 Winner 2026 (WINNER) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-06-09T13:26:34.429Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xa48a952bc8458b3f4d1ff16f106dda96cbe17b73` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | Winner 2026 |
| **Symbol** | WINNER |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Tue, 09 Jun 2026 13:26:34 GMT

### Summary

`Winner2026` is a custom BEP-20 (`ERC20`) tax token for PancakeSwap V2 with configurable buy/sell taxes (capped at 10%) and an auto-swap mechanism that converts collected fees to BNB and forwards them to a `taxWallet`. Key owner-controlled features include tax rates, exclusions, AMM pair registry, and swap settings. No upgradeability or backdoor ownership restoration was found; however, owner centralization and a sell-DoS vector via `taxWallet` configuration elevate risk. Overall Risk: MEDIUM - Single-owner control with a potential sell freeze via `taxWallet` configuration; otherwise clean, non-upgradeable code.

### Risk Assessment

Token Quick Facts:

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 3% (max 10%) | ✅ Low |
| Sell Tax | 3% (max 10%) | ✅ Low |
| Max Transaction | None | ✅ No restrictions |
| Contract Type | Standard (no proxy) | Info |
| Ownership | Active (owner: 0xeFD8...D601) | ⚠️ Centralized |
| Pause Function | No | ✅ No restrictions |

Security Assessment:

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | Owner-configurable settings; reentrancy surface via `taxWallet.call` |
| Centralization | High | Single EOA owner controls taxes, pairs, exemptions, wallet |
| Code Quality | Low | Clear, bounded loops; no OZ backdoors; minor comments issue |
| Exploit Likelihood | Medium | Owner can induce sell DoS by setting non-payable `taxWallet` |
| **Overall Risk Score** | **87/100** | One high (sell DoS), two medium (reentrancy surface, pair control), lows |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `MAX_TAX()` | `10` | Maximum allowed buy/sell tax percent |
| `buyTax()` | `3` | Current buy tax rate (3%) |
| `decimals()` | `18` | Token decimal precision |
| `maxSwapAmount()` | `5000000000000000000000000` | Max tokens per auto-swap (5,000,000 WINNER) |
| `name()` | `Winner 2026` | Contract name identifier |
| `owner()` | `0xeFD8D8A6fAA98aB3d5e2a4Df999509b88341D601` | Address with admin privileges |
| `pancakePair()` | `0x57d875cc0b83df118c3b0c699FaF7DE9dF3501Ee` | WINNER/WBNB liquidity pair address |
| `pancakeRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router used for swaps |
| `sellTax()` | `3` | Current sell tax rate (3%) |
| `swapEnabled()` | `true` | Auto-swap of collected fees is enabled |
| `swapThreshold()` | `500000000000000000000000` | Min tokens to trigger swap (500,000 WINNER) |
| `symbol()` | `WINNER` | Token ticker symbol |
| `taxWallet()` | `0xeFD8D8A6fAA98aB3d5e2a4Df999509b88341D601` | Recipient of swap proceeds (BNB) |
| `totalSupply()` | `1000000000000000000000000000` | Total minted supply (1,000,000,000 WINNER) |

### Findings Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| Critical | 0 | — |
| High | 1 | Owner can brick sells by setting `taxWallet` to non-payable/reverting contract |
| Medium | 2 | Reentrancy surface via `taxWallet.call`; Owner-controlled AMM pair map can over-tax targeted transfers |
| Low | 2 | Misleading comment on modifier behavior; Owner-tunable swap params can cause large dump events |

### Critical Findings

(None)

### High Findings

#### 🟠 [H-1] Owner can freeze/brick sells by setting `taxWallet` to a non-payable or reverting contract

Description:
During auto-swap in `_swapTokensForBNB`, BNB is forwarded to `taxWallet` using a low-level `call`. If `taxWallet` is set to a contract that rejects ETH (no payable fallback or explicit revert), the send will fail and the function reverts with `BNBTransferFailed()`. Because `_swapTokensForBNB` is invoked inside `_transfer()` on sells when `contractBalance >= swapThreshold`, every such sell will revert, effectively freezing sells until the owner changes `taxWallet` or settings.

```solidity
function _swapTokensForBNB(uint256 tokenAmount) internal lockSwap {
    ...
    try pancakeRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount, 0, path, address(this), block.timestamp + 300
    ) {
        uint256 bnbGained = address(this).balance - bnbBefore;
        if (bnbGained > 0) {
            (bool sent, ) = payable(taxWallet).call{value: bnbGained}("");
            if (!sent) revert BNBTransferFailed(); // causes sell to revert when triggered
            emit TaxSwappedAndSent(tokenAmount, bnbGained);
        }
    } catch {
        // swap failure swallowed, but BNB send failure is not
    }
}
```

Impact:
- Complete denial of service on sells once `swapThreshold` is met, until configuration is corrected.
- Can be intentionally used to trap liquidity (temporary honeypot behavior on sells).

Location:
- `_swapTokensForBNB()` send to `taxWallet` and revert path.

💡 Recommendation:
> Action Required:
> 1. Do not send BNB inside token transfer flow. Adopt a pull pattern: accumulate BNB and let `taxWallet` withdraw via a separate function.
> 2. Alternatively, wrap the BNB send in a non-reverting path (e.g., best-effort send with no revert, or emit event on failure and allow manual withdrawal).
> 3. Operationally, restrict `taxWallet` to a payable EOA. Consider enforcing EOA via `extcodesize == 0` check (understanding its limitations).

---

### Medium Findings

#### 🟡 [M-1] External call to `taxWallet` during swap introduces reentrancy surface

Description:
`_swapTokensForBNB` performs `(bool sent, ) = payable(taxWallet).call{value: bnbGained}("")`, allowing arbitrary code execution if `taxWallet` is a contract. While `_inSwap` prevents recursive swap-triggering, a malicious `taxWallet` (especially if also `owner`) can reenter and invoke admin functions mid-transfer, potentially altering configuration in unexpected states or triggering operational DoS scenarios.

```solidity
(bool sent, ) = payable(taxWallet).call{value: bnbGained}("");
```

Impact:
- Reentrant calls can change taxes, pair mappings, or exclusions mid-transaction, complicating state assumptions and audits.
- Combined with [H-1], can be used to grief or destabilize trading.

Location:
- `_swapTokensForBNB()` BNB forward call.

💡 Recommendation:
> Action Required:
> - Prefer a pull-payment pattern to eliminate external calls during transfer.
> - If push is retained, limit `taxWallet` to a payable EOA and/or add reentrancy guard at external entry points that can be called from `taxWallet`.
> - Document this requirement operationally and monitor `taxWallet` type on-chain.

---

#### 🟡 [M-2] Owner-controlled `isAMMPair` can over-tax targeted transfers by marking arbitrary addresses as “sell” destinations

Description:
Sell tax is applied when `to` is marked as `isAMMPair[to] == true`. The owner can arbitrarily set any address as an AMM pair, causing transfers to that address to be treated as sells and taxed at the sell rate.

```solidity
function setAMMPair(address pair, bool isPair) external onlyOwner {
    if (pair == address(0)) revert ZeroAddress();
    isAMMPair[pair] = isPair;
    emit AMMPairUpdated(pair, isPair);
}
```

Impact:
- Owner can selectively increase tax burden on transfers to specific addresses (e.g., centralized exchanges, bridges, users).
- Non-standard behavior may surprise users and integrators.

Location:
- `setAMMPair()` and tax logic in `_transfer()`.

💡 Recommendation:
> Action Required:
> - Restrict `isAMMPair` to known DEX pairs (optionally hardcode Pancake factory check).
> - Alternatively, maintain an allowlist of factory-created pairs only and prevent arbitrary EOA entries.

---

### Low Findings

#### 🟢 [L-1] Misleading comment about modifier post-code execution on revert

Description:
`lockSwap` comment claims the post-modifier code “always executes, even on revert inside body”. In Solidity, a revert unwinds the entire call and none of the state changes, including the modifier’s postlude, persist. While the logic is safe (no permanent lock), the statement is inaccurate and could mislead maintenance.

```solidity
modifier lockSwap() {
    _inSwap = true;
    _;
    _inSwap = false; // comment says "always executes, even on revert inside body"
}
```

Impact:
- Documentation inconsistency that may cause future contributors to make unsafe assumptions.

Location:
- `lockSwap` modifier.

💡 Recommendation:
> Action Required:
> - Update comment to reflect actual Solidity behavior: on revert, state changes including `_inSwap` are reverted; no permanent lock occurs.

---

#### 🟢 [L-2] Owner-tunable swap parameters may cause large dump events or gas spikes

Description:
Owner can set `swapThreshold` and `maxSwapAmount` arbitrarily. If set very high, tokens can accumulate and later be swapped in large chunks, causing noticeable price impact; if set very low, frequent swaps can increase gas usage and slippage during sells.

```solidity
function setSwapSettings(bool _enabled, uint256 _threshold, uint256 _maxAmount) external onlyOwner {
    if (_threshold == 0) revert ThresholdMustBePositive();
    if (_maxAmount < _threshold) revert MaxAmountBelowThreshold();
    ...
}
```

Impact:
- Market impact risk, MEV susceptibility, and UX degradation.

Location:
- `setSwapSettings()` and swap logic in `_transfer()`.

💡 Recommendation:
> Action Required:
> - Enforce sane bounds (e.g., 0.01%–1% of supply) or publish transparent operational policies for these parameters.

---

### Good Practices

- Non-upgradeable design (no proxy, no delegatecall), reducing upgrade risk.
- `MAX_TAX` hard cap (10%) prevents excessive fees.
- Bounded batch updates (`MAX_BATCH = 200`) to avoid gas DoS.
- Internal swap uses `_inSwap` guard to prevent recursive swaps.
- Try/catch around router swap prevents hard failures on swap path.
- Rescue functions disallow rescuing the native token (`CannotRescueWinner`).

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard (no proxy) | Low (no upgrade risk) |
| Upgrade Control | None (immutable code) | Low |
| Ownership Status | Active (0xeFD8...D601) | High (centralized) |
| Owner Address | 0xeFD8D8A6fAA98aB3d5e2a4Df999509b88341D601 | Current owner/admin |
| Total Supply | 1,000,000,000 WINNER | Low (fixed cap, fully minted) |
| Buy Tax | 3% (max 10%) | Low |
| Sell Tax | 3% (max 10%) | Low |
| Max Transaction | None | Low (no limits) |

- Taxes: Applied only on buys (from AMM pair) and sells (to AMM pair); wallet-to-wallet transfers are untaxed. Owner can modify taxes within a 10% cap.
- Exemptions: Owner can exclude any address, including pairs, affecting tax application; transparency recommended.
- Auto-swap: Collected fees accumulate in the contract and are swapped to BNB, then forwarded to `taxWallet`. Owner can tune thresholds and amounts; extreme settings can cause market impact.
- Centralization: Single-owner model controls taxes, exemptions, AMM pairs, `taxWallet`, and swap behavior. While no hidden backdoors detected and renunciation appears genuine if executed, current operations require trust in the owner to avoid abusive settings (e.g., [H-1] sell DoS via non-payable `taxWallet`).

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
