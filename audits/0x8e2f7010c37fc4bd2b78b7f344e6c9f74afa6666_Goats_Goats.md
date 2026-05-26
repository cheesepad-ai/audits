# 🔍 Goats (Goats) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-05-26T06:39:45.520Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0x8e2f7010c37fc4bd2b78b7f344e6c9f74afa6666` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | Goats |
| **Symbol** | Goats |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Tue, 26 May 2026 06:39:45 GMT

### Summary

This is a tax-enabled `ERC20` token (`Goats`) with 9 decimals and fixed buy/sell taxes of 3% routed to a contract that swaps for native and distributes to `mktAddress`, `devAddress`, and `goatDayAddress`. Key controls include owner-gated trading enablement, fee exemptions, AMM pair configuration, and treasury withdrawals by `mktAddress`. No proxy/upgradeability or mint/burn beyond constructor mint; overall code is straightforward but has centralized treasury controls and MEV/pricing risks around swaps. Overall Risk: MEDIUM – Centralized treasury control and MEV/slippage risk, but no critical backdoors or upgradeability.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 3% | ✅ Low |
| Sell Tax | 3% | ✅ Low |
| Max Transaction | None | ✅ No hard limits |
| Contract Type | Standard | Info only |
| Ownership | Active (EOA) | ⚠️ Centralized |
| Pause Function | Trading must be enabled once; no pause | ✅ No pause after enable |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | No critical bugs found; swap uses amountOutMin=0 and external calls |
| Centralization | High | Single EOA owner; `mktAddress` can withdraw native/foreign tokens anytime |
| Code Quality | Medium | Clean, OZ-like; some economic/operational risks in swap/distribution |
| Exploit Likelihood | Low | No apparent critical exploit paths; risks are economic/operational |
| **Overall Risk Score** | **87/100** | 0 critical, 1 high, 2 medium, 2 low |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn address used to lock/burn tokens |
| `FEE_DIVISOR()` | `10000` | Basis points divisor (10000 = 100%) |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | WBNB token address on BSC |
| `buyTax()` | `300` | 3% buy tax to treasury contract balance |
| `decimals()` | `9` | Token has 9 decimal places |
| `devAddress()` | `0x9b97e5C352DD285E5361998c8a4bE7A0f4bF8414` | Recipient of one-third of swap proceeds |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 Router (BSC mainnet) |
| `goatDayAddress()` | `0x9b97e5C352DD285E5361998c8a4bE7A0f4bF8414` | Recipient of one-third of swap proceeds |
| `lastSwapBackBlock()` | `0` | No swap executed yet (pre-trading) |
| `lpPair()` | `0x27E1aAdadcEcfAB6f7f6a1c4FEE2Ceac7ca1FBD9` | Token–WBNB pair address |
| `mktAddress()` | `0x9b97e5C352DD285E5361998c8a4bE7A0f4bF8414` | Receives remaining swap proceeds; treasury controller |
| `name()` | `Goats` | Contract name identifier |
| `owner()` | `0x9b97e5C352DD285E5361998c8a4bE7A0f4bF8414` | Admin with configuration privileges |
| `sellTax()` | `300` | 3% sell tax to treasury contract balance |
| `swapEnabled()` | `true` | Tax conversion to native is active |
| `swapTokensAtAmt()` | `500000000000000` | ~500,000 tokens threshold (0.05% supply) |
| `symbol()` | `Goats` | Token ticker |
| `totalSupply()` | `1000000000000000000` | 1,000,000,000 tokens (9 decimals) |
| `tradingAllowed()` | `false` | Public trading not enabled yet |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 0 | None |
| High | 1 | Centralized treasury withdrawal by `mktAddress` |
| Medium | 2 | MEV/slippage from `amountOutMin=0`; Owner-controlled AMM pair flags affecting taxation |
| Low | 2 | Fixed 35k gas ETH sends may fail; Potential price impact from burst swaps |

### Critical Findings

None

### High Findings

#### 🟠 [H-1] Centralized Treasury Control: `mktAddress` Can Withdraw All Native and Rescue Any Tokens

**Description:**
`mktAddress` can unilaterally withdraw the entire native balance and rescue any ERC20 tokens from the contract at any time. This power persists even if ownership is renounced, concentrating control over collected taxes and airdropped tokens.

```solidity
function withdrawStuckBNB() external {
    require(msg.sender == mktAddress, "Not MKT");
    uint256 amount = address(this).balance;
    bool success;
    (success, ) = address(mktAddress).call{value: amount}("");
    emit StuckBNBWithdrawn(mktAddress, amount);
}

function rescueTokens(address _token) external {
    require(msg.sender == mktAddress, "Not MKT");
    require(_token != address(0), "_token address cannot be 0");
    require(_token != address(this), "Cannot rescue project token");
    uint256 _contractBalance = IERC20(_token).balanceOf(address(this));
    SafeERC20.safeTransfer(IERC20(_token), address(mktAddress), _contractBalance);
    emit TokensRescued(_token, mktAddress, _contractBalance);
}
```

**Impact:**
- Marketing/dev proceeds and any tokens held by the contract can be redirected or drained by a single EOA.
- Users must fully trust `mktAddress` to act honestly; renouncing `owner()` does not mitigate this risk.

**Location:**
`withdrawStuckBNB()` and `rescueTokens()` in `Goats` contract.

**💡 Recommendation:**
> **Action Required:** Reduce centralization and add safeguards:
> 1. Gate withdrawals to a multisig with 3+ independent signers
> 2. Add optional timelock (24–48h) for withdrawals
> 3. Emit granular events and consider per-address caps/allowlists for rescued tokens

---

### Medium Findings

#### 🟡 [M-1] Unbounded Slippage in Tax Swaps (`amountOutMin = 0`) Enables MEV and Poor Execution

**Description:**
Tax conversions use `swapExactTokensForETHSupportingFeeOnTransferTokens` with `amountOutMin` set to `0`, allowing any output amount. This invites sandwiching/MEV and poor execution, reducing funds available to recipients and potentially impacting token price.

```solidity
dexRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(
    tokenAmt,
    0, // amountOutMin = 0
    path,
    address(this),
    block.timestamp
);
```

**Impact:**
- Adverse price impact on swaps; treasury/recipient underfunding.
- Increased MEV risk as attackers can freely manipulate price around swaps.

**Location:**
`swapTokensForETH()` in `Goats` contract.

**💡 Recommendation:**
> **Action Required:** Add slippage protections:
> - Compute `amountOutMin` using price oracle/observations or use a configurable minOut bps parameter
> - Break large swaps into smaller tranches or use TWAP-aware execution

---

#### 🟡 [M-2] Owner-Configurable AMM Pairs Can Force/Remove Taxes on Arbitrary Addresses

**Description:**
The owner can mark any address as an AMM pair, which changes buy/sell detection. This can force 3% tax on transfers to/from arbitrary addresses or remove tax from the real LP by unflagging it.

```solidity
function setAMMPair(address _pair, bool _isPair) external onlyOwner {
    require(_pair != address(0), "Zero Address");
    require(_pair != lpPair, "Cannot modify initial pair");
    isAMMPair[_pair] = _isPair;
    emit AMMPairUpdated(_pair, _isPair);
}
```

**Impact:**
- Transfers to/from targeted addresses can be unexpectedly taxed, affecting user expectations.
- Disabling tax on secondary pools (by unflagging) can alter tokenomics unpredictably.

**Location:**
`setAMMPair()` in `Goats` contract.

**💡 Recommendation:**
> **Action Required:** Constrain pair management:
> - Restrict additions to verified DEX pairs (factory-created)
> - Maintain an allowlist of known factories or emit community-governed approvals

---

### Low Findings

#### 🟢 [L-1] Fixed 35,000 Gas Stipend for ETH Distributions May Fail for Contract Recipients

**Description:**
ETH distributions use low-level `call` with a 35,000 gas stipend, which may be insufficient for some recipient contract wallets, silently failing and leaving funds on the contract.

```solidity
(bool success, ) = goatDayAddress.call{value: share, gas: 35000}("");
(bool success, ) = devAddress.call{value: share, gas: 35000}("");
(bool success, ) = mktAddress.call{value: remainingBalance, gas: 35000}("");
```

**Impact:**
- Distributions may fail for contracts with heavier logic; funds accumulate in contract until `withdrawStuckBNB()` is used (centralized).

**Location:**
`convertTaxes()` in `Goats` contract.

**💡 Recommendation:**
> **Action Required:** Improve robustness:
> - Remove fixed gas or make it configurable; log failures distinctly
> - Consider pull-based claiming to avoid forced sends

---

#### 🟢 [L-2] Potential Large Price Impact from Burst Swaps up to 4× Threshold

**Description:**
The contract sells up to `swapTokensAtAmt * 4` in one execution, potentially causing noticeable price impact on thin liquidity.

```solidity
if (contractBalance > swapTokensAtAmt * 4) {
    contractBalance = swapTokensAtAmt * 4;
}
```

**Impact:**
- Price pressure and slippage during conversions, indirectly affecting holders.

**Location:**
`convertTaxes()` in `Goats` contract.

**💡 Recommendation:**
> **Action Required:** Smoother execution:
> - Reduce per-swap cap (e.g., 1× threshold) or split across blocks
> - Add rate limiting or VWAP/TWAP-aware swap scheduling

---

### Good Practices

- Uses a simple, OZ-like `ERC20` with built-in overflow checks in Solidity 0.8.x
- Proper reentrancy prevention during swaps via `inSwap` and `lockTheSwap`
- No upgradeability/proxy pattern; immutable `WETH`, `router`, and initial `lpPair`
- Ownership renunciation is genuine (no restore/backdoor variables or modifiers)
- Fees are fixed (no owner function to raise taxes), reducing rug vectors

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard (non-upgradeable) | Low upgrade risk |
| Upgrade Control | None (no proxy) | Low |
| Ownership Status | Active (EOA) | High centralization |
| Owner Address | 0x9b97e5C352DD285E5361998c8a4bE7A0f4bF8414 | Current owner |
| Total Supply | 1,000,000,000 tokens (9 decimals) | Low |
| Buy Tax | 3% (fixed) | Low |
| Sell Tax | 3% (fixed) | Low |
| Max Transaction | None | Low |

- Taxes: 3% on buys/sells route to the contract, then swapped for native and distributed: one-third each to `goatDayAddress` and `devAddress`, remainder to `mktAddress`. No reflection, no liquidity auto-add, no burn.
- Centralization: `mktAddress` can withdraw all native and rescue any ERC20 from the contract at any time, persisting after any ownership renunciation. Users must trust these addresses. Owner controls exempt list, swap toggle, and AMM pair flags; owner must enable trading before public use.
- Market impact: Conversions sell up to 4× threshold with `amountOutMin=0`, exposing treasury to MEV and slippage and potentially creating price pressure during swaps.

Ownership properly renounced assessment: If `owner()` is later set to `address(0)`, there are no hidden restore functions or secondary owner-like backdoors in code. However, centralized treasury powers remain with `mktAddress`.

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
