# 🔍 Baby Badger (BBADGER) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2025-12-19T07:34:30.137Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xd84e42a446593ec908306d77e5f5cd53b1f2a99c` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | Baby Badger |
| **Symbol** | BBADGER |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Fri, 19 Dec 2025 07:34:30 GMT

### Summary
`BBADGER` is a tax-enabled `ERC20` token (decimals `9`) with automatic swapback that sends 60% of collected BNB to `marketingAddress` and 40% to `devAddress`. Trading is gated by `tradingAllowed`, and a configurable “launch” window can apply a 90% tax. Centralized owner control over taxes (up to 30% buy/sell), fee exemptions, and payout addresses, plus a configurable high-tax launch window, materially increases user risk. Overall Risk: HIGH – Owner can set a prolonged 90% tax window and high ongoing taxes; funds routing is centralized.

### Risk Assessment

Token Quick Facts:

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 0% (on-chain at block 72169870) | ✅ Low |
| Sell Tax | 0% (on-chain at block 72169870) | ✅ Low |
| Max Transaction | None | ✅ No restrictions |
| Contract Type | Standard (non-upgradeable) | Info only |
| Ownership | Active (`owner()` set) | ⚠️ Centralized |
| Pause Function | No (but `tradingAllowed` gate) | ⚠️ Can delay trading |

Security Assessment:

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | External calls in transfer path; public BNB withdrawal logic |
| Centralization | High | Owner can set up to 30% taxes, fee exemptions, launch tax window |
| Code Quality | Medium | Reasonable; some missing events; tax-on-selected-pairs only |
| Exploit Likelihood | Medium | Main risks are admin actions and tokenomics misuse |
| **Overall Risk Score** | **82/100** | 0 critical, 2 high, 2 medium, 2 low |

## On-Chain Function Results

The following functions were called on-chain at block 72169870. The table below shows the results:

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn address constant, used for irretrievable tokens |
| `FEE_DIVISOR()` | `10000` | Basis points divisor; 100 = 1% |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | Wrapped BNB used for swaps and LP |
| `buyTax()` | `0` | Current buy marketing tax (basis points) |
| `decimals()` | `9` | Token decimal precision for UI/display |
| `devAddress()` | `0x3695f137a95DC3Da5A221e3dd71A663Fb2f7befA` | Receives 40% of swapback BNB |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router |
| `lastSwapBackBlock()` | `0` | Swapback has not executed yet |
| `launchBlock()` | `0` | 90% launch tax window not configured yet |
| `lpPair()` | `0x211E27044264740c71b306C7D8665af8c0f7Cc01` | BBADGER-WBNB Pancake LP pair |
| `marketingAddress()` | `0x8B066CB1804eE3E45a42765D025d4822BCF824d4` | Receives 60% of swapback BNB and withdrawals |
| `name()` | `Baby Badger` | Contract name identifier |
| `owner()` | `0x3695f137a95DC3Da5A221e3dd71A663Fb2f7befA` | Admin address with control powers |
| `sellTax()` | `0` | Current sell marketing tax (basis points) |
| `swapTokensAtAmt()` | `3000000000000000` | Token threshold to trigger swapback (0.3% supply) |
| `symbol()` | `BBADGER` | Token ticker |
| `totalSupply()` | `1000000000000000000` | Total tokens minted (1e18 units = 1B at 9 decimals) |
| `tradingAllowed()` | `false` | Trading for non-exempt addresses not enabled |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 0 | — |
| High | 2 | 90% configurable launch tax window; Owner-centralized controls (taxes, exemptions, addresses) |
| Medium | 2 | Public `withdrawStuckBNB` bypasses 60/40 split; Taxes only applied to hardcoded LP pair(s) |
| Low | 2 | External .call in transfer flow; Missing events for key parameter changes |

### Critical Findings

No critical findings identified.

### High Findings

---

#### 🟠 [H-1] Configurable 90% “launch” tax window can be arbitrarily long

**Description:**
Owner can enable trading and set `launchBlock` to an arbitrarily large future block. During this window, buys and sells are taxed at 90% (9000 basis points), overriding configured taxes and routing proceeds to team wallets.

```solidity
function enableTrading(uint256 _deadline) external onlyOwner {
    require(!tradingAllowed, "Trading already enabled");
    tradingAllowed = true;
    lastSwapBackBlock = block.number;
    launchBlock = block.number + _deadline;
}

function handleTax(address from, address to, uint256 amount) internal returns (uint256) {
    // ...
    if (taxes.marketingTax > 0) {
        if (block.number <= launchBlock) {
            if (isAMMPair[from]) {
                tax = uint128((amount * 9000) / FEE_DIVISOR);
            } else if (isAMMPair[to]) {
                tax = uint128((amount * 9000) / FEE_DIVISOR);
            }
        } else {
            tax = uint128((amount * taxes.marketingTax) / FEE_DIVISOR);
        }
        super._transfer(from, address(this), tax);
    }
    return tax;
}
```

**Impact:**
Owner can set an extremely long or effectively indefinite 90% tax window, siphoning most trade value to team-controlled wallets. Buyers/sellers incur severe losses.

**Location:**
`enableTrading()` and `handleTax()` tax logic.

**💡 Recommendation:**
> **Action Required:** Constrain the launch window.
> 1. Cap `_deadline` to a small number of blocks (e.g., ≤10).
> 2. Emit an event with `_deadline` and enforce a one-time, bounded launch tax.
> - Alternative: Hardcode a minimal, fixed anti-bot window.

---

#### 🟠 [H-2] Centralized owner control over taxes, fee exemptions, and payout addresses

**Description:**
Owner can set buy/sell taxes up to 30% each, whitelist arbitrary addresses from fees, update `marketingAddress`/`devAddress`, and determine trading start. This grants broad discretionary power over token economics.

```solidity
function updateTaxes(uint64 _buyMarketingTax, uint64 _sellMarketingTax) external onlyOwner {
    require(_buyMarketingTax <= 3000, "Buy tax cannot exceed 30%");
    require(_sellMarketingTax <= 3000, "Sell tax cannot exceed 30%");
    buyTax.marketingTax = _buyMarketingTax;
    sellTax.marketingTax = _sellMarketingTax;
}

function setExemptFromFee(address _address, bool _isExempt) external onlyOwner { ... }
function updateMarketingAddress(address _address) external onlyOwner { ... }
function updateDevAddress(address _address) external onlyOwner { ... }
function enableTrading(uint256 _deadline) external onlyOwner { ... }
```

**Impact:**
Owner can impose high taxes, selectively exempt wallets (including team wallets), redirect proceeds, and control launch timing. Users must fully trust the owner.

**Location:**
`updateTaxes()`, `setExemptFromFee()`, `updateMarketingAddress()`, `updateDevAddress()`, `enableTrading()`.

**💡 Recommendation:**
> **Action Required:** Reduce centralization risk.
> 1. Move admin controls to a multisig and/or timelock.
> 2. Lower maximum tax caps (e.g., ≤5%).
> 3. Emit events for all parameter changes (addresses, taxes, exemptions).

### Medium Findings

---

#### 🟡 [M-1] Public `withdrawStuckBNB()` bypasses 60/40 split and sends 100% to marketing

**Description:**
Anyone can call `withdrawStuckBNB()` to forward the contract’s entire BNB balance to `marketingAddress`, bypassing the 60/40 split enforced by `convertTaxes()`.

```solidity
function withdrawStuckBNB() external {
    bool success;
    (success, ) = address(marketingAddress).call{ value: address(this).balance }("");
}
```

**Impact:**
All residual BNB (including from taxes) can be pushed to `marketingAddress`, depriving `devAddress` of its 40% share. Centralized fund routing that contradicts declared split; also enables griefing-trigger of payout timing.

**Location:**
`withdrawStuckBNB()`.

**💡 Recommendation:**
> **Action Required:** Respect the split and add access control.
> 1. Restrict to `onlyOwner` or both team wallets.
> 2. Distribute per 60/40 split on withdrawal, not 100% to marketing.
> - Alternative: Remove this function; rely on `convertTaxes()` only.

---

#### 🟡 [M-2] Taxes apply only to hardcoded AMM pair; other pairs are untaxed

**Description:**
Tax is applied only when `from` or `to` is marked `isAMMPair`. Only the constructor-created pair is set; there is no function to add new pairs.

```solidity
mapping(address => bool) public isAMMPair;
// only set in constructor:
isAMMPair[lpPair] = true;

function handleTax(address from, address to, uint256 amount) internal returns (uint256) {
    Taxes memory taxes;
    if (isAMMPair[to]) {
        taxes = sellTax;
    } else if (isAMMPair[from]) {
        taxes = buyTax;
    }
    // wallet-to-wallet or untracked pair => no tax
}
```

**Impact:**
Trades through untracked pairs may incur no taxes, allowing tax bypasses and breaking expected tokenomics. Can also fragment liquidity.

**Location:**
`isAMMPair` mapping initialization and `handleTax()`.

**💡 Recommendation:**
> **Action Required:** Manage AMM pairs dynamically.
> 1. Add `onlyOwner` function to add/remove AMM pairs.
> 2. Optionally auto-detect common router/factory pairs.

### Low Findings

---

#### 🟢 [L-1] External .call to team addresses during transfers (potential reentrancy/side-effects)

**Description:**
`convertTaxes()` executes external `.call` to `marketingAddress` and `devAddress` within the token transfer path. Although gas is limited (35,000) and success is ignored, this is an unnecessary external interaction in a sensitive context.

```solidity
(success, ) = marketingAddress.call{ value: marketingShare, gas: 35000 }("");
(success, ) = devAddress.call{ value: remainingBalance, gas: 35000 }("");
```

**Impact:**
Potential reentrancy/side-effect vectors if set to contracts; may complicate transfer reliability or future integrations.

**Location:**
`convertTaxes()`.

**💡 Recommendation:**
> **Action Required:** Minimize external calls.
> 1. Accrue BNB and allow pull-based withdrawals with access control.
> 2. If keeping push, add reentrancy guard and emit events.

---

#### 🟢 [L-2] Missing events for key administrative changes

**Description:**
No events are emitted on `updateMarketingAddress()`, `updateDevAddress()`, and `updateTaxes()`, reducing transparency and off-chain monitoring capability.

```solidity
function updateMarketingAddress(address _address) external onlyOwner { ... }
function updateDevAddress(address _address) external onlyOwner { ... }
function updateTaxes(uint64 _buyMarketingTax, uint64 _sellMarketingTax) external onlyOwner { ... }
```

**Impact:**
Harder for users and tools to track changes to critical parameters.

**Location:**
Admin setter functions.

**💡 Recommendation:**
> **Action Required:** Emit events.
> 1. Add events for address/tax updates (e.g., `MarketingAddressUpdated`, `DevAddressUpdated`, `TaxesUpdated`).
> 2. Index the changed addresses/values.

### Good Practices
- Uses Solidity `^0.8.26` arithmetic (built-in overflow/underflow checks).
- Simple, non-upgradeable architecture (no proxy/delegatecall).
- Tax swapback capped by threshold and uses PancakeSwap V2 router.
- `exemptFromFees[address(this)] = true` prevents fee recursion on internal operations.
- Standard-like `Address` and `SafeERC20` libraries; no malicious modifications detected.
- Owner cannot mint beyond initial supply; `ERC20` implementation is straightforward.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard `ERC20` (decimals `9`) | Low |
| Upgrade Control | None (non-upgradeable) | Low |
| Ownership Status | Active (`owner()` set) | High (centralization) |
| Owner Address | 0x3695...befA | Current admin |
| Total Supply | 1e18 units (1,000,000,000 tokens at 9 decimals) | Low |
| Buy Tax | 0% (on-chain at snapshot) | Low |
| Sell Tax | 0% (on-chain at snapshot) | Low |
| Max Transaction | None | Low |

Details:
- Taxes route to contract, then swap to BNB; 60% to `marketingAddress`, 40% to `devAddress`. Threshold is 0.3% of supply by default, adjustable within 0.001%–0.5% limits.
- The launch window tax applies 90% on buys/sells while `block.number <= launchBlock`. The owner can choose the window length at `enableTrading()`, posing rug risk if set excessively high.
- Only the constructor-created Pancake pair is recognized for buy/sell tax logic; other pairs will not be taxed unless code is modified to add them.
- Centralization: Owner can set taxes up to 30% per side, change fee exemptions, and update payout addresses, requiring trust in the admin.
- No blacklist/max-tx/transfer limits present; `tradingAllowed` gating must be enabled by the owner for non-exempt transfers.

Ownership renunciation:
- If `owner` renounces (`address(0)`), there is no hidden restore or backdoor detected in `Ownable`. However, `withdrawStuckBNB()` and `rescueTokens()` (marketing-controlled) still allow centralized fund movements even post-renounce.

Balanced Assessment:
- Non-upgradeable design lowers upgrade risk. However, tax configuration, the 90% launch window, and centralized fund routing keep user risk high unless strong social trust exists in the owner/team.

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
