# 🔍 XPredict (PREDICT) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2025-12-25T02:22:08.282Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xdbba5e5e7088cfe4b796580c2e837993df2467e3` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | XPredict |
| **Symbol** | PREDICT |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Thu, 25 Dec 2025 02:22:08 GMT

### Summary

This is a tax-enabled `ERC20` token (`PREDICT`) on BSC with fixed 2% buy/sell fees routed to `marketing` (60%) and `dev` (40%) via automatic swapback to BNB using PancakeSwap V2. Trading is gated by `tradingAllowed`, and the owner can set fee exemptions, update wallet addresses, and adjust swap thresholds within bounds. No proxy or upgrade pattern is present, and ownership renunciation appears genuine (no backdoor). Overall Risk: MEDIUM - Centralized operational controls (trading gate, wallet redirection) and DEX-dependent swapback inside transfers.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 2% (200/10000) | ✅ Low |
| Sell Tax | 2% (200/10000) | ✅ Low |
| Max Transaction | None | ✅ No restrictions |
| Contract Type | Standard | Info only |
| Ownership | Active | ⚠️ Centralized |
| Pause Function | Trading gate via `tradingAllowed` | ⚠️ Can halt trading |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Low | No reentrancy surfaces exploitable in practice; safe math by 0.8.x |
| Centralization | Medium | Owner can gate trading, set exemptions, redirect tax wallets |
| Code Quality | Low | Clean, simple; libs appear unmodified OZ; events missing on some setters |
| Exploit Likelihood | Low | Fixed taxes, no blacklist/mint; DEX swap in transfer path is standard |
| **Overall Risk Score** | **90/100** | Few low/medium issues; no criticals detected |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn address placeholder; not actively used |
| `FEE_DIVISOR()` | `10000` | Basis for fee math (10000 = 100%) |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | Wrapped native token (WBNB) used in swaps |
| `buyTax()` | `200` | Buy tax rate for marketing: 200/10000 = 2% |
| `decimals()` | `9` | Token displays with 9 decimal places |
| `devAddress()` | `0xF49d4ee25fECd1061010152495557F7d02Ce3a6F` | Receives 40% of swapped tax proceeds |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router for swaps/liquidity |
| `lastSwapBackBlock()` | `0` | No tax conversion (swapback) executed yet |
| `lpPair()` | `0x4D06187f54Ba3d7C3BB08074ff8fC514E36D0fBF` | Token/WBNB AMM pair created in constructor |
| `marketingAddress()` | `0xF49d4ee25fECd1061010152495557F7d02Ce3a6F` | Receives 60% of swapped tax proceeds |
| `name()` | `XPredict` | Contract name identifier |
| `owner()` | `0xF49d4ee25fECd1061010152495557F7d02Ce3a6F` | Admin with controls over trading and settings |
| `sellTax()` | `200` | Sell tax rate for marketing: 200/10000 = 2% |
| `swapTokensAtAmt()` | `50000000000000` | Swap threshold (0.05% of supply) |
| `symbol()` | `PREDICT` | Token ticker |
| `totalSupply()` | `100000000000000000` | 100,000,000 tokens with 9 decimals |
| `tradingAllowed()` | `false` | Trading currently restricted to exempt addresses |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 0 | - |
| High | 0 | - |
| Medium | 2 | Trading gate centralization; Owner-controlled tax wallets and rescues |
| Low | 4 | Unrestricted BNB withdrawal trigger; DEX call in transfer path; Missing events; Excessive approval |

### Critical Findings

(None)

### High Findings

(None)

### Medium Findings

---

#### 🟡 [M-1] Trading Gate Can Lock Transfers for Non-Exempt Addresses

**Description:**
Transfers require `tradingAllowed` when neither party is fee-exempt. If the owner delays or never enables trading, non-exempt users cannot trade. If ownership is renounced before enabling, trading may remain disabled permanently.

```solidity
function _transfer(address from, address to, uint256 amount) internal virtual override {
    if (!exemptFromFees[from] && !exemptFromFees[to]) {
        require(tradingAllowed, "Trading not active");
        amount -= handleTax(from, to, amount);
    }
    super._transfer(from, to, amount);
}
```

**Impact:**
- Users may be unable to buy/sell/transfer unless whitelisted.
- Liquidity events can be staged to favor insiders via exemptions.

**Location:**
`PREDICT._transfer()`

**💡 Recommendation:**
> **Action Required:**
> 1. Enable trading (`enableTrading()`) before or immediately after liquidity addition.
> 2. Publicly commit to a go-live time and verify on-chain.
> - Alternative: Add an immutable launch block/time or timelock-controlled enable to reduce trust.

---

#### 🟡 [M-2] Centralized Control Over Tax Proceeds and Token Rescues

**Description:**
Owner can update `marketingAddress`/`devAddress` and set fee exemptions. `marketingAddress` can rescue any ERC20 from the contract, including this token’s accumulated fee tokens.

```solidity
function updateMarketingAddress(address _address) external onlyOwner { ... }
function updateDevAddress(address _address) external onlyOwner { ... }

function rescueTokens(address _token) external {
    require(msg.sender == marketingAddress, "Not marketing");
    uint256 _contractBalance = IERC20(_token).balanceOf(address(this));
    SafeERC20.safeTransfer(IERC20(_token), address(marketingAddress), _contractBalance);
}
```

**Impact:**
- Tax proceeds can be redirected at any time.
- Accumulated fee tokens can be extracted directly (bypassing swap and revenue split).
- Combined with exemptions and trading gate, increases rug/trust risk.

**Location:**
`PREDICT.updateMarketingAddress()`, `PREDICT.updateDevAddress()`, `PREDICT.rescueTokens()`

**💡 Recommendation:**
> **Action Required:**
> 1. Use a multisig for `owner`/wallets.
> 2. Emit events for all updates and consider timelocks.
> - Alternative: Restrict `rescueTokens` to exclude LP and native token, or time-lock its usage.

---

### Low Findings

---

#### 🟢 [L-1] Unrestricted `withdrawStuckBNB()` Allows Anyone To Trigger Payout

**Description:**
Any address can trigger sending the contract’s entire BNB balance to `marketingAddress`.

```solidity
function withdrawStuckBNB() external {
    bool success;
    (success, ) = address(marketingAddress).call{ value: address(this).balance }("");
}
```

**Impact:**
- Payout timing can be triggered by anyone, potentially interfering with planned distributions or accounting.
- Funds always go to `marketingAddress`, not a loss vector.

**Location:**
`PREDICT.withdrawStuckBNB()`

**💡 Recommendation:**
> **Action Required:**
> 1. Consider access control or rate limiting if timing matters.
> - Alternative: Emit an event to improve transparency when triggered.

---

#### 🟢 [L-2] External DEX Call During Transfer Path Without Reentrancy Guard

**Description:**
`handleTax()` may call `convertTaxes()` which swaps on Pancake during a transfer. Although Pancake is trusted and patterns are common, external calls inside transfer flow can be risky in general contexts.

```solidity
function handleTax(address from, address to, uint256 amount) internal returns (uint256) {
    if (balanceOf(address(this)) >= swapTokensAtAmt && !isAMMPair[from] && lastSwapBackBlock + 1 <= block.number) {
        convertTaxes();
    }
    ...
}
```

**Impact:**
- Minor theoretical reentrancy/gas griefing risk if router is compromised.
- Increased gas variability for users during taxed transfers.

**Location:**
`PREDICT.handleTax()`, `PREDICT.convertTaxes()`

**💡 Recommendation:**
> **Action Required:**
> 1. Keep router hardcoded and vetted (as done).
> - Alternative: Add a nonReentrant guard around conversion or move conversion to explicit function callable by anyone.

---

#### 🟢 [L-3] Missing Events for Administrative Changes

**Description:**
No events are emitted for `updateMarketingAddress`, `updateDevAddress`, and `updateSwapTokensAmt`, reducing transparency for off-chain monitors.

```solidity
function updateMarketingAddress(address _address) external onlyOwner { ... }
function updateDevAddress(address _address) external onlyOwner { ... }
function updateSwapTokensAmt(uint256 newAmount) external onlyOwner { ... }
```

**Impact:**
- Harder for users and analytics to track governance changes and operational parameters.

**Location:**
Administrative setters

**💡 Recommendation:**
> **Action Required:**
> 1. Emit events on address and parameter updates.

---

#### 🟢 [L-4] Excessive Approval of Owner’s Balance to Router

**Description:**
Router is approved for the entire owner balance at deployment.

```solidity
_approve(address(msg.sender), address(dexRouter), totalSupply());
```

**Impact:**
- Not exploitable with a genuine Pancake router, but unnecessary exposure if router is ever upgraded/forked maliciously.

**Location:**
Constructor

**💡 Recommendation:**
> **Action Required:**
> 1. Consider approving on-demand or reducing allowance post-liquidity add.

---

### Good Practices

- Uses Solidity 0.8.26 with built-in overflow checks; `unchecked` used safely.
- `Address` and `SafeERC20` libraries appear unmodified from OpenZeppelin patterns (v4.8+), no hidden backdoors detected.
- No blacklist, no arbitrary mint/burn, fixed tax rates (no owner-controlled tax changes).
- Proper handling to avoid multiple swapbacks per block via `lastSwapBackBlock`.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard (non-upgradeable) | Low |
| Upgrade Control | None (no proxy) | Low |
| Ownership Status | Active (0xF49d…e3a6F) | Medium (centralized operations) |
| Owner Address | 0xF49d4ee25fECd1061010152495557F7d02Ce3a6F | Current admin |
| Total Supply | 100,000,000 tokens (9 decimals) | Low |
| Buy Tax | 2% (marketing) | Low |
| Sell Tax | 2% (marketing) | Low |
| Max Transaction | None | Low |

The token levies a 2% tax on buys and sells only. Accumulated tokens are swapped to BNB, then split 60% to `marketingAddress` and 40% to `devAddress`. The owner can enable trading and set fee exemptions, which can shape launch dynamics; users must trust the owner to enable trading fairly and not to provide preferential exemptions. The owner can update payout addresses and rescue tokens from the contract, enabling direct extraction of accumulated fee tokens (not inherently malicious, but centralized).

Ownership renunciation is available and appears to be genuine with no `previousOwner` or restore functions discovered. If renounced before enabling trading, transfers for non-exempt users will remain blocked; ensure trading is enabled prior to renunciation. No proxy or upgrade risk is present.

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
