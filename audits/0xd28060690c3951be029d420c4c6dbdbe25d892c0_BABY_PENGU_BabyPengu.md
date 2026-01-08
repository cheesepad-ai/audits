# 🔍 BABY PENGU (BabyPengu) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 2 |
| **Audit Date** | 2026-01-08T05:30:48.376Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xd28060690c3951be029d420c4c6dbdbe25d892c0` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | BABY PENGU |
| **Symbol** | BabyPengu |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Thu, 08 Jan 2026 05:30:48 GMT

### Summary

This is a standard `ERC20` token (`BABYPENGU`) with fixed `9` decimals and a simple single-tax mechanism (3% buy/sell to `marketing/dev` via swapback on Pancake V2). Trading is gated by `tradingAllowed` (disabled by default), tax proceeds are auto-swapped for BNB and distributed 60% to `marketingAddress`, 40% to `devAddress`. Centralized controls over fee exemptions and payout addresses exist; some edge-case logic and external-call patterns introduce moderate risks. Overall Risk: MEDIUM - Centralized controls, tax-bypass on unlisted pairs, and reentrancy-susceptible external calls.

### Risk Assessment

Token Quick Facts:

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 3% | ✅ Low |
| Sell Tax | 3% | ✅ Low |
| Max Transaction | None | ✅ Reasonable |
| Contract Type | Standard | Info only |
| Ownership | Active | ⚠️ Centralized |
| Pause Function | No | ✅ No restrictions |

Security Assessment:

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | External calls in `convertTaxes()` from transfer path; no reentrancy guard |
| Centralization | Medium | Owner controls fee exemptions and payout addresses; marketing can rescue tokens |
| Code Quality | Medium | Some functions lack events; unnecessary approvals; unchecked ETH transfer results |
| Exploit Likelihood | Medium | Reentrancy and MEV risks exist but require conditions |
| **Overall Risk Score** | **84/100** | Medium risks (no criticals), several medium/low issues identified |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn address used to irreversibly lock tokens/liquidity |
| `FEE_DIVISOR()` | `10000` | Basis points divisor; 100 = 1% |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | Wrapped BNB address used for Pancake pairs |
| `buyTax()` | `300` | 3% buy tax routed to contract for later swap |
| `decimals()` | `9` | Token uses 9 decimal places |
| `devAddress()` | `0xd6c51A8669Ad078402802BDF434BEF205529bc3f` | Recipient for 40% of tax swap BNB |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router on BSC |
| `lastSwapBackBlock()` | `0` | Block of last tax swap; 0 means not executed yet |
| `lpPair()` | `0x649c93AfB669C5C74335DbEE1D58f79bAb5066B5` | WBNB trading pair for this token |
| `marketingAddress()` | `0xd6c51A8669Ad078402802BDF434BEF205529bc3f` | Recipient for 60% of tax swap BNB |
| `name()` | `BABY PENGU` | Contract name identifier |
| `owner()` | `0xd6c51A8669Ad078402802BDF434BEF205529bc3f` | Address with admin privileges |
| `sellTax()` | `300` | 3% sell tax routed to contract for later swap |
| `swapTokensAtAmt()` | `4444444444000000` | Swap threshold (~0.05% of supply) |
| `symbol()` | `BabyPengu` | Token ticker |
| `totalSupply()` | `8888888888000000000` | Total tokens ever created (8.888B with 9 decimals) |
| `tradingAllowed()` | `false` | Trading disabled until owner enables |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 4 | Reentrancy-prone external calls; Tax bypass on unlisted pairs; Centralized payout control; MEV/price-impact in swaps |
| Low | 6 | Public `withdrawStuckBNB`; Unnecessary router approval; Ignored ETH send results; Missing events; Hardcoded router; Operational trading switch risk |

### Critical Findings

None.

### High Findings

None.

### Medium Findings

---

#### 🟡 [M-1] External Calls in Transfer Path Without Reentrancy Guard

Description:
`convertTaxes()` is invoked from `handleTax()` during `_transfer()`. It performs external calls to the DEX router and then sends BNB to `marketingAddress` and `devAddress` using `call`. There is no reentrancy guard, and `lastSwapBackBlock` is updated only after external calls, creating potential reentrancy and double-swap conditions if a receiver reenters.

```solidity
function _transfer(address from, address to, uint256 amount) internal virtual override {
    if (!exemptFromFees[from] && !exemptFromFees[to]) {
        require(tradingAllowed, "Trading not active");
        amount -= handleTax(from, to, amount);
    }
    super._transfer(from, to, amount);
}

function handleTax(address from, address to, uint256 amount) internal returns (uint256) {
    if (
        balanceOf(address(this)) >= swapTokensAtAmt &&
        !isAMMPair[from] &&
        lastSwapBackBlock + 1 <= block.number
    ) {
        convertTaxes(); // external calls here
    }
    ...
}

function convertTaxes() private {
    ...
    dexRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(...);
    (success, ) = marketingAddress.call{ value: marketingShare, gas: 35000 }("");
    (success, ) = devAddress.call{ value: remainingBalance, gas: 35000 }("");
    lastSwapBackBlock = block.number; // updated after external calls
}
```

Impact:
- Potential reentrancy into token logic from `marketingAddress`/`devAddress` fallback (owner-controlled) or DEX callbacks.
- Possibility of multiple swaps within the same block before `lastSwapBackBlock` updates.
- AMM reserve manipulation mid-transfer can increase price impact or cause unexpected execution order.

Location:
`handleTax()` and `convertTaxes()`.

💡 Recommendation:
> Action Required:
> 1. Add a `nonReentrant` guard (e.g., OpenZeppelin `ReentrancyGuard`) and apply it to the swapback path.
> 2. Set `lastSwapBackBlock = block.number` before external calls (checks-effects-interactions).
> 3. Consider pulling BNB with `withdraw` pattern callable by owner off-path, or restrict marketing/dev to EOAs.
> - Alternative: Use a dedicated internal lock boolean to prevent nested `convertTaxes()` calls.

---

#### 🟡 [M-2] Taxes Not Applied on Unlisted AMM Pairs (Tax Bypass)

Description:
Taxes are only applied if either `to` or `from` is in `isAMMPair`. Only the initially created pair is marked; there is no function to add new pairs. Users can create a new pair and trade with 0% tax.

```solidity
if (isAMMPair[to]) {
    taxes = sellTax;
} else if (isAMMPair[from]) {
    taxes = buyTax;
}
// otherwise taxes defaults to zeros; no tax applied
```

Impact:
- Tax bypass reduces intended revenue for marketing/dev.
- Creates inconsistent trading experience and incentivizes alternative pools.

Location:
`handleTax()` tax selection logic.

💡 Recommendation:
> Action Required:
> 1. Add `onlyOwner` function to set/unset `isAMMPair(address, bool)`.
> 2. Optionally, default to applying taxes to unknown pairs or detect V2 pairs by codehash.

---

#### 🟡 [M-3] Centralized Control Over Fee Exemptions and Payout Addresses

Description:
Owner can arbitrarily set fee exemptions (`exemptFromFees`) and update `marketingAddress`/`devAddress`. `marketingAddress` can unilaterally `rescueTokens()` from the contract. This grants strong centralized control over tax routing and contract-held assets.

```solidity
function setExemptFromFee(address _address, bool _isExempt) external onlyOwner { ... }
function updateMarketingAddress(address _address) external onlyOwner { ... }
function updateDevAddress(address _address) external onlyOwner { ... }
function rescueTokens(address _token) external {
    require(msg.sender == marketingAddress, "Not marketing");
    ...
}
```

Impact:
- Users must fully trust the owner/marketing to not abuse exemptions or extract contract-held tokens.
- Ownership renunciation would still leave `marketingAddress` with rescue power.

Location:
Admin functions in `BABYPENGU`.

💡 Recommendation:
> Action Required:
> 1. Communicate centralization clearly to users.
> 2. Consider migrating control to a multisig.
> 3. If "renounced" plans exist, disable or time-lock `rescueTokens()` or restrict it to non-core assets.

---

#### 🟡 [M-4] MEV/Price-Impact Risk: Unbounded Slippage in Tax Swaps

Description:
Tax swaps use `swapExactTokensForETHSupportingFeeOnTransferTokens` with `amountOutMin = 0`, exposing swaps to MEV and price manipulation.

```solidity
dexRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(
    tokenAmt,
    0, // no slippage protection
    path,
    address(this),
    block.timestamp
);
```

Impact:
- Sandwichers can extract value from tax swaps, worsening BNB proceeds and market impact.

Location:
`swapTokensForETH()`.

💡 Recommendation:
> Action Required:
> 1. Apply a minimum out based on reserves or TWAP.
> 2. Limit swap size (already capped at `4 * swapTokensAtAmt`) and optionally randomize timing.

---

### Low Findings

---

#### 🟢 [L-1] Public `withdrawStuckBNB()` Allows Anyone to Push All BNB to Marketing

Description:
Anyone can call `withdrawStuckBNB()` to transfer the entire contract BNB balance to `marketingAddress`.

```solidity
function withdrawStuckBNB() external {
    bool success;
    (success, ) = address(marketingAddress).call{ value: address(this).balance }("");
}
```

Impact:
- Dev’s intended share can be bypassed for stuck funds (e.g., if dev transfer failed), centralizing recovery to marketing.
- Not a user-loss vector, but can cause internal fund misallocation.

Location:
`withdrawStuckBNB()`.

💡 Recommendation:
> Action Required:
> 1. Restrict to `onlyOwner` or `onlyMarketing/onlyDev` jointly.
> 2. Emit event for transparency.

---

#### 🟢 [L-2] Unnecessary Router Approval for Deployer’s Entire Balance

Description:
The constructor approves the router to spend the deployer’s entire balance, which is unnecessary and increases attack surface.

```solidity
_approve(address(msg.sender), address(dexRouter), totalSupply());
```

Impact:
- If router is compromised (unlikely) or misused, deployer tokens at risk.

Location:
Constructor.

💡 Recommendation:
> Action Required:
> 1. Remove this approval.
> 2. Let users approve exact amounts when using the router.

---

#### 🟢 [L-3] ETH Transfer Success Not Checked (Silent Failures)

Description:
ETH transfers to `marketingAddress` and `devAddress` ignore `success`. Failures leave funds stuck until manual withdrawal.

```solidity
(success, ) = marketingAddress.call{ value: marketingShare, gas: 35000 }("");
(success, ) = devAddress.call{ value: remainingBalance, gas: 35000 }("");
```

Impact:
- Dev may miss BNB share if their transfer fails; leftover funds may later be withdrawn entirely to marketing.

Location:
`convertTaxes()`.

💡 Recommendation:
> Action Required:
> 1. Require success or implement fallback handling.
> 2. Consider using pull payments to avoid forced sends.

---

#### 🟢 [L-4] Missing Events for Admin Updates

Description:
Updates to `marketingAddress`, `devAddress`, and swap threshold lack events.

```solidity
function updateMarketingAddress(address _address) external onlyOwner { ... }
function updateDevAddress(address _address) external onlyOwner { ... }
function updateSwapTokensAmt(uint256 newAmount) external onlyOwner { ... }
```

Impact:
- Reduces transparency for off-chain monitoring and users.

Location:
Admin setters.

💡 Recommendation:
> Action Required:
> 1. Emit events on each admin change.
> 2. Index new/old values.

---

#### 🟢 [L-5] Hardcoded Router Address (Chain Assumption)

Description:
Router is hardcoded to Pancake V2 mainnet. Deploying elsewhere without change will break critical functions.

```solidity
address _v2Router = 0x10ED43C7...; // BSC mainnet Pancake V2 router
```

Impact:
- Non-BSC deployments or forks may malfunction.

Location:
Constructor.

💡 Recommendation:
> Action Required:
> 1. Pass router as a constructor parameter.
> 2. Optionally add a one-time initializer for router/pair.

---

#### 🟢 [L-6] Operational Risk: Trading Can Be Irreversibly Disabled if Not Enabled Before Renounce

Description:
`tradingAllowed` can only be enabled once by the owner; if owner renounces before enabling, trading remains disabled forever.

```solidity
function enableTrading() external onlyOwner {
    require(!tradingAllowed, "Trading already enabled");
    tradingAllowed = true;
    lastSwapBackBlock = block.number;
}
```

Impact:
- Permanent token freeze if operational steps are missed.

Location:
`enableTrading()`.

💡 Recommendation:
> Action Required:
> 1. Ensure trading is enabled before any ownership changes.
> 2. Consider a timelocked enabling or multi-sig operational procedures.

---

### Good Practices

- Uses Solidity ≥0.8 with built-in overflow checks; careful `unchecked` blocks are appropriate.
- Swap threshold bounded between 0.001% and 0.5% of supply.
- No functions to arbitrarily increase taxes post-deployment (reduced rug potential).
- Pair trading at most once-per-block swapback throttling via `lastSwapBackBlock`.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard | Low |
| Upgrade Control | N/A (no proxy) | Low |
| Ownership Status | Active | High (centralization) |
| Owner Address | 0xd6c5...bc3f | Current owner |
| Total Supply | 8,888,888,888 (9 decimals) | Low |
| Buy Tax | 3% marketing | Low |
| Sell Tax | 3% marketing | Low |
| Max Transaction | None | Low |

- Taxes: Both buy and sell apply a flat 3% fee, accumulated on the contract and swapped to BNB. Distribution is 60% to `marketingAddress` and 40% to `devAddress`. No anti-whale or max wallet limits.
- Swapback: Triggered when the contract balance ≥ `swapTokensAtAmt` (~0.05% of supply), capped to 4x threshold per cycle. Uses no min-out, exposing to MEV and price impact. Executed on sells (i.e., when `from` is not a pair).
- Centralization: Owner can set fee exemptions, and update payout addresses. `marketingAddress` has `rescueTokens()` authority. Users must trust the owner and payout addresses.
- Pair coverage: Only the initially created Pancake pair is taxed; additional pairs will not be taxed unless code changes. This enables tax bypass on alternative pools.

Balanced Assessment: The contract is not upgradeable and has fixed tax rates, reducing some rug vectors. However, centralization remains significant (owner and marketing control), and the swapback design introduces moderate technical and MEV risks. No fake renounce/backdoor detected in `Ownable`; if renounced later, note that `marketingAddress` still holds token rescue power and tax proceeds continue to flow to marketing/dev.

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
