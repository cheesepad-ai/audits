# 🔍 WOOF (WOOF) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2025-12-22T01:15:23.718Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0x5d6c635b63fd5fabd7c2a0f24874bc28fc6abad2` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | WOOF |
| **Symbol** | WOOF |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Mon, 22 Dec 2025 01:15:23 GMT

### Summary

`WOOF` is a tax-enabled `ERC20` token (9 decimals) with buy/sell marketing fees (2% each) routed through automated swapbacks on PancakeSwap V2. Key controls include an owner-gated trading switch, fee exemptions, and owner-controlled `marketingAddress`/`devAddress` revenue routing. No proxy/upgradeability is present; renounce is real, but fee proceeds and rescues are centralized to team wallets. Overall Risk: MEDIUM – Centralized tax proceeds and a missing reentrancy guard around swapback introduce operational and MEV risks.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 2% marketing | ✅ Low |
| Sell Tax | 2% marketing | ✅ Low |
| Max Transaction | None | ✅ No restrictions |
| Contract Type | Standard (non-upgradeable) | Info |
| Ownership | Active (EOA owner) | ⚠️ Centralized |
| Pause Function | No (but trading gate) | ⚠️ Can block trading until enabled |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | Swapback without reentrancy guard; minOut=0 enables MEV; AMM pair list immutable |
| Centralization | Medium | Owner controls trading enable/fee exemptions/recipient wallets; marketing can rescue tokens |
| Code Quality | Low | Clean, OZ-like patterns; no obvious arithmetic or auth flaws |
| Exploit Likelihood | Medium | MEV likely; reentrancy requires malicious marketing/dev contract or misconfiguration |
| **Overall Risk Score** | **87/100** | 0 critical, 1 high, 2 medium, 2 low |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn address used to permanently lock tokens |
| `FEE_DIVISOR()` | `10000` | Tax denominator; 10000 equals 100% |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | Wrapped BNB used for BSC liquidity pairs |
| `buyTax()` | `200` | 2% marketing tax on buys from AMM pair |
| `decimals()` | `9` | Token uses 9 decimal places |
| `devAddress()` | `0x235B674bdafb045aaCCd0Ae0c5Ab6A22F7879752` | Receives 40% of tax swap proceeds |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router |
| `lastSwapBackBlock()` | `0` | No swapback executed yet |
| `lpPair()` | `0xF7E857822620C4d817406a7FffC6AA46afa1682D` | Pancake V2 WOOF-WBNB trading pair |
| `marketingAddress()` | `0x235B674bdafb045aaCCd0Ae0c5Ab6A22F7879752` | Receives 60% of tax swap proceeds |
| `name()` | `WOOF` | Contract name identifier |
| `owner()` | `0x235B674bdafb045aaCCd0Ae0c5Ab6A22F7879752` | Admin address with privileged functions |
| `sellTax()` | `200` | 2% marketing tax on sells to AMM pair |
| `swapTokensAtAmt()` | `210000000000000000000000` | Swapback threshold (~0.05% of supply) |
| `symbol()` | `WOOF` | Token ticker |
| `totalSupply()` | `420000000000000000000000000` | Total tokens minted at deployment |
| `tradingAllowed()` | `false` | Transfers between non-exempt blocked until enabled |

### Findings Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| Critical | 0 | — |
| High | 1 | Missing reentrancy guard around swapback and ETH payouts |
| Medium | 2 | Zero minOut in swaps enables MEV; Immutable AMM pair map allows tax bypass via new pairs |
| Low | 2 | Anyone can trigger ETH payout to marketing; Marketing can rescue this token from contract |

### Critical Findings

No critical findings identified.

### High Findings

#### 🟠 [H-1] Reentrancy risk: swapback and ETH payouts occur during `transfer()` without a reentrancy guard

**Description:**
`_transfer()` calls `handleTax()`, which may call `convertTaxes()` in the same transaction. `convertTaxes()` performs:
- Pancake router swap (external call)
- ETH payouts to `marketingAddress` and `devAddress` using `.call{gas: 35000}("")` twice

No mutex (`inSwap`), no `nonReentrant`, and `lastSwapBackBlock` does not prevent reentrancy within the same block before it’s updated. If `marketingAddress`/`devAddress` is a contract with a fallback, it can reenter token functions during a transfer, potentially causing nested swapbacks and unexpected state interactions.

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
        convertTaxes(); // external calls (router + .call to wallets)
    }
    ...
}

function convertTaxes() private {
    ...
    swapTokensForETH(contractBalance); // external call (router)
    bool success;
    (success, ) = marketingAddress.call{value: marketingShare, gas: 35000}("");
    (success, ) = devAddress.call{value: remainingBalance, gas: 35000}("");
    lastSwapBackBlock = block.number; // set only after external calls
}
```

**Impact:**
- Nested swapbacks in a single transaction can amplify price impact and slippage.
- If `marketingAddress`/`devAddress` is a malicious or buggy contract, reentrancy may cause unexpected execution flows and gas griefing.
- While direct theft is unlikely, invariant violations and cascading swaps are possible.

**Location:**
`_transfer()`, `handleTax()`, `convertTaxes()`

**💡 Recommendation:**
> **Action Required:**
> 1. Add a swap mutex:
> 
> ```solidity
> bool private inSwap;
> modifier swapping() { inSwap = true; _; inSwap = false; }
> ```
> 
> 2. Wrap `convertTaxes()` with `if (!inSwap)` and mark `convertTaxes()` as `swapping`.
> 3. Alternatively, use OpenZeppelin `ReentrancyGuard` and guard `convertTaxes()` calls.
> 4. Set `lastSwapBackBlock` before external calls, then restore on failure to minimize reentrancy windows.

### Medium Findings

#### 🟡 [M-1] MEV risk: `amountOutMin` set to 0 in swapback enables sandwich/front-run losses

**Description:**
`swapTokensForETH()` calls the router with `amountOutMin = 0`, allowing swaps at any price. MEV bots can sandwich swapback transactions, extracting value and reducing ETH proceeds for `marketingAddress`/`devAddress`.

```solidity
function swapTokensForETH(uint256 tokenAmt) private {
    address[] memory path = new address[](2);
    path[0] = address(this);
    path[1] = WETH;
    dexRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmt,
        0, // <- no slippage protection
        path,
        address(this),
        block.timestamp
    );
}
```

**Impact:**
- Reduced revenue from swapbacks due to predatory pricing.
- Increased price impact on the token during automatic conversions.

**Location:**
`swapTokensForETH()`

**💡 Recommendation:**
> **Action Required:**
> - Use a dynamic `amountOutMin` based on TWAP/spot via an oracle or setting a conservative slippage tolerance (e.g., 3-5%).
> - Consider splitting large swapbacks into smaller chunks or introduce variable thresholds.

---

#### 🟡 [M-2] Immutable AMM pair list allows tax bypass via new liquidity pairs

**Description:**
Only the initial pair created in the constructor is marked as an AMM pair. There is no function to add/remove pairs. Attackers or arbitrageurs can create alternative pools and route trades through them to avoid buy/sell taxation.

```solidity
lpPair = IDexFactory(dexRouter.factory()).createPair(address(this), WETH);
isAMMPair[lpPair] = true;
// No function to add future pairs to isAMMPair
```

**Impact:**
- Reduced fee collection.
- Potential manipulation by routing through non-taxed pools, impacting tokenomics.

**Location:**
Constructor; mapping `isAMMPair`

**💡 Recommendation:**
> **Action Required:**
> - Add an `onlyOwner` function to manage `isAMMPair` entries with events.
> - Optionally, auto-mark pairs created against known routers/factories if applicable.

### Low Findings

#### 🟢 [L-1] Anyone can trigger ETH payout to marketing via `withdrawStuckBNB()`

**Description:**
`withdrawStuckBNB()` is publicly callable and forwards the entire ETH balance to `marketingAddress`. While designed as a rescue, it enables arbitrary callers to trigger payouts at any time.

```solidity
function withdrawStuckBNB() external {
    bool success;
    (success, ) = address(marketingAddress).call{ value: address(this).balance }("");
}
```

**Impact:**
- Unpredictable timing of ETH transfers can complicate operations/accounting.
- Not a direct loss; funds go to the intended wallet.

**Location:**
`withdrawStuckBNB()`

**💡 Recommendation:**
> **Action Required:**
> - Restrict to `onlyOwner` or `onlyMarketing`.
> - Emit an event for transparency.

---

#### 🟢 [L-2] `rescueTokens()` allows marketing to drain contract-held `WOOF` tokens

**Description:**
`marketingAddress` can rescue any ERC20 from the contract, including `WOOF` itself, bypassing the automated swapback. This centralizes control over fee accumulation and can affect market dynamics.

```solidity
function rescueTokens(address _token) external {
    require(msg.sender == marketingAddress, "Not marketing");
    require(_token != address(0), "_token address cannot be 0");
    uint256 _contractBalance = IERC20(_token).balanceOf(address(this));
    SafeERC20.safeTransfer(IERC20(_token), address(marketingAddress), _contractBalance);
}
```

**Impact:**
- Sudden large transfers of `WOOF` from the contract to marketing can lead to manual dumps or uneven fee realization.
- Trust assumption in `marketingAddress`.

**Location:**
`rescueTokens(address)`

**💡 Recommendation:**
> **Action Required:**
> - Consider disallowing `rescueTokens(address(this))` or gating it with `onlyOwner` and a timelock.
> - Emit an event with the rescued token and amount.

### Good Practices

- Uses Solidity 0.8.x with built-in overflow/underflow checks and explicit `unchecked` only where safe
- Standard ERC20 implementation; no reflection or complex fee math
- No upgradeability/proxy pattern; implementation is immutable
- Ownership renounce is real (no `previousOwner`/restore backdoors)
- Router/pair are immutable; allowances configured appropriately for router operations
- External calls in swapback use low gas and ignore failures to avoid hard reverts

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard ERC20 with buy/sell tax | Low intrinsic risk |
| Upgrade Control | None (non-upgradeable) | Low |
| Ownership Status | Active (EOA owner) | Medium (centralized controls) |
| Owner Address | 0x235B...9752 | Privileged |
| Total Supply | 420,000,000,000,000,000 × 10^9 (4.2e26 units) | Low |
| Buy Tax | 2% to marketing | Low |
| Sell Tax | 2% to marketing | Low |
| Max Transaction | None | Low |

- Fees: 2% on buys and sells, collected in tokens, swapped to ETH/BNB when `balanceOf(this) >= swapTokensAtAmt` (~0.05% of supply). Proceeds distributed 60% to `marketingAddress` and 40% to `devAddress`.
- Controls: Owner can enable trading, adjust fee exemptions, and update `marketingAddress`/`devAddress`. `rescueTokens()` lets marketing withdraw any ERC20 from the contract, including this token. This centralizes fee handling and requires trust in the team.
- AMM Pairing: Only the initial Pancake V2 WOOF-WBNB pair is taxed. Additional pools are not auto-taxed, allowing potential fee bypass via alternate pairs unless the code is extended.

Balanced Assessment: No proxy or upgrade risk. Primary concerns are operational: MEV exposure during swapback due to `minOut=0`, potential reentrancy due to external calls within transfers, and centralized control over fee proceeds. If the team is trusted and addresses are EOAs, risks decrease. If ownership is renounced, note that marketing retains `rescueTokens()` and ETH receipt rights, preserving some centralization over proceeds.

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
