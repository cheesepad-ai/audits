# 🔍 World Cup Inu (WINU) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 2 |
| **Audit Date** | 2026-05-25T23:28:34.144Z (UTC) |
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

**Completed:** Mon, 25 May 2026 23:28:34 GMT

### Summary

`WorldCupInu` is a tax-based `ERC20` token on BSC with adjustable buy/sell taxes (default 3%/3%) and owner-controlled limits and exemptions. It routes tax proceeds to a `marketingWallet` via swaps and enforces max transaction and wallet limits with a hard floor of 2% of total supply. No proxy or mint/burn after deployment were found; primary risks are centralization of controls and MEV exposure on tax swaps. Overall Risk: MEDIUM – Owner retains broad control; no backdoors detected.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 3% (max 10%) | ✅ Low |
| Sell Tax | 3% (max 10%) | ✅ Low |
| Max Transaction | 2% of supply (floor ≥2%) | ✅ Reasonable |
| Contract Type | Standard (no proxy) | Info only |
| Ownership | Active (0x5796...) | ⚠️ Centralized |
| Pause Function | Trading gate (`tradingEnabled`) | ⚠️ Can halt trading (until enabled) |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | MEV on swaps; arbitrary AMM marking affects fees/limits |
| Centralization | Medium | Owner can change taxes (≤10%), limits, exemptions, AMM pairs; withdraw BNB |
| Code Quality | Medium | Custom minimal libs; SafeERC20/Address deviate from OZ |
| Exploit Likelihood | Low | No reentrancy/proxy/backdoor; typical tax-token risks |
| **Overall Risk Score** | **86/100** | No criticals; moderate centralization/MEV concerns |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn/sink address used for irretrievable tokens |
| `FEE_DENOMINATOR()` | `10000` | Basis points denominator for tax calculations |
| `MAX_LIMIT()` | `200` | Enforces min limit floor at 2% of supply |
| `MAX_TAX()` | `1000` | Maximum allowed tax is 10% (1000/10000) |
| `PANCAKE_ROUTER()` | `0x10ED...024E` | PancakeSwap V2 router used for swaps |
| `TOTAL_SUPPLY()` | `1000000000000000000` | Total base units minted (1e18 = 1,000,000,000 tokens @9 decimals) |
| `WETH()` | `0xbb4C...095c` | WBNB token address on BSC |
| `buyTax()` | `300` | Buy tax set to 3% (300/10000) |
| `decimals()` | `9` | Token uses 9 decimals |
| `dexRouter()` | `0x10ED...024E` | Router instance controlling swaps |
| `limitsEnabled()` | `true` | Max tx/wallet limits currently enforced |
| `lpPair()` | `0x31f2...2544` | Main liquidity pair address |
| `marketingWallet()` | `0x049C...Bdf5` | Destination for swap proceeds and rescues |
| `maxTxAmount()` | `20000000000000000` | 2% of total supply in base units |
| `maxWalletAmount()` | `20000000000000000` | 2% of total supply in base units |
| `name()` | `World Cup Inu` | Contract name identifier |
| `owner()` | `0x57969346cc1879071E3C1b2f8d6c3523E9CA329D` | Address holding admin privileges |
| `sellTax()` | `300` | Sell tax set to 3% (300/10000) |
| `swapEnabled()` | `true` | Automated tax swap is enabled |
| `swapTokensAtAmount()` | `2500000000000000` | Swap threshold 0.25% of supply |
| `symbol()` | `WINU` | Token ticker |
| `totalSupply()` | `1000000000000000000` | Same as TOTAL_SUPPLY; total minted |
| `tradingEnabled()` | `false` | Public trading not yet enabled |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 3 | MEV/slippage risk on swaps; Arbitrary AMM pair marking affects fees/limits; ManualSwap can dump full balance |
| Low | 3 | Custom SafeERC20/Address deviations; Trading gate can brick if misused; Owner-controlled exemptions create unequal trading |

### Critical Findings

None.

### High Findings

None.

### Medium Findings

---

#### 🟡 [M-1] Zero-minOut swaps enable MEV/sandwiching and poor execution on tax conversions

**Description:**
`swapExactTokensForETHSupportingFeeOnTransferTokens` is called with `amountOutMin = 0`, exposing swaps to front‑running and poor price execution.

```solidity
function swapTokensForBNB(uint256 tokenAmount) private {
    address[] memory path = new address[](2);
    path[0] = address(this);
    path[1] = WETH;

    dexRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        0, // no slippage protection
        path,
        address(this),
        block.timestamp
    );
}
```

**Impact:**
Attackers can sandwich tax swaps to extract value, depress price, and reduce BNB proceeds to `marketingWallet`.

**Location:**
`swapTokensForBNB()` in `WorldCupInu`.

**💡 Recommendation:**
> **Action Required:**
> 1. Use a reasonable `amountOutMin` (e.g., from TWAP or off-chain oracle) to mitigate slippage.
> 2. Add a configurable minimum-out basis points parameter controlled by governance.
> - Alternative: Rate-limit swaps or randomize swap sizes/timing to reduce predictability.

---

#### 🟡 [M-2] Owner can arbitrarily mark any address as AMM pair, affecting fees and bypassing wallet limit

**Description:**
`setAMMPair` allows the owner to set any address as an AMM pair. In `_transfer`, fees and wallet-limit logic depend on `isAMMPair[from]`/`isAMMPair[to]`.

```solidity
function setAMMPair(address pair, bool value) external onlyOwner {
    require(pair != address(0), "Zero address");
    require(pair != lpPair, "Main pair cannot be removed");
    isAMMPair[pair] = value;
    emit AMMPairUpdated(pair, value);
}

if (limitsEnabled && !swapping && !exemptFromTx[from] && !exemptFromTx[to]) {
    require(amount <= maxTxAmount, "Max transaction exceeded");

    if (!isAMMPair[to]) {
        require(balanceOf(to) + amount <= maxWalletAmount, "Max wallet exceeded");
    }
}
```

**Impact:**
- Transfers to addresses flagged as AMM pairs skip the max-wallet check.
- Transfers from/to such addresses are reclassified as buy/sell, changing applicable tax rates.
- Enables selective treatment of users, impacting fairness and predictability.

**Location:**
`setAMMPair()` and `_transfer()` conditions.

**💡 Recommendation:**
> **Action Required:**
> 1. Restrict AMM pair updates to validated DEX pairs (verify factory/pair code).
> 2. Maintain an allowlist of known factories or disable arbitrary updates after launch.
> - Alternative: Add a one-way “lock pairs” function after configuration.

---

#### 🟡 [M-3] `manualSwap` can dump entire contract token balance regardless of `swapEnabled`/threshold

**Description:**
`manualSwap()` ignores `swapEnabled` and threshold; it swaps the entire contract token balance in one transaction.

```solidity
function manualSwap() external {
    require(_msgSender() == marketingWallet || _msgSender() == owner(), "Not authorized");
    uint256 contractBalance = balanceOf(address(this));
    require(contractBalance > 0, "No tokens to swap");

    swapping = true;

    uint256 initialBalance = address(this).balance;
    swapTokensForBNB(contractBalance); // full dump
    uint256 newBalance = address(this).balance - initialBalance;

    if (newBalance > 0) {
        (bool success, ) = payable(marketingWallet).call{value: newBalance}("");
        emit TaxesSwapped(contractBalance, success ? newBalance : 0);
    }

    swapping = false;
}
```

**Impact:**
Large, sudden sells can cause severe price impact and slippage, enabling value extraction or destabilizing markets.

**Location:**
`manualSwap()` in `WorldCupInu`.

**💡 Recommendation:**
> **Action Required:**
> 1. Respect `swapEnabled` and `swapTokensAtAmount` in `manualSwap`.
> 2. Add a configurable max swap chunk size and time throttle.
> - Alternative: Split swaps into smaller batches automatically.

---

### Low Findings

---

#### 🟢 [L-1] Custom `Address.functionCall` lacks `isContract` verification (deviates from OpenZeppelin)

**Description:**
The custom `Address` and `SafeERC20` libraries differ from OZ: `functionCall` doesn’t verify target code size; `safeTransfer` accepts empty return data as success.

```solidity
library Address {
    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.call(data);
        if (success) {
            return returndata;
        }
        if (returndata.length > 0) {
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        }
        revert(errorMessage);
    }
}

library SafeERC20 {
    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        bytes memory returndata = address(token).functionCall(
            abi.encodeWithSelector(token.transfer.selector, to, value),
            "SafeERC20: low-level transfer failed"
        );
        if (returndata.length > 0) {
            require(abi.decode(returndata, (bool)), "SafeERC20: transfer failed");
        }
    }
}
```

**Impact:**
In general contexts, this can silently succeed for non-contract targets or non-standard tokens. Here, usage is limited to `rescueTokens`, mitigating impact.

**Location:**
`Address` and `SafeERC20` libraries.

**💡 Recommendation:**
> **Action Required:**
> 1. Align with OpenZeppelin’s `Address`/`SafeERC20` (add `isContract` check; strict return handling).
> - Alternative: Scope-check target code size before calling in `rescueTokens`.

---

#### 🟢 [L-2] Trading gate can brick the token if owner misuses `renounceOwnership` before enabling trading

**Description:**
Transfers by non-exempt addresses require `tradingEnabled == true`. If ownership is renounced before enabling trading, trading cannot be enabled thereafter.

```solidity
if (!exemptFromFees[from] && !exemptFromFees[to]) {
    require(tradingEnabled, "Trading is not enabled");
}

function enableTrading() external onlyOwner {
    require(!tradingEnabled, "Trading already enabled");
    tradingEnabled = true;
    emit TradingEnabled();
}
```

**Impact:**
Token could remain untradable for regular users permanently.

**Location:**
`_transfer()` and `enableTrading()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Operational safeguard: Enable trading before ownership renounce.
> - Alternative: Add a one-time irreversible initializer callable by anyone to enable trading after a set time.

---

#### 🟢 [L-3] Owner-controlled exemptions may create unequal market conditions

**Description:**
Owner can set/unset fee/tx exemptions for arbitrary accounts.

```solidity
function setExemptFromFee(address account, bool isExempt) external onlyOwner { ... }
function setExemptFromTx(address account, bool isExempt) external onlyOwner { ... }
```

**Impact:**
Privileged addresses can bypass taxes and limits, enabling non-uniform trading advantages.

**Location:**
`setExemptFromFee`, `setExemptFromTx` and their removers.

**💡 Recommendation:**
> **Action Required:**
> 1. Publish and maintain a transparent list of exempt addresses.
> - Alternative: Reduce exemptions post-launch and/or time-lock changes.

---

### Good Practices

- No mint/burn after deployment; fixed `TOTAL_SUPPLY`.
- `MAX_TAX` capped at 10%; cannot exceed by owner.
- Max tx and wallet limits cannot be set below 2% of supply (prevents honeypot-style lockups).
- Main LP pair cannot be removed from AMM mapping.
- Tax swap size capped to 5x threshold per `swapBack` to avoid oversized dumps.
- Clear events for all sensitive parameter changes.
- Ownership pattern is simple; no hidden backdoor or fake renounce detected.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard (no proxy) | Low upgrade risk |
| Upgrade Control | N/A | Low |
| Ownership Status | Active (0x5796...) | Medium centralization |
| Owner Address | 0x57969346cc1879071E3C1b2f8d6c3523E9CA329D | Current owner |
| Total Supply | 1,000,000,000 tokens (9 decimals) | Low |
| Buy Tax | 3% (max 10%) to marketing | Medium (owner-adjustable) |
| Sell Tax | 3% (max 10%) to marketing | Medium (owner-adjustable) |
| Max Transaction | 2% (floor ≥2%) | Low |
| Max Wallet | 2% (floor ≥2%) | Low |

- Taxes are routed entirely to `marketingWallet` after swaps; owner/marketing can trigger `manualSwap` and withdraw all BNB at any time. This is a standard marketing-tax pattern but centralizes control and introduces sell pressure when swapping.
- Limits have a 2% floor, reducing risk of post-launch honeypot via tiny maxTx/wallet. However, owner can mark arbitrary addresses as AMM pairs, changing fee classification and bypassing the wallet limit for those addresses.
- Balanced Assessment: No proxy/upgrades lower upgrade risk, but trust is required in the active owner for taxes, exemptions, and swap operations. MEV risk exists due to zero minOut swaps. Ownership appears properly implemented with no restore backdoor present.

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
