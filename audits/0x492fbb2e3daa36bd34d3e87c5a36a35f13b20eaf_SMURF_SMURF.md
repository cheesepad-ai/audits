# 🔍 SMURF (SMURF) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-01-01T04:16:12.550Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0x492fbb2e3daa36bd34d3e87c5a36a35f13b20eaf` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | SMURF |
| **Symbol** | SMURF |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Thu, 01 Jan 2026 04:16:12 GMT

### Summary

This contract implements a tax-enabled `ERC20` token (`SMURF`) with 9 decimals on BSC, integrating PancakeSwap V2 router for swaps and automatic tax conversion to ETH (WBNB). It charges a fixed 2% buy/sell tax sent to the contract and converted to ETH, distributed 60% to `marketingAddress` and 40% to `devAddress`. No upgradeability or blacklist; transfers are gated by `tradingAllowed` pre-launch. Overall risk is primarily centralization and MEV exposure in tax swaps. Overall Risk: MEDIUM – Owner/marketing controls and MEV-prone swap logic, but no backdoors, no upgradeability.

### Risk Assessment

Token Quick Facts:

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 2% | ✅ Low |
| Sell Tax | 2% | ✅ Low |
| Max Transaction | None | ✅ No hard limits |
| Contract Type | Standard (non-upgradeable) | Info |
| Ownership | Active (EOA `0xa074...e29`) | ⚠️ Centralized |
| Pause Function | No (pre-launch gate only) | ✅ No post-launch pause |

Security Assessment:

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Low | Standard ERC20, simple tax; no complex external logic |
| Centralization | Medium | Owner can change fee exemptions/addresses; marketing can pull funds |
| Code Quality | Medium | Generally clean; minor type narrowing and event omissions |
| Exploit Likelihood | Low | No critical attack surface observed |
| **Overall Risk Score** | **91/100** | 0 critical, 0 high, 3 medium, 5 low → 100 - (0*10 + 0*5 + 3*3 + 5*1) = 91 |

## On-Chain Function Results

The following functions were called on-chain at block 73651506. The table below shows the results:

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn address used to irreversibly lock tokens |
| `FEE_DIVISOR()` | `10000` | Basis points denominator (1% = 100) for tax calculations |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | WBNB token address used as base asset in swaps |
| `buyTax()` | `200` | Buy tax in bps (200 = 2%) applied on buys from AMM pair |
| `decimals()` | `9` | Token uses 9 decimals for balances and display |
| `devAddress()` | `0xa0745972cb3D18d08E302dd317411e3d1E723e29` | Receives 40% of converted tax ETH |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router used for swaps/liquidity |
| `lastSwapBackBlock()` | `0` | No tax-conversion swap has executed yet |
| `lpPair()` | `0x53cd8D37799EBb2243A7B5eb2030252660eF8c49` | Token/WBNB pair used to detect buys/sells |
| `marketingAddress()` | `0xa0745972cb3D18d08E302dd317411e3d1E723e29` | Receives 60% of converted tax ETH |
| `name()` | `SMURF` | Contract name identifier |
| `owner()` | `0xa0745972cb3D18d08E302dd317411e3d1E723e29` | Admin EOA controlling owner-only functions |
| `sellTax()` | `200` | Sell tax in bps (200 = 2%) applied on sells to AMM pair |
| `swapTokensAtAmt()` | `500000000000000` | Swap threshold (~0.05% of supply) to convert taxes |
| `symbol()` | `SMURF` | Token ticker |
| `totalSupply()` | `1000000000000000000` | Total minted supply (1,000,000,000 tokens at 9 decimals) |
| `tradingAllowed()` | `false` | Trading not enabled; only fee-exempt can transfer |

### Findings Summary

| Severity | Count | Key Issues |
|----------|-------|-----------|
| Critical | 0 | None |
| High | 0 | None |
| Medium | 3 | Untaxed alternative AMM pairs; MEV/slippage risk on tax swaps; Persistent marketing privileges post-renounce |
| Low | 5 | Potential reentrancy vector (low impact); uint128 narrowing; Unlimited router allowance from deployer; Missing events; Fixed 35k gas stipend may block refunds |

### Critical Findings

None.

### High Findings

None.

### Medium Findings

---

#### 🟡 [M-1] Taxes apply only to a single hardcoded pair; alternative AMM pools can bypass taxes

**Description:**
Only the constructor-created pair is marked in `isAMMPair`. There is no function to add or manage additional pairs. Trades through other pools will be treated as wallet-to-wallet and incur no tax, undermining tokenomics and expected revenue.

```solidity
mapping(address => bool) public isAMMPair;
// ...
lpPair = IDexFactory(dexRouter.factory()).createPair(address(this), WETH);
isAMMPair[lpPair] = true;
// no function to add/remove other pairs
```

**Impact:**
Third parties can create parallel pools with zero tax, reducing protocol revenue and enabling tax arbitrage.

**Location:**
`constructor()` and `isAMMPair` mapping usage in `handleTax()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Add an `onlyOwner` function to set/unset additional AMM pairs.
> 2. Optionally auto-detect pairs via known factory contracts and allowlist.

---

#### 🟡 [M-2] Tax swaps use amountOutMin=0 and deadline=block.timestamp (MEV/slippage risk)

**Description:**
Swaps use zero minimum output and a same-block deadline, making conversions vulnerable to sandwich/front-run attacks, extracting value from the tax pool.

```solidity
dexRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(
    tokenAmt,
    0,
    path,
    address(this),
    block.timestamp
);
```

**Impact:**
Adversaries can manipulate price around the swap to capture value, reducing net ETH reaching `marketingAddress` and `devAddress`.

**Location:**
`swapTokensForETH()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Introduce slippage controls (e.g., oracle-based minOut or configurable basis points).
> 2. Randomize or delay swaps; consider TWAP/anti-MEV strategies.

---

#### 🟡 [M-3] Persistent centralized privileges via `marketingAddress` after ownership renounce

**Description:**
Even if `owner` renounces, `marketingAddress` retains the ability to pull all ETH (`withdrawStuckBNB()`) and rescue any ERC20 tokens (`rescueTokens()`), including protocol-held tokens. While not a fake renounce, centralization persists.

```solidity
function withdrawStuckBNB() external {
    bool success;
    (success, ) = address(marketingAddress).call{ value: address(this).balance }("");
}

function rescueTokens(address _token) external {
    require(msg.sender == marketingAddress, "Not marketing");
    // transfers any ERC20 held by the contract to marketingAddress
}
```

**Impact:**
Users may assume full decentralization post-renounce, but a centralized party still controls funds accrued in the contract and any tokens sent to it.

**Location:**
`withdrawStuckBNB()` and `rescueTokens()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Clarify publicly that `marketingAddress` retains powers post-renounce.
> 2. Optionally gate these functions by multisig/timelock or remove if not required.

---

### Low Findings

---

#### 🟢 [L-1] Potential reentrancy surface during `convertTaxes()` via ETH transfers (low impact)

**Description:**
`convertTaxes()` performs external calls to `marketingAddress` and `devAddress` using `.call`. Although gas is capped at 35k and amounts are ETH only, a malicious contract could attempt reentrancy.

```solidity
(success, ) = marketingAddress.call{ value: marketingShare, gas: 35000 }("");
(success, ) = devAddress.call{ value: remainingBalance, gas: 35000 }("");
```

**Impact:**
Limited due to low gas stipend and lack of sensitive state after swap; worst case is benign reentrancy with no state corruption.

**Location:**
`convertTaxes()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Add a simple `nonReentrant` modifier or update state before external calls.
> 2. Consider pull-payment model with explicit withdrawals.

---

#### 🟢 [L-2] Unnecessary uint128 narrowing may cause future-proofing issues

**Description:**
Tax intermediate is cast to `uint128`. While safe under current supply and tax, this is unnecessarily restrictive.

```solidity
uint128 tax = 0;
tax = uint128((amount * taxes.marketingTax) / FEE_DIVISOR);
```

**Impact:**
Future increases in supply or tax logic could risk truncation if reused elsewhere.

**Location:**
`handleTax()`.

**💡 Recommendation:**
> **Action Required:**
> - Use `uint256` for `tax` to match ERC20 math and remove narrowing.

---

#### 🟢 [L-3] Unlimited router allowance from deployer EOA

**Description:**
The deployer’s entire `totalSupply` is approved to the router at deployment.

```solidity
_approve(address(msg.sender), address(dexRouter), totalSupply());
```

**Impact:**
If the router is compromised or misused by the deployer’s workflows, tokens could be transferred via `transferFrom()`. This relies on the router’s trustworthiness (PancakeSwap V2 is widely trusted).

**Location:**
`constructor()`.

**💡 Recommendation:**
> **Action Required:**
> - Reduce allowances to exact amounts needed for operations, or revoke after liquidity provisioning.

---

#### 🟢 [L-4] Missing events for critical updates reduces transparency

**Description:**
No events are emitted for `updateMarketingAddress`, `updateDevAddress`, or `updateSwapTokensAmt`.

```solidity
function updateMarketingAddress(address _address) external onlyOwner { ... }
function updateDevAddress(address _address) external onlyOwner { ... }
function updateSwapTokensAmt(uint256 newAmount) external onlyOwner { ... }
```

**Impact:**
Off-chain indexers and users cannot easily monitor configuration changes.

**Location:**
Owner update functions.

**💡 Recommendation:**
> **Action Required:**
> - Emit events on each parameter change (MarketingUpdated, DevUpdated, SwapThresholdUpdated).

---

#### 🟢 [L-5] Fixed 35,000 gas stipend may break refunds to contract wallets

**Description:**
ETH transfers during tax conversion use a 35k gas stipend, which may be insufficient for some contracts (e.g., multisigs with non-trivial `receive()`).

```solidity
(success, ) = marketingAddress.call{ value: marketingShare, gas: 35000 }("");
(success, ) = devAddress.call{ value: remainingBalance, gas: 35000 }("");
```

**Impact:**
Failed transfers cause ETH to remain in the contract until `withdrawStuckBNB()` is called (which itself may fail if receiver reverts).

**Location:**
`convertTaxes()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Allow configurable gas stipends or use a pull-based claim model.
> 2. Add a fallback sweep function callable by owner/marketing with no gas cap.

---

### Good Practices

- Non-upgradeable standard `ERC20`; no proxy or delegatecall.
- Fixed buy/sell tax (2% each); no owner function to raise taxes.
- No blacklist or transfer pause after enabling trading.
- Uses well-known PancakeSwap V2 router and WBNB addresses on BSC.
- Uses OZ-style `Address` and `SafeERC20` patterns with no malicious modifications detected.
- Overflow-safe via Solidity 0.8.x with carefully bounded unchecked blocks.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard (non-upgradeable) | Low |
| Upgrade Control | None | Low |
| Ownership Status | Active | Medium (centralization) |
| Owner Address | 0xa0745972cb3D18d08E302dd317411e3d1E723e29 | Current owner |
| Total Supply | 1,000,000,000 tokens (9 decimals) | Low |
| Buy Tax | 2% (to contract, later 60% marketing/40% dev) | Low |
| Sell Tax | 2% (to contract, later 60% marketing/40% dev) | Low |
| Max Transaction | None | Low |

Details:
- Tax accrual swaps are triggered when the contract’s token balance ≥ `swapTokensAtAmt` (~0.05% supply). Swaps are restricted to at most once per block and not triggered on buy transactions (`!isAMMPair[from]`).
- ETH distribution from tax conversions: 60% to `marketingAddress`, 40% to `devAddress`. Both are initially the deployer EOA. These can be updated by `owner`.
- Only the constructor-created `lpPair` is recognized for buy/sell detection; all other pools are untaxed. This can dilute tax revenue and enable tax-free routing.
- Pre-launch gate: `tradingAllowed` restricts trading until the owner enables it. After enabling, there is no pause function to stop trading.
- Balanced assessment: No upgradeable proxy (good), but centralized control over fee exemptions and fund withdrawals persists. Users must trust `owner`/`marketingAddress` for operational integrity and honest tax distribution.

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
