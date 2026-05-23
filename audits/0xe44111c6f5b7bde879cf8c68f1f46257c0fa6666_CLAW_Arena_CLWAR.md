# 🔍 CLAW Arena (CLWAR) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-05-23T16:17:38.949Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xe44111c6f5b7bde879cf8c68f1f46257c0fa6666` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | CLAW Arena |
| **Symbol** | CLWAR |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Sat, 23 May 2026 16:17:38 GMT

### Summary

This is a standard `ERC20` tax token (`ClawArena`) with 9 decimals and automated tax collection/swapback to BNB routed to `marketing`, `treasury`, and `nodes`. Taxes are fixed at 3% on buys and sells (1% each component), no blacklist or max tx, and `tradingAllowed` gate controls launch. Centralization exists around owner and especially `marketingAddress` which can unilaterally withdraw all contract BNB and rescued tokens; distribution calls use a 35k gas stipend and ignore failure, potentially diverting all BNB to marketing. Overall Risk: MEDIUM – Solid baseline with no backdoors or proxy, but notable centralization and MEV/gas-related distribution risks.

### Risk Assessment

Token Quick Facts:

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 3% (1% marketing, 1% treasury, 1% nodes) | ✅ Low |
| Sell Tax | 3% (1% marketing, 1% treasury, 1% nodes) | ✅ Low |
| Max Transaction | None | ✅ No hard limits |
| Contract Type | Standard | Info |
| Ownership | Active (owner can change settings) | ⚠️ Centralized |
| Pause Function | No (launch gate only) | ✅ No pause after enable |

Security Assessment:

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | Swapback uses amountOutMin=0 (MEV), 35k gas payouts ignore failure |
| Centralization | High | Owner can whitelist/launch; marketing can pull all BNB/tokens |
| Code Quality | Medium | Clean; minor issues (no events for updates, fixed gas stipends) |
| Exploit Likelihood | Low | No reentrancy/proxy/backdoor; risks are mostly trust/MEV |
| **Overall Risk Score** | **83/100** | No criticals; 1 high, several medium/low issues |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn address for irrecoverable token sends |
| `FEE_DIVISOR()` | `10000` | Basis points denominator for fee calculations (10000 = 100%) |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | Wrapped BNB token used for swaps |
| `buyTax()` | `["100","100","100","300"]` | Buy tax bps: 1% marketing, 1% treasury, 1% nodes, 3% total |
| `decimals()` | `9` | Token uses 9 decimal places |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap v2 router on BSC |
| `lastSwapBackBlock()` | `0` | Last tax conversion block; 0 means not executed yet |
| `lpPair()` | `0x947e0f7aF1BadcEaA8AD8A4C97b954C9410684c4` | Created liquidity pair with WBNB |
| `marketingAddress()` | `0x3AD00B29567990aEd5287974979b0cED84B04DdC` | Receives remaining BNB; admin for withdrawals |
| `name()` | `CLAW Arena` | Contract name identifier |
| `nodesAddress()` | `0x3AD00B29567990aEd5287974979b0cED84B04DdC` | Receives one-third of converted BNB |
| `owner()` | `0x03d883a16a0ACbc62112d37370d42A51E333Bb17` | Admin with authority to modify settings |
| `sellTax()` | `["100","100","100","300"]` | Sell tax bps: 1% each; total 3% |
| `swapTokensAtAmt()` | `2000000000000000` | Swapback threshold (0.05% of total supply) |
| `symbol()` | `CLWAR` | Token symbol |
| `totalSupply()` | `4000000000000000000` | Total tokens (4,000,000,000 with 9 decimals) |
| `tradingAllowed()` | `false` | Launch gate disabled; trading not active |
| `treasuryAddress()` | `0x3AD00B29567990aEd5287974979b0cED84B04DdC` | Receives one-third of converted BNB |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|-----------|
| Critical | 0 | |
| High | 1 | Marketing-only withdrawal plus ignored payout failures can divert all BNB |
| Medium | 3 | Owner can bypass launch via exemptions; MEV due to minOut=0; 35k gas payout DoS |
| Low | 4 | Untracked new AMM pairs; Unlimited router approvals; No events for updates; Non-standard 9 decimals UI risk |

### Critical Findings

No critical findings identified.

### High Findings

#### 🟠 [H-1] Marketing-only withdrawal and ignored payout failures enable capture of all converted BNB

**Description:**
Payouts to `treasuryAddress` and `nodesAddress` use `.call{gas:35000}` and ignore `success`. Failures leave BNB in the contract. A separate `withdrawStuckBNB()` function, callable only by `marketingAddress`, transfers the entire BNB balance to `marketingAddress`, enabling unilateral capture of funds supposedly shared among recipients.

```solidity
(success, ) = treasuryAddress.call{value: share, gas: 35000}("");
(success, ) = nodesAddress.call{value: share, gas: 35000}("");
...
(success, ) = marketingAddress.call{value: remainingBalance, gas: 35000}("");

function withdrawStuckBNB() external {
    require(msg.sender == marketingAddress, "Not marketing");
    bool success;
    (success, ) = address(marketingAddress).call{ value: address(this).balance }("");
}
```

**Impact:**
- If `treasuryAddress`/`nodesAddress` revert or require more than 35k gas, their shares remain in the contract.
- `marketingAddress` can subsequently sweep the entire BNB balance, diverting funds from other recipients. This undermines stated distribution and can be viewed as deceptive.

**Location:**
`convertTaxes()` payout calls; `withdrawStuckBNB()` function.

**💡 Recommendation:**
> **Action Required:**
> 1. Do not ignore call failures; revert on failed mandatory payouts or track debt and retry later.
> 2. Remove or restrict `withdrawStuckBNB()` (use `onlyOwner` or multisig; proportionally split stuck funds).
> 3. Avoid hard gas stipends; allow enough gas or support pull-pattern withdrawals with explicit functions for each recipient.

---

### Medium Findings

#### 🟡 [M-1] Owner can bypass `tradingAllowed` by exempting AMM pair or counterparties

**Description:**
Transfers skip the `tradingAllowed` gate when either party is in `exemptFromFees`. Owner can set exemptions for any address, including the LP pair, enabling trading before `enableTrading()`.

```solidity
if (!exemptFromFees[from] && !exemptFromFees[to]) {
    require(tradingAllowed, "Trading not active");
    amount -= handleTax(from, to, amount);
}

function setExemptFromFee(address _address, bool _isExempt) external onlyOwner {
    ...
    exemptFromFees[_address] = _isExempt;
}
```

**Impact:**
- Stealth/bot trading can occur prior to public launch, enabling unfair advantage or sniping.
- Launch assurances relying on `tradingAllowed` can be circumvented by owner discretion.

**Location:**
`_transfer()` gating; `setExemptFromFee()` owner function.

**💡 Recommendation:**
> **Action Required:**
> 1. Exclude LP pairs from being exempt or add a one-way, publicly verifiable launch sequence.
> 2. Emit events and publish a launch policy; consider a timelock on exemptions pre-launch.

---

#### 🟡 [M-2] Swapback uses amountOutMin = 0, exposing holders to MEV/sandwich losses

**Description:**
The router call sets `amountOutMin` to zero, allowing swaps to execute at any price, easily exploited by sandwich attacks during swapback.

```solidity
dexRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(
    tokenAmt,
    0, // amountOutMin
    path,
    address(this),
    block.timestamp
);
```

**Impact:**
- MEV bots can front-run/back-run swapback, extracting value and reducing BNB proceeds sent to recipients.
- Indirect loss to holders via worsened execution.

**Location:**
`swapTokensForETH()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Use a reasonable `amountOutMin` based on TWAP/price oracle or sliding slippage.
> 2. Consider splitting large swaps into smaller chunks and randomizing timing.

---

#### 🟡 [M-3] Fixed 35,000 gas stipends may DoS payouts to contract recipients

**Description:**
BNB sends to recipients use `.call{gas:35000}`. Smart contract recipients with non-trivial fallback/receive logic may require more gas and thus fail.

```solidity
(success, ) = treasuryAddress.call{value: share, gas: 35000}("");
(success, ) = nodesAddress.call{value: share, gas: 35000}("");
(success, ) = marketingAddress.call{value: remainingBalance, gas: 35000}("");
```

**Impact:**
- Payouts silently fail for contract recipients, leaving BNB stranded in the contract until swept (see [H-1]).
- Funds distribution becomes unreliable and opaque.

**Location:**
`convertTaxes()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Avoid arbitrary gas caps; allow default gas or implement pull-based withdrawals.
> 2. If pushing, require `success` and revert or track owed amounts for later claim.

---

### Low Findings

#### 🟢 [L-1] Taxes apply only to the single tracked LP; new pools can bypass taxes/swapback

**Description:**
`isAMMPair` is set only for the created `lpPair` and cannot be extended.

```solidity
lpPair = IDexFactory(dexRouter.factory()).createPair(address(this), WETH);
isAMMPair[lpPair] = true;
```

**Impact:**
- Trading on untracked pools avoids taxes and won’t trigger swapback, enabling evasion and inconsistent behavior across venues.

**Location:**
Constructor; no function to add pairs.

**💡 Recommendation:**
> **Action Required:**
> - Add an `onlyOwner` function to manage `isAMMPair` for additional pools, with events.

---

#### 🟢 [L-2] Unlimited approvals to PancakeRouter increase exposure if router is ever compromised

**Description:**
The contract and deployer grant unlimited approvals to the router.

```solidity
_approve(address(this), address(dexRouter), type(uint256).max);
_approve(address(msg.sender), address(dexRouter), totalSupply());
```

**Impact:**
- If router is replaced/compromised, approved balances could be pulled. Risk is low for canonical router.

**Location:**
Constructor.

**💡 Recommendation:**
> **Action Required:**
> - Limit allowances or reset to exact amounts when adding liquidity; consider revoking after use.

---

#### 🟢 [L-3] No events for address updates reduces transparency

**Description:**
Updates to `marketingAddress`, `treasuryAddress`, and `nodesAddress` do not emit events.

```solidity
function updateMarketingAddress(address _address) external onlyOwner { ... }
function updateTreasuryAddress(address _address) external onlyOwner { ... }
function updateNodesAddress(address _address) external onlyOwner { ... }
```

**Impact:**
- Off-chain indexers and users may miss critical admin changes.

**Location:**
Admin update functions.

**💡 Recommendation:**
> **Action Required:**
> - Emit events on each address update for auditability.

---

#### 🟢 [L-4] Non-standard 9 decimals can cause UI/analytics inconsistencies

**Description:**
`decimals()` returns 9 instead of the more common 18.

```solidity
function decimals() public view virtual override returns (uint8) {
    return 9;
}
```

**Impact:**
- Some tools or dashboards may misdisplay balances if they assume 18 decimals.

**Location:**
`ERC20.decimals()` override.

**💡 Recommendation:**
> **Action Required:**
> - Document decimals prominently; ensure DEX listings/trackers are configured correctly.

---

### Good Practices

- No proxy/upgradeability; code is immutable post-deploy.
- No mint/burn after deployment; total supply fixed at construction.
- Taxes are fixed in code; no owner function to raise taxes post-deploy.
- `tradingAllowed` launch gate prevents trading for non-exempt addresses until enabled.
- Swapback throttled to once per block via `lastSwapBackBlock`.
- No blacklist/anti-bot transfer blockers beyond standard launch gate.
- Libraries and patterns align with OpenZeppelin-style implementations; no hidden backdoors detected.
- Ownership renunciation (if called) is permanent; no `previousOwner` or restore mechanisms found.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard | Low upgrade risk |
| Upgrade Control | None (no proxy) | Low |
| Ownership Status | Active | High centralization |
| Owner Address | 0x03d883a16a0ACbc62112d37370d42A51E333Bb17 | Owner can modify settings |
| Total Supply | 4,000,000,000 CLWAR (9 decimals) | Low |
| Buy Tax | 3% (1%/1%/1%) | Low |
| Sell Tax | 3% (1%/1%/1%) | Low |
| Max Transaction | None | Low |

- Distribution mechanics: On buys/sells, 3% tax is collected to the contract. When the contract’s token balance exceeds 0.05% of supply and the tx is not from an AMM pair, `convertTaxes()` swaps tokens to BNB and attempts to distribute: 1/3 to `treasury`, 1/3 to `nodes`, and the remainder to `marketing`. Failures are ignored and `marketing` can sweep all BNB later, introducing centralization/trust risk.
- Launch control: `tradingAllowed` blocks non-exempt transfers until enabled. Owner can whitelist addresses (including LP), enabling pre-launch trades.
- Balanced Assessment: Absence of proxy reduces upgrade risk. However, users must trust the owner and especially the `marketingAddress` for fair distribution and handling of stuck funds. MEV exposure on swapbacks and fixed gas sends can degrade proceeds.

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
