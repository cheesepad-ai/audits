# 🔍 Asteroid Shiba (ASTEROID) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-06-23T19:59:16.084Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0x46c791b0e5f76b8f18efcf87c3074b0079fa6666` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | Asteroid Shiba |
| **Symbol** | ASTEROID |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Tue, 23 Jun 2026 19:59:16 GMT

### Summary

`ASTEROID` is a tax/rewarded `ERC20` token (9 decimals) on BSC using a separate `ASTEROIDDividendTracker` to distribute BNB or a configurable reward token via PancakeSwap V3 routes. Normal buy/sell taxes total 4% (1.5% rewards + 2.5% operations), with an optional 5-minute decaying launch tax if enabled. The design is highly owner-controlled (and “marketing wallet”-controlled for BNB custody), with replaceable dividend tracker, configurable reward token, and the ability to drain contract BNB. Overall Risk: HIGH – Strong centralization and treasury-drain controls; potential configuration pitfalls and MEV exposure.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 4% (1.5% rewards, 2.5% ops) | ✅ Low |
| Sell Tax | 4% (1.5% rewards, 2.5% ops) | ✅ Low |
| Max Transaction | None | ⚠️ Restrictive controls absent |
| Contract Type | Standard (no proxy) | Info |
| Ownership | Active | ⚠️ Centralized |
| Pause Function | No (pre-trade gate via `tradingEnabled`) | ✅ No hard pause |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | No critical vulns found; MEV exposure; minor reentrancy surface |
| Centralization | High | Owner can swap tracker/reward; marketing wallet can drain BNB/tokens |
| Code Quality | Medium | Threshold unit-mismatch; duplicate/unused vars; strict V3 deadline |
| Exploit Likelihood | Medium | Mostly admin/operational risk; MEV drains swaps’ value |
| **Overall Risk Score** | **79/100** | No critical bugs; high centralization; some medium technical risks |

## On-Chain Function Results

The following functions were called on-chain at block 105969151. The table below shows the results:

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `_totalSupply()` | `420690000000000000000` | Cached total supply constant used by token for thresholds |
| `buyTaxes()` | `["15","25"]` | Per-mille fees: 1.5% rewards, 2.5% operations (total 4%) |
| `deadWallet()` | `0x000000000000000000000000000000000000dEaD` | Burn address; receives LP or tokens to lock/burn |
| `decimals()` | `9` | Token has 9 decimal places |
| `devWallet()` | `0xe77fB3b91A65D436c81Ef9379D2E6Bd7c0589884` | Receives 40% of operations BNB |
| `dividendTracker()` | `0xBAFB95396991256b312eA8bB70d79fD56fA7B86c` | Dividend tracker contract handling rewards |
| `gasForProcessing()` | `300000` | Gas limit for auto dividend distribution loop |
| `getClaimWait()` | `3600` | Minimum 1 hour between dividend claims |
| `getCurrentRewardToken()` | `SpaceX` | Name of current reward token for dividends |
| `getLastProcessedIndex()` | `0` | Index pointer for dividend processing progress |
| `getNumberOfDividendTokenHolders()` | `1` | Number of addresses eligible for dividends |
| `getTotalDividendsDistributed()` | `0` | Aggregate BNB distributed as dividends so far |
| `launchTaxEnabled()` | `false` | Anti-bot decaying launch tax currently disabled |
| `marketingWallet()` | `0xe77fB3b91A65D436c81Ef9379D2E6Bd7c0589884` | Receives 60% of operations BNB |
| `name()` | `Asteroid Shiba` | Token name identifier |
| `owner()` | `0xe77fB3b91A65D436c81Ef9379D2E6Bd7c0589884` | Admin address with control functions |
| `pair()` | `0xc452BDa9Cf97505caa0708aaBBc0B008808deE33` | Pancake V2 WBNB pair address |
| `rewardToken()` | `0xbe9D156892E55e7154BcD3cB0FEA677F9D3103E1` | Hardcoded token address (not used for payouts) |
| `router()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 Router |
| `sellTaxes()` | `["15","25"]` | Per-mille sell fees: 1.5% rewards, 2.5% operations |
| `startTradingTime()` | `0` | Trading not enabled yet (no start timestamp) |
| `swapEnabled()` | `true` | Internal swap for BNB/ops/dividends is enabled |
| `swapTokensAtAmount()` | `210345000000000000` | Token threshold to trigger swap (9 decimals included) |
| `symbol()` | `ASTEROID` | Token ticker |
| `totalSupply()` | `420690000000000000000` | ERC20 total tokens ever minted |
| `tradingEnabled()` | `false` | Trading gate is still disabled |

### Findings Summary

| Severity | Count | Key Issues |
|----------|-------|-----------|
| Critical | 0 | — |
| High | 2 | Centralized BNB/tokens drain; Replaceable dividend tracker/reward control |
| Medium | 2 | MEV exposure (minOut=0); Swap threshold unit-mismatch (1e9 multiplier) |
| Low | 5 | Strict 2s V3 deadline; Duplicate/misleading `rewardToken`; No public AMM pair setter; Dust BNB accumulation; No reentrancy guard around value sends |

### High Findings

---

#### 🟠 [H-1] Centralized Treasury Control: Marketing wallet can drain contract BNB and arbitrary tokens

**Description:**
The `marketingWallet` (set by `onlyOwner`) can withdraw the entire BNB balance via `forceSend()` and any ERC20 tokens (except ASTEROID itself) via `rescueBEP20Tokens()`. This includes BNB accumulated for dividends before forwarding and any dust remaining after swaps.

```solidity
function rescueBEP20Tokens(address tokenAddress) external {
    require(msg.sender == marketingWallet, "Only marketing wallet");
    require(tokenAddress != address(this), "Cannot rescue own token");
    IERC20(tokenAddress).transfer(
        msg.sender,
        IERC20(tokenAddress).balanceOf(address(this))
    );
}

function forceSend() external {
    require(msg.sender == marketingWallet, "Only marketing wallet");
    uint256 BNBbalance = address(this).balance;
    payable(owner()).sendValue(BNBbalance);
}
```

**Impact:**
- Complete trust required in the `marketingWallet`. It can drain all BNB and third-party tokens from the contract at any time, diverting funds otherwise destined for dividends or operations. Post-renounce, this secondary admin remains powerful.

**Location:**
`ASTEROID.rescueBEP20Tokens()` and `ASTEROID.forceSend()`

**💡 Recommendation:**
> **Action Required:**
> 1. Restrict these functions to a multisig and add a timelock delay.
> 2. Emit detailed events with amounts and recipients; consider capping withdrawals.
> 3. Optionally remove or time-limit `forceSend()` in production; or route all BNB to tracker trustlessly.

---

#### 🟠 [H-2] Replaceable Dividend Tracker and Reward Configuration enables unilateral reward manipulation

**Description:**
The owner can replace the `dividendTracker` contract and change reward routing parameters at will. Although `updateDividendTracker()` enforces an Ownable-compatible tracker (by calling `onlyOwner` functions), a malicious tracker owned by `ASTEROID` can still withhold or misdirect rewards. The owner can also change the reward token and V3 fee tiers mid-flight.

```solidity
function updateDividendTracker(address newAddress) public onlyOwner {
    ASTEROIDDividendTracker newDividendTracker = ASTEROIDDividendTracker(payable(newAddress));
    newDividendTracker.excludeFromDividends(address(newDividendTracker), true);
    newDividendTracker.excludeFromDividends(address(this), true);
    newDividendTracker.excludeFromDividends(owner(), true);
    newDividendTracker.excludeFromDividends(address(router), true);
    dividendTracker = newDividendTracker;
}

function setRewardToken(address newToken) external onlyOwner {
    dividendTracker.setRewardToken(newToken);
}

function setRewardFees(uint24 _bnbUsdtFee, uint24 _rewardFee) external onlyOwner {
    dividendTracker.setRewardFees(_bnbUsdtFee, _rewardFee);
}
```

**Impact:**
- Users must trust the owner not to deploy a tracker that blackholes rewards, delays claims, or pays out illiquid/worthless tokens.
- Reward distribution policy can change suddenly.

**Location:**
`ASTEROID.updateDividendTracker()`, `ASTEROID.setRewardToken()`, `ASTEROID.setRewardFees()`

**💡 Recommendation:**
> **Action Required:**
> 1. Govern tracker/reward changes via multisig + timelock.
> 2. Hard-cap fee tiers and validate routes; optionally whitelist acceptable reward tokens.
> 3. Publish a transparent upgrade policy and audit the deployed tracker.

### Medium Findings

---

#### 🟡 [M-1] MEV/Sandwich exposure: swaps use `amountOutMin = 0` with no price protection

**Description:**
`swapTokensForBNB()` uses the “supporting fee on transfer” path with `amountOutMin = 0`, allowing any output amount. This is highly susceptible to front-running and sandwich attacks that reduce realized BNB proceeds for operations and dividends.

```solidity
router.swapExactTokensForETHSupportingFeeOnTransferTokens(
    tokenAmount,
    0, // accept any amount of ETH
    path,
    address(this),
    block.timestamp
);
```

**Impact:**
- Attackers can extract value from swap transactions, reducing funds for dividends and operations and causing greater price impact against holders.

**Location:**
`ASTEROID.swapTokensForBNB()`

**💡 Recommendation:**
> **Action Required:**
> - Use a slippage guard (dynamic `amountOutMin` from an oracle/TWAP) or bounded price impact.
> - Split swaps and randomize timing/amounts to reduce predictability.

---

#### 🟡 [M-2] Swap-threshold setter multiplies by `10**9` after unit-checked require, risking misconfiguration

**Description:**
`setSwapTokensAtAmount()` checks `amount <= totalSupply()/100` (units: smallest tokens), then multiplies `amount` by `10**9` when setting. This suggests the function expects “whole tokens” without decimals, but the require compares against fully-decimalized `totalSupply()`. This unit mismatch can inflate threshold 1e9x beyond intended or silently pass wrong values.

```solidity
function setSwapTokensAtAmount(uint256 amount) external onlyOwner {
    require(amount <= (totalSupply() / 100), "Swap Threshold should be less than 1% of total supply");
    swapTokensAtAmount = amount * 10 ** 9; // multiplies again
}
```

**Impact:**
- Threshold may become far larger/smaller than intended, delaying swaps (dividends/ops starved) or causing excessive swapping.

**Location:**
`ASTEROID.setSwapTokensAtAmount()`

**💡 Recommendation:**
> **Action Required:**
> - Accept and store `amount` directly in smallest units; remove `* 10**9`.
> - Alternatively, clearly document expected units and adjust the `require` to the same unit.

### Low Findings

---

#### 🟢 [L-1] Overly strict 2-second deadline in V3 reward swap may cause frequent fallback to BNB payouts

**Description:**
The dividend tracker’s V3 swap uses a hardcoded `deadline = block.timestamp + 2`. Network delays or block inclusion times can exceed this, causing the try/catch to fallback to sending BNB instead of the configured reward token.

```solidity
IV3Router(V3_ROUTER).exactInput{value: amt}(IV3Router.ExactInputParams({
    path: path,
    recipient: user,
    deadline: block.timestamp + 2,
    amountIn: amt,
    amountOutMinimum: 0
}));
```

**Impact:**
- Holders may receive BNB when a custom reward token is intended; inconsistent UX and policy.

**Location:**
`DividendPayingToken.swapBnbForCustomToken()`

**💡 Recommendation:**
> **Action Required:**
> - Use a more forgiving deadline (e.g., 120–300 seconds) and consider a bounded `amountOutMinimum`.

---

#### 🟢 [L-2] Duplicate/misleading `rewardToken` variable in `ASTEROID` (unused for dividends)

**Description:**
The main token contract declares a constant `rewardToken` address unused by the dividend logic (actual reward token is set and read in the dividend tracker). This can mislead integrators and users viewing `ASTEROID.rewardToken()`.

```solidity
address public constant rewardToken = 0xbe9D156892E55e7154BcD3cB0FEA677F9D3103E1; // not used by dividends
```

**Impact:**
- UI/wallets may display an incorrect reward token, confusing holders.

**Location:**
`ASTEROID` contract state

**💡 Recommendation:**
> **Action Required:**
> - Remove or rename the constant to avoid confusion; rely on tracker’s reported reward token/name.

---

#### 🟢 [L-3] No public function to add/remove AMM pairs

**Description:**
`_setAutomatedMarketMakerPair()` is private and only the Pancake V2 pair is added in the constructor. If the token is listed elsewhere, taxes/logic relying on AMM detection may not apply.

```solidity
function _setAutomatedMarketMakerPair(address newPair, bool value) private { ... }
```

**Impact:**
- New pairs won’t be recognized; tax logic and dividend exclusions may be incorrect.

**Location:**
`ASTEROID._setAutomatedMarketMakerPair()`

**💡 Recommendation:**
> **Action Required:**
> - Add an `onlyOwner` function to manage recognized AMM pairs safely.

---

#### 🟢 [L-4] Integer division dust in `swapAndLiquify()` accumulates BNB in contract

**Description:**
`unitBalance = deltaBalance / swapTax` floors remainder. Dust BNB remains in the contract and can accumulate, later withdrawable via `forceSend()`.

```solidity
uint256 unitBalance = deltaBalance / (swapTax);
uint256 operationsAmt = unitBalance * sellTaxes.operations;
uint256 dividends = unitBalance * sellTaxes.rewards;
```

**Impact:**
- Minor accounting mismatch; leftover BNB centralized.

**Location:**
`ASTEROID.swapAndLiquify()`

**💡 Recommendation:**
> **Action Required:**
> - Send the remainder to dividends or operations to avoid dust buildup.

---

#### 🟢 [L-5] No reentrancy guard around value transfers

**Description:**
The contract performs external calls sending BNB to `marketingWallet`, `devWallet`, and `dividendTracker` without a reentrancy guard. The `swapping` flag reduces impact, but a malicious wallet could attempt reentrancy.

```solidity
payable(marketingWallet).sendValue(marketingShare);
payable(devWallet).sendValue(operationsAmt - marketingShare);
(bool success, ) = address(dividendTracker).call{value: dividends}("");
```

**Impact:**
- Low risk due to flow and roles, but best practice is to guard.

**Location:**
`ASTEROID.swapAndLiquify()`

**💡 Recommendation:**
> **Action Required:**
> - Add `ReentrancyGuard` to BNB-sending functions or restrict wallets to EOAs/multisig contracts with non-reentrant receive hooks.

### Good Practices

- Uses a dedicated dividend tracker with correction accounting to prevent reward drift on balance changes.
- Dividend sends use 3,000 gas stipends to minimize reentrancy surface on user payouts.
- Trading gate (`tradingEnabled`) prevents pre-launch trading unless excluded addresses are used for setup.
- No upgradeable proxy pattern (code is immutable once deployed).

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard | Low (no upgrade proxy) |
| Upgrade Control | N/A | Low |
| Ownership Status | Active | High (centralized controls) |
| Owner Address | 0xe77f...9884 | Single EOA controls |
| Total Supply | 420,690,000,000 (9 decimals) | Low |
| Buy Tax | 4% (1.5% rewards, 2.5% ops) | Low |
| Sell Tax | 4% (1.5% rewards, 2.5% ops) | Low |
| Max Transaction | None | Medium (no anti-whale) |

Detailed analysis:
- Taxes: Post-launch, total 4% both directions. An optional launch tax decays from 90% to 4% over 5 minutes, only if `launchTaxEnabled` and within the initial 300 seconds after `enableTradingEnabled()`. Owner cannot re-trigger the launch window later (no reset of `startTradingTime`), which is positive from a predictability perspective.
- Rewards: Distributed in BNB by default; owner can configure a custom reward token via the dividend tracker using PCS V3 paths (BNB->USDT->Reward). Failure to swap (strict deadline or liquidity issues) gracefully falls back to sending BNB.
- Funds Flow: Swap proceeds are split per current sell tax ratios between operations (60% marketing, 40% dev) and dividends. Integer division dust remains in contract and can be withdrawn by the marketing wallet (`forceSend`), centralizing control of any surplus BNB.
- Centralization/Rug Potential: The owner can 1) change the dividend tracker and reward token, 2) change marketing/dev wallets, and 3) marketing wallet can drain all BNB and third-party tokens via privileged functions. Users must trust the operators to act fairly. No blacklists or direct transfer blocking are implemented beyond the pre-launch trading gate. No honeypot pattern observed in transfer path; buys and sells are symmetrical after launch.

Modified Library Code Review (Tampering Check):
- `SafeMath`, `SafeMathInt`, `SafeMathUint`: Custom implementations consistent with standard semantics; arithmetic guarded; no suspicious assembly or hidden overflow enablers detected.
- `Ownable`: Minimal custom variant; no `previousOwner` or restore paths; `renounceOwnership()` sets `owner` to `address(0)` without any backdoor. However, separate privileged roles (`marketingWallet`) remain powerful even after renounce.
- `Address.sendValue`: Matches OpenZeppelin’s semantics (forwards all gas, reverts on failure). No hidden behavior.

Ownership Renunciation Verification:
- On-chain `owner()` is a live EOA (not renounced). No hidden restore/backdoor detected. Note: Even if renounced, `marketingWallet` retains strong privileges (BNB/token drain), so “renounced” would not fully decentralize control.

Proxy Contract Detection:
- No EIP-1967/1822 slots; no `delegatecall`; not upgradeable. Upgrade risk is low; governance risk centers on owner/marketing wallet controls, not proxy mechanics.

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
