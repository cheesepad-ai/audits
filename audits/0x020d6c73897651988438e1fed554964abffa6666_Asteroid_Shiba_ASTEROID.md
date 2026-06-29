# 🔍 Asteroid Shiba (ASTEROID) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-06-29T17:37:14.258Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0x020d6c73897651988438e1fed554964abffa6666` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | Asteroid Shiba |
| **Symbol** | ASTEROID |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Mon, 29 Jun 2026 17:37:14 GMT

### Summary

`ASTEROID` is a tax-based `ERC20` on BSC with automated BNB-to-reward-token dividends via a dedicated dividend tracker and owner-controlled operational wallets. It charges per‑mille taxes on buys/sells (1.5% rewards, 2.5% operations) and accumulates/sells fees to fund marketing/dev and dividends. Centralization is significant: a single EOA owner can replace the dividend tracker and control marketing/dev wallets, with a critical path to redirect dividends. Overall Risk: HIGH – Single-owner control over dividend infrastructure and external-call reentrancy surface.

### Risk Assessment

Token Quick Facts:

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 4% (1.5% rewards + 2.5% ops) | ⚠️ Moderate |
| Sell Tax | 4% (1.5% rewards + 2.5% ops) | ⚠️ Moderate |
| Max Transaction | None | ⚠️ None (whale risk) |
| Contract Type | Standard (no proxy) | Info |
| Ownership | Active EOA + secondary admin wallets | ⚠️ Centralized |
| Pause Function | Trading gate until enabled | ⚠️ Can delay start |

Security Assessment:

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | High | Dividend tracker replaceable by owner; external-call reentrancy to admin wallets |
| Centralization | High | Single EOA owner; owner controls tracker/reward token; admin wallets withdraw BNB |
| Code Quality | Medium | Mixed custom/OZ, some bugs (mis-scaled threshold, unused vars) |
| Exploit Likelihood | Medium | Requires owner action for worst cases; reentrancy feasible if wallets set to contracts |
| **Overall Risk Score** | **73/100** | 1 critical, 1 high, 3 medium, 4 low findings |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `_totalSupply()` | `420690000000000000000` | Public supply constant used for thresholds (decimals 9) |
| `buyTaxes()` | `["15","25"]` | 1.5% rewards, 2.5% operations on buys (per‑mille) |
| `deadWallet()` | `0x000000000000000000000000000000000000dEaD` | Burn/LP sink address |
| `decimals()` | `9` | Token uses 9 decimals |
| `devWallet()` | `0xEbE6Ea187cBAAd90cfE6d418A6717de8B718D4A0` | Dev wallet receives 40% of ops BNB |
| `dividendTracker()` | `0xA3Ab639b3701590Ef840ee4218dF91A3C3019367` | Current dividend tracker contract address |
| `gasForProcessing()` | `300000` | Gas cap for auto dividend processing |
| `getClaimWait()` | `3600` | Minimum 1 hour between claims |
| `getCurrentRewardToken()` | `SpaceX` | Current reward token name from tracker |
| `getLastProcessedIndex()` | `0` | Dividend tracker’s processing cursor |
| `getNumberOfDividendTokenHolders()` | `1` | Number of eligible dividend holders |
| `getTotalDividendsDistributed()` | `0` | Total BNB distributed so far |
| `marketingWallet()` | `0xEbE6Ea187cBAAd90cfE6d418A6717de8B718D4A0` | Marketing wallet (60% of ops BNB) |
| `name()` | `Asteroid Shiba` | Token name |
| `owner()` | `0xEbE6Ea187cBAAd90cfE6d418A6717de8B718D4A0` | EOA with admin privileges |
| `pair()` | `0x6CF8cf21cCD09d3099Ae5903b95FDB6A9C284287` | Pancake V2 pair (ASTEROID/WBNB) |
| `rewardToken()` | `0xbe9D156892E55e7154BcD3cB0FEA677F9D3103E1` | Unused constant in main token |
| `router()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router |
| `sellTaxes()` | `["15","25"]` | 1.5% rewards, 2.5% operations on sells |
| `swapEnabled()` | `true` | Internal tax swaps enabled |
| `swapTokensAtAmount()` | `210345000000000000` | Swap threshold ≈ 0.05% of supply |
| `symbol()` | `ASTEROID` | Token symbol |
| `totalSupply()` | `420690000000000000000` | ERC20 total token supply (decimals 9) |
| `tradingEnabled()` | `false` | Trading not yet enabled |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 1 | Owner can replace dividend tracker to siphon dividends |
| High | 1 | Reentrancy via `sendValue` allows fee-bypass by malicious admin wallets |
| Medium | 3 | Mis-scaled swap threshold; MEV/slippage on dividend swaps; 3000-gas BNB payouts fail for contracts |
| Low | 4 | Shadowed `_totalSupply`; unused vars/functions; limited AMM pair recognition; unnecessary SafeMath |

### Critical Findings

#### 🔴 [C-1] Owner Can Replace Dividend Tracker And Redirect Dividends

**Description:**
The owner can set an arbitrary `dividendTracker` via `updateDividendTracker()`. During fee conversion, BNB destined for dividends is sent to `address(dividendTracker)` using a raw value call with empty data, relying on the tracker’s `receive()` to distribute. A malicious tracker contract owned by `ASTEROID` (to satisfy `onlyOwner` checks) can accept BNB and never distribute to holders, effectively siphoning the entire rewards share.

```solidity
function updateDividendTracker(address newAddress) public onlyOwner {
    ASTEROIDDividendTracker newDividendTracker = ASTEROIDDividendTracker(payable(newAddress));

    newDividendTracker.excludeFromDividends(address(newDividendTracker), true);
    newDividendTracker.excludeFromDividends(address(this), true);
    newDividendTracker.excludeFromDividends(owner(), true);
    newDividendTracker.excludeFromDividends(address(router), true);
    dividendTracker = newDividendTracker;
}

function swapAndLiquify(uint256 tokens, uint256 swapTax) private {
    // ...
    uint256 dividends = unitBalance * sellTaxes.rewards;
    if (dividends > 0) {
        (bool success, ) = address(dividendTracker).call{value: dividends}("");
        if (success) emit SendDividends(tokens, dividends);
    }
}
```

**Impact:**
- Complete loss of all future dividend distributions for holders.
- Owner can silently redirect dividends to any contract and retain BNB/tokens.
- Users have no on-chain assurance the tracker is honest even after “updates.”

**Location:**
- `ASTEROID.updateDividendTracker()` and `ASTEROID.swapAndLiquify()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Hard-restrict `dividendTracker` to a vetted implementation: enforce `codehash`/`interface` checks and require immutable tracker after deployment or timelocked replacement.
> 2. If replacement must be allowed, add:
>    - Timelock (24–48h) and on-chain announcement before changing tracker
>    - Multisig approval for `updateDividendTracker()`
>    - A strict interface with verifiable distribution logic (e.g., hash-locked bytecode)
> 3. Alternatively, remove the ability to change `dividendTracker` after initialization.

---

### High Findings

#### 🟠 [H-1] External Calls To Admin Wallets Using sendValue Enable Reentrancy And Fee Bypass

**Description:**
`swapAndLiquify()` sends BNB to `marketingWallet` and `devWallet` using `Address.sendValue`, which forwards all gas to untrusted recipients while `swapping` is true. The owner can set these wallets to malicious contracts whose fallback may reenter `ASTEROID` (e.g., execute buys/sells) during the no-fee `swapping` window, allowing fee-free trades or state manipulation.

```solidity
function swapAndLiquify(uint256 tokens, uint256 swapTax) private {
    // ...
    uint256 operationsAmt = unitBalance * sellTaxes.operations;
    if (operationsAmt > 0) {
        uint256 marketingShare = (operationsAmt * 60) / 100;
        payable(marketingWallet).sendValue(marketingShare);
        payable(devWallet).sendValue(operationsAmt - marketingShare);
    }
    // ...
}

bool private swapping;

function _transfer(address from, address to, uint256 amount) internal override {
    // when swapping == true, fees are disabled
    bool canSwap = contractTokenBalance >= swapTokensAtAmount;
    if (canSwap && !swapping && swapEnabled && !automatedMarketMakerPairs[from] && !_isExcludedFromFees[from] && !_isExcludedFromFees[to]) {
        swapping = true;
        // ...
        swapping = false;
    }
    bool takeFee = !swapping;
    // ...
}
```

**Impact:**
- Malicious admin-wallet contracts can execute fee-free trades within the same transaction.
- Potential bypass of tax logic and inconsistent accounting.
- In extreme cases, reentrancy may trigger unexpected state flows.

**Location:**
- `ASTEROID.swapAndLiquify()` and `_transfer()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Do not forward all gas to untrusted addresses; use `call` with a low gas stipend (e.g., 2300) or pull mechanism.
> 2. Introduce a nonReentrant guard (e.g., ReentrancyGuard) around swap/fee-distribution paths.
> 3. Consider queueing ops payouts for manual claim by EOA-only wallets to avoid arbitrary code execution on send.

---

### Medium Findings

#### 🟡 [M-1] Mis-Scaled Swap Threshold In `setSwapTokensAtAmount()` (1e9 Overscaling)

**Description:**
`setSwapTokensAtAmount()` compares `amount` to `totalSupply()/100` (already scaled by `decimals()`), then multiplies `amount` by `10**9`, overscaling the threshold by 1e9. This can set an unreachable threshold and permanently stall fee conversions (no ops funding/dividends).

```solidity
function setSwapTokensAtAmount(uint256 amount) external onlyOwner {
    require(amount <= (totalSupply() / 100), "Swap Threshold should be less than 1% of total supply");
    swapTokensAtAmount = amount * 10 ** 9; // BUG: double-scales the value
}
```

**Impact:**
- Swaps may never trigger, halting dividends and operations funding.
- Operational funds/dividends accumulate as tokens, not BNB.

**Location:**
- `ASTEROID.setSwapTokensAtAmount()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Accept `amount` in raw token units and set `swapTokensAtAmount = amount` (no extra scaling), OR
> 2. Accept “human” units and convert consistently (e.g., multiply once by `10**decimals()`), and
> 3. Update the require check to compare values in the same unit.

---

#### 🟡 [M-2] Dividend Swaps Use `amountOutMinimum = 0` And 2s Deadline (High MEV/Slippage Risk)

**Description:**
The dividend tracker swaps BNB to reward tokens via Pancake V3 with `amountOutMinimum = 0` and `deadline = block.timestamp + 2`. This exposes swaps to sandwich attacks, poor pricing, and deadline failures; although it falls back to BNB payout, users can receive significantly worse rates.

```solidity
function swapBnbForCustomToken(address user, uint256 amt) internal returns (bool) {
    bytes memory path = /* ... */;
    try IV3Router(V3_ROUTER).exactInput{value: amt}(IV3Router.ExactInputParams({
        path: path,
        recipient: user,
        deadline: block.timestamp + 2,
        amountIn: amt,
        amountOutMinimum: 0
    })) { /* ... */ } catch { return false; }
}
```

**Impact:**
- Holders may receive less reward token due to MEV/slippage.
- 2-second deadlines can cause frequent reverts; falls back to BNB.

**Location:**
- `DividendPayingToken.swapBnbForCustomToken()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Add configurable slippage protection (`amountOutMinimum`) and a reasonable deadline buffer (e.g., 5–10 minutes).
> 2. Consider TWAP or V2 path fallback if V3 path is illiquid.

---

#### 🟡 [M-3] 3000-Gas Stipend For BNB Payouts Can Lock Dividends For Contract Wallets

**Description:**
BNB dividends fallback uses `call{gas: 3000}`. Many smart-contract wallets need more than 2300–3000 gas to execute fallback/receive logic; repeated failures keep dividends unclaimed.

```solidity
(bool success, ) = user.call{ value: _withdrawableDividend, gas: 3000 }("");
if (!success) {
    withdrawnDividends[user] = withdrawnDividends[user].sub(_withdrawableDividend);
    return 0;
}
```

**Impact:**
- Contract-based holders may be unable to receive BNB dividends, degrading UX and fairness.

**Location:**
- `DividendPayingToken._withdrawDividendOfUser()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Provide a claim path that swaps to tokens and transfers (ERC20 transfer), avoiding low-gas BNB sends.
> 2. Allow users to set a preferred payout token (always tokenized path), or increase gas with caution.

---

### Low Findings

#### 🟢 [L-1] Shadowed `_totalSupply` Public Variable Causes Confusion

**Description:**
`ASTEROID` defines a public `_totalSupply` while `ERC20` maintains its own private `_totalSupply`. Only `ERC20.totalSupply()` is authoritative; duplication can confuse integrators.

```solidity
uint256 public _totalSupply = 420_690_000_000 * (10 ** 9);
```

**Impact:**
- Potential misreads by off-chain tools; maintenance hazards.

**Location:**
- `ASTEROID` state variable `_totalSupply`.

**💡 Recommendation:**
> **Action Required:**
> - Remove the public `_totalSupply` or make it `immutable` named `INITIAL_SUPPLY` to document intent, relying on `totalSupply()`.

---

#### 🟢 [L-2] Unused Variables/Functions

**Description:**
Multiple unused elements increase code surface and confusion:
- `ASTEROID.currentRewardToken` never used
- `ASTEROID.rewardToken` constant unused
- `addLiquidity()` never called

```solidity
string private currentRewardToken;
address public constant rewardToken = 0xbe9D...;
function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private { /* unused */ }
```

**Impact:**
- Code bloat; potential future misuse.

**Location:**
- `ASTEROID` contract.

**💡 Recommendation:**
> **Action Required:**
> - Remove or repurpose unused variables/functions; keep code minimal and auditable.

---

#### 🟢 [L-3] No Function To Register Additional AMM Pairs

**Description:**
Only the initial `pair` is marked as AMM. Trades via other pairs (e.g., USDT) won’t be recognized as buys/sells and won’t be taxed as intended.

```solidity
mapping(address => bool) public automatedMarketMakerPairs;
// _setAutomatedMarketMakerPair is private and never called externally
```

**Impact:**
- Tax evasion via alternate pairs; inconsistent fee policy.

**Location:**
- `ASTEROID.automatedMarketMakerPairs`.

**💡 Recommendation:**
> **Action Required:**
> - Add an `onlyOwner` function to register/unregister AMM pairs and reflect in dividend exclusions.

---

#### 🟢 [L-4] SafeMath Unnecessary On Solidity 0.8+ (Gas Overhead)

**Description:**
Solidity 0.8+ provides built-in overflow checks. Continued SafeMath usage wastes gas and adds clutter.

**Impact:**
- Minor gas inefficiency.

**Location:**
- SafeMath usages across contracts.

**💡 Recommendation:**
> **Action Required:**
> - Remove SafeMath in 0.8+ or restrict to places needing custom messages.

---

### Good Practices

- Dividends accounting uses magnified per-share math to preserve precision.
- Fee conversion caps per-swap outflow (4× threshold) to reduce single-tx dumps.
- Trading gate prevents prelaunch trading for non-exempt addresses.
- Dividend processing bounded by `gasForProcessing` to avoid OOG.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard (no proxy) | Lower upgrade risk |
| Upgrade Control | Tracker replaceable by owner | Critical (dividends can be redirected) |
| Ownership Status | Active (EOA) | High centralization |
| Owner Address | 0xEbE6... | Single admin |
| Total Supply | 420,690,000,000 (9 decimals) | Standard |
| Buy Tax | 4% (1.5% R + 2.5% Ops) | Moderate |
| Sell Tax | 4% (1.5% R + 2.5% Ops) | Moderate |
| Max Transaction | None | Whale risk |

Details:
- Taxes: Collected tokens are swapped for BNB. Ops share is split 60%/40% to `marketingWallet`/`devWallet`; rewards share is forwarded to `dividendTracker`.
- Dividends: BNB is converted to the current reward token (via V3 WBNB→USDT→token) and sent to holders; fallback to BNB send if swap fails.
- Centralization: Owner can change the dividend tracker, reward token, fee tiers (V3 path), marketing/dev wallets, claim wait, gas for processing, dividend exclusions, and trading enablement. Marketing/dev wallets can receive BNB directly during swaps and can withdraw any non-native tokens from the main contract. Even with ownership renounced, marketing wallet retains withdrawal powers for BEP20 tokens and BNB via `forceSend` (if invoked prior to renounce or while owner is set); thus renounce does not fully decentralize operations.

Balanced Assessment:
- Upgradeability of the dividend mechanism is effectively centralized via `updateDividendTracker()`. Without a timelock/multisig safeguard, holders must fully trust the owner not to redirect dividends. While the swap/ops/distribution pipeline is typical for reflection/dividend tokens, the current controls concentrate too much authority in a single EOA.

**Ownership Renunciation Note:**
- Currently not renounced. If renounced in future, ensure no secondary admin paths retain rug capabilities. In this code, marketing wallet retains token withdrawal authority; this should be disclosed transparently.



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
