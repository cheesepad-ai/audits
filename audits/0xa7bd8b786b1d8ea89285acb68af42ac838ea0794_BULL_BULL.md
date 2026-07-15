# 🔍 BULL (BULL) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-07-15T23:12:21.536Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xa7bd8b786b1d8ea89285acb68af42ac838ea0794` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | BULL |
| **Symbol** | BULL |

---

## 🤖 Analysis #1: Claude Opus 4.8

**Completed:** Wed, 15 Jul 2026 23:12:21 GMT

### Summary

BULL is a BEP-20 reflection/dividend token on BSC (PancakeSwap) that rewards holders in a configurable reward token (currently "SpaceX"), routing BNB dividends through PancakeSwap V3. It features owner-controlled buy/sell/launch taxes (currently 3%/3%, launch 10%), an auto-processing dividend tracker, and a CREATE2 vanity-address factory. Trading is not yet enabled. The contract has centralization risks, a hardcoded owner-privileged reward token that can be redirected, and several exploitable dividend-withdrawal and swap-accounting weaknesses.

### Risk Assessment

**Token Quick Facts**

| Property | Value |
|----------|-------|
| Name / Symbol | BULL / BULL |
| Decimals | 18 |
| Total Supply | 1,000,000,000,000 BULL |
| Owner | 0x681BD50B72693beBcEc8bb2AD110ba20C7f10Bd5 (EOA) |
| Buy Tax | 3% (15+15 per mille) |
| Sell Tax | 3% (15+15 per mille) |
| Launch Tax | 10% (50+50 per mille), 1 hour |
| Max Tax Cap | 20% (200 per mille) |
| Trading Enabled | No |
| Mint after deploy | No (`_tokengeneration` one-time) |
| Reward Token | 0xbe9D...03E1 (mutable, currently "SpaceX") |

**Security Assessment**

| Category | Status |
|----------|--------|
| Mint function | ✅ One-time generation, no post-deploy mint |
| Ownership | ⚠️ Active EOA owner, many privileged setters |
| Renounce ownership | ✅ Available but not used |
| Trading toggle | ⚠️ Owner-gated; irreversible once on |
| Tax limits | ✅ Capped at 20% |
| Blacklist | ✅ None |
| Reward token mutability | 🔴 Owner can redirect rewards arbitrarily |
| Reentrancy | ⚠️ Low-gas external calls in withdrawal path |
| Fund rescue | ⚠️ marketingWallet can pull all BNB/tokens |

### On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `MAX_TAX_PER_MILLE()` | `200` | Max combined tax cap = 20% (per-mille units). |
| `_totalSupply()` | `1000000000000000000000000000000` | 1 trillion tokens with 18 decimals. |
| `buyTaxes()` | `["15","15"]` | Buy tax: 1.5% rewards + 1.5% ops = 3%. |
| `deadWallet()` | `0x...dEaD` | Burn address for LP tokens. |
| `decimals()` | `18` | Standard 18 decimals. |
| `devWallet()` | `0x681B...0Bd5` | Dev wallet, same as marketing/owner. |
| `dividendTracker()` | `0x44eC...0B61` | Deployed dividend tracker contract. |
| `gasForProcessing()` | `300000` | Gas budget for auto dividend processing. |
| `getClaimWait()` | `3600` | Minimum 1-hour interval between auto-claims. |
| `getCurrentRewardToken()` | `SpaceX` | Reward token name; currently "SpaceX". |
| `getLastProcessedIndex()` | `0` | Dividend processing index, unstarted. |
| `getNumberOfDividendTokenHolders()` | `1` | Only one holder tracked (pre-launch). |
| `getTotalDividendsDistributed()` | `0` | No dividends distributed yet. |
| `launchTaxDuration()` | `3600` | Launch tax window lasts 1 hour. |
| `launchTaxes()` | `["50","50"]` | Launch tax: 5%+5% = 10%. |
| `marketingWallet()` | `0x681B...0Bd5` | Marketing wallet = owner/dev; can rescue funds. |
| `name()` | `BULL` | Token name. |
| `owner()` | `0x681B...0Bd5` | Contract owner (EOA). |
| `pair()` | `0xD28B...B214` | PancakeSwap BULL/WBNB pair. |
| `rewardToken()` | `0xbe9D...03E1` | Immutable constant default reward token. |
| `router()` | `0x10ED...024E` | PancakeSwap V2 router. |
| `sellTaxes()` | `["15","15"]` | Sell tax: 1.5%+1.5% = 3%. |
| `swapEnabled()` | `true` | Internal swap-to-BNB enabled. |
| `swapTokensAtAmount()` | `500000000000000000000000000` | Swap threshold = 0.05% of supply. |
| `symbol()` | `BULL` | Token symbol. |
| `totalSupply()` | `1000000000000000000000000000000` | 1 trillion tokens. |
| `tradingEnabled()` | `false` | Trading not yet enabled by owner. |
| `tradingEnabledAt()` | `0` | Trading start timestamp unset. |

### Additional Read Functions

| Function | Parameters | Return Type |
|----------|------------|-------------|
| `allowance(address, address)` | address, address | `uint256` |
| `automatedMarketMakerPairs(address)` | address | `bool` |
| `balanceOf(address)` | address | `uint256` |
| `dividendTokenBalanceOf(address)` | address | `uint256` |
| `getAccountDividendsInfo(address)` | address | `address, int256, int256, uint256, uint256, uint256, uint256, uint256` |
| `getAccountDividendsInfoAtIndex(uint256)` | uint256 | `address, int256, int256, uint256, uint256, uint256, uint256, uint256` |
| `isExcludedFromFees(address)` | address | `bool` |
| `withdrawableDividendOf(address)` | address | `uint256` |

### Findings Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 3 |
| 🟡 Medium | 4 |
| 🟢 Low | 4 |

### Critical Findings

#### 🔴 [C-1] Dividend withdrawal uses zero-slippage V3 swaps, enabling MEV sandwich draining of the reward pool

**Description:**
`swapBnbForCustomToken` performs a V3 swap with `amountOutMinimum: 0` and `deadline: block.timestamp + 2`, converting all dividend BNB to the reward token per user.

```solidity
IV3Router(V3_ROUTER).exactInput{value: amt}(
    IV3Router.ExactInputParams({
        path: path,
        recipient: user,
        deadline: block.timestamp + 2,
        amountIn: amt,
        amountOutMinimum: 0
    })
)
```

Every auto-claim executes an on-chain swap with no minimum output. Since claims are triggered automatically inside `_transfer` (via `dividendTracker.process`), attackers can sandwich each dividend swap, extracting value from every holder's reward. On a thin reward-token pool, near-100% of dividend BNB can be siphoned.

**Impact:**
Systemic loss of dividend value to MEV bots; holders receive near-zero reward tokens while attackers capture the BNB.

**Location:**
`DividendPayingToken.swapBnbForCustomToken`, `_withdrawDividendOfUser`.

**💡 Recommendation:**
> **Action Required:** Compute a real `amountOutMinimum` from an on-chain oracle/TWAP, batch dividend swaps instead of per-user swaps, and avoid triggering swaps automatically inside transfers.

---

### High Findings

#### 🟠 [H-1] Owner can arbitrarily redirect all holder rewards to any token

**Description:**
`setRewardToken` (both on BULL and the tracker) lets the owner change the reward token to any address at any time with no timelock.

```solidity
function setRewardToken(address newToken) external onlyOwner {
    dividendTracker.setRewardToken(newToken);
}
```

The reward token already differs from the hardcoded default (on-chain name is "SpaceX"). A malicious or compromised owner could point rewards at a worthless/honeypot token, or a token with a transfer-tax that reverts, effectively nullifying all dividends.

**Impact:**
Complete owner control over what holders actually receive; rewards can be rendered worthless or bricked.

**Location:**
`BULL.setRewardToken`, `DividendPayingToken.setRewardToken`.

**💡 Recommendation:**
> **Action Required:** Add a timelock and event, restrict to a curated allowlist, or renounce ownership after configuration.

---

#### 🟠 [H-2] marketingWallet can drain all contract BNB and any non-BULL token

**Description:**
`forceSend` sends the entire contract BNB balance to the owner, and `rescueBEP20Tokens` transfers the full balance of any other token to `marketingWallet`.

```solidity
function forceSend() external {
    require(msg.sender == marketingWallet, "Only marketing wallet");
    payable(owner()).sendValue(address(this).balance);
}
```

Contract BNB includes pending dividend/operations funds accumulated before distribution. `marketingWallet`, `devWallet`, and `owner` are all the same EOA.

**Impact:**
A single EOA can sweep contract BNB (including funds intended for dividends) and any accidental/legitimate tokens held by the contract.

**Location:**
`BULL.forceSend`, `BULL.rescueBEP20Tokens`.

**💡 Recommendation:**
> **Action Required:** Restrict rescue to genuinely stuck tokens, exclude dividend-earmarked BNB, and use a multisig for privileged wallets.

---

#### 🟠 [H-3] swapAndLiquify computes payouts using sell taxes regardless of actual fee source

**Description:**
Accumulated fees may originate from buys, sells, or launch taxes, but `swapAndLiquify` always divides using `sellTaxes` for `operations`/`rewards` splits and uses `swapTax = sellTaxes.rewards + sellTaxes.operations` as the divisor.

```solidity
uint256 unitBalance = deltaBalance / (swapTax);
uint256 operationsAmt = unitBalance * sellTaxes.operations;
uint256 dividends = unitBalance * sellTaxes.rewards;
```

If launch taxes or buy taxes differ in ratio from sell taxes, the split of BNB between marketing and dividends is misattributed, and residual dust remains permanently stuck in the contract.

**Impact:**
Incorrect dividend/marketing allocation; BNB can be silently stranded or over/under-allocated to marketing.

**Location:**
`BULL.swapAndLiquify`.

**💡 Recommendation:**
> **Action Required:** Track accumulated reward vs operations tokens separately and split proceeds by the actual accrued proportions.

---

### Medium Findings

#### 🟡 [M-1] Reentrancy exposure in dividend withdrawal via external calls with subsequent state mutation

**Description:**
`_withdrawDividendOfUser` updates `withdrawnDividends[user]` before an external low-gas `call`, then decrements it on failure. Although 3000 gas limits reentrancy on the raw send, the V3 swap path (`swapBnbForCustomToken`) forwards full gas to an external router with a user-controlled `recipient`, breaking the checks-effects-interactions ordering guarantees.

```solidity
withdrawnDividends[user] = withdrawnDividends[user].add(_withdrawableDividend);
...
bool success = swapBnbForCustomToken(user, _withdrawableDividend);
```

**Impact:**
Potential for callback-based manipulation of tracker state during processing; increased attack surface.

**Location:**
`DividendPayingToken._withdrawDividendOfUser`.

**💡 Recommendation:**
> **Action Required:** Add a `nonReentrant` guard and finalize all state before any external interaction.

---

#### 🟡 [M-2] Launch tax can be re-raised after launch up to 20%

**Description:**
`setLaunchTaxes`, `setBuyTaxes`, and `setSellTaxes` remain callable anytime and can each set taxes up to `MAX_TAX_PER_MILLE` (20%). Combined with `setLaunchTaxDuration` (up to 2 hours), the owner can re-impose high taxes on active trading windows.

```solidity
function setSellTaxes(uint256 rewards, uint256 operations) external onlyOwner {
    require(rewards + operations <= MAX_TAX_PER_MILLE, "Sell tax too high");
    sellTaxes = Taxes(rewards, operations);
}
```

**Impact:**
Owner can raise effective taxes to 20% after launch, harming holders/sellers.

**Location:**
`BULL.setBuyTaxes`, `setSellTaxes`, `setLaunchTaxes`.

**💡 Recommendation:**
> **Action Required:** Lower the max cap and/or lock tax setters after launch via a timelock.

---

#### 🟡 [M-3] deadline of block.timestamp + 2 unreliable and swaps can silently fail

**Description:**
V3 swaps use `deadline: block.timestamp + 2`. On BSC this margin is small; the `try/catch` swallows failures and falls back to a 3000-gas BNB send that will also fail for contract recipients, causing dividend forfeiture (returns 0 and reverts the withdrawn increment).

**Impact:**
Users can silently fail to receive dividends; funds stay in contract, subject to H-2 sweep.

**Location:**
`DividendPayingToken.swapBnbForCustomToken`, `_withdrawDividendOfUser`.

**💡 Recommendation:**
> **Action Required:** Use a reasonable deadline and provide a pull-based fallback (e.g., WBNB or claimable balance) instead of a low-gas raw send.

---

#### 🟡 [M-4] setSwapTokensAtAmount double-scales the threshold by decimals

**Description:**
The constructor sets `swapTokensAtAmount` already in wei units, but the setter multiplies the raw amount by `10 ** decimals()` again while the require check compares against `totalSupply() / 100` (in wei), creating inconsistent units and enabling accidental extreme thresholds.

```solidity
require(amount <= (totalSupply() / 100), ...);
swapTokensAtAmount = amount * 10 ** decimals();
```

An `amount` passing the check (e.g. up to 1% of raw supply) is then multiplied by 1e18, producing an absurdly large threshold that disables swaps.

**Impact:**
Misconfiguration can permanently disable fee swapping; confusing/unsafe unit handling.

**Location:**
`BULL.setSwapTokensAtAmount`.

**💡 Recommendation:**
> **Action Required:** Standardize units—either treat `amount` as whole tokens consistently in both the check and assignment.

---

### Low Findings

#### 🟢 [L-1] tx.origin used for event attribution and processing

**Description:**
`processDividendTracker` and `_transfer` emit `ProcessedDividendTracker` with `tx.origin` as processor. While not directly exploitable here, `tx.origin` usage is discouraged and can mislead off-chain accounting.

**Impact:**
Misattribution in analytics; anti-pattern.

**Location:**
`BULL.processDividendTracker`, `BULL._transfer`.

**💡 Recommendation:**
> **Action Required:** Use `msg.sender` for processor attribution.

---

#### 🟢 [L-2] Unused code and dead functions increase surface

**Description:**
`addLiquidity` is never called; `currentRewardToken` is declared but never used; `SafeMath` is redundant under Solidity ^0.8. `IPair.sync` is imported but unused.

**Impact:**
Larger bytecode, reader confusion, potential for latent misuse.

**Location:**
`BULL.addLiquidity`, `currentRewardToken`, `SafeMath` usage.

**💡 Recommendation:**
> **Action Required:** Remove dead code and rely on native overflow checks.

---

#### 🟢 [L-3] No zero-address / sanity validation on setRewardToken and setRewardFees

**Description:**
`setRewardToken` accepts any address (including zero), and `setRewardFees` accepts arbitrary V3 fee tiers, which if invalid make all swaps revert and dividends undeliverable.

**Impact:**
Misconfiguration can brick dividend delivery.

**Location:**
`DividendPayingToken.setRewardToken`, `setRewardFees`.

**💡 Recommendation:**
> **Action Required:** Validate non-zero address and restrict fee tiers to known valid values.

---

#### 🟢 [L-4] Auto dividend processing inside every transfer increases gas and failure risk

**Description:**
`_transfer` calls `dividendTracker.process(gas)` and per-account `setBalance` on every non-swapping transfer, wrapped in `try/catch`. This raises transfer gas costs and, combined with per-user swaps, concentrates failure risk in normal transfers.

**Impact:**
Higher user gas costs; unpredictable transfer behavior.

**Location:**
`BULL._transfer`.

**💡 Recommendation:**
> **Action Required:** Make dividend processing external/manual or gate it behind a lower-frequency trigger.

---

### Good Practices

- Supply is minted once via `_tokengeneration`; no post-deploy mint path exists.
- Tax setters are bounded by `MAX_TAX_PER_MILLE` (20%), preventing 100% honeypot taxes.
- No blacklist or arbitrary transfer-blocking of individual holders.
- `initialOwner` zero-address check in constructor and zero-address checks in wallet setters.
- Dividend tracker forbids transfers (`require(false)`), preventing manipulation of tracker share tokens.
- LP tokens (if `addLiquidity` were used) are sent to the dead wallet.

### Tokenomics Analysis

| Parameter | Value | Notes |
|-----------|-------|-------|
| Total Supply | 1,000,000,000,000 BULL | Fixed, minted at deploy |
| Buy Tax | 3% (1.5% rewards / 1.5% ops) | Within cap |
| Sell Tax | 3% (1.5% rewards / 1.5% ops) | Within cap |
| Launch Tax | 10% (5% rewards / 5% ops), 1h | Applies both directions during window |
| Max Tax Cap | 20% | Owner can raise to this anytime |
| Swap Threshold | 0.05% of supply | Slow-sell capped at 4× per swap |
| Reward Token | Mutable ("SpaceX" currently) | Owner-redirectable (H-1) |
| Reward Routing | BNB→USDT→reward via PancakeSwap V3 | Zero slippage (C-1) |
| Fee Distribution | Marketing (ops) + dividends (rewards) | Split misattributed (H-3) |
| Marketing/Dev/Owner | Same EOA | Centralized; can sweep BNB (H-2) |
| Trading Status | Disabled | Owner enables once, irreversible |

Overall, tokenomics are within conventional ranges, but reward delivery is fragile (zero-slippage V3 swaps, mutable reward token) and control is heavily centralized in a single EOA that can redirect rewards and sweep contract BNB.

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
