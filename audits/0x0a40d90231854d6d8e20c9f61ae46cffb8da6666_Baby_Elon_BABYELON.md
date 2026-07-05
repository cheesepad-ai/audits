# 🔍 Baby Elon (BABYELON) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 2 |
| **Audit Date** | 2026-07-05T14:19:04.466Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0x0a40d90231854d6d8e20c9f61ae46cffb8da6666` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | Baby Elon |
| **Symbol** | BABYELON |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Sun, 05 Jul 2026 14:19:04 GMT

### Summary

This is a custom tax-and-dividend `ERC20` called `BabyElon` with automated BNB-fee conversion and BNB→reward-token dividends via a dedicated `DividendTracker`. It applies configurable buy/sell/launch taxes, auto-swaps to BNB, routes a share to a marketing wallet, and streams the remainder to the dividend tracker for holder rewards. Strong owner and marketing wallet powers remain (tax changes up to 25%, reward-token changes, sweeping BNB/tokens), but there is no upgradeable proxy or hidden ownership restoration detected. Overall Risk: MEDIUM - Owner/marketing wallet centralization and some logic/operational risks.

### Risk Assessment

Token Quick Facts:

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 4% (20+20 per mille) | ✅ Low |
| Sell Tax | 4% (20+20 per mille) | ✅ Low |
| Max Transaction | None | ✅ No hard limit |
| Contract Type | Standard (non-upgradeable) | Info |
| Ownership | Active (owner: 0xae23...) | ⚠️ Centralized |
| Pause Function | No (trading can only be enabled once) | ✅ No halt after enable |

Security Assessment:

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | External value transfer to marketing wallet without reentrancy guard; dividend swap deadline tight |
| Centralization | High | Owner can change taxes (≤25%), reward token/fees, wallets; marketing wallet can drain BNB |
| Code Quality | Medium | Some mis-unit logic, unused code, redundant SafeMath; clear structure overall |
| Exploit Likelihood | Medium | No obvious critical bugs; risks mostly operational/centralization |
| **Overall Risk Score** | **80/100** | No criticals; 1 high, 4 medium, 3 low issues |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `MAX_TAX_PER_MILLE()` | `250` | Maximum combined tax is 25% to cap owner changes |
| `_totalSupply()` | `1000000000000000000000000000000000` | Internal supply constant used during construction |
| `buyTaxes()` | `["20","20"]` | Buy tax split: 2% rewards, 2% operations (4% total) |
| `deadWallet()` | `0x000000000000000000000000000000000000dEaD` | Burn/LP lock recipient address |
| `decimals()` | `18` | Token uses 18 decimals |
| `devWallet()` | `0xBA52Bf19D94a7CB3a87037F1564F6CCA51A3b8F3` | Development wallet receiving funds if configured |
| `dividendTracker()` | `0xa05d196FEf36ea106b5AA61d7664a6A9B7d8dB46` | Current dividend tracker contract address |
| `gasForProcessing()` | `300000` | Gas cap for automatic dividend processing |
| `getClaimWait()` | `3600` | Minimum 1 hour between dividend claims |
| `getCurrentRewardToken()` | `SpaceX` | Human-readable name of current reward token |
| `getLastProcessedIndex()` | `0` | Tracker’s last processed holder index |
| `getNumberOfDividendTokenHolders()` | `1` | Count of addresses eligible for dividends |
| `getTotalDividendsDistributed()` | `0` | Total BNB sent to tracker so far |
| `launchTaxDuration()` | `3600` | Launch tax period: 1 hour post-enable |
| `launchTaxes()` | `["125","125"]` | Launch tax split: 12.5% rewards, 12.5% ops (25% total) |
| `marketingWallet()` | `0xBA52Bf19D94a7CB3a87037F1564F6CCA51A3b8F3` | Marketing wallet receiving operations share |
| `name()` | `Baby Elon` | Token name string |
| `owner()` | `0xae2358bC13b20dDa50a1e0Efa992659E722e8d0e` | Admin with authority over settings |
| `pair()` | `0x7402489ec7eCf7ea48915D610F67224114De4488` | Pancake v2 pair with WBNB |
| `rewardToken()` | `0xbe9D156892E55e7154BcD3cB0FEA677F9D3103E1` | Current reward token address (mainnet constant) |
| `router()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | Pancake v2 router (BSC mainnet) |
| `sellTaxes()` | `["20","20"]` | Sell tax split: 2% rewards, 2% ops (4% total) |
| `swapEnabled()` | `true` | Internal swapping feature active |
| `swapTokensAtAmount()` | `500000000000000000000000000000` | Swap threshold (0.05% of supply) |
| `symbol()` | `BABYELON` | Token symbol string |
| `totalSupply()` | `1000000000000000000000000000000000` | Total token supply (1e15 tokens with 18 decimals) |
| `tradingEnabled()` | `false` | Trading not enabled yet for non-exempt addresses |
| `tradingEnabledAt()` | `0` | Trading enable timestamp not set |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|-----------|
| Critical | 0 | — |
| High | 1 | Owner/marketing wallet centralized control over taxes, rewards, withdrawals |
| Medium | 4 | Reentrancy surface on marketing wallet payout; mis-units in swap threshold setter; tracker hot-swappable; launch split used for all swaps |
| Low | 3 | Tight V3 deadline; non-standard Ownable/SafeMath clones; unused/opaque code paths |

### Critical Findings

None.

### High Findings

---

#### 🟠 [H-1] Centralized Controls: Owner and Marketing Wallet Can Change Economics and Drain BNB

**Description:**
The `owner` can change taxes up to 25% per-side, alter reward token and fee tiers, exclude accounts from dividends, and replace the dividend tracker. The `marketingWallet` can withdraw any BNB from the token contract via `forceSend()` and arbitrary ERC20 tokens via `rescueBEP20Tokens()`.

```solidity
function setBuyTaxes(uint256 rewards, uint256 operations) external onlyOwner { ... }
function setSellTaxes(uint256 rewards, uint256 operations) external onlyOwner { ... }
function setRewardToken(address newToken) external onlyOwner { ... }
function setRewardFees(uint24 _bnbUsdtFee, uint24 _rewardFee) external onlyOwner { ... }
function updateDividendTracker(address newAddress) public onlyOwner { ... }

function rescueBEP20Tokens(address tokenAddress) external {
    require(msg.sender == marketingWallet, "Only marketing wallet");
    ...
}
function forceSend() external {
    require(msg.sender == marketingWallet, "Only marketing wallet");
    uint256 BNBbalance = address(this).balance;
    payable(owner()).sendValue(BNBbalance);
}
```

**Impact:**
- Owner can raise taxes up to 25% (buy/sell) and change reward token at any time, materially impacting holders.
- Marketing wallet can empty the contract’s BNB balance at any time, diverting funds intended for dividends/operations.
- Dividend tracker can be replaced to alter reward logic or block distributions.

**Location:**
`BabyElon` admin and marketing functions

**💡 Recommendation:**
> Action Required:
> 1. Place owner/marketing privileges behind a multisig and timelock (24–48+ hours).
> 2. Add caps and rate-limits on tax/parameter changes; emit events with sufficient notice.
> 3. Consider restricting or removing `forceSend()` and tightening `rescueBEP20Tokens()` (e.g., allowlist, timelock).

---

### Medium Findings

---

#### 🟡 [M-1] External Call to Marketing Wallet Without Reentrancy Guard During Swaps

**Description:**
`swapAndLiquify()` sends BNB to `marketingWallet` using `Address.sendValue`, which forwards all gas and has no reentrancy guard. Although `swapping` mitigates fee recursion, reentrancy into other token functions remains possible.

```solidity
function swapAndLiquify(uint256 tokens, uint256 swapTax) private {
    ...
    uint256 operationsAmt = unitBalance * sellTaxes.operations;
    if (operationsAmt > 0) {
        payable(marketingWallet).sendValue(operationsAmt); // external call
    }
    ...
}
library Address {
function sendValue(address payable recipient, uint256 amount) internal {
    (bool success, ) = recipient.call{value: amount}("");
    require(success, "Address: unable to send value");
}
}
```

**Impact:**
A malicious `marketingWallet` contract could reenter and invoke token functions at unexpected states (e.g., transfers during `swapping`), increasing complexity and potential for unforeseen bugs/DoS.

**Location:**
`BabyElon.swapAndLiquify()`, `Address.sendValue()`

**💡 Recommendation:**
> Action Required:
> 1. Add a `ReentrancyGuard` and mark swap/transfer critical paths `nonReentrant`.
> 2. Prefer pull pattern (withdraw by marketing wallet) or limit gas sent (e.g., use `.call{value: amount, gas: X}` with checks).

---

#### 🟡 [M-2] Mis-Units in `setSwapTokensAtAmount()` Can Set an Unintended Threshold

**Description:**
The function checks `amount <= totalSupply()/100` (wei units), then multiplies by `10**decimals()` again, effectively scaling by 1e18, producing an unexpectedly large threshold.

```solidity
function setSwapTokensAtAmount(uint256 amount) external onlyOwner {
    require(amount <= (totalSupply() / 100), "...");
    swapTokensAtAmount = amount * 10 ** decimals(); // unit mismatch
}
```

**Impact:**
- Threshold may be set excessively high, preventing swaps from triggering, starving dividend and operations flows.
- Confusion for operators expecting `amount` to be in “human” units.

**Location:**
`BabyElon.setSwapTokensAtAmount()`

**💡 Recommendation:**
> Action Required:
> 1. Use consistent units. Either:
>    - Accept wei units and set `swapTokensAtAmount = amount;`, or
>    - Accept human units and compare against `(totalSupply() / 100) / 10**decimals()`.
> 2. Document unit expectations in Natspec.

---

#### 🟡 [M-3] Owner Can Replace Dividend Tracker (`updateDividendTracker`) Without Ownership Verification

**Description:**
`updateDividendTracker()` accepts any address and immediately calls `onlyOwner`-gated functions on it, implicitly assuming the tracker’s `owner` is the token contract. It doesn’t verify ownership before switching.

```solidity
function updateDividendTracker(address newAddress) public onlyOwner {
    BabyElonDividendTracker newDividendTracker = BabyElonDividendTracker(payable(newAddress));
    newDividendTracker.excludeFromDividends(address(newDividendTracker), true); // assumes owner == BabyElon
    ...
    dividendTracker = newDividendTracker;
}
```

**Impact:**
- If the new tracker isn’t owned by the token contract, calls will revert (breaking updates).
- The owner can still stage a malicious tracker (then transfer its ownership to the token) to alter reward logic or censor addresses.

**Location:**
`BabyElon.updateDividendTracker()`

**💡 Recommendation:**
> Action Required:
> 1. Require `newDividendTracker.owner() == address(this)` before assignment.
> 2. Emit event with old/new addresses; consider a timelock or DAO approval.

---

#### 🟡 [M-4] Dividend Split Logic Always Uses Sell Tax Split During Swaps

**Description:**
BNB split between operations and dividends during swaps is derived from `sellTaxes` only, regardless of whether the accumulated tokens originated from buys or sells.

```solidity
uint256 swapTax = sellTaxes.rewards + sellTaxes.operations;
...
uint256 unitBalance = deltaBalance / (swapTax);
uint256 operationsAmt = unitBalance * sellTaxes.operations;
uint256 dividends = unitBalance * sellTaxes.rewards;
```

**Impact:**
If `buyTaxes` differs from `sellTaxes`, the funds allocation will not reflect the actual configured buy split, leading to misallocation.

**Location:**
`BabyElon.swapAndLiquify()`

**💡 Recommendation:**
> Action Required:
> 1. Track buy vs sell accrual separately or unify tax config.
> 2. Use a single consistent tax baseline or weights captured at accrual time.

---

### Low Findings

---

#### 🟢 [L-1] Very Tight V3 Swap Deadline Increases Failure Rate

**Description:**
V3 exactInput uses `deadline: block.timestamp + 2`, which is prone to failure under mempool delays.

```solidity
IV3Router(V3_ROUTER).exactInput{value: amt}(
    IV3Router.ExactInputParams({
        path: path,
        recipient: user,
        deadline: block.timestamp + 2, // very tight
        amountIn: amt,
        amountOutMinimum: 0
    })
)
```

**Impact:**
More frequent swap failures, falling back to sending BNB (not reward token), degrading user experience.

**Location:**
`DividendPayingToken.swapBnbForCustomToken()`

**💡 Recommendation:**
> Action Required:
> 1. Increase deadline (e.g., +120 seconds) and consider slippage controls for safety.

---

#### 🟢 [L-2] Non-Standard `Ownable` and `SafeMath` Clones (Differ From OpenZeppelin v4.x)

**Description:**
Custom `Ownable` and `SafeMath` are included instead of importing OZ v4.x. Differences include event emission order and redundant SafeMath under Solidity 0.8.

```solidity
function renounceOwnership() public virtual onlyOwner {
    emit OwnershipTransferred(_owner, address(0)); // emits before setting
    _owner = address(0);
}
library SafeMath { /* redundant under ^0.8.0 */ }
```

**Impact:**
Reduced external assurance from audited OZ libraries; minor behavioral differences may hinder tooling and audits.

**Location:**
`Ownable`, `SafeMath` libraries

**💡 Recommendation:**
> Action Required:
> 1. Prefer importing unmodified OpenZeppelin v4.x libraries.
> 2. If keeping clones, add thorough unit/integration tests and Natspec.

---

#### 🟢 [L-3] Dead/Unused or Misleading Code

**Description:**
- `addLiquidity()` is present but never used.
- `currentRewardToken` string in `BabyElon` is unused.
- `DividendPayingToken._transfer()` contains unreachable code after `require(false)`.

```solidity
function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private { ... } // unused
string private currentRewardToken; // unused

function _transfer(address from, address to, uint256 value) internal virtual override {
    require(false);
    // unreachable code
}
```

**Impact:**
Confuses maintainers; increases bytecode size and audit surface.

**Location:**
`BabyElon`, `DividendPayingToken`

**💡 Recommendation:**
> Action Required:
> 1. Remove unused variables and functions.
> 2. Delete unreachable code and clarify intent with comments.

---

### Good Practices

- Trading can only be enabled once; cannot be disabled to trap liquidity later.
- Taxes are capped at 25% per side via `MAX_TAX_PER_MILLE`.
- Dividend tracker ownership is the token contract, preventing EOAs from hijacking tracker controls.
- `swapping` flag helps prevent recursive fee-taking during internal swaps.
- Dividend withdrawal accounting safely rolls back on failed transfers.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard (non-upgradeable) | Low (no upgrade risk) |
| Upgrade Control | None | Low |
| Ownership Status | Active (0xae23...) | High (centralized controls) |
| Owner Address | 0xae2358bC13b20dDa50a1e0Efa992659E722e8d0e | Current owner |
| Total Supply | 1e15 tokens (18 decimals) | Neutral (very large nominal) |
| Buy Tax | 4% (2% rewards, 2% ops) | Low |
| Sell Tax | 4% (2% rewards, 2% ops) | Low |
| Max Transaction | None | Low |

The contract takes fees on buys/sells, auto-swaps tokens to BNB, sends the operations portion to `marketingWallet`, and streams the rewards portion to the dividend tracker, which attempts to swap BNB for a configurable reward token via Pancake V3 (fallback: send raw BNB). Launch-phase tax is 25% for 1 hour after enable. There is no inherent blacklist or transfer lock after enabling trading, reducing honeypot risk. However, centralization persists: the owner can reconfigure taxes and the reward token at will (within 25% cap), and the marketing wallet can drain BNB from the token contract. Users must trust both the owner and marketing wallet’s discretion.

Balanced Assessment: The absence of a proxy reduces upgrade risk. Nevertheless, strong centralized authorities exist (owner, marketing wallet). If managed by a robust multisig and timelock, user risk would decrease substantially. No evidence of fake renounced ownership or hidden backdoors was found; should renunciation occur, it appears legitimate given the presented code.

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
