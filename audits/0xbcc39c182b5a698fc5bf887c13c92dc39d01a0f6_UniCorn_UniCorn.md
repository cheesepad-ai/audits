# 🔍 UniCorn (UniCorn) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2025-12-23T12:31:06.570Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xbcc39c182b5a698fc5bf887c13c92dc39d01a0f6` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | UniCorn |
| **Symbol** | UniCorn |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Tue, 23 Dec 2025 12:31:06 GMT

### Summary

`UniCorn` is a tax-bearing `ERC20` token (decimals `9`) deployed on BNB Chain with fixed buy/sell taxes routed to `marketing` and `dev` wallets (split 60/40 on swap). Trading is initially disabled and must be enabled by the `owner`; owner can manage fee exemptions, tax swap threshold, and payout wallets. The code is non-upgradeable and largely standard, but includes centralization risks and a permissionless ETH withdrawal that can bypass the intended 60/40 split. Overall Risk: MEDIUM – Trust required in owner/marketing, and a notable payout logic flaw.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 2% (200/10000) | ✅ Low |
| Sell Tax | 2% (200/10000) | ✅ Low |
| Max Transaction | None | ✅ Reasonable |
| Contract Type | Standard | Info only |
| Ownership | Active | ⚠️ Centralized |
| Pause Function | No (one-way enable) | ✅ No restrictions |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | Permissionless ETH withdrawal can bypass 60/40 split; minor MEV/reentrancy surfaces |
| Centralization | Medium | Owner controls exemptions/thresholds/wallets; marketing can rescue tokens |
| Code Quality | Medium | Generally clean; a few logic/usability issues; unchecked external call results |
| Exploit Likelihood | Medium | Primary risks are logic/centralization, not direct theft vectors |
| **Overall Risk Score** | **80/100** | 0 critical, 1 high, 4 medium, 3 low findings |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn sink address for irrecoverable tokens |
| `FEE_DIVISOR()` | `10000` | Basis-points denominator (10000 = 100%) |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | WBNB token used for swaps on PancakeSwap |
| `buyTax()` | `200` | Buy tax rate in bps (2%) to contract for distribution |
| `decimals()` | `9` | Token uses 9 decimal places |
| `devAddress()` | `0x0423badACcf42425773ac1b1bb2fB53c6dC8c3ef` | Dev wallet receiving 40% of swapped BNB |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router on BSC |
| `lastSwapBackBlock()` | `0` | No tax swap-back executed/enabled yet |
| `lpPair()` | `0x5CF5023eEa890E00620d7C7557bD1f0FC5865736` | Primary AMM pair used to detect buys/sells |
| `marketingAddress()` | `0x0423badACcf42425773ac1b1bb2fB53c6dC8c3ef` | Marketing wallet receiving 60% of swapped BNB |
| `name()` | `UniCorn` | Contract name identifier |
| `owner()` | `0x0423badACcf42425773ac1b1bb2fB53c6dC8c3ef` | Address with admin privileges |
| `sellTax()` | `200` | Sell tax rate in bps (2%) to contract for distribution |
| `swapTokensAtAmt()` | `5000000000000000` | Token threshold to trigger swap-back (0.05% supply) |
| `symbol()` | `UniCorn` | Ticker symbol |
| `totalSupply()` | `10000000000000000000` | 10,000,000,000 tokens with 9 decimals (1e19 units) |
| `tradingAllowed()` | `false` | Transfers for non-exempt parties currently disabled |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 0 | — |
| High | 1 | Permissionless `withdrawStuckBNB()` bypasses 60/40 split |
| Medium | 4 | Centralized token rescues; Tax swap during transfer with external calls; Static AMM pair set; Post-renounce privileged wallet persistence |
| Low | 3 | Zero minOut on swaps (MEV); Fixed 35k gas payout may fail; Unchecked external call results |

### Critical Findings

— None found

### High Findings

#### 🟠 [H-1] Permissionless withdrawStuckBNB() bypasses intended 60/40 revenue split

**Description:**
`withdrawStuckBNB()` is `external` and unrestricted. Anyone can trigger sending the entire contract BNB balance to `marketingAddress`, effectively bypassing the intended 60/40 split enforced by `convertTaxes()` and depriving `devAddress` of its share.

```solidity
function withdrawStuckBNB() external {
    bool success;
    (success, ) = address(marketingAddress).call{
        value: address(this).balance
    }("");
}
```

**Impact:**
- Any third party can drain all accumulated BNB to `marketingAddress` at any time.
- Breaks the 60/40 split to `marketing/dev`, enabling griefing against `devAddress` (especially once `marketingAddress != devAddress`).
- Undermines expected tokenomics/disclosures.

**Location:**
`withdrawStuckBNB()` in `UniCorn`

**💡 Recommendation:**
> **Action Required:** Restrict access and preserve split:
> 1. Make `withdrawStuckBNB()` `onlyOwner` or remove it entirely.
> 2. If kept, enforce 60/40 split inside it (mirroring `convertTaxes()`).
> 3. Consider removing it and rely solely on `convertTaxes()` for distribution.

---

### Medium Findings

#### 🟡 [M-1] Marketing can rescue arbitrary tokens from contract (including this token), enabling discretionary redirection of fees

**Description:**
`rescueTokens()` allows `marketingAddress` (not `owner`) to transfer any ERC20 from the contract to itself. This includes `address(this)`, enabling marketing to extract fee-accumulated tokens before they are swapped (bypassing the 60/40 split), or pull any ERC20 (including LP tokens if deposited).

```solidity
function rescueTokens(address _token) external {
    require(msg.sender == marketingAddress, "Not marketing");
    require(_token != address(0), "_token address cannot be 0");
    uint256 _contractBalance = IERC20(_token).balanceOf(address(this));
    SafeERC20.safeTransfer(IERC20(_token), address(marketingAddress), _contractBalance);
}
```

**Impact:**
- Centralized control of accumulated fee tokens, with potential to bypass `devAddress` share.
- Can move any ERC20 held by the contract without owner approval or timelock.

**Location:**
`rescueTokens()` in `UniCorn`

**💡 Recommendation:**
> **Action Required:** Add safeguards:
> - Restrict to `onlyOwner` and optionally multi-sig/timelock.
> - Disallow rescuing `address(this)` unless split is preserved or taxes are swapped first.
> - Emit detailed events and consider allowlist of tokens safe to rescue.

---

#### 🟡 [M-2] External calls during transfer without reentrancy guard (marketing/dev payouts)

**Description:**
`handleTax()` may call `convertTaxes()` during `_transfer()`. `convertTaxes()` performs external calls to `marketingAddress` and `devAddress` with 35,000 gas. Although EOA wallets are expected, a malicious contract wallet could attempt reentrancy.

```solidity
function handleTax(address from, address to, uint256 amount) internal returns (uint256) {
    if (balanceOf(address(this)) >= swapTokensAtAmt && !isAMMPair[from] && lastSwapBackBlock + 1 <= block.number) {
        convertTaxes();
    }
    ...
}

function convertTaxes() private {
    ...
    (success, ) = marketingAddress.call{ value: marketingShare, gas: 35000 }("");
    ...
    (success, ) = devAddress.call{ value: remainingBalance, gas: 35000 }("");
    ...
    lastSwapBackBlock = block.number;
}
```

**Impact:**
- Potential, albeit constrained, reentrancy into token methods during a transfer flow.
- State (`lastSwapBackBlock`) updated after external calls, not before (weaker CEI posture).

**Location:**
`handleTax()` and `convertTaxes()` in `UniCorn`

**💡 Recommendation:**
> **Action Required:** Strengthen CEI and reentrancy posture:
> - Set `lastSwapBackBlock` before external calls or use a local “inSwap” guard.
> - Consider OpenZeppelin `ReentrancyGuard` or equivalent internal lock around swap/payouts.
> - Keep payout wallets EOAs or enforce EOA-only via off-chain policy.

---

#### 🟡 [M-3] Only the initial AMM pair is recognized; other pairs are untaxed

**Description:**
`isAMMPair` is only set for the initially created `lpPair`, with no mechanism to add new pairs. Buys/sells through any other pool will be treated as wallet-to-wallet transfers and not taxed.

```solidity
lpPair = IDexFactory(dexRouter.factory()).createPair(address(this), WETH);
isAMMPair[lpPair] = true;
```

**Impact:**
- Trading via unrecognized pairs (created later) incurs no tax, diverging from expected tokenomics.
- Potential route for tax evasion.

**Location:**
Constructor in `UniCorn` and absence of a setter for `isAMMPair`

**💡 Recommendation:**
> **Action Required:** Provide controlled pair management:
> - Add `onlyOwner` function to add/remove AMM pairs with events.
> - Optionally auto-detect common DEX factory pairs.

---

#### 🟡 [M-4] “Renounced” ownership would still leave centralized fund control via marketing wallet

**Description:**
If `owner` renounces, `marketingAddress` retains powerful abilities (`rescueTokens()`, `withdrawStuckBNB()` as currently written) to move funds. While not a fake-renounce backdoor (no owner restore), it can mislead users expecting decentralization.

```solidity
function renounceOwnership() external virtual onlyOwner {
    emit OwnershipTransferred(_owner, address(0));
    _owner = address(0);
}
```

**Impact:**
- Users may assume decentralization post-renounce while centralized fund flows remain.
- Governance expectations may be undermined.

**Location:**
`Ownable.renounceOwnership()` and `UniCorn` wallet-rescue/withdraw functions

**💡 Recommendation:**
> **Action Required:** Clarify and/or restrict:
> - Disclose clearly that `marketingAddress` retains fund movement authority post-renounce.
> - Consider gating rescues and withdrawals behind owner-only or governance mechanisms.

---

### Low Findings

#### 🟢 [L-1] Zero `amountOutMin` on swaps increases MEV/slippage risk

**Description:**
`swapTokensForETH()` uses `amountOutMin = 0`, allowing swaps to execute at any price, exposing to MEV and poor rates.

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
- Increased slippage, worse execution during volatile markets or MEV attacks.

**Location:**
`swapTokensForETH()` in `UniCorn`

**💡 Recommendation:**
> **Action Required:** Add configurable slippage protection:
> - Use a basis-points minOut parameter based on TWAP/Oracle or recent on-chain price.
> - Or compute minOut from reserves with a safety margin.

---

#### 🟢 [L-2] Fixed 35k gas payouts may fail for contract wallets; failures silently ignored

**Description:**
Payouts use `gas: 35000` and ignore `success`, potentially leaving ETH stuck.

```solidity
(success, ) = marketingAddress.call{ value: marketingShare, gas: 35000 }("");
(success, ) = devAddress.call{ value: remainingBalance, gas: 35000 }("");
```

**Impact:**
- Contract wallets with heavier fallback may fail to receive funds.
- Silent failures reduce transparency; balances accumulate until manually withdrawn (currently to marketing via `withdrawStuckBNB()`).

**Location:**
`convertTaxes()` in `UniCorn`

**💡 Recommendation:**
> **Action Required:** Improve robustness:
> - Consider removing gas limit or making it configurable.
> - Handle failures with events or retries; avoid silently ignoring.

---

#### 🟢 [L-3] Owner can arbitrarily exempt addresses from fees and trading gate

**Description:**
`setExemptFromFee()` allows the owner to exempt any address, bypassing taxes and the `tradingAllowed` gate for that address.

```solidity
function setExemptFromFee(address _address, bool _isExempt) external onlyOwner {
    require(_address != address(0), "Zero Address");
    require(_address != address(this), "Cannot unexempt contract");
    exemptFromFees[_address] = _isExempt;
    emit SetExemptFromFees(_address, _isExempt);
}
```

**Impact:**
- Centralized control; can advantage specific wallets or enable pre-trading.
- Not a direct vulnerability but important for users to understand.

**Location:**
`setExemptFromFee()` in `UniCorn`

**💡 Recommendation:**
> **Action Required:** Governance and transparency:
> - Use multisig/timelock for changes.
> - Emit events (already done) and disclose exemption policy publicly.

---

### Good Practices

- Non-upgradeable, no proxy/delegatecall patterns in `UniCorn` (reduces upgrade risk).
- Taxes are fixed in code; no owner-controlled tax rate functions (reduces abuse risk).
- Uses standard, unmodified OpenZeppelin-style `Address` and `SafeERC20` patterns.
- One-way trading enable; no pause/blacklist functions that could freeze markets.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard | Low |
| Upgrade Control | None (no proxy) | Low |
| Ownership Status | Active | Medium (centralized controls) |
| Owner Address | 0x0423...c3ef | Current owner |
| Total Supply | 10,000,000,000 (9 decimals) | Low |
| Buy Tax | 2% to contract | Low |
| Sell Tax | 2% to contract | Low |
| Max Transaction | None | Low |

- Tax Flow: On buy/sell, `2%` is taken on AMM interactions only. Accumulated tokens are swapped to BNB on sells when `swapTokensAtAmt` is reached; BNB split 60% to `marketing`, 40% to `dev`. Wallet-to-wallet transfers are untaxed post trading enable.
- Centralization: `owner` controls fee exemptions, swap threshold, and payout wallets. `marketingAddress` can rescue any ERC20 from the contract; anyone can call `withdrawStuckBNB()` to route all ETH to marketing, bypassing the split. Even if `owner` renounces, `marketingAddress` retains substantial fund control. Users must trust these parties.
- Liquidity: No direct functions to handle LP tokens. If LP tokens are ever sent to the contract, `marketingAddress` can extract them via `rescueTokens()`.

Balanced Assessment: The absence of a proxy reduces upgrade risk, but centralized wallet controls and the permissionless ETH withdrawal that undermines the 60/40 split require trust. If governance is strong (multisig, disclosures), risks are mitigated. Without such safeguards, users must fully trust the owner/marketing.

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
