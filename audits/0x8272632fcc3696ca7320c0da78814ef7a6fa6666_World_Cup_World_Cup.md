# 🔍 World Cup (World Cup) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-05-26T01:29:50.678Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0x8272632fcc3696ca7320c0da78814ef7a6fa6666` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | World Cup |
| **Symbol** | World Cup |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Tue, 26 May 2026 01:29:50 GMT

### Summary

This is a custom taxed `ERC20` token (`WorldCup`) with 9 decimals, fixed buy/sell marketing tax of 3% routed through a swap-and-distribute mechanism. Trading is gated via `tradingAllowed`, and the owner can exempt addresses from fees, set AMM pairs, and control swap settings; fund withdrawals are controlled by `mktAddress`. No proxy or upgradeability is present; libraries mirror OpenZeppelin semantics without malicious alterations. Overall Risk: MEDIUM - Centralized controls and selective trading via fee-exemptions; otherwise standard tax token patterns.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 3% | ✅ Low |
| Sell Tax | 3% | ✅ Low |
| Max Transaction | None | ✅ No hard restrictions |
| Contract Type | Standard (non-upgradeable) | Info |
| Ownership | Active (`owner() != address(0)`) | ⚠️ Centralized |
| Pause Function | No general pause; pre-launch gate via `tradingAllowed` | ⚠️ Can block trading until enabled |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | Standard taxed ERC20; selective trading possible via fee-exemptions; safe swap/back logic with minor caveats |
| Centralization | Medium | Owner controls trading gate and settings; `mktAddress` can withdraw ETH and rescue tokens |
| Code Quality | Medium | Mostly OZ-like; a few non-standard patterns and unchecked low-level calls |
| Exploit Likelihood | Low | No clear critical exploit; risks are mainly governance/centralization and UX misconfigurations |
| **Overall Risk Score** | **84/100** | 0 critical, 1 high, 3 medium, 2 low |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn/sink address for irrecoverable tokens |
| `FEE_DIVISOR()` | `10000` | Basis points divisor; 300 = 3% |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | WBNB address used in swaps (BSC) |
| `buyTax()` | `300` | 3% marketing tax applied on buys |
| `decimals()` | `9` | Token uses 9 decimal places |
| `devAddress()` | `0xEfd1c05f55E95ACE80Fc39E44C79664236fd90ee` | Receives 1/3 of swapped ETH |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router |
| `lastSwapBackBlock()` | `0` | No swaps executed yet at the snapshot |
| `lpPair()` | `0x31932d8b0f50d58C3cA23a397f0886568267C64d` | Created token–WBNB pair |
| `mktAddress()` | `0xEfd1c05f55E95ACE80Fc39E44C79664236fd90ee` | Receives remaining ETH from tax conversions |
| `name()` | `World Cup` | Contract name |
| `owner()` | `0xEfd1c05f55E95ACE80Fc39E44C79664236fd90ee` | Admin controlling settings and gating |
| `rewardPoolAddress()` | `0xEfd1c05f55E95ACE80Fc39E44C79664236fd90ee` | Receives 1/3 of swapped ETH |
| `sellTax()` | `300` | 3% marketing tax applied on sells |
| `swapEnabled()` | `true` | Tax-to-ETH swapping enabled |
| `swapTokensAtAmt()` | `500000000000000` | Swap threshold = 0.05% of supply |
| `symbol()` | `World Cup` | Token symbol (non-standard equal to name) |
| `totalSupply()` | `1000000000000000000` | 1e9 tokens with 9 decimals (1e18 base units) |
| `tradingAllowed()` | `false` | Trading gate currently off; owner must enable |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 0 | — |
| High | 1 | Selective trading via fee exemptions bypasses `tradingAllowed` |
| Medium | 3 | Residual privileged `mktAddress` after renounce; Owner-controlled AMM-pair taxation; Unchecked low-level send semantics mismatch |
| Low | 2 | Unlimited router approvals; Non-standard symbol equals name (UI risk) |

### Critical Findings

None.

### High Findings

---

#### 🟠 [H-1] Trading Gate Can Be Bypassed via Fee Exemptions (Selective Trading/Honeypot Risk)

**Description:**
The `tradingAllowed` gate is only enforced when both `from` and `to` are not fee-exempt. The owner can set fee exemptions on arbitrary addresses (including the DEX pair), enabling trading for selected entities before `tradingAllowed` is turned on, and disabling fees in those paths.

```solidity
function _transfer(address from, address to, uint256 amount) internal virtual override {
    if (!exemptFromFees[from] && !exemptFromFees[to]) {
        require(tradingAllowed, "Trading not active");
        amount -= handleTax(from, to, amount);
    }
    super._transfer(from, to, amount);
}

function setExemptFromFee(address _address, bool _isExempt) external onlyOwner {
    exemptFromFees[_address] = _isExempt;
}
```

If the owner exempts the LP pair address, both buys (pair -> user) and sells (user -> pair) bypass the gate and taxes. This creates asymmetric market conditions and can be used to advantage specific traders or bots.

**Impact:**
- Selective early trading without public launch
- Zero-tax trading for exempted actors
- Potential perception of honeypot or unfair launch dynamics

**Location:**
`WorldCup._transfer()` and `setExemptFromFee()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Enforce `tradingAllowed` regardless of fee-exempt status during pre-launch:
>    - Check `tradingAllowed` first, then optionally apply fee exemptions.
> 2. Alternatively, allow trading only when `from` or `to` is a curated whitelist (separate from fee exemptions).
> 3. Emit clear launch events and avoid exempting LP/router for trading unless explicitly communicated.

---

### Medium Findings

---

#### 🟡 [M-1] Residual Privileges After Ownership Renounce via `mktAddress` (ETH Withdraw and Token Rescue)

**Description:**
Even if `owner` renounces, `mktAddress` retains permanent authority to withdraw all ETH and rescue any ERC20 tokens (except this token) from the contract. This power is independent of `owner` and cannot be revoked after renounce.

```solidity
function withdrawStuckBNB() external {
    require(msg.sender == mktAddress, "Not MKT");
    uint256 amount = address(this).balance;
    (success, ) = address(mktAddress).call{value: amount}("");
}

function rescueTokens(address _token) external {
    require(msg.sender == mktAddress, "Not MKT");
    require(_token != address(this), "Cannot rescue project token");
    uint256 _contractBalance = IERC20(_token).balanceOf(address(this));
    SafeERC20.safeTransfer(IERC20(_token), address(mktAddress), _contractBalance);
}
```

**Impact:**
- Users may assume decentralization post-renounce, but a privileged actor remains able to move ETH and third-party tokens.
- Centralization/trust risk persists after renounce.

**Location:**
`withdrawStuckBNB()` and `rescueTokens()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Consider gating these functions behind `onlyOwner` plus `mktAddress` or a multisig.
> 2. If true decentralization is desired post-renounce, disable or time-lock these functions.
> 3. Clearly document that `mktAddress` retains control even after renounce.

---

#### 🟡 [M-2] Owner-Controlled AMM Pair Mapping Allows Arbitrary Addresses to be Taxed as Buys/Sells

**Description:**
The owner can mark any address as an AMM pair, which changes transfer classification and applies buy/sell taxes to transfers involving that address.

```solidity
mapping(address => bool) public isAMMPair;

function setAMMPair(address _pair, bool _isPair) external onlyOwner {
    require(_pair != lpPair, "Cannot modify initial pair");
    isAMMPair[_pair] = _isPair;
}
```

**Impact:**
- Unexpected taxation on transfers to/from arbitrary addresses if flagged as AMM pairs.
- Confusing user experience and potential unintended taxation.

**Location:**
`setAMMPair()` and `handleTax()` decision on `isAMMPair`.

**💡 Recommendation:**
> **Action Required:**
> 1. Restrict pair designation to factory-created pairs only.
> 2. Emit explicit events and publish an allowlist policy.
> 3. Consider removing this control if not strictly necessary.

---

#### 🟡 [M-3] Unchecked Low-Level ETH Sends Can Misroute Funds and Emit Misleading Events

**Description:**
Low-level calls in `convertTaxes()` and `withdrawStuckBNB()` ignore the `success` flag or continue execution without reverting, potentially emitting events even when transfers fail. In `convertTaxes()`, failed reward/dev sends effectively redirect more ETH to `mktAddress`.

```solidity
// convertTaxes()
(success, ) = rewardPoolAddress.call{value: share, gas: 35000}("");
(success, ) = devAddress.call{value: share, gas: 35000}("");
// remaining sent to mktAddress regardless of previous failures
(success, ) = mktAddress.call{ value: remainingBalance, gas: 35000 }("");

// withdrawStuckBNB()
(success, ) = address(mktAddress).call{value: amount}("");
emit StuckBNBWithdrawn(mktAddress, amount);
```

**Impact:**
- If reward/dev recipients revert or consume >35k gas, funds get redirected to `mktAddress`.
- Events may suggest success even when ETH wasn’t received.
- Accounting/auditing confusion; fairness concerns.

**Location:**
`convertTaxes()` and `withdrawStuckBNB()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Check `success` and revert or handle failed transfers deterministically.
> 2. Emit events only after successful transfers.
> 3. Consider pull-based claiming instead of push with gas stipends.

---

### Low Findings

---

#### 🟢 [L-1] Unlimited Approvals to DEX Router for Owner and Contract

**Description:**
The contract approves `dexRouter` for `type(uint256).max` from the contract and for `totalSupply()` from the deployer EOA.

```solidity
_approve(address(this), address(dexRouter), type(uint256).max);
_approve(address(msg.sender), address(dexRouter), totalSupply());
```

**Impact:**
- If the router address were malicious or replaced on other deployments, allowances could be abused.
- On BSC, the router is Pancake V2 (trusted), reducing practical risk.

**Location:**
Constructor.

**💡 Recommendation:**
> **Action Required:**
> 1. Use exact allowances for operations (add liquidity), then reset to zero.
> 2. Keep router addresses to well-known audited deployments only.

---

#### 🟢 [L-2] Non-Standard Symbol Equals Name

**Description:**
The `symbol()` returns the same value as `name()` (`"World Cup"`), which is unusual and can confuse UIs.

```solidity
constructor(address _v2Router) ERC20("World Cup", "World Cup") {}
```

**Impact:**
- UX issues in wallets and listing platforms.

**Location:**
Constructor string arguments.

**💡 Recommendation:**
> **Action Required:**
> - Use a short ticker-like `symbol` (e.g., `WORLDCUP`) distinct from `name`.

---

### Good Practices

- No upgradeability or proxy mechanics; implementation is immutable after deployment.
- Taxes are fixed at 3% buy/sell and not owner-adjustable (reduces “stealth tax hike” risk).
- `inSwap` lock (`lockTheSwap` modifier) prevents re-entrancy during tax conversion.
- Uses OZ-like `Address`, `SafeERC20`, and `Context` semantics; no malicious modifications detected.
- Swap threshold bounded by owner with sensible min/max constraints (0.001% to 0.5% of supply).

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard taxed ERC20 | Low (no upgrade risk) |
| Upgrade Control | None (no proxy) | Low |
| Ownership Status | Active (0xEfd1... owner) | High centralization until renounce |
| Owner Address | 0xEfd1c05f55E95ACE80Fc39E44C79664236fd90ee | Current admin |
| Total Supply | 1,000,000,000 tokens (9 decimals) | Low |
| Buy Tax | 3% marketing | Low |
| Sell Tax | 3% marketing | Low |
| Max Transaction | None | Medium (possible volatility) |

The token levies a 3% fee on buys/sells only (wallet-to-wallet transfers untaxed). Collected tokens are swapped to BNB; proceeds are split equally between `rewardPoolAddress` and `devAddress`, with the remainder to `mktAddress`. Distribution uses low-level calls with 35k gas stipends; failed sends effectively reroute more to `mktAddress`. The owner controls trading enablement, fee exemptions, AMM pair designations, and swap thresholds.

Balanced Assessment: With no proxy and fixed tax rates, upgrade/governance risk is lower. However, the owner’s ability to exempt addresses enables selective pre-launch trading and tax bypass, and `mktAddress` holds ongoing withdrawal authority even post-renounce. Users must trust the owner and designated addresses to operate fairly and transparently.

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
