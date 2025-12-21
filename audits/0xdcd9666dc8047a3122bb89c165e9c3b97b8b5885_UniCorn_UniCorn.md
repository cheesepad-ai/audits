# 🔍 UniCorn (UniCorn) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2025-12-21T13:55:00.493Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xdcd9666dc8047a3122bb89c165e9c3b97b8b5885` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | UniCorn |
| **Symbol** | UniCorn |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Sun, 21 Dec 2025 13:55:00 GMT

### Summary

This contract is a standard `ERC20`-like token (`UniCorn`) with 9 decimals, fixed supply, and a launch trading lock controlled by `owner`. There are no taxes, no mint/burn, and no blacklist beyond a pre-launch trading lock whitelist. Centralization exists around launch controls and rescue permissions. Overall Risk: LOW - Simple token logic, with moderate centralization at launch and minor rescue-related risks.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | None | ✅ Low |
| Sell Tax | None | ✅ Low |
| Max Transaction | None | ✅ Reasonable |
| Contract Type | Standard | Info only |
| Ownership | Active | ⚠️ Centralized |
| Pause Function | No (one-way launch lock) | ✅ No restrictions after enable |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Low | No complex logic; minimal external calls; no fees |
| Centralization | Medium | Owner controls launch and whitelisting; fund can rescue assets |
| Code Quality | Low | Straightforward; minor edge cases and known ERC20 allowance race |
| Exploit Likelihood | Low | No apparent critical attack surface |
| **Overall Risk Score** | **92/100** | 0 critical, 0 high, 2 medium, 2 low |

## On-Chain Function Results

The following functions were called on-chain at block 72430940. The table below shows the results:

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `decimals()` | `9` | Token uses 9 decimal places |
| `fundAddress()` | `0x0423badACcf42425773ac1b1bb2fB53c6dC8c3ef` | Address authorized to rescue BNB/tokens from this contract |
| `name()` | `UniCorn` | Token name identifier |
| `owner()` | `0x0423badACcf42425773ac1b1bb2fB53c6dC8c3ef` | Admin with power to enable trading and manage exclusions |
| `symbol()` | `UniCorn` | Token ticker symbol |
| `totalSupply()` | `10000000000000000000` | Total tokens ever created; equals 10,000,000,000 tokens (9 decimals) |
| `tradingActive()` | `false` | Trading not yet enabled for non-whitelisted addresses |

### Findings Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| Critical | 0 | None |
| High | 0 | None |
| Medium | 2 | Centralized launch/trading lock; LP/token rescue could enable rug if LP sent here |
| Low | 2 | Reentrancy/DoS risk in `rescueBNB`; ERC20 `approve` race condition |

### Medium Findings

---

#### 🟡 [M-1] Centralized Launch Control via Trading Lock and Whitelist

**Description:**
Transfers are blocked until `owner` calls `enableTrading()`. The owner can also selectively exclude addresses from the lock, allowing privileged trading before the public launch.

```solidity
function _transfer(address from, address to, uint256 amount) internal {
    ...
    require(
        tradingActive ||
            _isExcludedFromTradingLock[from] ||
            _isExcludedFromTradingLock[to],
        "Trading is not active"
    );
    ...
}

function excludeFromTradingLock(address account, bool excluded) external onlyOwner {
    _isExcludedFromTradingLock[account] = excluded;
}

function enableTrading() external onlyOwner {
    require(!tradingActive, "Trading already enabled");
    tradingActive = true;
}
```

**Impact:**
- Owner can allow insider/preferred wallets to trade before public, potentially enabling unfair launch advantages.
- Non-whitelisted users cannot transfer until owner enables trading.

**Location:**
`_transfer()` trading gate; `excludeFromTradingLock()`; `enableTrading()`.

**💡 Recommendation:**
> **Action Required:** Mitigate launch centralization.
> 1. Publicly announce and commit to a trading start time.
> 2. Avoid using whitelist beyond necessary bootstrap (e.g., router/pair).
> 3. Consider verifiable timelock/ownership renunciation post-launch.

---

#### 🟡 [M-2] Rescue Function Can Withdraw Any ERC20 (Including LP Tokens) Held by Contract

**Description:**
`onlyFundAddress` can withdraw arbitrary ERC20 tokens from this contract, including LP tokens, if those tokens are sent here.

```solidity
function rescueToken(address token) external onlyFundAddress {
    IERC20 tokenContract = IERC20(token);
    uint256 tokenBalance = tokenContract.balanceOf(address(this));
    require(tokenBalance > 0, "No tokens to withdraw");
    require(
        tokenContract.transfer(fundAddress, tokenBalance),
        "Token transfer failed"
    );
}
```

**Impact:**
- If LP tokens are “locked” by sending them to this token contract, `fundAddress` can withdraw them, enabling a liquidity rug.
- Users might falsely assume assets in this contract are safe/locked.

**Location:**
`rescueToken()` function.

**💡 Recommendation:**
> **Action Required:** Clarify and constrain rescue.
> 1. Do not use this contract as a token/LP locker.
> 2. If needed, block rescuing specific tokens (e.g., LP token address, this token).
> 3. Publicly document rescue policy and set `fundAddress` to a secure multisig.

### Low Findings

---

#### 🟢 [L-1] Reentrancy/DoS Risk in `rescueBNB()` via External Call to `fundAddress`

**Description:**
`rescueBNB()` performs a low-level call to `fundAddress`, which can reenter and cause a revert (self-DoS) if fallback reenters `rescueBNB()` or otherwise reverts.

```solidity
function rescueBNB() external onlyFundAddress {
    uint256 balance = address(this).balance;
    require(balance > 0, "No BNB to withdraw");
    (bool success, ) = payable(fundAddress).call{value: balance}("");
    require(success, "BNB transfer failed");
}
```

**Impact:**
- If `fundAddress`’s fallback reverts or reenters improperly, the withdrawal can fail. This is owner-controlled but fragile.

**Location:**
`rescueBNB()` function.

**💡 Recommendation:**
> **Action Required:** Harden the rescue.
> 1. Ensure `fundAddress` fallback does not reenter or revert.
> 2. Add a reentrancy guard or use pull pattern with `withdraw()` on `fundAddress`.
> 3. Consider emitting an event and using `Address.sendValue`-like helper.

---

#### 🟢 [L-2] Standard ERC20 Allowance Race Condition with `approve()`

**Description:**
`approve()` directly sets allowance, enabling the well-known race where a spender can use the old allowance before the new value is set.

```solidity
function approve(address spender, uint256 amount) external returns (bool) {
    _approve(msg.sender, spender, amount);
    return true;
}
```

**Impact:**
- Spender may spend both the old and new allowances if the holder changes allowance from non-zero to non-zero.

**Location:**
`approve()` function.

**💡 Recommendation:**
> **Action Required:** Mitigate allowance race.
> - Encourage users to set allowance to 0 before setting a new non-zero value, or use `increaseAllowance`/`decreaseAllowance`.

---

### Good Practices

- No upgradeability or proxy pattern; immutable logic reduces upgrade risk.
- No taxes, reflections, or complex AMM interactions; reduced attack surface.
- Ownership renunciation is straightforward with no apparent backdoors.
- Solidity 0.8.x arithmetic checks remove overflow/underflow risks without SafeMath.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard (non-upgradeable) | Low |
| Upgrade Control | N/A | Low |
| Ownership Status | Active (on-chain owner set) | Medium (centralization) |
| Owner Address | 0x0423…c3ef | Current admin |
| Total Supply | 10,000,000,000 tokens (9 decimals) | Low |
| Buy Tax | 0% | Low |
| Sell Tax | 0% | Low |
| Max Transaction | None | Low |

- Launch Control: Trading is locked until `owner` enables `tradingActive`. The owner can pre-whitelist addresses to trade before public launch. This centralization is common but should be transparently communicated.
- Mint/Burn: No minting or burning; fixed supply allocated to deployer at construction.
- Blacklist/Whitelist: Only a launch whitelist `_isExcludedFromTradingLock`. No ongoing blacklist logic.
- Rescue Functions: `fundAddress` can withdraw any ERC20 and any native balance from this contract. Do not treat the contract as a “locker” for LP or other tokens. Set `fundAddress` to a secure multisig if used operationally.
- Ownership Renunciation: If `owner` renounces, trading cannot be enabled afterward (if not already), and `fundAddress` cannot be changed further. No hidden restore/backdoor detected; if renounced, it is effectively permanent for owner-only actions.

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
