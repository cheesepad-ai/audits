# 🔍 Santa Bnb (SBNB) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2025-12-14T01:55:38.207Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0x87cb007bc05c75f207a689afc5fe1ce1e5ca2bd9` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | Santa Bnb |
| **Symbol** | SBNB |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Sun, 14 Dec 2025 01:55:38 GMT

### Summary

This is a standard `ERC20` tax token (`TaxableToken`) using OpenZeppelin v5.x with configurable transfer tax, anti-whale limits, and cooldown. Key features include a flat `transferTaxBps` (default 2%), `maxTransferAmount`, `maxWalletPercent`, per-sender cooldown, and owner-controlled blacklist/whitelist. The codebase is simple and uses unmodified OpenZeppelin libraries; however, owner privileges can fully restrict trading or selectively tax/exempt addresses. Overall Risk: HIGH - Centralized controls (blacklist and adjustable limits) can create honeypot-like behavior.

### Risk Assessment

Token Quick Facts:

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 2% flat transfer tax | ✅ Low |
| Sell Tax | 2% flat transfer tax | ✅ Low |
| Max Transaction | 5% of supply (default) | ✅ Reasonable |
| Contract Type | Standard (non-upgradeable) | Info |
| Ownership | Active | ⚠️ Centralized |
| Pause Function | No | ✅ No restrictions |

Security Assessment:

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Low | Simple logic, OZ v5.x, no external calls in transfer path |
| Centralization | High | Owner can blacklist, change tax/limits, and exemptions |
| Code Quality | Low | Clean, OZ-based; tax/limits correctly ordered |
| Exploit Likelihood | Medium | No technical exploits found; admin-abuse risk remains |
| **Overall Risk Score** | **82/100** | 0 Critical, 2 High, 2 Medium, 2 Low |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| decimals() | 18 | Token decimal places |
| maxSupply() | 100000000000000000000000000 | Maximum token supply allowed at deployment |
| maxTransferAmount() | 5000000000000000000000000 | Per-transfer limit; owner-adjustable |
| maxWalletPercent() | 200 | Anti-whale wallet cap in bps (2%) |
| name() | Santa Bnb | Contract name identifier |
| owner() | 0x4a93EC63EC2115398114D858597C7996ACFdd0a1 | Address with admin privileges |
| symbol() | SBNB | Token ticker |
| taxRecipient() | 0x4a93EC63EC2115398114D858597C7996ACFdd0a1 | Address receiving transfer taxes |
| totalSupply() | 100000000000000000000000000 | Total tokens currently minted |
| transferCooldown() | 30 | Minimum seconds between sends per address |
| transferTaxBps() | 200 | 2% tax on transfers |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 0 | — |
| High | 2 | Owner blacklist can freeze funds; Owner-adjustable limits can de facto lock trading |
| Medium | 2 | TaxRecipient bypasses wallet cap; Owner-controlled exclusions undermine fairness |
| Low | 2 | `maxSupply` unused post-deploy; Sender-only cooldown may hinder integrations |

### Critical Findings

None.

### High Findings

---

#### 🟠 [H-1] Owner Blacklist (`_bots`) Can Freeze Funds or Block Sells (Honeypot Risk)

**Description:**
The owner can arbitrarily flag any account (including DEX routers/pools or retail addresses) as a bot, causing all transfers involving that address to revert. This can be used to block sells or trap user funds.

```solidity
mapping(address => bool) private _bots;

function setBotStatus(address account, bool status) external onlyOwner {
    require(account != address(0), "Invalid address");
    _bots[account] = status;
    emit BotStatusUpdated(account, status);
}

function _update(address from, address to, uint256 amount) internal override {
    if (from != address(0) && to != address(0)) {
        // Bot check
        require(!_bots[from] && !_bots[to], "Bot address");
        ...
    }
    super._update(from, to, amount);
}
```

**Impact:**
- Owner can selectively freeze accounts or disable sells by blacklisting the LP or router.
- De facto honeypot behavior possible at any time post-launch.

**Location:**
`_update()` transfer path and `setBotStatus()` admin setter.

**💡 Recommendation:**
> **Action Required:**
> 1. Limit blacklist scope (e.g., immutable list set before trading start) or remove this power.
> 2. If keeping, gate via timelock and/or multisig, publish policies, and log all changes.
> - Alternative: Replace hard blacklist with protective measures limited to launch phase only.

---

#### 🟠 [H-2] Owner-Adjustable Limits Can Lock Trading

**Description:**
The owner can set `maxTransferAmount` to an arbitrarily small non-zero value and tune `transferCooldown` and `maxWalletPercent` to restrict transfers severely.

```solidity
require(amount <= maxTransferAmount, "Exceeds max tx");
...
function setMaxTransferAmount(uint256 amount) external onlyOwner {
    require(amount > 0, "Zero not allowed");
    maxTransferAmount = amount;
    emit MaxTransferAmountUpdated(amount);
}

function setCooldown(uint256 seconds_) external onlyOwner {
    require(seconds_ <= 300, "Too long");
    transferCooldown = seconds_;
    emit CooldownUpdated(seconds_);
}

function setMaxWalletPercent(uint256 bps) external onlyOwner {
    require(bps >= 50 && bps <= 1000, "Out of bounds"); // 0.5% - 10%
    maxWalletPercent = bps;
    emit MaxWalletPercentUpdated(bps);
}
```

**Impact:**
- Owner can effectively prevent normal trading (e.g., set tiny max transfer, long cooldown).
- Users may be unable to sell/buy meaningful amounts post-launch.

**Location:**
`_update()` checks and admin setters.

**💡 Recommendation:**
> **Action Required:**
> 1. Enforce reasonable lower bounds (e.g., min transfer >= X% of supply).
> 2. Add timelock/multisig for changes and publish parameter governance.
> - Alternative: Permanently lock limits after launch (immutable values) if decentralization is desired.

---

### Medium Findings

---

#### 🟡 [M-1] TaxRecipient Not Subject to Max Wallet Limit (Bypass)

**Description:**
The wallet cap only checks the primary `to` address and only against `netAmount`. The `taxRecipient` receives `tax` via a separate transfer that is not checked against max wallet limits, allowing it to exceed `maxWalletPercent`.

```solidity
// To checks use netAmount and ignore taxRecipient
if (!toExcluded) {
    uint256 walletLimit = (totalSupply() * maxWalletPercent) / 10_000;
    require(balanceOf(to) + netAmount <= walletLimit, "Exceeds max wallet");
}

// Collect tax without wallet cap enforcement on taxRecipient
if (tax > 0) {
    super._update(from, taxRecipient, tax);
    emit TaxCollected(tax);
}
```

**Impact:**
- `taxRecipient` can accumulate unlimited tokens relative to the wallet cap, undermining anti-whale policies.
- If `taxRecipient` later sells, it can significantly impact price/liquidity.

**Location:**
`_update()` transfer logic around wallet cap and tax collection.

**💡 Recommendation:**
> **Action Required:**
> 1. Enforce wallet cap for `taxRecipient` unless it is excluded.
> 2. Alternatively, always mark and maintain `taxRecipient` as excluded in `setTaxRecipient()`.

---

#### 🟡 [M-2] Owner-Controlled Exclusions Undermine Fairness and Limits

**Description:**
The owner can exclude any address from all taxes, limits, and cooldown. While intended for admin/contract wallets, this ability enables privileged trading and selective tax exemptions.

```solidity
mapping(address => bool) private _excluded;

function setExclusion(address account, bool status) external onlyOwner {
    require(account != address(0), "Invalid address");
    _excluded[account] = status;
    emit ExclusionUpdated(account, status);
}
```

**Impact:**
- Preferential treatment of certain addresses possible (e.g., tax-free, no limits).
- Creates asymmetric market conditions and trust assumptions.

**Location:**
`setExclusion()` and checks in `_update()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Restrict exclusions to a fixed, auditable set or remove after launch.
> 2. If retained, adopt multisig + timelock and publish a transparent policy.

---

### Low Findings

---

#### 🟢 [L-1] `maxSupply` Is Not Enforced Beyond Constructor

**Description:**
`maxSupply` is immutable but only used in the constructor check. No minting functions exist after deployment, making `maxSupply` informational.

```solidity
uint256 public immutable maxSupply;
require(initialSupply_ <= maxSupply_, "Initial > max");
_mint(owner_, initialSupply_);
```

**Impact:**
- Minor clarity issue; readers may expect runtime enforcement. Practical risk is minimal due to no post-deploy minting.

**Location:**
State variable and constructor.

**💡 Recommendation:**
> **Action Required:**
> - Document that `maxSupply` is a static cap validated at deployment only.

---

#### 🟢 [L-2] Sender-Only Cooldown May Hinder Some Integrations

**Description:**
Cooldown applies only to the sender (`from`) and uses per-address timestamps. Routers or smart wallets sending multiple sequential transactions for the same `from` may hit cooldown unexpectedly.

```solidity
if (!fromExcluded && transferCooldown > 0) {
    require(block.timestamp >= _lastTransfer[from] + transferCooldown, "Cooldown active");
}
// updated after tax
_lastTransfer[from] = block.timestamp;
```

**Impact:**
- Potential integration friction with DEXes/aggregators; not a security issue.

**Location:**
Cooldown logic in `_update()`.

**💡 Recommendation:**
> **Action Required:**
> - Consider allowing router exemptions or disabling cooldown after launch.

---

### Good Practices

- Uses unmodified OpenZeppelin `ERC20` v5.4.0, `Ownable` v5.0.0, `Context` v5.0.1 (no malicious changes detected).
- No upgradeability or proxy pattern (immutable implementation).
- All admin parameter changes emit dedicated events.
- Reasonable caps: `transferTaxBps` ≤ 10%; `transferCooldown` ≤ 5 minutes; `maxWalletPercent` bounded (0.5%–10%).
- No external calls in transfer path; no reentrancy surfaces.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard `ERC20` with flat transfer tax | Low (code risk) |
| Upgrade Control | None (non-upgradeable) | Low (no upgrade risk) |
| Ownership Status | Active (owner: 0x4a93...d0a1) | High (centralized control) |
| Owner Address | 0x4a93EC63EC2115398114D858597C7996ACFdd0a1 | Current admin |
| Total Supply | 100,000,000 tokens (18 decimals) | Low |
| Buy Tax | 2% flat | Low |
| Sell Tax | 2% flat | Low |
| Max Transaction | 5% default (owner-adjustable) | Medium (can be made restrictive) |

Detailed:
- Initial supply equals `maxSupply` and was minted to `owner`, who is excluded from limits/tax by default.
- Owner can change `transferTaxBps` up to 10%, `maxTransferAmount` arbitrarily, `maxWalletPercent` between 0.5% and 10%, and `transferCooldown` up to 5 minutes.
- Blacklist (`_bots`) and exclusion (`_excluded`) controls allow the owner to selectively restrict or privilege wallets, including disabling sells or creating honeypot-like conditions post-launch.
- `taxRecipient` initially equals `owner` and is excluded; if changed, the new recipient is not auto-excluded and can accumulate beyond wallet cap due to separate tax transfer path not enforcing the cap.

Balanced Assessment:
- The contract’s simplicity and OZ inheritance reduce technical bug risk, but centralized admin powers materially affect user risk. While such controls can help at launch (anti-bot, anti-whale), they also enable trading restrictions or selective taxation later. If trust in the owner (EOA) is high and governance is transparent (ideally multisig/timelock), risk is mitigated; otherwise, users must assume elevated centralization risk. Ownership renunciation is supported by standard OZ `Ownable` and would be effective (no hidden restore), but currently ownership is active.

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
