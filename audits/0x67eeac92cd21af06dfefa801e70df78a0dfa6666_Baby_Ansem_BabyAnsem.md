# 🔍 Baby Ansem (BabyAnsem) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-06-28T09:42:49.386Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0x67eeac92cd21af06dfefa801e70df78a0dfa6666` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | Baby Ansem |
| **Symbol** | BabyAnsem |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Sun, 28 Jun 2026 09:42:49 GMT

### Summary

This is a standard `ERC20` tax token with fixed supply, 9 decimals, auto-swap of collected fees to `WETH` (WBNB) and distribution to `devAddress` (40%) and `mktAddress` (60%). It enforces a buy/sell marketing tax of 3% and optionally a launch tax that linearly decays from 90% to 3% over 5 minutes after `enableTrading()`. Owner can whitelist addresses to bypass fees and trading checks and can mark arbitrary addresses as AMM pairs. No proxy or upgradeability and no hidden backdoors detected. Overall Risk: MEDIUM - Centralized controls (whitelist, AMM marking) and potential high launch tax; no critical code vulnerabilities identified.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 3% (Launch: up to 90% for 5m) | ⚠️ High (launch window risk) |
| Sell Tax | 3% (Launch: up to 90% for 5m) | ⚠️ High (launch window risk) |
| Max Transaction | None | ✅ No restrictions |
| Contract Type | Standard | Info |
| Ownership | Active | ⚠️ Centralized |
| Pause Function | No | ✅ No restrictions |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | No critical vulns; owner can bypass trading via whitelists |
| Centralization | High | Single owner controls whitelists, AMM flags, treasury addresses |
| Code Quality | Low | Clean, OZ-like; no unsafe patterns found |
| Exploit Likelihood | Low | No reentrancy/overflow issues; typical tax token risks |
| **Overall Risk Score** | **89/100** | 0 critical, 0 high, 3 medium, 2 low |

## On-Chain Function Results

The following functions were called on-chain at block 106846722. The table below shows the results:

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Standard burn address often used to lock/burn tokens |
| `FEE_DIVISOR()` | `10000` | Basis-points divisor for fee calculations (bps = fee/10000) |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | WBNB address on BSC used for swaps/liquidity |
| `buyTax()` | `300` | 3% buy tax in basis points, sent to contract then swapped |
| `decimals()` | `9` | Number of decimal places for display/UX |
| `devAddress()` | `0xD10B27459cAff7566e480E237a0069F5cfC75215` | Receives 40% of swap ETH from fees |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap v2 router on BSC |
| `lastSwapBackBlock()` | `0` | No swapback executed yet (set when swapping begins) |
| `launchTaxEnabled()` | `false` | Launch tax currently disabled |
| `launchTaxStart()` | `0` | Not set until `enableTrading()` is called |
| `lpPair()` | `0x7E7bfDC47c3461213d0eD442e6598F5a50d99B10` | PancakeSwap pair created at deployment |
| `mktAddress()` | `0xD10B27459cAff7566e480E237a0069F5cfC75215` | Receives 60% of swap ETH; controls withdrawals/rescues |
| `name()` | `Baby Ansem` | Contract name identifier |
| `owner()` | `0xD10B27459cAff7566e480E237a0069F5cfC75215` | Address with admin privileges |
| `sellTax()` | `300` | 3% sell tax in basis points |
| `swapEnabled()` | `true` | Fee-to-ETH swapping is enabled |
| `swapTokensAtAmt()` | `210000000000000000000` | Swap threshold (0.05% of total supply) |
| `symbol()` | `BabyAnsem` | Token symbol identifier |
| `totalSupply()` | `420000000000000000000000` | Total tokens minted (fixed supply) |
| `tradingAllowed()` | `false` | Trading gate not yet opened |

### Findings Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 3 | Whitelist bypass of trading/taxes; Arbitrary AMM marking; High launch tax window |
| Low | 2 | Unnecessary router allowance from deployer; Gas-limited payouts may fail silently/centralized recovery |

### Critical Findings

No critical findings identified.

### High Findings

No high-severity findings identified.

### Medium Findings

---

#### 🟡 [M-1] Whitelist Exemption Bypasses `tradingAllowed` And Fees

**Description:**
Transfers apply the trading gate and fees only when both `from` and `to` are not exempt. The owner can exempt any address via `setExemptFromFee()`, which lets that address buy/sell to the AMM pair even when `tradingAllowed` is `false` and with zero fees. This enables privileged early trading and unfair launch conditions.

```solidity
function _transfer(address from, address to, uint256 amount) internal virtual override {
    if (!exemptFromFees[from] && !exemptFromFees[to]) {
        require(tradingAllowed, "Trading not active");
        amount -= handleTax(from, to, amount);
    }
    super._transfer(from, to, amount);
}

function setExemptFromFee(address _address, bool _isExempt) external onlyOwner {
    require(_address != address(0), "Zero Address");
    require(_address != address(this), "Cannot unexempt contract");
    exemptFromFees[_address] = _isExempt;
    emit SetExemptFromFees(_address, _isExempt);
}
```

**Impact:**
- Owner can allow specific wallets (or the AMM pair itself) to trade before public launch and without paying tax.
- Creates asymmetry and potential for insider advantage and market manipulation around launch.

**Location:**
`_transfer()` override; `setExemptFromFee()`.

**💡 Recommendation:**
> **Action Required:** Separate trading gate from fee exemptions.
> 1. Apply `require(tradingAllowed)` irrespective of exemptions, except during initial liquidity operations gated by a dedicated flag.
> 2. Limit exemptions to fee-only behavior, not trading gating.
> - Alternative: Temporarily whitelist only router/pair for initial liquidity, then revoke before launch.

---

#### 🟡 [M-2] Owner Can Mark Arbitrary Addresses As AMM Pairs

**Description:**
The owner can set any address as an AMM pair via `setAMMPair()`. Fee logic treats transfers to marked addresses as “sells” and from them as “buys”. This could be abused to tax transfers to arbitrary EOAs or to change fee behavior unpredictably.

```solidity
mapping(address => bool) public isAMMPair;

function setAMMPair(address _pair, bool _isPair) external onlyOwner {
    require(_pair != address(0), "Zero Address");
    require(_pair != lpPair, "Cannot modify initial pair");
    isAMMPair[_pair] = _isPair;
    emit AMMPairUpdated(_pair, _isPair);
}
```

**Impact:**
- Owner could mark an EOA or centralized wallet as an AMM pair to impose 3% fee on wallet-to-wallet transfers to that address.
- Unclear or shifting fee behavior reduces user predictability and trust.

**Location:**
`setAMMPair()` and fee logic in `handleTax()`.

**💡 Recommendation:**
> **Action Required:** Restrict AMM pair designation.
> 1. Only allow factory-created pairs with `WETH()` (or a configured base asset).
> 2. Consider a one-time freeze after initial setup.

---

#### 🟡 [M-3] Potentially Confiscatory Launch Tax Up To 90%

**Description:**
If `launchTaxEnabled` is set when `enableTrading()` is called, buy/sell taxes start at 90% and linearly decay to 3% over 300 seconds. Users unaware of the launch tax can suffer severe immediate losses.

```solidity
function _launchTax(uint256 elapsed) private pure returns (uint256) {
    uint256 t = 9000 - (8700 * elapsed) / LAUNCH_DURATION; // min 300
    return t < 300 ? 300 : t;
}
```

**Impact:**
- Purchases in early blocks can lose up to 90% to tax.
- Significant economic risk to users; high potential for value transfer to team wallets via `convertTaxes()`.

**Location:**
`handleTax()` and `_launchTax()`.

**💡 Recommendation:**
> **Action Required:** Add protective parameters and transparency.
> 1. Cap launch tax at a safer maximum (e.g., 10–15%) or remove it.
> 2. Emit event on enabling/disabling launch tax and clearly document in UI/announcements.

---

### Low Findings

---

#### 🟢 [L-1] Unnecessary Full-Supply Allowance From Deployer To Router

**Description:**
The constructor grants the router an allowance equal to the entire total supply from the deployer. Uniswap/Pancake routers pull tokens from `msg.sender` so third parties cannot drain deployer funds; however, this is unnecessary and may raise auditor/user concerns.

```solidity
_approve(address(msg.sender), address(dexRouter), totalSupply());
```

**Impact:**
- No direct exploit with standard routers, but poor hygiene and confusing to users/reviewers.

**Location:**
Constructor.

**💡 Recommendation:**
> **Action Required:** Remove or minimize deployer’s router allowance.
> - Approve only the amounts needed for initial liquidity, then reset to zero.

---

#### 🟢 [L-2] Gas-Limited Payouts Can Fail Silently; Centralized Recovery By `mktAddress`

**Description:**
ETH distributions to `devAddress` and `mktAddress` use a 35,000 gas stipend and ignore call success flags. Failures cause ETH to remain in the contract. `withdrawStuckBNB()` permits `mktAddress` to withdraw all ETH at any time, centralizing control of stuck funds.

```solidity
(bool success, ) = devAddress.call{value: devShare, gas: 35000}("");
// ...
(bool success, ) = mktAddress.call{value: remainingBalance, gas: 35000}("");
// ...
function withdrawStuckBNB() external {
    require(msg.sender == mktAddress, "Not MKT");
    uint256 amount = address(this).balance;
    (success, ) = address(mktAddress).call{value: amount}("");
}
```

**Impact:**
- ETH distributions may fail to contracts needing more gas.
- Residual ETH can be swept solely by `mktAddress`, increasing centralization risk.

**Location:**
`convertTaxes()` and `withdrawStuckBNB()`.

**💡 Recommendation:**
> **Action Required:** Improve payout robustness and governance.
> 1. Consider removing custom gas limit or make it configurable.
> 2. Emit events for failed payouts and implement retry logic.
> 3. Move treasury control to a multisig and publish addresses.

---

### Good Practices

- Uses Solidity 0.8.x checked arithmetic and standard `ERC20` logic
- No proxy/upgradeability; immutable `dexRouter`, `WETH`, `lpPair` set at construction
- Taxes are fixed after deployment (3% buy/sell), no admin function to increase beyond launch window
- Swapback uses `lockTheSwap` to avoid recursive swaps and MEV reentry paths
- `rescueTokens()` prevents rescuing the project token itself
- `setAMMPair()` cannot modify the initial `lpPair`

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard | Lower technical risk (no upgrades) |
| Upgrade Control | None (no proxy) | Low |
| Ownership Status | Active (not renounced) | High (centralized control) |
| Owner Address | `0xD10B...5215` | Current admin |
| Total Supply | 420,000,000,000,000 (9 decimals) | Fixed supply |
| Buy Tax | 3% (optional launch up to 90%) | Medium-High (launch risk) |
| Sell Tax | 3% (optional launch up to 90%) | Medium-High (launch risk) |
| Max Transaction | None | Low |

Details:
- Fees are collected to the contract and swapped to `WETH` (WBNB), then distributed: 40% to `devAddress`, 60% to `mktAddress`. These are initially the same as the `owner()` and can be updated by `onlyOwner`. This concentrates economic power over fee revenue and any accidentally sent ETH.
- Optional launch tax can be as high as 90% for the first 5 minutes after `enableTrading()`. This should be clearly disclosed; users buying in that window risk substantial losses.
- Whitelisting lets selected addresses bypass fees and trading gating. This can facilitate adding liquidity before launch but also enables privileged early trading if misused.
- No blacklist, no max wallet, no max tx; post-launch, user transfers are generally unrestricted aside from taxes.

Balanced assessment:
- The absence of proxies reduces upgrade risk. However, centralization remains due to single-owner permissions and treasury controls. Launch tax and whitelisting can materially affect fairness and user outcomes. Moving treasury addresses to a multisig and constraining admin powers would reduce risk.

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
