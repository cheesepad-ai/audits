# 🔍 Baby Asteroid (BabyAsteroid) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-04-28T13:47:54.446Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0x3a1ce7f765ab55b2b971fd1b03df40533a1729cf` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | Baby Asteroid |
| **Symbol** | BabyAsteroid |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Tue, 28 Apr 2026 13:47:54 GMT

### Summary

This is a tax-enabled `ERC20` token (`BabyAsteroid`) on BSC with fixed buy/sell marketing fees (3% each), swap-back to BNB via PancakeSwap V2, and owner-controlled fee exemptions and treasury recipient addresses. Trading is gated by `tradingAllowed` until the owner enables it. No mint/burn after deployment and no upgradeability. Overall, code follows a typical tax token pattern with some centralization controls and minor reentrancy hardening gaps. Overall Risk: MEDIUM - Centralized treasury controls and external calls during transfers without a reentrancy guard

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 3% (marketing) | ✅ Low |
| Sell Tax | 3% (marketing) | ✅ Low |
| Max Transaction | None | ✅ Reasonable |
| Contract Type | Standard (non-upgradeable) | Info |
| Ownership | Active (owner set) | ⚠️ Centralized |
| Pause Function | Pre-launch gate only (`tradingAllowed`) | ✅ No post-launch pause |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | External calls in `convertTaxes()` during `transfer()` without reentrancy guard; MEV on swap-back |
| Centralization | Medium | Owner can change treasury addresses and fee exemptions; marketing can drain contract ETH/tokens |
| Code Quality | Low | Clean, OZ-like; fixed taxes; minimal complexity |
| Exploit Likelihood | Low | No known critical bugs; potential reentrancy constrained |
| **Overall Risk Score** | **92/100** | 0 critical, 0 high, 2 medium, 2 low |

## On-Chain Function Results

The following functions were called on-chain at block 95180931. The table below shows the results:

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Common burn address for locking tokens |
| `FEE_DIVISOR()` | `10000` | Tax denominator; 100 = 1%, 300 = 3% |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | WBNB token on BSC used for pairing |
| `buyTax()` | `300` | 3% buy marketing fee (sent to contract) |
| `decimals()` | `9` | Token uses 9 decimal places |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router |
| `donationAddress()` | `0xB6d4DdE1A08DB00803ED683d45e5691E75643547` | Receives 1/3 of swap-back BNB |
| `lastSwapBackBlock()` | `0` | No swap-back has happened yet |
| `listingAddress()` | `0xB6d4DdE1A08DB00803ED683d45e5691E75643547` | Receives 1/3 of swap-back BNB |
| `lpPair()` | `0x9551bDd4269362Dac1b536af431250eF8fc945E8` | Main AMM pair with WBNB |
| `marketingAddress()` | `0xB6d4DdE1A08DB00803ED683d45e5691E75643547` | Receives remaining BNB; can withdraw/rescue |
| `name()` | `Baby Asteroid` | Contract name identifier |
| `owner()` | `0xB6d4DdE1A08DB00803ED683d45e5691E75643547` | Admin with onlyOwner privileges |
| `sellTax()` | `300` | 3% sell marketing fee (sent to contract) |
| `swapTokensAtAmt()` | `210000000000000000000` | Swap threshold (0.05% of total supply) |
| `symbol()` | `BabyAsteroid` | Token ticker symbol |
| `totalSupply()` | `420000000000000000000000` | Total tokens minted at deploy |
| `tradingAllowed()` | `false` | Trading gate not enabled yet |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 2 | External calls during transfer without reentrancy guard; Centralized treasury withdrawals by marketing address |
| Low | 2 | Pre-launch trading gate and exemptions; Tax bypass on non-registered AMM pairs |
| Informational | 0 | — |

### Critical Findings

None.

### High Findings

None.

### Medium Findings

---

#### 🟡 [M-1] External Calls During Transfers Without Reentrancy Guard

**Description:**
`convertTaxes()` is invoked from `handleTax()` inside the token `transfer()` flow. It performs multiple external calls to the DEX router (`swapExactTokensForETHSupportingFeeOnTransferTokens`) and then forwards BNB to `donationAddress`, `listingAddress`, and `marketingAddress` via low-level `call`. There is no reentrancy guard (`inSwap`/`nonReentrant`) and `lastSwapBackBlock` is only updated at the end, creating a window where a malicious treasury address (settable by owner) could reenter token logic during swap-back callbacks.

```solidity
function _transfer(address from, address to, uint256 amount) internal virtual override {
    if (!exemptFromFees[from] && !exemptFromFees[to]) {
        require(tradingAllowed, "Trading not active");
        amount -= handleTax(from, to, amount);
    }
    super._transfer(from, to, amount);
}

function handleTax(address from, address to, uint256 amount) internal returns (uint256) {
    if (
        balanceOf(address(this)) >= swapTokensAtAmt &&
        !isAMMPair[from] &&
        lastSwapBackBlock + 1 <= block.number
    ) {
        convertTaxes(); // External calls inside transfer flow
    }
    // ...
}

function convertTaxes() private {
    // ...
    swapTokensForETH(contractBalance); // External router call

    bool success;
    uint256 bnbBalance = address(this).balance;
    uint256 share = bnbBalance / 3;

    if (share > 0) {
        (success, ) = donationAddress.call{value: share, gas: 35000}("");
        (success, ) = listingAddress.call{value: share, gas: 35000}("");
    }
    uint256 remainingBalance = address(this).balance;
    if (remainingBalance > 0) {
        (success, ) = marketingAddress.call{value: remainingBalance, gas: 35000}("");
    }
    lastSwapBackBlock = block.number; // Updated only after external calls
}
```

**Impact:**
- A malicious `marketingAddress`/`listingAddress`/`donationAddress` contract could reenter via fallback and trigger nested transfers during swap-back. While current guards reduce practical harm (e.g., typically zero contract balance post-swap), lack of a reentrancy guard increases risk of unexpected state interactions, griefing, or complex exploitation paths in future changes.
- Potential DoS/griefing if external calls perform complex logic and interact back with the token during sensitive flow.

**Location:**
`handleTax()` and `convertTaxes()`; reentrancy window before `lastSwapBackBlock` is updated.

**💡 Recommendation:**
> **Action Required:**
> 1. Add an `inSwap` boolean guard or `nonReentrant` (ReentrancyGuard) to prevent reentrancy during `convertTaxes()`.
> 2. Set the guard (or `lastSwapBackBlock`) before performing external calls; clear it after completion.
> 3. Consider using `success` checks and accumulating failed payouts for retry to avoid unexpected behaviors.

---

#### 🟡 [M-2] Centralized Control of Tax Proceeds and Asset Rescue

**Description:**
Taxed tokens are swapped to BNB and forwarded to `donationAddress`, `listingAddress`, and `marketingAddress`. Additionally, `withdrawStuckBNB()` and `rescueTokens()` are callable by `marketingAddress` (not `owner`). The owner can set these treasury addresses arbitrarily. Post-renounce, the last-set `marketingAddress` retains unilateral ability to drain the contract’s ETH and any ERC20 sent to it.

```solidity
function withdrawStuckBNB() external {
    require(msg.sender == marketingAddress, "Not marketing");
    (success, ) = address(marketingAddress).call{ value: address(this).balance }("");
}

function rescueTokens(address _token) external {
    require(msg.sender == marketingAddress, "Not marketing");
    uint256 _contractBalance = IERC20(_token).balanceOf(address(this));
    SafeERC20.safeTransfer(IERC20(_token), address(marketingAddress), _contractBalance);
}

function updateMarketingAddress(address _address) external onlyOwner { marketingAddress = _address; }
function updateListingAddress(address _address) external onlyOwner { listingAddress = _address; }
function updateDonationAddress(address _address) external onlyOwner { donationAddress = _address; }
```

**Impact:**
- Complete trust required in `marketingAddress` for custody of tax revenue and any rescued assets.
- If `owner` renounces without setting a trusted `marketingAddress`, funds can be controlled by the previously set address indefinitely.
- Users must trust off-chain actors for proper distribution; potential for treasury rug.

**Location:**
`withdrawStuckBNB()`, `rescueTokens()`, update functions for treasury addresses.

**💡 Recommendation:**
> **Action Required:**
> 1. Use a multisig (3+ signers) for `marketingAddress` and other treasury addresses.
> 2. Optionally gate withdrawals/rescues via `onlyOwner` or dual control (owner + marketing).
> 3. Emit explicit events for withdrawals/rescues and consider timelocks to enhance transparency.

---

### Low Findings

---

#### 🟢 [L-1] Pre-Launch Trading Gate and Fee Exemptions Can Prefer Whitelisted Traders

**Description:**
Transfers require `tradingAllowed == true` unless either side is exempt. Owner can call `setExemptFromFee()` to whitelist addresses pre-launch.

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

**Impact:**
Early trading access for selected addresses can create fairness concerns (pre-launch sniping). Not a direct security bug but a trust consideration.

**Location:**
`_transfer()` gate and `setExemptFromFee()`.

**💡 Recommendation:**
> **Action Required:**
> - Disclose whitelist policy; consider time-locked enablement or public announcement before enabling trading.

---

#### 🟢 [L-2] Taxes Apply Only to Registered AMM Pair; Other Pools Untaxed

**Description:**
Buy/sell tax logic relies on `isAMMPair` mapping. Only `lpPair` is set in the constructor; no function exists to add more AMM pairs.

```solidity
if (isAMMPair[to]) { taxes = sellTax; }
else if (isAMMPair[from]) { taxes = buyTax; }
```

**Impact:**
Trades through unregistered pools (e.g., user-created pairs or aggregators) will not be taxed, reducing expected treasury income and allowing tax circumvention.

**Location:**
`handleTax()` buy/sell detection.

**💡 Recommendation:**
> **Action Required:**
> - Add `onlyOwner` functions to manage `isAMMPair` mapping (add/remove pairs) or document that only the primary pair is taxed.

---

### Good Practices

- Uses Solidity 0.8.26 built-in overflow checks; `unchecked` used safely with prior bounds.
- `ERC20` and libraries closely mirror OpenZeppelin patterns; no suspicious modifications detected.
- Fixed buy/sell taxes (3%) cannot be altered post-deploy, limiting abuse.
- Swap threshold clamped between 0.001% and 0.5% supply to avoid extreme values.
- Success of treasury payouts not required, preventing swap-back hard reverts if receivers fail.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard (non-upgradeable) | Low |
| Upgrade Control | None | Low |
| Ownership Status | Active | Medium (centralized control) |
| Owner Address | 0xB6d4...3547 | Admin of settings and exemptions |
| Total Supply | 420,000,000,000,000 × 10^9 = 4.2e23 | Low (fixed) |
| Buy Tax | 3% (marketing) | Low |
| Sell Tax | 3% (marketing) | Low |
| Max Transaction | None | Low |

- Fees: 3% on buys and sells; proceeds converted to BNB and split 1/3 to `donationAddress`, 1/3 to `listingAddress`, remainder to `marketingAddress`. Owner cannot change tax rates post-deploy, reducing common tax-abuse risk.
- Treasury custody: High trust required in `marketingAddress` (and related treasury addresses) which can be updated by `owner` at any time. `marketingAddress` can extract all BNB and any ERC20 from the contract via `withdrawStuckBNB()`/`rescueTokens()`.
- Trading gate: `tradingAllowed` must be enabled by owner; prior to that, only exempt addresses can trade.
- AMM pairs: Only the constructor-created WBNB pair is taxed; other pools can bypass tax.

Ownership Renunciation Consideration:
- If `owner()` is set to `address(0)`, there is no function to restore ownership (no hidden backdoor detected). However, the last-set treasury addresses retain control over tax proceeds and rescues. This is not fake renunciation but remains a centralization of treasury funds.

Modified Library Code Review (OpenZeppelin):
- `Context`, `ERC20`, `Ownable`-like pattern, `Address`, and `SafeERC20` appear consistent with OpenZeppelin v4.x semantics. No hidden admins, no altered arithmetic, and no suspicious inline assembly beyond standard OZ `_revert` bubbling. No malicious modifications detected.

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
