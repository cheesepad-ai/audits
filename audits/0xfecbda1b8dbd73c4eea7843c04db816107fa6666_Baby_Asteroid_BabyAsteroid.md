# 🔍 Baby Asteroid (BabyAsteroid) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-04-28T13:44:40.748Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xfecbda1b8dbd73c4eea7843c04db816107fa6666` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | Baby Asteroid |
| **Symbol** | BabyAsteroid |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Tue, 28 Apr 2026 13:44:40 GMT

### Summary

`BabyAsteroid` is a custom `ERC20` token (9 decimals) with fixed buy/sell marketing taxes (3% each) and an automated swap-back that converts collected tokens to BNB and distributes to `donationAddress`, `listingAddress`, and `marketingAddress`. Trading is gated by an owner-controlled switch (`tradingAllowed`), and a separate `marketingAddress` can withdraw BNB and rescue arbitrary tokens from the contract. No proxy or upgrade pattern is present; no hidden ownership backdoors detected. Overall Risk: MEDIUM – Fixed tax and no upgradeability reduce risk, but centralized controls (trading switch/treasury) and launch-phase operational risks remain.

### Risk Assessment

Token Quick Facts:

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 3% (marketing) | ✅ Low |
| Sell Tax | 3% (marketing) | ✅ Low |
| Max Transaction | None | ✅ No hard limits |
| Contract Type | Standard (non-upgradeable) | Info |
| Ownership | Active (owner and marketing controller) | ⚠️ Centralized |
| Pause Function | Trading gate via `tradingAllowed` | ⚠️ Can halt trading |

Security Assessment:

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Low | No reentrancy/overflow issues detected; fixed taxes |
| Centralization | High | Owner controls trading; `marketingAddress` controls treasury/rescue |
| Code Quality | Medium | Generally clean; some unchecked low-level calls; missing events |
| Exploit Likelihood | Medium | MEV around swap-back; tax bypass via untracked pairs |
| **Overall Risk Score** | **71/100** | 0 critical, 2 high, 2 medium, 3 low |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn address for irretrievable token sends |
| `FEE_DIVISOR()` | `10000` | Tax basis points divisor (1% = 100) |
| `WETH()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | WBNB address used for pairing/swaps |
| `buyTax()` | `300` | 3% buy tax allocated to marketing |
| `decimals()` | `9` | Token uses 9 decimal places |
| `dexRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router on BSC |
| `donationAddress()` | `0x6c4928Ec8F480045B2a37e1Ec0A76104e52a8FA4` | Receives 1/3 of swap-back BNB |
| `lastSwapBackBlock()` | `0` | No swap-back executed yet |
| `listingAddress()` | `0x6c4928Ec8F480045B2a37e1Ec0A76104e52a8FA4` | Receives 1/3 of swap-back BNB |
| `lpPair()` | `0x3B8e2AB4E9AD9e2Cec109432cF38cB17eB11f7C7` | Primary AMM pair with WBNB |
| `marketingAddress()` | `0x6c4928Ec8F480045B2a37e1Ec0A76104e52a8FA4` | Receives remaining BNB; treasury controller |
| `name()` | `Baby Asteroid` | Contract name identifier |
| `owner()` | `0xB6d4DdE1A08DB00803ED683d45e5691E75643547` | Address with `onlyOwner` admin rights |
| `sellTax()` | `300` | 3% sell tax allocated to marketing |
| `swapTokensAtAmt()` | `210000000000000000000` | Swap-back threshold (~0.05% of supply) |
| `symbol()` | `BabyAsteroid` | Token ticker |
| `totalSupply()` | `420000000000000000000000` | Total tokens ever minted |
| `tradingAllowed()` | `false` | Trading currently disabled for non-exempt |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 0 | — |
| High | 2 | Centralized trading gate freeze risk; Single-EOA treasury/rescue control |
| Medium | 2 | Tax bypass via untracked AMM pairs; MEV/price impact from swap-backs |
| Low | 3 | Unchecked low-level ETH transfers; Missing admin-change events; Unnecessary max approval to router |

### Critical Findings

None.

### High Findings

---

#### 🟠 [H-1] Centralized Trading Gate Can Permanently Freeze Transfers If Misused

**Description:**
Transfers for non-exempt addresses are blocked until `tradingAllowed` is set to `true` by `onlyOwner`. If the owner renounces or loses the key before enabling trading, non-exempt holders can be permanently frozen.

```solidity
function _transfer(address from, address to, uint256 amount) internal virtual override {
    if (!exemptFromFees[from] && !exemptFromFees[to]) {
        require(tradingAllowed, "Trading not active");
        amount -= handleTax(from, to, amount);
    }
    super._transfer(from, to, amount);
}

function enableTrading() external onlyOwner {
    require(!tradingAllowed, "Trading already enabled");
    tradingAllowed = true;
    lastSwapBackBlock = block.number;
}
```

**Impact:**
- Owner can halt all non-exempt transfers until enabling trading.
- If owner renounces or is compromised before enabling, tokens can be locked indefinitely (no recovery path).

**Location:**
`_transfer()` gate and `enableTrading()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Enable trading before any public distribution and before any ownership renunciation.
> 2. Consider adding a one-way auto-unlock at a specific block/timestamp or a community multisig-controlled `enableTrading()`.
> 3. Emit an event with timestamp/block when enabling, for transparency.

---

#### 🟠 [H-2] Single-EOA Treasury and Token Rescue Control (No Timelock/Multisig)

**Description:**
A separate `marketingAddress` (set by `onlyOwner`) can withdraw all BNB from the contract and rescue arbitrary ERC20 tokens. These operations are not timelocked nor multisig-guarded.

```solidity
function withdrawStuckBNB() external {
    require(msg.sender == marketingAddress, "Not marketing");
    (bool success, ) = address(marketingAddress).call{ value: address(this).balance }("");
}

function rescueTokens(address _token) external {
    require(msg.sender == marketingAddress, "Not marketing");
    uint256 _contractBalance = IERC20(_token).balanceOf(address(this));
    SafeERC20.safeTransfer(IERC20(_token), address(marketingAddress), _contractBalance);
}

function updateMarketingAddress(address _address) external onlyOwner {
    marketingAddress = _address;
}
```

**Impact:**
- Complete trust required in a single EOA for treasury management.
- Can extract all swap-back proceeds and any ERC20 tokens held by the contract (including LP tokens sent to the contract).
- Owner can redirect control by changing `marketingAddress`.

**Location:**
`withdrawStuckBNB()`, `rescueTokens()`, `updateMarketingAddress()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Move `marketingAddress` to a 3+ signers multisig.
> 2. Add a 24–48h timelock for treasury/rescue operations.
> 3. Emit events on withdrawals and rescues with amounts and asset addresses.

---

### Medium Findings

---

#### 🟡 [M-1] Tax Bypass via Untracked AMM Pairs

**Description:**
Taxes apply only when `isAMMPair[to]` (sell) or `isAMMPair[from]` (buy) is true. Only the initially created pair is tracked; there is no function to add more AMM pairs.

```solidity
isAMMPair[lpPair] = true;

function handleTax(address from, address to, uint256 amount) internal returns (uint256) {
    Taxes memory taxes;
    if (isAMMPair[to]) {
        taxes = sellTax;     // sells taxed
    } else if (isAMMPair[from]) {
        taxes = buyTax;      // buys taxed
    }
    ...
}
```

**Impact:**
- Anyone can create a secondary liquidity pool where transfers are treated as regular transfers (0% tax), bypassing intended buy/sell taxation and reducing treasury inflows.

**Location:**
`constructor()` sets only `lpPair`; `handleTax()` relies on `isAMMPair`.

**💡 Recommendation:**
> **Action Required:**
> 1. Add `onlyOwner` functions to manage `isAMMPair[address]` and track all official pools.
> 2. Consider taxing any interaction with known router/pair factories if design intends universal taxation.

---

#### 🟡 [M-2] MEV/Sandwich and Price Impact Risks from Automatic Swap-Back During User Trades

**Description:**
`convertTaxes()` swaps tokens for BNB when thresholds are met, and it is triggered inside `handleTax()` during user transfers (notably on sells). This may increase gas and introduce front-running/sandwich risk.

```solidity
if (balanceOf(address(this)) >= swapTokensAtAmt && !isAMMPair[from] && lastSwapBackBlock + 1 <= block.number) {
    convertTaxes(); // calls router.swapExactTokensForETHSupportingFeeOnTransferTokens
}
```

**Impact:**
- MEV bots can detect impending contract sell-pressure and sandwich the user, worsening execution price.
- Users may experience higher-than-expected slippage during swap-back blocks.

**Location:**
`handleTax()` and `convertTaxes()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Limit swap-back size further (e.g., percent-of-liquidity) and randomize triggers.
> 2. Consider offloading swap-backs to separate maintenance calls (not inside user transfers).
> 3. Emit clear events on swap-backs for transparency.

---

### Low Findings

---

#### 🟢 [L-1] Unchecked Low-Level ETH Transfers May Skip Intended Beneficiaries

**Description:**
ETH distributions use low-level `.call` with fixed gas and ignore failures. If `donationAddress` or `listingAddress` reverts or requires more gas, they receive nothing, and the remainder goes to `marketingAddress`.

```solidity
(bool success, ) = donationAddress.call{value: share, gas: 35000}("");
(bool success, ) = listingAddress.call{value: share, gas: 35000}("");
// remainder to marketing regardless of above results
(success, ) = marketingAddress.call{ value: remainingBalance, gas: 35000 }("");
```

**Impact:**
- Non-deterministic allocation: failed recipients silently receive nothing.
- Funds may be unintentionally redirected to `marketingAddress`.

**Location:**
`convertTaxes()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Require success or accumulate unpaid shares for retry.
> 2. Increase/remove gas stipend if recipients are contracts.
> 3. Emit events on failed payouts for accountability.

---

#### 🟢 [L-2] Missing Events for Admin Updates

**Description:**
Critical admin updates do not emit events, reducing transparency and off-chain monitoring.

```solidity
function updateMarketingAddress(address _address) external onlyOwner { ... }
function updateListingAddress(address _address) external onlyOwner { ... }
function updateDonationAddress(address _address) external onlyOwner { ... }
```

**Impact:**
- Harder for users/tools to track changes in payout addresses.

**Location:**
Admin address update functions.

**💡 Recommendation:**
> **Action Required:**
> 1. Emit events for all admin updates:
>    - `MarketingAddressUpdated`, `ListingAddressUpdated`, `DonationAddressUpdated`.

---

#### 🟢 [L-3] Unnecessary Max Approval From Deployer to Router

**Description:**
The constructor grants the router a full allowance over the deployer’s tokens. While routers can’t arbitrarily pull from non-callers, this approval is unnecessary and expands attack surface if the deployer key is compromised.

```solidity
_approve(address(msg.sender), address(dexRouter), totalSupply());
```

**Impact:**
- Slightly increases risk if deployer account is later compromised.

**Location:**
`constructor()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Remove deployer-to-router approval from the constructor.
> 2. Let users grant allowances only when they intend to interact with the router.

---

### Good Practices

- Uses solidity 0.8.26 with built-in overflow/underflow checks; `unchecked` blocks are safe and justified.
- No upgradeability/proxy pattern; immutable `dexRouter`, `WETH`, `lpPair`.
- Fixed buy/sell tax percentages with no owner function to increase taxes post-deploy.
- `exemptFromFees[address(this)] = true` and guard prevents unexempting the contract, avoiding recursive taxation on swap-back.
- Swap-back capped per call (`<= 4 * swapTokensAtAmt`) and throttled to avoid multiple same-block swaps.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard (non-upgradeable) | Low upgrade risk |
| Upgrade Control | None (no proxy) | Low |
| Ownership Status | Active (owner can enable trading, set fee exemptions, update payout addrs) | High centralization |
| Owner Address | 0xB6d4DdE1A08DB00803ED683d45e5691E75643547 | Current owner |
| Total Supply | 420000000000000000000000 (9 decimals → 420T units) | Info |
| Buy Tax | 3% (marketing) | Low |
| Sell Tax | 3% (marketing) | Low |
| Max Transaction | None | Low |

Detailed:
- Taxes: 3% on buys and sells only when interacting with the tracked `lpPair`. Wallet-to-wallet transfers are 0% (no fees). No functions to raise taxes exist, reducing rug risk via tax hikes.
- Swap-back: Accrued tokens swap to BNB at ~0.05% of supply threshold (`swapTokensAtAmt`) and distribute 1/3 to `donationAddress`, 1/3 to `listingAddress`, remainder to `marketingAddress`. If donations/listing calls fail, remaining BNB goes to `marketingAddress`, concentrating funds.
- Centralization: `owner` can gate trading and set fee exemptions; `marketingAddress` can extract treasury/any ERC20 from the contract. No timelock/multisig controls. Users must trust these roles.

Modified Libraries Review (Tampering Check):
- `ERC20`: OZ-like with `decimals()` fixed at 9; no mint/burn exposed to public; arithmetic patterns align with OZ v4.x; no hidden fees/blacklists.
- `Ownable`: Minimal OZ-style; `renounceOwnership()` sets `owner` to `address(0)`; no `previousOwner` or restore function. No fake renounce pattern detected.
- `Address`/`SafeERC20`: Match OZ v4.x patterns (including `verifyCallResultFromTarget`); no malicious assembly or altered math. Missing `safeIncreaseAllowance`/`safeDecreaseAllowance` is non-malicious.

Ownership Renunciation Verification:
- On-chain `owner()` is non-zero (active). If renounced later, no hidden backdoor functions or secondary owner-like roles exist in code. Note that `marketingAddress` still retains treasury/rescue powers even after owner renounces.

Proxy Detection:
- No `delegatecall` or EIP-1967/1822 storage slots. Not upgradeable.

Gas/Code Quality:
- Generally efficient. Consider:
  - Emitting events on admin address updates.
  - Removing unnecessary deployer-to-router approval.
  - Optionally batching/pacing swap-backs to minimize MEV exposure.

Overall, the contract is straightforward with fixed taxes and no mutable fee parameters or upgrade hooks. Primary risks are operational/centralization around trading enablement and treasury control.

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
