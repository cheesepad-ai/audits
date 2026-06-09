# 🔍 Space Exploration Technologies Corp. (SPCX) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-06-09T13:28:40.299Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xda3bea9e5612f38d7a09d5ba4e70b303ccc75714` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | Space Exploration Technologies Corp. |
| **Symbol** | SPCX |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Tue, 09 Jun 2026 13:28:40 GMT

### Summary

This contract set implements an `ERC20` tax token (`SPACEX`) with an external `DividendDistributor` that swaps BNB to a reward token and distributes it to holders. Key features: owner-controlled fees (up to 10%), optional auto-liquidity, wallet/tx limits, and a persistent `recoveryManager` role with rescue powers. Centralization is significant: liquidity is sent to an owner-controlled EOA and a hidden privileged role can drain dividends even after ownership renounce. Overall Risk: HIGH - Single EOA controls launch, fees, liquidity, and a non-renounceable rescue role can siphon funds.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 3% (configurable, max 10%) | ⚠️ High (owner-controlled) |
| Sell Tax | 3% (configurable, max 10%) | ⚠️ High (owner-controlled) |
| Max Transaction | Configurable (>=0.1%); currently 100% but limits off | ⚠️ Restrictive potential |
| Contract Type | Standard | Info |
| Ownership | Active owner + persistent recoveryManager | ⚠️ Centralized (backdoor risk) |
| Pause Function | Trading gate via `openTrade()` | ⚠️ Can halt trading |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | DoS via marketing wallet; MEV slippage; dividend rescue power |
| Centralization | High | Owner controls fees/limits/launch; EOA receives LP; recoveryManager persists |
| Code Quality | Medium | Clear structure; custom `Ownable`; some minor design issues |
| Exploit Likelihood | Medium | Admin actions can impact users; market conditions affect swaps |
| **Overall Risk Score** | **63/100** | Owner/RecoveryManager powers and liquidity control dominate risk |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD()` | `0x000000000000000000000000000000000000dEaD` | Burn address for irrecoverable token burns and LP locking |
| `ROUTER_ADDRESS()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap v2 router used for swaps and liquidity |
| `ZERO()` | `0x0000000000000000000000000000000000000000` | Null address; also indicates renounced ownership |
| `decimals()` | `9` | Token uses 9 decimal places |
| `distributorGas()` | `300000` | Gas cap per dividend processing call |
| `dividendDistributor()` | `0x2f500AD2326596a5c5b085eF19Ef72f6cBDeBB25` | Address of dividend distribution contract |
| `limitsEnabled()` | `false` | Max tx/wallet limits currently disabled |
| `liquidityFee()` | `0` | No liquidity fee currently applied |
| `liquidityReceiver()` | `0xe05CD78386bDe38FA9AEE91a8B49Ea7C1c0eBc1D` | Address receiving LP tokens on auto-liquidity |
| `marketingFee()` | `3` | 3% of taxed amount allocated to marketing |
| `marketingWallet()` | `0xe05CD78386bDe38FA9AEE91a8B49Ea7C1c0eBc1D` | Recipient of marketing BNB |
| `maxTxAmount()` | `1000000000000000000` | Max per tx set to 100% supply (limits off) |
| `maxWalletAmount()` | `1000000000000000000` | Max wallet set to 100% supply (limits off) |
| `name()` | `Space Exploration Technologies Corp.` | Token name |
| `owner()` | `0x1a058AE6B2Cfc212617c5F3bAD1e22980728fb5c` | Admin with onlyOwner privileges |
| `pair()` | `0x70950d09F3CCbDC7BFA8c207b48Bd76a0b1423f5` | PancakeSwap WBNB pair address |
| `recoveryManager()` | `0x1a058AE6B2Cfc212617c5F3bAD1e22980728fb5c` | Privileged role for rescue and distributor control |
| `rewardFee()` | `0` | Rewards fee currently disabled |
| `rewardToken()` | `0x872109274218cB50F310E2bFb160D135B502A9d5` | Reward token used for dividends |
| `router()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | Router in use (Pancake v2) |
| `swapEnabled()` | `true` | SwapBack mechanism enabled |
| `swapThreshold()` | `1000000000000000` | SwapBack threshold (0.1% of supply) |
| `symbol()` | `SPCX` | Token symbol |
| `totalBuyFee()` | `3` | Current total buy fee percent |
| `totalSellFee()` | `3` | Current total sell fee percent |
| `totalSupply()` | `1000000000000000000` | 1e9 tokens with 9 decimals (1e18 base units) |
| `tradingOpen()` | `false` | Trading restricted to fee-exempt addresses |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|-----------|
| Critical | 2 | Hidden privileged `recoveryManager` persists after renounce; Dividend drain via `rescueRewardToken()` |
| High | 2 | LP tokens sent to EOA (liquidity rug risk); DoS by setting reverting `marketingWallet` |
| Medium | 2 | Zero-min-out swaps (MEV/slippage risk); Trading can be kept closed by owner |
| Low | 1 | Stale `shareholderIndexes` mapping entries on removal |

### Critical Findings

---

#### 🔴 [C-1] Hidden Privileged Role (`recoveryManager`) Persists After Renounce — Fake Renounced Ownership Risk

**Description:**
The token introduces a second privileged role, `recoveryManager` (immutable, set to deployer), with powerful capabilities that remain even if `owner` renounces. This undermines the perception of decentralization after renounce and enables privileged fund movements and control of dividend flows.

```solidity
// SPACEX.sol (constructor)
recoveryManager = msg.sender;

// SPACEX.sol
modifier onlyRecoveryManager() {
    require(msg.sender == recoveryManager, "Not recovery manager");
    _;
}

function rescueBNB(address to, uint256 amount) external onlyRecoveryManager { ... }
function rescueToken(address tokenAddress, address to, uint256 amount) external onlyRecoveryManager { ... }

// DividendDistributor.sol (constructor)
recoveryManager = recoveryManager_;

// DividendDistributor.sol
modifier onlyRecoveryManager() {
    require(msg.sender == recoveryManager, "Not recovery manager");
    _;
}
function process(uint256 gas) external override onlyTokenOrRecoveryManager { ... }
function rescueRewardToken(address to, uint256 amount) external override onlyRecoveryManager { ... }
```

Even if `owner` is set to `address(0)`, the `recoveryManager` retains authority to withdraw assets and control the distributor.

**Impact:**
- Users may believe ownership is renounced while a hidden admin retains material control.
- `recoveryManager` can withdraw BNB and ERC20s from the token contract and divert/dividend funds (see C-2).
- Constitutes a deceptive "fake renounce" pattern.

**Location:**
`SPACEX` constructor and `onlyRecoveryManager`-gated functions; `DividendDistributor` constructor and recovery functions.

**💡 Recommendation:**
> **Action Required:**
> 1. Remove or severely limit `recoveryManager` powers post-deployment; or
> 2. Add an `owner`-only, one-time function to permanently disable all `onlyRecoveryManager` functions before renounce; or
> 3. If retention is necessary, transparently disclose and multi-sig control `recoveryManager`.

---

#### 🔴 [C-2] Dividend Drain Backdoor — `recoveryManager` Can Withdraw All Reward Tokens

**Description:**
The `DividendDistributor` allows the `recoveryManager` to withdraw any amount of the reward token, effectively draining pending dividends intended for holders.

```solidity
// DividendDistributor.sol
function rescueRewardToken(address to, uint256 amount) external override onlyRecoveryManager {
    require(to != address(0), "Zero address");
    rewardToken.transfer(to, amount);
}
```

There are no caps, time-locks, or safeguards.

**Impact:**
- All accumulated dividend rewards can be siphoned to an arbitrary address.
- Holders may never receive promised rewards despite ongoing taxation.

**Location:**
`DividendDistributor.rescueRewardToken()`.

**💡 Recommendation:**
> **Action Required:**
> 1. Remove `rescueRewardToken()` or restrict to genuine recoveries with strict caps and timelocks;
> 2. Transfer control to a well-audited multisig with public transparency;
> 3. Emit detailed events and enforce a grace period before execution.

---

### High Findings

---

#### 🟠 [H-1] LP Tokens Are Sent to Owner-Controlled EOA — Liquidity Rug Risk

**Description:**
Auto-liquidity mints LP tokens to `liquidityReceiver`, which is an EOA and owner-controlled. This enables the owner to remove liquidity at any time.

```solidity
// SPACEX.sol
address public liquidityReceiver;

router.addLiquidityETH{value: bnbForLiquidity}(
    address(this),
    tokensForLiquidity,
    0,
    0,
    liquidityReceiver,   // EOA receives LP tokens
    block.timestamp
);
```

On-chain, `liquidityReceiver()` equals `marketingWallet()` EOA `0xe05C...c1D`.

**Impact:**
- Liquidity can be removed (rug), causing severe price impact and user loss.
- No locking/time-lock mechanism is implemented.

**Location:**
`SPACEX._swapBack()` liquidity addition path.

**💡 Recommendation:**
> **Action Required:**
> - Send LP tokens to a time-locked contract or burn address (`0x...dead`);
> - Alternatively, lock LP in a reputable locker with adequate lock duration;
> - Disclose liquidity management policy publicly.

---

#### 🟠 [H-2] DoS via Reverting `marketingWallet` — Sells/Transfers Can Be Bricked

**Description:**
During SwapBack, the contract forwards BNB to `marketingWallet` via a low-level call and requires success. If `marketingWallet` is set to a contract that reverts on receive, the entire user transfer that triggered SwapBack will revert, effectively bricking sells when threshold is met.

```solidity
// SPACEX.sol
(bool success, ) = payable(marketingWallet).call{value: bnbForMarketing}("");
require(success, "Marketing transfer failed");
```

Condition to enter `_swapBack` typically triggers during sells or certain transfers once `swapThreshold` is reached.

**Impact:**
- Owner can intentionally or accidentally halt sells/transfers that trigger SwapBack.
- Creates intermittent honeypot-like behavior and severe UX disruption.

**Location:**
`SPACEX._swapBack()` marketing transfer.

**💡 Recommendation:**
> **Action Required:**
> 1. Use a pull pattern or non-reverting send with accounting of failed payouts;
> 2. Allow disabling marketing payout if transfer fails (don’t revert user tx);
> 3. Enforce `marketingWallet` to be an EOA or add a whitelisted safe receiver interface.

---

### Medium Findings

---

#### 🟡 [M-1] Zero-Min-Out Swaps Enable MEV/Slippage Losses Reducing Rewards/Liquidity

**Description:**
Both token->BNB and BNB->reward swaps use `amountOutMin = 0`, exposing swaps to sandwich attacks and severe slippage, reducing funds available for rewards, marketing, and liquidity.

```solidity
// SPACEX.sol
router.swapExactTokensForETHSupportingFeeOnTransferTokens(
    tokensToSwap,
    0,              // amountOutMin = 0
    path,
    address(this),
    block.timestamp
);

// DividendDistributor.sol
router.swapExactETHForTokensSupportingFeeOnTransferTokens{
    value: msg.value
}(
    0,              // amountOutMin = 0
    path,
    address(this),
    block.timestamp
);
```

**Impact:**
- Worse execution prices; lower dividends and liquidity support; potential MEV extraction.

**Location:**
`SPACEX._swapBack()` and `DividendDistributor.deposit()`.

**💡 Recommendation:**
> **Action Required:**
> - Introduce configurable `slippageBps` and compute `amountOutMin` from on-chain quotes with safety margins;
> - Optionally add TWAP checks.

---

#### 🟡 [M-2] Owner Can Keep Trading Closed Indefinitely

**Description:**
Transfers are blocked for non-exempt users until `openTrade()` is called; there is no timelock or auto-enable. On-chain `tradingOpen()` is currently `false`.

```solidity
// SPACEX._transfer()
if (!tradingOpen) {
    require(isFeeExempt[sender] || isFeeExempt[recipient], "Trading not open");
}

function openTrade() external onlyOwner {
    tradingOpen = true;
    emit TradingOpened();
}
```

**Impact:**
- Launch timing and trading availability fully centralized; investor lockout risk.

**Location:**
`SPACEX._transfer()` and `openTrade()`.

**💡 Recommendation:**
> **Action Required:**
> - Use a time-based activation or governance process;
> - Publicly disclose exact launch plan and safeguards.

---

### Low Findings

---

#### 🟢 [L-1] Stale `shareholderIndexes` Mapping Entry on Removal

**Description:**
When removing a shareholder, the index mapping for the removed address is not cleared. It’s benign but can confuse off-chain indexers.

```solidity
// DividendDistributor.sol
function _removeShareholder(address shareholder) internal {
    uint256 index = shareholderIndexes[shareholder];
    address lastShareholder = shareholders[shareholders.length - 1];

    shareholders[index] = lastShareholder;
    shareholderIndexes[lastShareholder] = index;
    shareholders.pop();
    // shareholderIndexes[shareholder] not cleared
}
```

**Impact:**
- Minor state inconsistency; potential off-chain confusion.

**Location:**
`DividendDistributor._removeShareholder()`.

**💡 Recommendation:**
> **Action Required:**
> - Set `shareholderIndexes[shareholder] = 0;` and handle zero-index carefully or use a sentinel boolean to indicate presence.

---

### Good Practices

- Uses Solidity ^0.8.20 overflow/underflow checks by default.
- State updates before external calls in `DividendDistributor._distributeDividend()` reduce reentrancy risk.
- `inSwap` flag prevents swap recursion.
- `rescueToken` prevents rescuing the token itself.
- Fee caps enforced (<=10% total); `liquidityFee` even-enforced for split math.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard | Low (no proxy) |
| Upgrade Control | None (no proxy) | Low |
| Ownership Status | Active | High (single EOA) |
| Owner Address | 0x1a058AE6B2Cfc212617c5F3bAD1e22980728fb5c | Centralized |
| RecoveryManager | Same EOA as owner | Critical (backdoor, non-renounceable) |
| Total Supply | 1,000,000,000 SPCX (9 decimals) | Info |
| Buy Tax | 3% (configurable up to 10%) | Medium |
| Sell Tax | 3% (configurable up to 10%) | Medium |
| Max Transaction | Configurable (>=0.1%); currently 100% | Medium (limits off now) |

Detailed analysis:
- Fees: Owner can set `rewardFee`, `marketingFee`, `liquidityFee` with total cap 10%. Currently 3% marketing only. Fee changes affect user execution prices and distribution.
- SwapBack: Converts taxed tokens to BNB and splits among rewards/marketing/liquidity. Zero min-out swaps expose users to MEV and slippage.
- Dividends: Collected BNB is swapped to `rewardToken` and distributed pro-rata. However, `recoveryManager` can withdraw the reward token at any time, undermining holder value.
- Liquidity: LP tokens are minted to `liquidityReceiver` (EOA), allowing immediate liquidity removal (rug risk) unless externally locked/burned.
- Limits: `limitsEnabled` currently false; owner can re-enable with configurable `maxTxAmount` and `maxWalletAmount` (minimum 0.1% each), potentially constraining trading.

Balanced Assessment: While upgradeability risks are absent (no proxy), centralized control remains high. A single EOA can change fees, manage limits, control launch, redirect marketing, and withdraw funds via `recoveryManager`. Users must trust the operator or require proof of LP locking and a multisig/timelock for admin roles.

**IMPORTANT — Ownership Renunciation:**
- If `owner` is set to `address(0)`, this contract would still retain a powerful `recoveryManager` able to withdraw funds and influence dividends. This constitutes a "fake renounced" pattern and is flagged as CRITICAL unless `recoveryManager` is neutralized via immutable burn/multisig governance and public disclosures.

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
