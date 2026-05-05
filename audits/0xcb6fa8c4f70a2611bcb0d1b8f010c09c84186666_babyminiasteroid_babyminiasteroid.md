# 🔍 babyminiasteroid   ( babyminiasteroid ) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-05-05T06:18:57.412Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xcb6fa8c4f70a2611bcb0d1b8f010c09c84186666` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | babyminiasteroid   |
| **Symbol** |  babyminiasteroid  |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Tue, 05 May 2026 06:18:57 GMT

### Summary

This is a tax-and-dividends `ERC20` token (`BananaToken`) that routes buy/sell/transfer fees to fund wallet, burns, optional liquidity, and a cloned `BABYTOKENDividendTracker` to distribute rewards in a separate “ETH” reward token. Key owner-controlled settings include fees, blacklists (freezing), max limits, referral fees, and swap/liquidity behavior; LP tokens are sent to the fund wallet. Overall trust and centralization risks are significant due to unilateral owner control over fees, blacklisting, distributions, and LP custody. Overall Risk: HIGH – Owner can freeze accounts, raise fees, capture liquidity, and withdraw funds.

### Risk Assessment

Token Quick Facts:

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 2.9% (fund 0.5%, reward 2.4%, burn 0.1%, liquidity 0%) | ✅ Low |
| Sell Tax | 2.9% (fund 0.5%, reward 2.4%, burn 0.1%, liquidity 0%) | ✅ Low |
| Max Transaction | Effectively None (set to max uint) | ⚠️ Restrictive controls disabled (owner can change) |
| Contract Type | Standard `ERC20` + cloned dividend tracker | Info |
| Ownership | Active (EOA owner); tracker owned by token contract | ⚠️ Centralized |
| Pause Function | No global pause; has blacklist freeze | ⚠️ Can freeze addresses |

Security Assessment:

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | No reentrancy seen; MEV risk on swaps with minOut=0 |
| Centralization | High | Owner can blacklist, change fees, withdraw funds, receive LP |
| Code Quality | Medium | Unreachable code, event param order bug, duplicate libs |
| Exploit Likelihood | Medium | Owner actions can disrupt trading; MEV drains possible |
| **Overall Risk Score** | **65/100** | High centralization (4 High, 4 Medium, 3 Low findings) |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `ETH()` | `0xFEcbdA1b8dbd73C4EeA7843C04DB816107fA6666` | Reward token used for dividend payouts |
| `ReceiveAddress()` | `0x956b4279606AB95fA03EaB4756e4619907927717` | Initial receiver of total supply and approvals |
| `_buyBurnFee()` | `10` | 0.1% burn on buys (basis points, /10000) |
| `_buyFundFee()` | `50` | 0.5% fund fee on buys |
| `_buyLiquidityFee()` | `0` | No liquidity fee on buys |
| `_buyRewardFee()` | `240` | 2.4% reward fee on buys |
| `_inviType()` | `0` | Referral applies on buy and sell when enabled |
| `_inviterFee()` | `0` | Referral fee disabled (sum of levels is zero) |
| `_mainPair()` | `0xfEb5cdd83F863E1f953Ee5DECBAa9F8c00458851` | Primary DEX pair address |
| `_sellBurnFee()` | `10` | 0.1% burn on sells |
| `_sellFundFee()` | `50` | 0.5% fund fee on sells |
| `_sellLiquidityFee()` | `0` | No liquidity fee on sells |
| `_sellRewardFee()` | `240` | 2.4% reward fee on sells |
| `_swapRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 router on BSC |
| `_tokenDistributor()` | `0x277353e61985AC9CCEbd61D71AF206cb15A0E63F` | Helper contract to pull swapped tokens |
| `airdropNumbs()` | `0` | Airdrop spam disabled |
| `bindAmount()` | `0` | No referral handshake trigger on transfers |
| `currency()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | WBNB as base swap currency |
| `currencyIsEth()` | `true` | Treat WBNB-as-ETH for withdrawals to BNB |
| `decimals()` | `18` | Token decimals |
| `dividendTracker()` | `0x0C63EA8e979cC6577f02d613461F4F119169f361` | Dividend tracker clone address |
| `enableOffTrade()` | `false` | Trading not restricted by prelaunch gates |
| `fundAddress()` | `0x956b4279606AB95fA03EaB4756e4619907927717` | Fee/LP receiver wallet |
| `gasForProcessing()` | `300000` | Gas cap for dividend processing |
| `generateLpReceiverAddr()` | `0x956b4279606AB95fA03EaB4756e4619907927717` | Receives LP tokens from liquidity adds |
| `getBuyFee()` | `290` | Total buy fee 2.9% |
| `getClaimWait()` | `3600` | Dividends claim wait: 1 hour |
| `getLastProcessedIndex()` | `0` | Dividend iteration index pointer |
| `getMinimumTokenBalanceForDividends()` | `1000000000000000000` | Min 1 token required for dividends |
| `getNumberOfDividendTokenHolders()` | `2` | Two addresses tracked for dividends |
| `getSellFee()` | `290` | Total sell fee 2.9% |
| `getTotalDividendsDistributed()` | `0` | No dividends distributed yet |
| `kb()` | `0` | Anti-bot block window disabled |
| `lenOfInvitorRewardPercentList()` | `0` | No referral levels configured |
| `maxBuyAmount()` | `115792...` | Max uint: effectively no max buy |
| `maxSellAmount()` | `115792...` | Max uint: effectively no max sell |
| `maxWalletAmount()` | `115792...` | Max uint: effectively no wallet cap |
| `name()` | `babyminiasteroid  ` | Token name |
| `numTokensSellRate()` | `100` | Swap 100% of thresholded balance |
| `owner()` | `0x956b4279606AB95fA03EaB4756e4619907927717` | Privileged admin address |
| `secondTime()` | `0` | Secondary whitelist window disabled |
| `startTradeTime()` | `0` | Launch not toggled via `launch()` |
| `swapAndLiquifyEnabled()` | `true` | Automated swaps/liquidity enabled |
| `swapAtAmount()` | `100000000000000000000000` | Swap threshold amount |
| `symbol()` | ` babyminiasteroid ` | Token symbol |
| `totalFundAmountReceive()` | `0` | Fund wallet receipts tracked (currency) |
| `totalSupply()` | `4200000000000000000000000000000000` | Total tokens minted |
| `transferFee()` | `0` | Peer-to-peer transfer fee disabled |

### Findings Summary

| Severity | Count | Key Issues |
|---------|-------|------------|
| Critical | 0 | — |
| High | 4 | Owner can freeze addresses; LP sent to fund wallet (no lock); Uncapped owner-settable fees; MEV risk on swaps (no slippage) |
| Medium | 4 | Owner can withdraw arbitrary tokens/BNB; Airdrop loop DoS/gas griefing; Dividend tracker permanently owner-controlled; Potential fee-induced DoS |
| Low | 3 | Misleading `isReward` as blacklist; Event parameter order bug; Unreachable code in dividend token `_transfer()` |

### Critical Findings

None identified.

### High Findings

---

#### 🟠 [H-1] Owner-Managed Blacklist Can Freeze User Funds

**Description:**
The token uses `_rewardList` as a blacklist. If set to `true` for an address, every transfer from that address reverts, effectively freezing funds. The name `isReward` is misleading.

```solidity
mapping(address => bool) public _rewardList;

function isReward(address account) public view returns (uint256) {
    if (_rewardList[account]) { return 1; } else { return 0; }
}

function _transfer(address from, address to, uint256 amount) internal override {
    require(isReward(from) <= 0, "isReward > 0 !");
    ...
}

function multi_bclist(address[] calldata addresses, bool value) public onlyOwner {
    for (uint256 i; i < addresses.length; ++i) {
        _rewardList[addresses[i]] = value;
    }
}
```

**Impact:**
Owner can freeze any holder’s tokens (including preventing selling) at any time. This poses censorability and honeypot-like risk.

**Location:**
`BananaToken._transfer()` and `multi_bclist()`.

**💡 Recommendation:**
> Action Required:
> 1. Rename `_rewardList`/`isReward()` to `blacklist` for transparency.
> 2. Remove or strictly limit blacklist powers (e.g., immutable after launch, multisig + timelock).
> 3. Emit events on blacklist changes; consider only blocking bots during a short, audited window.

---

#### 🟠 [H-2] Liquidity Tokens Are Sent to Fund Wallet (No Lock) – Rug Pull Risk

**Description:**
When adding liquidity, LP tokens are sent to `generateLpReceiverAddr`, defaulting to `fundAddress`. There is no locking mechanism or time delay.

```solidity
address public generateLpReceiverAddr; // default = fundAddress

function addLiquidityWBNB(uint256 tokenAmount, uint256 WBNBAmount) private {
    _approve(address(this), address(_swapRouter), tokenAmount);
    try _swapRouter.addLiquidity(
        address(currency),
        address(this),
        WBNBAmount,
        tokenAmount,
        0,
        0,
        generateLpReceiverAddr, // LP tokens sent here
        block.timestamp
    ) {} catch { emit Failed_addLiquidity(); }
}
```

**Impact:**
The recipient can immediately remove liquidity, drain the paired asset, and crash price (rug pull). Users must fully trust the LP holder.

**Location:**
`BananaToken.addLiquidityWBNB()` and `generateLpReceiverAddr` usage.

**💡 Recommendation:**
> Action Required:
> 1. Send LP tokens to a time-locked contract or burn address (`0xdead`) if permanent lock is intended.
> 2. If custody needed, use multisig + on-chain timelock with public transparency.
> 3. Disclose LP management policy in documentation.

---

#### 🟠 [H-3] Uncapped, Owner-Settable Fees Can Break Trading or Confiscate Value

**Description:**
Owner can set buy/sell/burn/liquidity/reward fees to arbitrary values with no upper bounds.

```solidity
function setTradeFee(uint256[] calldata customs) external onlyOwner {
    _buyFundFee = customs[0];
    _buyLiquidityFee = customs[1];
    _buyRewardFee = customs[2];
    _buyBurnFee = customs[3];
    _sellFundFee = customs[4];
    _sellLiquidityFee = customs[5];
    _sellRewardFee = customs[6];
    _sellBurnFee = customs[7];
}
```

Fees are applied in `_transfer()` without caps:
```solidity
if (_swapPairList[from]) { // buy
    fees = amount.mul(getBuyFee()).div(10000);
} else if (_swapPairList[to]) { // sell
    fees = amount.mul(getSellFee()).div(10000);
}
```

**Impact:**
- Excessive fees can act as a honeypot or confiscatory tax.
- Fees > 10000 cause SafeMath underflows (revert), halting trades (DoS).

**Location:**
`BananaToken.setTradeFee()`, `_transfer()`.

**💡 Recommendation:**
> Action Required:
> 1. Enforce strict maximums (e.g., total fee <= 10%).
> 2. Emit events for fee changes; consider timelock before activation.
> 3. If higher fees needed briefly (e.g., anti-bot), hardcode bounded windows.

---

#### 🟠 [H-4] Swaps Use minOut=0 (No Slippage Protection) – MEV/Sandwich Risk

**Description:**
All router swaps set `amountOutMin` to `0`, allowing execution at any price.

```solidity
_swapRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
    tokenAmount,
    0, // no slippage protection
    path,
    address(_tokenDistributor),
    block.timestamp
);
...
_swapRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
    dividendsAmount,
    0, // no slippage protection
    buyRewardTokenPath,
    address(this),
    block.timestamp
);
```

**Impact:**
- MEV bots can sandwich and extract value from swaps.
- Severe price impact and value loss for the treasury/dividends.

**Location:**
`BananaToken.swapTokensForCurrency()`, `distributeCurrency()`.

**💡 Recommendation:**
> Action Required:
> 1. Add configurable slippage tolerance (e.g., basis points) and non-zero `amountOutMin`.
> 2. Consider TWAP or private relays for large swaps to reduce MEV.
> 3. Split swaps into smaller chunks if necessary.

### Medium Findings

---

#### 🟡 [M-1] Owner Can Withdraw Arbitrary Tokens/BNB From Contract

**Description:**
The owner can transfer any ERC20 out, and withdraw all BNB.

```solidity
function withdraw(address token, address recipient, uint amount) external onlyOwner {
    IERC20(token).transfer(recipient, amount);
}

function withdrawBNB() external onlyOwner {
    payable(owner()).transfer(address(this).balance);
}
```

**Impact:**
- Owner can extract accrued fees, reward tokens, or mistakenly sent tokens.
- If misused, dividends/fund allocations may be diverted.

**Location:**
`BananaToken.withdraw()`, `withdrawBNB()`.

**💡 Recommendation:**
> Action Required:
> 1. Limit withdrawals to non-fee/non-dividend tokens or to whitelisted assets with timelock/multisig.
> 2. Add transparency events and caps; consider DAO control for treasury.

---

#### 🟡 [M-2] Airdrop Loop Can Cause Gas Griefing/Transfer Failures

**Description:**
Owner can set `airdropNumbs` arbitrarily; transfers on AMM pairs will loop and transfer 1 token to pseudo-random addresses each iteration.

```solidity
function setAirdropNumbs(uint256 newValue) public onlyOwner {
    airdropNumbs = newValue;
}

if (airdropNumbs > 0 && (_swapPairList[from] || _swapPairList[to]) && takeFee) {
    for (uint256 a = 0; a < airdropNumbs; a++) {
        super._transfer(from, address(uint160(uint256(keccak256(...)))), 1);
    }
    amount = amount.sub(airdropNumbs);
}
```

**Impact:**
- High gas per trade; possible out-of-gas DoS.
- If `amount < airdropNumbs`, subtraction underflow reverts, blocking trades.

**Location:**
`BananaToken._transfer()`.

**💡 Recommendation:**
> Action Required:
> 1. Cap `airdropNumbs` to a low, audited maximum (e.g., <= 5).
> 2. Add checks to ensure `amount >= airdropNumbs`.
> 3. Prefer off-chain airdrops or separate functions.

---

#### 🟡 [M-3] Dividend Tracker Permanently Controlled by Token Contract (No Renounce Path)

**Description:**
The tracker’s owner is set to the `BananaToken` contract via `__Ownable_init` during `initialize()`. There is no function in `BananaToken` to renounce or transfer the tracker’s ownership, and only the token contract (not EOA) can pass `onlyOwner` checks in the tracker.

```solidity
function initialize(...) external initializer {
    DividendPayingToken.__DividendPayingToken_init(...); // sets owner = msg.sender (BananaToken)
    ...
}
```

**Impact:**
- Permanent centralization of dividend controls via the token contract.
- If `BananaToken` renounces its own EOA owner, many tracker admin functions become unreachable.

**Location:**
`BABYTOKENDividendTracker.initialize()` and `OwnableUpgradeable`.

**💡 Recommendation:**
> Action Required:
> 1. Expose a token function to transfer or renounce tracker ownership (to multisig/timelock).
> 2. Document governance process for dividend parameters.

---

#### 🟡 [M-4] Owner-Settable Limits and Fees Can Induce DoS

**Description:**
Max limits and fees are owner-settable without caps. Setting values incorrectly can revert transfers (e.g., `amount < airdropNumbs`, fees > 10000 bp).

```solidity
function setMaxBuyAmount(uint256 _maxBuyAmount) external onlyOwner { ... }
function setMaxSellAmount(uint256 newValue) external onlyOwner { ... }
function setWalletLimit(uint256 _amount) external onlyOwner { ... }
function setTransferFee(uint256 newValue) public onlyOwner { transferFee = newValue; }
```

**Impact:**
- Accidental or malicious configuration can halt trading or disallow normal transfers.

**Location:**
Various `set*` functions and `_transfer()` checks.

**💡 Recommendation:**
> Action Required:
> 1. Impose sane upper/lower bounds with validation.
> 2. Add timelock + events for parameter changes.

### Low Findings

---

#### 🟢 [L-1] Misleading Naming: `isReward`/`_rewardList` Is a Blacklist

**Description:**
`isReward()` implies a reward flag but is used to block transfers (blacklist). This can confuse users and auditors.

```solidity
require(isReward(from) <= 0, "isReward > 0 !");
```

**Impact:**
Reduced transparency; may be used to obfuscate blacklist behavior.

**Location:**
`BananaToken._transfer()`.

**💡 Recommendation:**
> Action Required:
> - Rename to `blacklist`/`isBlacklisted` and update error messages accordingly.

---

#### 🟢 [L-2] Event Parameter Order Bug in Referral Binding

**Description:**
Event indexing/order mismatches logical meaning (invitee/inviter reversed).

```solidity
event BindingConfirmed(address indexed invitee, address indexed inviter);

function _handleHandshake(address from, address to) private {
    if (balanceOf(to) == 0 && referrer[to] == address(0)) {
        referrer[to] = from;
        emit BindingConfirmed(from, to); // reversed: should be (to, from)
    }
}
```

**Impact:**
Off-chain analytics see swapped fields; data integrity issues.

**Location:**
`BananaToken._handleHandshake()`.

**💡 Recommendation:**
> Action Required:
> - Emit as `emit BindingConfirmed(to, from);`.

---

#### 🟢 [L-3] Unreachable Code in Dividend Token `_transfer()`

**Description:**
`DividendPayingToken._transfer()` hard reverts, leaving dead code below.

```solidity
function _transfer(address from, address to, uint256 value) internal virtual override {
    require(false);
    int256 _magCorrection = magnifiedDividendPerShare.mul(value).toInt256Safe();
    ...
}
```

**Impact:**
Confusing for reviewers; minor bytecode bloat.

**Location:**
`DividendPayingToken._transfer()`.

**💡 Recommendation:**
> Action Required:
> - Remove the dead code below the unconditional revert.

### Good Practices

- Uses well-known patterns for dividend tracking with magnified shares.
- Employs `try/catch` around external swaps to prevent reverts.
- Avoids direct dividend transfers during token transfer to reduce reentrancy risk.
- Standard `IERC20` interfaces and PancakeSwap V2 router integration.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard `ERC20` + cloned tracker | Low by itself |
| Upgrade Control | Not upgradeable (no proxy) | Low |
| Ownership Status | Active (EOA: `0x956b...`) | High centralization |
| Owner Address | `0x956b4279606AB95fA03EaB4756e4619907927717` | Current owner |
| Total Supply | 4,200,000,000,000,000 tokens (18 decimals) | Info |
| Buy Tax | 2.9% (0.5% fund, 2.4% reward, 0.1% burn) | Low |
| Sell Tax | 2.9% (0.5% fund, 2.4% reward, 0.1% burn) | Low |
| Max Transaction | None (max uint) | Low (but owner-changeable) |

Details and risks:
- Fees route to three sinks: fund wallet (custodied), burns, and dividends (reward token at `ETH()` address). Liquidity fee currently 0%.
- Liquidity additions, when enabled, send LP tokens to `generateLpReceiverAddr` (defaults to `fundAddress`), enabling potential liquidity withdrawal (rug risk) unless externally locked.
- Owner can at any time adjust fees (no caps), max transaction/wallet limits, enable referral tiers, and blacklist addresses. This centralization can materially impact user ability to trade or receive dividends.
- Swaps use zero slippage controls (`amountOutMin = 0`), making treasury/dividend conversions MEV-exploitable.
- Dividend tracker is controlled by the token contract; no external renounce/transfer path is provided, binding governance to the token owner’s will.

Libraries and inheritance integrity:
- `Context`, `Ownable`, `Initializable`, `ContextUpgradeable`, `OwnableUpgradeable`, `ERC20Upgradeable` closely match OpenZeppelin v4.x patterns with no malicious modifications detected. SafeMath usage is redundant on Solidity 0.8+ but harmless.
- `Clones` library code matches the minimal proxy pattern; no hidden backdoors detected.

Ownership Renunciation:
- Owner is active (EOA). No evidence of fake renunciation or ownership backdoors. Dividend tracker ownership is held by the token contract by design; no external backdoor detected, but governance remains centralized.

Balanced Assessment:
- While upgradeability is not used, the combination of owner-controlled fees, blacklist, LP custody, and treasury withdrawals requires high trust in the owner. This is typical for managed tokens but must be clearly disclosed.



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
