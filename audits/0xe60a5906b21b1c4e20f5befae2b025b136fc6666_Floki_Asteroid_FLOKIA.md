# 🔍 Floki Asteroid (FLOKIA) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-06-28T17:07:06.661Z (UTC) |
| **Blockchain** | BNB Smart Chain |
| **Contract Address** | `0xe60a5906b21b1c4e20f5befae2b025b136fc6666` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | Floki Asteroid |
| **Symbol** | FLOKIA |

---

## 🤖 Analysis #1: GPT-5

**Completed:** Sun, 28 Jun 2026 17:07:06 GMT

### Summary

This is a custom `ERC20` token (`FLOKIA`) with dividend distribution in a separate `DividendTracker` using a rewards token. It implements buy/sell/transfer taxes (default 3% reward on buys and sells), blacklist controls, “launch/shutdown” trading gates, owner-controlled limits, and an owner/marketing-controlled treasury withdrawal. No proxy detected; heavy centralization and freeze controls exist, with a secondary admin (`marketingWalletAddr`) capable of draining funds. Overall Risk: HIGH - Broad owner and secondary-admin controls can freeze funds, halt trading, drain treasury, and alter taxes/limits at will.

### Risk Assessment

**Token Quick Facts:**

| Property | Value | Status |
|----------|-------|--------|
| Buy Tax | 3% reward (others 0%) | ⚠️ Moderate (owner-changeable) |
| Sell Tax | 3% reward (others 0%) | ⚠️ Moderate (owner-changeable) |
| Max Transaction | None (0) | ✅ No cap (owner-changeable) |
| Contract Type | Standard (non-proxy) | Info |
| Ownership | Active owner + secondary admin | ⚠️ Centralized control |
| Pause Function | Yes (via `shutdown()`/gates) | ⚠️ Can halt trading |

**Security Assessment:**

| Category | Risk Level | Notes |
|----------|------------|-------|
| Security | Medium | No proxy; swaps and external calls guarded by `inSwap`, but several logic pitfalls |
| Centralization | High | Owner can freeze, blocklist, halt trading; secondary admin can drain funds |
| Code Quality | Medium | Generally clean; some logic inconsistencies (percent units, price check, events) |
| Exploit Likelihood | Medium | Direct exploits unlikely; admin misuse/honeypot patterns are the main risk |
| **Overall Risk Score** | **68/100** | High centralization, blacklists, admin drain, honeypot toggles |

## On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `DEAD_ADDRESS()` | `0x000000000000000000000000000000000000dEaD` | Burn sink where tokens are irrecoverably sent |
| `USDT_ADDRESS()` | `0x55d398326f99059fF775485246999027B3197955` | USDT token on BSC used in swap path |
| `ZERO_ADDRESS()` | `0x0000000000000000000000000000000000000000` | Null address used for validations |
| `airdropNumbs()` | `0` | Count of 1-token “airdrop” micro-transfers per trade |
| `buyBurnFee()` | `0` | Buy burn tax (basis points) |
| `buyFundFee()` | `0` | Buy marketing/fund tax (basis points) |
| `buyLPFee()` | `0` | Buy liquidity tax (basis points) |
| `buyLimitAmt()` | `0` | Max buy amount; 0 means none |
| `buyRewardFee()` | `300` | Buy reward tax = 3% (basis points) |
| `claimWait()` | `60` | Seconds between dividend claims |
| `currencyAddr()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | WBNB used as base currency |
| `decimals()` | `18` | Token decimals |
| `dividendTracker()` | `0x68E43c91cd8A97A761960e4D49AE1eE67ceB8C80` | Dividend tracker contract address |
| `gasForProcessing()` | `500000` | Gas budget for dividend processing per call |
| `isStartTrade()` | `false` | Trading not launched (gates active) |
| `killBlockTimestamp()` | `0` | Auto-blacklist window length (seconds) |
| `mainPairAddr()` | `0x98Dfd95Eb55F65c31c2167F0f42898cD6fB10B39` | Main AMM pair address |
| `marketingWalletAddr()` | `0x78F1d33BA8fC2042F46CE448818f14F0933bF496` | Secondary admin and marketing recipient |
| `minSwapValue()` | `0` | Minimum swap value threshold (disabled) |
| `minimumTokenBalanceForDividends()` | `10000000000000000000000` | 10,000 tokens minimum to receive rewards |
| `name()` | `Floki Asteroid` | Contract name identifier |
| `owner()` | `0x78F1d33BA8fC2042F46CE448818f14F0933bF496` | Admin with full control |
| `receiveGeneratedLpAddr()` | `0x78F1d33BA8fC2042F46CE448818f14F0933bF496` | Address receiving LP tokens minted |
| `rewardTokenAddr()` | `0xbe9D156892E55e7154BcD3cB0FEA677F9D3103E1` | Token used as dividend reward |
| `sellBurnFee()` | `0` | Sell burn tax (basis points) |
| `sellFundFee()` | `0` | Sell marketing/fund tax (basis points) |
| `sellLPFee()` | `0` | Sell liquidity tax (basis points) |
| `sellRewardFee()` | `300` | Sell reward tax = 3% (basis points) |
| `startTradeTimestamp()` | `0` | Trading start time (not launched) |
| `swapAtAmount()` | `0` | Threshold to trigger swaps (0 = always check) |
| `swapRouter()` | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap v2 router |
| `symbol()` | `FLOKIA` | Ticker symbol |
| `tokenDistributor()` | `0xd6fAcc8D9c8E4faFbd8D2c8954399D14582Bb7e1` | Helper contract to hold swapped currency |
| `tokenSwapPercentage()` | `300` | 300% of tx amount target for swap flushing |
| `totalSupply()` | `1000000000000000000000000000` | 1,000,000,000 tokens (18 decimals) |
| `transferFee()` | `0` | Transfer tax (basis points) |
| `v3SwapRouterAddr()` | `0x13f4EA83D0bd40E75C8222255bc855a974568Dd4` | PancakeSwap v3 router |
| `walletLimitAmt()` | `0` | Max wallet amount; 0 means none |
| `wethAddress()` | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | WBNB address (router WETH) |

### Findings Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| Critical | 0 | — |
| High | 5 | Owner can freeze/blocklist funds; Secondary admin can drain funds; Owner receives LP (can rug liquidity); Uncapped owner-set taxes/limits enable honeypot behavior; Single-sig, no timelock/multisig |
| Medium | 3 | Launch gate bypass via fee-exclusion; Mis-scaled `tokenSwapPercentage` (300%); Misused price query for `minSwapValue` |
| Low | 3 | Event emits wrong old/new values; Inaccurate `isContract()` heuristic; Dead/unreachable code in dividend `_transfer` |

### Critical Findings

— None identified in the reviewed code and current on-chain state. Note: If ownership is later renounced to `address(0)`, the presence of `onlyMarketWalletOrOwner` keeps powerful privileges with `marketingWalletAddr`, which would then constitute a fake-renounce pattern. At that time, this would be CRITICAL.

### High Findings

---

#### 🟠 [H-1] Owner can arbitrarily freeze funds and mass-blacklist recipients (permanent lock)

**Description:**
The contract can permanently freeze user funds via `isBlocked`. Additionally, during the early “kill window,” any recipient of a trade can be auto-added to the blocklist. The owner can re-open trading at a future time to trigger new kill windows, effectively mass-blacklisting fresh buyers repeatedly.

```solidity
mapping(address => bool) public isBlocked;

function _transfer(address from, address to, uint256 amount) internal override {
    require(!isBlocked[from], "ERC20: from is blocked");
    ...
    if (
        isStartTrade() && 
        block.timestamp < startTradeTimestamp + killBlockTimestamp &&
        !isLiquidityPair[to]
    ) {
        _setIsBlocked(to, true);
    }
    ...
}

function multiSetIsBlock(address[] calldata addresses, bool status) external onlyOwner {
    for (uint256 i; i < addresses.length; i++) {
        _setIsBlocked(addresses[i], status);
    }
}

function setStartTradeTimestamp(uint256 newValue) external onlyOwner {
    require(newValue > block.timestamp, "new value must be greater than current timestamp");
    startTradeTimestamp = newValue;
}
```

**Impact:**
- Owner can permanently freeze any account’s ability to transfer out.
- Owner can “relaunch” with a new `startTradeTimestamp` and non-zero `killBlockTimestamp` to auto-blocklist new recipients, trapping funds acquired during that window.

**Location:**
`FLOKIA._transfer()` and admin setters shown above.

**💡 Recommendation:**
> Action Required:
> 1. Remove or strictly limit `isBlocked` functionality; if required, enforce transparent, time-bound, and appealable blocks.
> 2. Eliminate auto-blocklisting during launch; or make it opt-in-short and irrevocably disabled after first launch.
> 3. Emit events for blocklist changes and consider DAO/multisig governance for such actions.

---

#### 🟠 [H-2] Secondary admin (`marketingWalletAddr`) can drain contract funds even after ownership renounce

**Description:**
The `onlyMarketWalletOrOwner` modifier grants the `marketingWalletAddr` the power to withdraw any tokens or ETH from the contract via `claimToken()`. If the owner renounces, the marketing wallet retains this authority, creating a “fake renounce” scenario where a powerful backdoor persists.

```solidity
modifier onlyMarketWalletOrOwner() {
    require(owner() == msg.sender || marketingWalletAddr == msg.sender, "Only owner or marketing wallet can call this funcion");
    _;
}

function claimToken(address token, uint256 amount, address to) external onlyMarketWalletOrOwner {
    if (token == address(0)) {
        TransferHelper.safeTransferETH(to, amount);
    } else {
        TransferHelper.safeTransfer(token, to, amount);
    }
}
```

**Impact:**
- Central entity can siphon all accumulated fees/revenues at any time.
- If ownership is renounced, users may be misled about decentralization while the marketing wallet retains de facto treasury control.

**Location:**
`FLOKIA.onlyMarketWalletOrOwner` and `claimToken()`.

**💡 Recommendation:**
> Action Required:
> 1. Remove marketing wallet privileges for treasury withdrawals or restrict via multisig+timelock.
> 2. If renounce is intended, disable all privileged functions or migrate to DAO governance.
> 3. Clearly disclose this control to users.

---

#### 🟠 [H-3] Owner receives all newly minted LP tokens (liquidity can be rugged)

**Description:**
When adding liquidity, minted LP tokens are sent to `receiveGeneratedLpAddr`, which is owner-controlled and set to the marketing wallet by default.

```solidity
address public receiveGeneratedLpAddr;
// ...
function addLiquidityCurrency(uint256 currencyAmount, uint256 tokenAmount) private {
    ...
    swapRouter.addLiquidity(
        address(currencyAddr),
        address(this),
        currencyAmount,
        tokenAmount,
        0,
        0,
        receiveGeneratedLpAddr, // owner-controlled
        block.timestamp
    );
}
```

**Impact:**
- Owner can remove liquidity at any time, causing price collapse and loss for holders.

**Location:**
`FLOKIA.addLiquidityCurrency()` and `setReceiveGeneratedLpAddr()`.

**💡 Recommendation:**
> Action Required:
> 1. Send LP to a time-locked, verifiable burn address (e.g., `0x...dEaD`) to truly lock liquidity.
> 2. Alternatively, place LP under a robust multisig+timelock with public commitments.

---

#### 🟠 [H-4] Owner-controlled taxes/limits and airdrop micro-transfers can create honeypot conditions

**Description:**
- All fee parameters are owner-set without caps. `transferFee`, buy/sell fees can be set to extremely high values.
- `airdropNumbs` forces `1`-token micro-transfers to pseudo-random addresses per trade, consuming sender balance and gas; settable by owner.

```solidity
function setFees(uint256[] calldata fees) external onlyOwner { ... } // all tax components
function setTransferFee(uint256 newValue) external onlyOwner { transferFee = newValue; }
function setAirdropNumbs(uint256 newValue) external onlyOwner { airdropNumbs = newValue; }

if (airdropNumbs > 0 && (isLiquidityPair[from] || isLiquidityPair[to])) {
    address ad;
    for (uint256 i = 0; i < airdropNumbs; i++) {
        ad = address(uint160(type(uint160).max / (i + amount)));
        super._transfer(from, ad, 1);
    }
    amount -= airdropNumbs * 1;
}
```

**Impact:**
- Owner can effectively block sells/transfers by setting punitive taxes or large `airdropNumbs`, causing transfers to revert or deplete balances via micro-transfers.
- Creates honeypot-like behavior or severe slippage/gas griefing.

**Location:**
`FLOKIA._transfer()` and admin setters.

**💡 Recommendation:**
> Action Required:
> 1. Impose hard caps on all fee parameters (e.g., max 10%).
> 2. Remove or cap `airdropNumbs` to a very small number, or disable after launch.
> 3. Disclose risks; consider immutability or DAO control for tax parameters.

---

#### 🟠 [H-5] Single EOA ownership without timelock/multisig over powerful controls

**Description:**
A single externally-owned account controls trading gates, blacklists, fees, LP recipient, and treasury withdrawals (via `marketingWalletAddr`). No timelock or multisig is enforced.

**Impact:**
- Full trust in a single party is required. Admin can halt trading, freeze funds, drain treasury, or rug liquidity at any time without notice.

**Location:**
All `onlyOwner` and `onlyMarketWalletOrOwner` functions across `FLOKIA`.

**💡 Recommendation:**
> Action Required:
> 1. Migrate admin keys to a 3/5 (or larger) multisig and add a 24–48h timelock for sensitive actions.
> 2. Publish governance processes and addresses.

---

### Medium Findings

---

#### 🟡 [M-1] Fair launch/trading gates are bypassable via fee-exempt addresses

**Description:**
All “pre-launch” restrictions are enforced only if `takeFee == true`. Excluding an address from fees makes `takeFee = false`, bypassing the “can’t trade before start trade” checks, allowing privileged wallets to trade pre-launch.

```solidity
bool takeFee = !inSwap;
if (isExcludedFromFee[from] || isExcludedFromFee[to]) {
    takeFee = false;
}
if (takeFee) {
    if (!isStartTrade()) {
        ...
        if (isLiquidityPair[from] || isLiquidityPair[to]) {
            require(false, "can't trade before start trade");
        }
    }
}
```

**Impact:**
- Privileged wallets can buy/sell before official launch, potentially front-running the market.

**Location:**
`FLOKIA._transfer()` gating logic.

**💡 Recommendation:**
> Action Required:
> 1. Enforce launch gates irrespective of fee-exemption, or time-limit exemptions.
> 2. Disclose pre-launch trading permissions for transparency.

---

#### 🟡 [M-2] Mis-scaled `tokenSwapPercentage` (uses /100 not /10000); default 300 = 300% of tx

**Description:**
When conditions are met on sells, the contract tries to flush `tokenSwapPercentage` of the transaction amount from the contract’s token balance. Division by `100` (percent) is used instead of basis points (`10000`) like other fees.

```solidity
uint256 numTokensSellToFund = (amount * tokenSwapPercentage) / 100; // 300 -> 300%
```

**Impact:**
- With `tokenSwapPercentage = 300` (on-chain), swaps target up to 300% of tx amount from the contract balance, creating excessive sell pressure and price impact if the contract holds many tokens.

**Location:**
`FLOKIA._transfer()` pre-sell “canSwap” block.

**💡 Recommendation:**
> Action Required:
> 1. Use basis points for consistency: divide by `10000`.
> 2. Reset default to a reasonable value (e.g., 100–300 bps).
> 3. Add upper bounds to prevent excessive dumps.

---

#### 🟡 [M-3] Incorrect price function used for `minSwapValue` gating (uses `getAmountsIn` on reverse path)

**Description:**
`getTokenValue(amount)` uses `getAmountsIn` with path `currency -> token`, but `distributeCurrency` needs estimated output of selling tokens for currency (path `token -> currency` via `getAmountsOut`).

```solidity
function getTokenValue(uint256 amount) public view returns(uint256){
    address[] memory path = new address[](2);
    path[0] = currencyAddr;
    path[1] = address(this);
    return swapRouter.getAmountsIn(amount, path)[0]; // wrong direction
}
```

**Impact:**
- `minSwapValue` check may be inaccurate, either skipping swaps when appropriate or swapping when below intended threshold.

**Location:**
`FLOKIA.getTokenValue()` and `distributeCurrency()` where it is used.

**💡 Recommendation:**
> Action Required:
> 1. For sell-value estimate, use `getAmountsOut(tokenAmount, [this, currency])`.
> 2. Consider slippage buffers and failure handling.

---

### Low Findings

---

#### 🟢 [L-1] Event `ClaimWaitUpdated` emits new value twice instead of (new, old)

**Description:**
In `DividendTracker.setClaimWait`, the `claimWait` is updated before emitting the event, causing both `newValue` and `oldValue` to log the same value.

```solidity
function setClaimWait(uint256 _claimWait) external onlyOwner {
    claimWait = _claimWait;
    emit ClaimWaitUpdated(_claimWait, claimWait); // emits (new, new)
}
```

**Impact:**
- Misleading event logs hinder off-chain tracking.

**Location:**
`DividendTracker.setClaimWait()`.

**💡 Recommendation:**
> Action Required:
> 1. Emit event before updating or pass the proper old value to the event.

---

#### 🟢 [L-2] Inaccurate `isContract()` heuristic

**Description:**
The contract checks `code.length > 25` to detect contracts. This threshold is arbitrary; minimal proxies or small contracts may bypass detection.

```solidity
function isContract(address _addr) public view returns (bool) {
    return _addr.code.length > 25;
}
```

**Impact:**
- Pre-launch anti-bot or anti-LP logic may be inconsistently enforced.

**Location:**
`FLOKIA.isContract()`.

**💡 Recommendation:**
> Action Required:
> 1. Use `code.length > 0`. Note: contract detection is imperfect; consider alternative anti-bot designs.

---

#### 🟢 [L-3] Dead/unreachable code in dividend token `_transfer`

**Description:**
`DividendPayingToken._transfer` reverts unconditionally, making the subsequent dividend correction code unreachable in that function (accounting occurs elsewhere via `_setBalance`, `_mint`, `_burn`).

```solidity
function _transfer(address from, address to, uint256 value) internal virtual override {
    require(false);
    int256 _magCorrection = magnifiedDividendPerShare.mul(value).toInt256Safe();
    magnifiedDividendCorrections[from] = magnifiedDividendCorrections[from].add(_magCorrection);
    magnifiedDividendCorrections[to] = magnifiedDividendCorrections[to].sub(_magCorrection);
}
```

**Impact:**
- Minor code clarity issue; potential to confuse auditors/tools.

**Location:**
`DividendPayingToken._transfer()`.

**💡 Recommendation:**
> Action Required:
> 1. Remove unreachable code or add a clear comment explaining intentional non-transferability.

---

### Good Practices

- Uses a dedicated `DividendTracker` with accounting isolated from the main token.
- `inSwap` flag prevents recursive fee logic during swaps.
- Extensive use of try/catch and “safe” transfer helpers to avoid blocking operations.
- No upgradeable proxy detected; logic is static.

### Tokenomics Analysis

| Feature | Value/Status | Risk Assessment |
|---------|--------------|-----------------|
| Contract Type | Standard (non-proxy) | Low upgrade risk |
| Upgrade Control | N/A | — |
| Ownership Status | Active owner + secondary admin | High (centralized) |
| Owner Address | 0x78F1...F496 | Centralized admin |
| Total Supply | 1,000,000,000 | Normal |
| Buy Tax | 3% reward | Medium (owner-changeable) |
| Sell Tax | 3% reward | Medium (owner-changeable) |
| Max Transaction | None | Medium (owner can add/change later) |

- Fees and limits are entirely owner-controlled, including the ability to set high taxes, add wallet/buy limits, and toggle airdrop micro-transfers per trade that can break sells and impose gas griefing. This enables honeypot-like configurations post-deployment.
- Liquidity minted is directed to an owner-controlled address, enabling full liquidity removal at any time. Dividend distribution relies on a specific v3 path that might not have adequate liquidity; failures are silently tolerated (dividends could stall).
- Centralized control over trading gates and blacklists creates significant rug and censorship risks. While upgradeability is absent (no proxy), admin privileges are broad; consider multisig and timelock for any serious deployment.

Overall, while the code avoids obvious low-level vulnerabilities and reentrancy in practice, it intentionally concentrates power in the owner/marketing wallet, enabling fund freezes, treasury drains, and liquidity rugs. Users must fully trust the administrators.

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
