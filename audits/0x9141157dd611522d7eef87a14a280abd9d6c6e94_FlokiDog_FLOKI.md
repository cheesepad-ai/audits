# 🔍 FlokiDog (FLOKI) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-07-16T22:05:50.736Z (UTC) |
| **Blockchain** | BNB Smart Chain Testnet |
| **Contract Address** | `0x9141157dd611522d7eef87a14a280abd9d6c6e94` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | FlokiDog |
| **Symbol** | FLOKI |

---

## 🤖 Analysis #1: Claude Opus 4.8

**Completed:** Thu, 16 Jul 2026 22:05:50 GMT

### Summary

`CheesePadStandardToken` is a fixed-supply ERC-20 token built on OpenZeppelin Contracts v5.5.0, with a configurable decimals value and a one-time deployment fee mechanism paid in native currency to a fee receiver. The entire supply is minted to the deployer at construction. The contract contains no mint/burn functions post-deployment, no owner privileges, no pause, and no blacklist. The core ERC-20 logic is standard and unmodified OpenZeppelin code, which is well-audited and safe. The only custom logic is the constructor, which is low-risk.

Note: the on-chain deployment (`FlokiDog`/`FLOKI`, 18 decimals, 420B supply) reflects an instance parameterized at deployment; the source itself is a generic template.

### Risk Assessment

**Token Quick Facts**

| Property | Value |
|----------|-------|
| Token Name | FlokiDog (on-chain instance) |
| Symbol | FLOKI (on-chain instance) |
| Decimals | 18 (configurable, capped at 18) |
| Total Supply | 420,000,000,000 (fixed at deploy) |
| Mintable After Deploy | No |
| Burnable | No (no public burn) |
| Pausable | No |
| Blacklist / Fee-on-Transfer | No |
| Owner Privileges | None |
| Base | OpenZeppelin ERC20 v5.5.0 |

**Security Assessment**

| Category | Status |
|----------|--------|
| Reentrancy | ⚠️ External call in constructor (low risk) |
| Access Control | ✅ No privileged roles |
| Supply Manipulation | ✅ Fixed supply, no post-deploy mint |
| Standard Compliance | ✅ Compliant ERC-20 |
| Honeypot Indicators | ✅ None detected |
| Upgradeability | ✅ Non-upgradeable |

### On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `decimals()` | `18` | Token uses 18 decimal places for display, standard for ERC-20 tokens. |
| `name()` | `FlokiDog` | Human-readable token name set at deployment. |
| `symbol()` | `FLOKI` | Token ticker symbol set at deployment. |
| `totalSupply()` | `420000000000000000000000000000` | Fixed supply of 420 billion tokens (18 decimals); no further minting possible. |

### Additional Read Functions

| Function | Parameters | Return Type |
|----------|------------|-------------|
| `allowance(address, address)` | address, address | `uint256` |
| `balanceOf(address)` | address | `uint256` |

### Findings Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 0 |
| 🟢 Low | 3 |

### Critical Findings

None.

### High Findings

None.

### Medium Findings

None.

### Low Findings

#### 🟢 [L-1] Unchecked external fee transfer with potential reentrancy surface in constructor

**Description:**
The constructor performs a raw `call` to an arbitrary `feeReceiver_` address before minting completes.

```solidity
(bool ok, ) = feeReceiver_.call{value: msg.value}("");
require(ok, "Fee transfer failed");

// Mint to deployer
uint256 scaledSupply = totalSupply_ * (10 ** uint256(decimals_));
_mint(msg.sender, scaledSupply);
```

While reentrancy into the token is not exploitable here (no state relevant to the attacker is manipulable during construction, and code is not yet deployed at that address), the pattern of an external call before state finalization is worth noting. There is no meaningful attack vector because `_mint` targets `msg.sender` and no partial state persists.

**Impact:**
Negligible in practice; the external call cannot be leveraged to manipulate token accounting. If the fee receiver is a contract that reverts, deployment fails (intended).

**Location:**
`CheesePadStandardToken` constructor.

**💡 Recommendation:**
> **Action Required:** Move the fee transfer to occur after `_mint`, or use a pull-payment pattern, to follow checks-effects-interactions consistently. Low priority.

---

#### 🟢 [L-2] Total supply multiplication can overflow / revert for extreme inputs

**Description:**
The scaled supply is computed as `totalSupply_ * (10 ** uint256(decimals_))`. For very large `totalSupply_` combined with 18 decimals, this can revert due to overflow (Solidity 0.8 checked arithmetic).

```solidity
uint256 scaledSupply = totalSupply_ * (10 ** uint256(decimals_));
```

**Impact:**
Deployment reverts for pathological inputs. No fund risk; purely a deployment-time usability concern controlled by the deployer.

**Location:**
`CheesePadStandardToken` constructor.

**💡 Recommendation:**
> **Action Required:** Document expected input ranges; optionally validate `totalSupply_` against a sane maximum before scaling.

---

#### 🟢 [L-3] No zero-supply or parameter sanity validation

**Description:**
The constructor allows `totalSupply_ == 0`, producing a token with no supply. There is also no validation that `name_`/`symbol_` are non-empty.

**Impact:**
Cosmetic / deployer error only. A misconfigured deployment produces a useless but harmless token.

**Location:**
`CheesePadStandardToken` constructor.

**💡 Recommendation:**
> **Action Required:** Add `require(totalSupply_ > 0, "Zero supply")` if a non-zero supply is always intended.

### Good Practices

- Uses the latest audited OpenZeppelin ERC-20 base (v5.5.0) without modifying core transfer/allowance logic.
- Custom errors (ERC-6093) for gas efficiency and clear revert reasons.
- Fixed supply minted once in constructor; no post-deploy mint function eliminates inflation risk.
- No owner, pause, blacklist, or fee-on-transfer hooks — no honeypot or rug-pull vectors.
- `decimals_` capped at 18 and `feeReceiver_` validated against the zero address.
- Fee value is strictly checked (`msg.value == feeAmount_`), preventing accidental over/underpayment.

### Tokenomics Analysis

| Aspect | Detail |
|--------|--------|
| Supply Model | Fixed; entire supply minted to deployer at construction |
| Total Supply (instance) | 420,000,000,000 FLOKI (18 decimals) |
| Inflation | None — no mint function exists post-deployment |
| Deflation / Burn | None — no public burn function |
| Distribution | 100% to deployer (`msg.sender`); distribution handled off-contract |
| Transfer Tax / Fees | None on transfers; only a one-time native-currency deploy fee |
| Owner Control | None — renounced by design (no ownable module) |
| Centralization Risk | Concentration risk: entire supply held by deployer at launch until distributed |

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
