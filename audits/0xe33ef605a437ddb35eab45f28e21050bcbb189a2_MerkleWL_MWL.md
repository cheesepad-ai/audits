# 🔍 MerkleWL (MWL) - AI Security Audit

## 📊 Audit Information

| Property | Value |
|----------|-------|
| **Audit Revision** | 1 |
| **Audit Date** | 2026-07-16T22:06:25.531Z (UTC) |
| **Blockchain** | BNB Smart Chain Testnet |
| **Contract Address** | `0xe33ef605a437ddb35eab45f28e21050bcbb189a2` |
| **AI Models Used** | 1 model(s) |

## 📋 Token Information

| Property | Value |
|----------|-------|
| **Token Name** | MerkleWL |
| **Symbol** | MWL |

---

## 🤖 Analysis #1: Claude Opus 4.8

**Completed:** Thu, 16 Jul 2026 22:06:25 GMT

### Summary

`MockERC20` is a minimal ERC-20 token built on OpenZeppelin Contracts (ERC20 v5.3.0). It adds a custom `decimals` value, mints an initial supply to the deployer, and exposes an unrestricted public `mint` function. The OpenZeppelin base is well-audited and standard. The dominant issue is the permissionless `mint` function, which allows anyone to create unlimited tokens. On-chain this is deployed as "MerkleWL" (MWL) with 18 decimals and a 1,000,000-token supply, consistent with a mock/test or whitelist utility token.

### Risk Assessment

**Token Quick Facts**

| Property | Value |
|----------|-------|
| Name | MerkleWL |
| Symbol | MWL |
| Decimals | 18 |
| Total Supply | 1,000,000 MWL |
| Base | OpenZeppelin ERC20 v5.3.0 |
| Mintable | Yes — unrestricted (public) |
| Burnable | Not exposed publicly |
| Pausable | No |
| Access Control | None |
| Upgradeable | No |

**Security Assessment**

| Category | Status |
|----------|--------|
| Reentrancy | ✅ No external calls |
| Access Control | ❌ Public `mint`, no ownership |
| Integer Overflow | ✅ Solidity ≥0.8 + OZ checks |
| Supply Manipulation | ❌ Anyone can mint arbitrarily |
| Standard Compliance | ✅ ERC-20 compliant |
| Fee-on-transfer / Rebasing | ✅ None |
| Blacklist / Trading Restrictions | ✅ None |

### On-Chain Function Results

| Function | On-Chain Value | Explanation |
|----------|----------------|-------------|
| `decimals()` | `18` | Token uses 18 decimal places for display, standard for ERC-20 tokens. |
| `name()` | `MerkleWL` | Human-readable token name; suggests a Merkle whitelist utility token. |
| `symbol()` | `MWL` | Ticker symbol for the token. |
| `totalSupply()` | `1000000000000000000000000` | Equals 1,000,000 tokens; but supply is inflatable via public `mint`. |

### Additional Read Functions

| Function | Parameters | Return Type |
|----------|------------|-------------|
| `allowance(address, address)` | address, address | `uint256` |
| `balanceOf(address)` | address | `uint256` |

### Findings Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 0 |
| 🟡 Medium | 1 |
| 🟢 Low | 1 |

### Critical Findings

#### 🔴 [C-1] Unrestricted Public `mint` Allows Unlimited Token Creation

**Description:**
The `mint` function has no access control. Any external caller can mint an arbitrary number of tokens to any address.

```solidity
function mint(address to, uint256 amount) external {
    _mint(to, amount);
}
```

There is no `onlyOwner`, role gating, supply cap, or any restriction.

**Impact:**
Anyone can inflate the supply infinitely, diluting all holders and rendering the token economically worthless. If the token gates access (e.g., a Merkle whitelist "MerkleWL") or has any value, an attacker can mint to bypass controls or dump. This is catastrophic for any production use.

**Location:**
`contracts/mock/MockERC20.sol` — `mint(address,uint256)`.

**💡 Recommendation:**
> **Action Required:** Restrict minting. Inherit `Ownable` (or `AccessControl`) and add `onlyOwner`/role modifier to `mint`. If this contract is only ever a test mock, ensure it is never deployed to mainnet or used to represent real value; the on-chain deployment indicates it may already be live, so migrate to an access-controlled token.

---

### High Findings

None.

### Medium Findings

#### 🟡 [M-1] Test/Mock Contract Deployed to a Live Network

**Description:**
The contract is named `MockERC20` and lives under `contracts/mock/`, indicating it is intended for testing. However, on-chain results confirm it is deployed and responding to calls at block 119543396 with a real name/symbol ("MerkleWL"/"MWL").

**Impact:**
Mock contracts typically omit production safeguards (as seen with the open `mint`). Using a mock in production exposes users to all its unhardened behaviors and the C-1 minting risk.

**Location:**
`contracts/mock/MockERC20.sol` (contract-level).

**💡 Recommendation:**
> **Action Required:** Do not use mock contracts in production. Deploy a purpose-built, access-controlled, and audited token contract instead, and clearly separate test artifacts from deployable code.

---

### Low Findings

#### 🟢 [L-1] No Maximum Supply Cap

**Description:**
The contract defines no `MAX_SUPPLY` constant or cap check in `mint`. Even if minting were access-controlled, supply could grow without an on-chain, enforceable ceiling.

**Impact:**
Holders have no cryptographic guarantee of scarcity; supply expectations rely entirely on off-chain trust in the minter.

**Location:**
`contracts/mock/MockERC20.sol` — `mint` / constructor.

**💡 Recommendation:**
> **Action Required:** If scarcity matters, introduce a `MAX_SUPPLY` constant and require `totalSupply() + amount <= MAX_SUPPLY` in `mint`.

---

### Good Practices

- Uses a current, well-audited OpenZeppelin ERC20 base (v5.3.0) with ERC-6093 custom errors.
- Solidity `^0.8.28` provides built-in overflow/underflow protection.
- Correctly overrides `decimals()` with `virtual override` to support a configurable value.
- No custom transfer hooks, fee-on-transfer, rebasing, blacklist, or hidden logic that could break composability.
- Standard, fully ERC-20 compliant interface surface.

### Tokenomics Analysis

| Aspect | Detail |
|--------|--------|
| Initial Supply | 1,000,000 MWL minted to deployer at construction |
| Supply Model | Inflationary / uncapped |
| Minting | Public, unrestricted — any address can mint any amount |
| Burning | Not publicly exposed (`_burn` internal, unused) |
| Distribution | Entire initial supply to deployer (`msg.sender`) |
| Ownership / Admin | None — no owner, roles, or admin controls |
| Value Integrity | Undermined by open `mint`; supply is not trustworthy |

The tokenomics are unsound for any value-bearing use: the fixed-looking 1,000,000 supply is illusory because anyone can mint arbitrarily via C-1. Combined with the absence of a cap (L-1) and admin controls, holders have no scarcity or governance guarantees. This structure is acceptable only for local testing, not production.

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
