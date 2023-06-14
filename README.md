# yAcademy Rate-Limit Nullifier Review <!-- omit in toc -->

**Review Resources:**

[Repo](https://github.com/zBlock-1/circom-rln)

[Docs](https://rate-limiting-nullifier.github.io/rln-docs/rln.html)

[Specs](https://rfc.vac.dev/spec/58/)

**Auditors:**

 - @MarkuSchick
 - @Elpacos

## Table of Contents <!-- omit in toc -->

1. [Review Summary](#review-summary)
2. [Scope](#scope)
3. [Assumptions](#assumptions)
4. [Issues not addressed](#issues-not-addressed)
5. [Tools used](#tools-used)
6. [Code Evaluation Matrix](#code-evaluation-matrix)
7. [Findings Explanation](#findings-explanation)
    - [Low 1](#1-low---unused-public-inputs-optimized-out)
    - [Low 2](#2-low---specification-uses-incorrect-definition-of-identity-commitment)
8. [Final remarks](#final-remarks)
9. [CircomSpect Output](#circomSpect-output)

## Review Summary

**Rate-Limit Nullifier**

The main goal of RLN v2 circuits is to make it possible to have a custom amount of messages (signals) per epoch without using a separate circuit or high-degree polynomials for [Shamir's Secret Sharing](https://rate-limiting-nullifier.github.io/rln-docs/sss.html).

The circuits of the [Rate-Limit Nullifier Github](https://github.com/zBlock-1/circom-rln) were reviewed over 15 days. The code review was performed by 1 auditor between 31st May, 2023 and 14th June, 2023. The repository was static during the review.

## Scope

The scope of the review consisted of the following circuits within the repo:

- **Circuits**
- rln.circom
- utils.circom
- withdraw.circom

The scope of the review consisted of the following contracts at the specific commit:

[37073131b9c5910228ad6bdf0fc50080e507166a](https://github.com/zBlock-1/circom-rln/tree/37073131b9c5910228ad6bdf0fc50080e507166a)

After the findings were presented to the Rate-Limit Nullifier team, fixes were made and included in several PRs.

This review is a code review to identify potential vulnerabilities in the code. The reviewers did not investigate security practices or operational security and assumed that privileged accounts could be trusted. The reviewers did not evaluate the security of the code relative to a standard or specification. The review may not have identified all potential attack vectors or areas of vulnerability.

yAcademy and the auditors make no warranties regarding the security of the code and do not warrant that the code is free from defects. yAcademy and the auditors do not represent nor imply to third parties that the code has been audited nor that the code is free from defects. By deploying or using the code, Rate-Limit Nullifier and users of the contracts agree to use the code at their own risk.


Code Evaluation Matrix
---

| Category                 | Mark      | Description |
| ------------------------ | -------   | ----------- |
| Mathematics              | Good      | Math is relative simple and well described        |
| Complexity               | Very Good      | Clean and simple implementation      |
| Libraries                | Good      | Uses well-tested standard library       |
| Decentralization         | Good      | No privileged actors      |
| Code stability           | Good      | Minimal changes        |
| Documentation            | Very Good | Full documentation and specification  |
| Monitoring               | -         | -                                            |
| Testing and verification | Good   | High coverage, but no automated testing |

## Findings Explanation

Findings are broken down into sections by their respective impact:
 - Critical, High, Medium, Low impact
     - These are findings that range from attacks that may cause loss of funds, impact control/ownership of the contracts, or cause any unintended consequences/actions that are outside the scope of the requirements
 - Gas savings
     - Findings that can improve the gas efficiency of the contracts
 - Informational
     - Findings including recommendations and best practices

---

## Critical Findings

None.

## High Findings

None.

## Medium Findings

None.

## Low Findings

#### REPORTED BY markus, elpacos:

### 1. Low - Unused public inputs ban be optimized out

As described in the [0xParc ZK Bug Tracker](https://github.com/0xPARCzk-bug-tracker#5-unused-public-inputs-optimized-out) the [circom optimizer](https://docs.circom.io/getting-started/compilation-options/#flags-and-options-related-to-the-compilers-output) can remove public inputs that are unused. 

#### Technical Details

The `Withdraw` circuit has a public input `address` that is not used in any constraints. Hence, the circom optimizer might remove this variable. But the address has to be part of the proof to prevent users from front-running a withdraw transaction.

#### Impact

Low. Most libraries (snarkjs, arkworks) [create constraints for all public inputs](https://geometry.xyz/notebook/groth16-malleability). We were unable to replicate this bug with [snarkjs](https://github.com/MarkuSchick/circom-rln/commit/2cc46eddef484721a2d541d37c0c539aa78a0688) and [arkworks](https://github.com/MarkuSchick/circom-rln/blob/arkworks-circom-test/src/main.rs).

#### Recommendation

Add a dummy constraint that uses the public input

```diff	
template Withdraw() {
    signal input identitySecret;
    signal input address; 

+   signal addressSquare;
+   addressSquare <== address * address;
    signal output identityCommitment <== Poseidon(1)([identitySecret]);
}

component main { public [address] } = Withdraw();
```

#### Developer Response


### 2. Low - Specification uses incorrect definition of identity commitment

#### REPORTED BY markus:

The [V2 Specification](https://rfc.vac.dev/spec/58/#rln-diff-flow) uses the `identity_secret` to compute the 
`identity_commitment` instead of the `identity_secret_hash`. The `identity_secret` is already used by the Semaphore circuits and should not get revealed in a Slashing event.


#### Technical Details

RLN [stays compatible](https://rfc.vac.dev/spec/32/#appendix-b-identity-scheme-choice) with Semaphore circuits by deriving the secret ("`identity_secret_hash`") as the hash of the semaphore secrets `identity_nullifier` and `identity_trapdoor`.

RLN V2 improves upon the V1 Protocol by allowing to set different rate-limits for users.
Hence, the definition of the user identity changes from 
the [V1 definition](https://rfc.vac.dev/spec/32/#user-identity):
    
```diff
identity_secret: [identity_nullifier, identity_trapdoor],
identity_secret_hash: poseidonHash(identity_secret),
identity_commitment: poseidonHash([identity_secret_hash])
+rate_commitment: poseidonHash([identity_commitment, userMessageLimit])
```

The [RLN-Diff flow](https://rfc.vac.dev/spec/58/#rln-diff-flow) wrongfully derives the `identity_commitment` from the `identity_secret` directly instead of the `identity_secret_hash`.

#### Impact

Medium. Using the `identity_secret` as *secret value* is problematic since a slasher can now [compromise the semaphore identity](https://rfc.vac.dev/spec/32/#appendix-b-identity-scheme-choice).
The official sdk implements the correct definition of the [identity commitment](https://github.com/Rate-Limiting-Nullifier/rlnjs/blob/7600ff9aeba7fa4699da7ca2428ef7623333d95b/src/common.ts#L19-L32). But an incorrect specification can lead to future implementation bugs. 

#### Recommendation

##### Short term:

Modify the following part of the [V2 Specification](https://rfc.vac.dev/spec/58/#registration-1):

```diff
Registration

-id_commitment in 32/RLN-V1 is equal to poseidonHash=(identity_secret). 
+id_commitment in 32/RLN-V1 is equal to poseidonHash=(identity_secret_hash). 
The goal of RLN-Diff is to set different rate-limits for different users. It follows that id_commitment must somehow depend on the user_message_limit parameter, where 0 <= user_message_limit <= message_limit. There are few ways to do that:
1. Sending identity_secret_hash = poseidonHash(identity_secret, userMessageLimit) 
and zk proof that user_message_limit is valid (is in the right range). This approach requires zkSNARK verification, which is an expensive operation on the blockchain.
-2. Sending the same identity_secret_hash as in 32/RLN-V1 (poseidonHash(identity_secret)) 
+2. Sending the same identity_commitment as in 32/RLN-V1 (poseidonHash(identity_secret_hash)) 
and a user_message_limit publicly to a server or smart-contract where 
-rate_commitment = poseidonHash(identity_secret_hash, userMessageLimit) is calculated. 
+rate_commitment = poseidonHash(identity_commitment, userMessageLimit) is calculated. 
The leaves in the membership Merkle tree would be the rate_commitments of the users. This approach requires additional hashing in the Circuit, but it eliminates the need for zk proof verification for the registration.
```
##### Long-term:

Rename the variable `identity_secret` in the circuit to avoid further confusion with a variable of the same name [derived from Semaphore](https://rfc.vac.dev/spec/32/#appendix-b-identity-scheme-choice).

#### Developer Response



## Gas Savings Findings

### 1. Gas - TODO_Title

TODO

#### Technical Details

TODO

#### Impact

Gas savings.

#### Recommendation

TODO

## Informational Findings

### 1. Informational - TODO_Title

TODO

#### Technical Details

TODO

#### Impact

Informational.

#### Recommendation

TODO

## Final remarks

TODO
