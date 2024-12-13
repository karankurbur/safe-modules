// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Safe4337Module.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";

contract PBHSafe4337Module is Safe4337Module {
    using UserOperationLib for PackedUserOperation;

    // TODO: Fix import from parent
    bytes32 private constant SAFE_OP_TYPEHASH = 0xc03dfc11d8b10bf9cf703d558958c8c42777f785d998c62060d85a4f0ef6ea7f;

    address public immutable PBH_SIGNATURE_AGGREGATOR;

    constructor(address _safe, address _pbhSignatureAggregator) Safe4337Module(_safe) {
        PBH_SIGNATURE_AGGREGATOR = _pbhSignatureAggregator;
    }

    /**
     * @dev Validates that the user operation is correctly signed and returns an ERC-4337 packed validation data
     * of `validAfter || validUntil || authorizer`:
     *  - `authorizer`: 20-byte address, 0 for valid signature or 1 to mark signature failure (this module does not make use of signature aggregators).
     *  - `validUntil`: 6-byte timestamp value, or zero for "infinite". The user operation is valid only up to this time.
     *  - `validAfter`: 6-byte timestamp. The user operation is valid only after this time.
     * @param userOp User operation struct.
     * @return validationData An integer indicating the result of the validation.
     */
    function _validateSignatures(PackedUserOperation calldata userOp) internal view returns (uint256 validationData) {
        (bytes memory operationData, uint48 validAfter, uint48 validUntil, bytes calldata signatures, bool isPBH) = _getSafeOp(userOp);

        // The `checkSignatures` function in the Safe contract does not force a fixed size on signature length.
        // A malicious bundler can pad the Safe operation `signatures` with additional bytes, causing the account to pay
        // more gas than needed for user operation validation (capped by `verificationGasLimit`).
        // `_checkSignaturesLength` ensures that there are no additional bytes in the `signature` than are required.
        bool validSignature = _checkSignaturesLength(signatures, ISafe(payable(userOp.sender)).getThreshold());

        try ISafe(payable(userOp.sender)).checkSignatures(keccak256(operationData), operationData, signatures) {} catch {
            validSignature = false;
        }

        address authorizer;

        // If the signature is valid and the userOp is a PBH userOp, return the PBH signature aggregator as the authorizer
        // Else return 0 for valid signature and 1 for invalid signature
        if (isPBH && validSignature) {
            authorizer = PBH_SIGNATURE_AGGREGATOR;
        } else {
            authorizer = !validSignature;
        }

        // The timestamps are validated by the entry point, therefore we will not check them again.
        validationData = _packValidationData(authorizer, validUntil, validAfter);
    }

    /**
     * @dev Decodes an ERC-4337 user operation into a Safe operation. 
     * @param userOp The ERC-4337 user operation.
     * @param checkPBH Should check if the userOp is a PBH userOp. Should only be true when the signer has the Safe has one signer.
     * @return operationData Encoded EIP-712 Safe operation data bytes used for signature verification.
     * @return validAfter The timestamp the user operation is valid from.
     * @return validUntil The timestamp the user operation is valid until.
     * @return signatures The Safe owner signatures extracted from the user operation.
     */
    function _getSafeOp(
        PackedUserOperation calldata userOp
    ) internal view returns (bytes memory operationData, uint48 validAfter, uint48 validUntil, bytes calldata signatures, bool isPBH) {
        // Extract additional Safe operation fields from the user operation signature which is encoded as:
        // `abi.encodePacked(validAfter, validUntil, signatures)`
        {
            bytes calldata sig = userOp.signature;
            validAfter = uint48(bytes6(sig[0:6]));
            validUntil = uint48(bytes6(sig[6:12]));
            isPBH = false;

            // World App Safe's only have one signer and maybe include a PBH bit.
            // Knowing this allows us to know check the length of the signature to know if the PBH bit is present.
            // Remove the PBH bit from the signature before the signature verification.
            if (ISafe(payable(userOp.sender)).getThreshold() == 1 && sig.length == 78) {
                signatures = sig[12:77]; // Extract only the ECDSA signature portion. Remove the PBH flag
                if (sig[77] == 0x01) {
                    isPBH = true;
                }
            } else {
                signatures = sig[12:];
            }
        }

        // It is important that **all** user operation fields are represented in the `SafeOp` data somehow, to prevent
        // user operations from being submitted that do not fully respect the user preferences. The only exception is
        // the `signature` bytes. Note that even `initCode` needs to be represented in the operation data, otherwise
        // it can be replaced with a more expensive initialization that would charge the user additional fees.
        {
            // In order to work around Solidity "stack too deep" errors related to too many stack variables, manually
            // encode the `SafeOp` fields into a memory `struct` for computing the EIP-712 struct-hash. This works
            // because the `EncodedSafeOpStruct` struct has no "dynamic" fields so its memory layout is identical to the
            // result of `abi.encode`-ing the individual fields.
            EncodedSafeOpStruct memory encodedSafeOp = EncodedSafeOpStruct({
                typeHash: SAFE_OP_TYPEHASH,
                safe: userOp.sender,
                nonce: userOp.nonce,
                initCodeHash: keccak256(userOp.initCode),
                callDataHash: keccak256(userOp.callData),
                verificationGasLimit: uint128(userOp.unpackVerificationGasLimit()),
                callGasLimit: uint128(userOp.unpackCallGasLimit()),
                preVerificationGas: userOp.preVerificationGas,
                maxPriorityFeePerGas: uint128(userOp.unpackMaxPriorityFeePerGas()),
                maxFeePerGas: uint128(userOp.unpackMaxFeePerGas()),
                paymasterAndDataHash: keccak256(userOp.paymasterAndData),
                validAfter: validAfter,
                validUntil: validUntil,
                entryPoint: SUPPORTED_ENTRYPOINT
            });

            bytes32 safeOpStructHash;
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                // Since the `encodedSafeOp` value's memory layout is identical to the result of `abi.encode`-ing the
                // individual `SafeOp` fields, we can pass it directly to `keccak256`. Additionally, there are 14
                // 32-byte fields to hash, for a length of `14 * 32 = 448` bytes.
                safeOpStructHash := keccak256(encodedSafeOp, 448)
            }

            operationData = abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), safeOpStructHash);
        }
    }

}
