import {
  SafeVersion,
  ToSafeSmartAccountParameters,
} from "permissionless/accounts";
import {
  Address,
  concat,
  concatHex,
  hashTypedData,
  Hex,
  pad,
  toHex,
  UnionPartialBy,
} from "viem";
import {
  entryPoint06Abi,
  entryPoint07Abi,
  entryPoint07Address,
  UserOperation,
} from "viem/account-abstraction";

const EIP712_SAFE_OPERATION_TYPE_V06 = {
  SafeOp: [
    { type: "address", name: "safe" },
    { type: "uint256", name: "nonce" },
    { type: "bytes", name: "initCode" },
    { type: "bytes", name: "callData" },
    { type: "uint256", name: "callGasLimit" },
    { type: "uint256", name: "verificationGasLimit" },
    { type: "uint256", name: "preVerificationGas" },
    { type: "uint256", name: "maxFeePerGas" },
    { type: "uint256", name: "maxPriorityFeePerGas" },
    { type: "bytes", name: "paymasterAndData" },
    { type: "uint48", name: "validAfter" },
    { type: "uint48", name: "validUntil" },
    { type: "address", name: "entryPoint" },
  ],
};

const EIP712_SAFE_OPERATION_TYPE_V07 = {
  SafeOp: [
    { type: "address", name: "safe" },
    { type: "uint256", name: "nonce" },
    { type: "bytes", name: "initCode" },
    { type: "bytes", name: "callData" },
    { type: "uint128", name: "verificationGasLimit" },
    { type: "uint128", name: "callGasLimit" },
    { type: "uint256", name: "preVerificationGas" },
    { type: "uint128", name: "maxPriorityFeePerGas" },
    { type: "uint128", name: "maxFeePerGas" },
    { type: "bytes", name: "paymasterAndData" },
    { type: "uint48", name: "validAfter" },
    { type: "uint48", name: "validUntil" },
    { type: "address", name: "entryPoint" },
  ],
};

const SAFE_VERSION_TO_ADDRESSES_MAP: {
  [key in SafeVersion]: {
    [key in "0.6" | "0.7"]: {
      SAFE_MODULE_SETUP_ADDRESS: Address;
      SAFE_4337_MODULE_ADDRESS: Address;
      SAFE_PROXY_FACTORY_ADDRESS: Address;
      SAFE_SINGLETON_ADDRESS: Address;
      MULTI_SEND_ADDRESS: Address;
      MULTI_SEND_CALL_ONLY_ADDRESS: Address;
    };
  };
} = {
  "1.4.1": {
    "0.6": {
      SAFE_MODULE_SETUP_ADDRESS: "0x8EcD4ec46D4D2a6B64fE960B3D64e8B94B2234eb",
      SAFE_4337_MODULE_ADDRESS: "0xa581c4A4DB7175302464fF3C06380BC3270b4037",
      SAFE_PROXY_FACTORY_ADDRESS: "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67",
      SAFE_SINGLETON_ADDRESS: "0x41675C099F32341bf84BFc5382aF534df5C7461a",
      MULTI_SEND_ADDRESS: "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526",
      MULTI_SEND_CALL_ONLY_ADDRESS:
        "0x9641d764fc13c8B624c04430C7356C1C7C8102e2",
    },
    "0.7": {
      SAFE_MODULE_SETUP_ADDRESS: "0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47",
      SAFE_4337_MODULE_ADDRESS: "0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226",
      SAFE_PROXY_FACTORY_ADDRESS: "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67",
      SAFE_SINGLETON_ADDRESS: "0x41675C099F32341bf84BFc5382aF534df5C7461a",
      MULTI_SEND_ADDRESS: "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526",
      MULTI_SEND_CALL_ONLY_ADDRESS:
        "0x9641d764fc13c8B624c04430C7356C1C7C8102e2",
    },
  },
};

export const getDefaultAddresses = (
  safeVersion: SafeVersion,
  entryPointVersion: "0.6" | "0.7",
  {
    addModuleLibAddress: _addModuleLibAddress,
    safeModuleSetupAddress: _safeModuleSetupAddress,
    safe4337ModuleAddress: _safe4337ModuleAddress,
    safeProxyFactoryAddress: _safeProxyFactoryAddress,
    safeSingletonAddress: _safeSingletonAddress,
    multiSendAddress: _multiSendAddress,
    multiSendCallOnlyAddress: _multiSendCallOnlyAddress,
  }: {
    addModuleLibAddress?: Address;
    safeModuleSetupAddress?: Address;
    safe4337ModuleAddress?: Address;
    safeProxyFactoryAddress?: Address;
    safeSingletonAddress?: Address;
    multiSendAddress?: Address;
    multiSendCallOnlyAddress?: Address;
  },
) => {
  const safeModuleSetupAddress =
    _safeModuleSetupAddress ??
    _addModuleLibAddress ??
    SAFE_VERSION_TO_ADDRESSES_MAP[safeVersion][entryPointVersion]
      .SAFE_MODULE_SETUP_ADDRESS;
  const safe4337ModuleAddress =
    _safe4337ModuleAddress ??
    SAFE_VERSION_TO_ADDRESSES_MAP[safeVersion][entryPointVersion]
      .SAFE_4337_MODULE_ADDRESS;
  const safeProxyFactoryAddress =
    _safeProxyFactoryAddress ??
    SAFE_VERSION_TO_ADDRESSES_MAP[safeVersion][entryPointVersion]
      .SAFE_PROXY_FACTORY_ADDRESS;
  const safeSingletonAddress =
    _safeSingletonAddress ??
    SAFE_VERSION_TO_ADDRESSES_MAP[safeVersion][entryPointVersion]
      .SAFE_SINGLETON_ADDRESS;
  const multiSendAddress =
    _multiSendAddress ??
    SAFE_VERSION_TO_ADDRESSES_MAP[safeVersion][entryPointVersion]
      .MULTI_SEND_ADDRESS;
  const multiSendCallOnlyAddress =
    _multiSendCallOnlyAddress ??
    SAFE_VERSION_TO_ADDRESSES_MAP[safeVersion][entryPointVersion]
      .MULTI_SEND_CALL_ONLY_ADDRESS;

  return {
    safeModuleSetupAddress,
    safe4337ModuleAddress,
    safeProxyFactoryAddress,
    safeSingletonAddress,
    multiSendAddress,
    multiSendCallOnlyAddress,
  };
};

function getPaymasterAndData(unpackedUserOperation: UserOperation) {
  return unpackedUserOperation.paymaster
    ? concat([
        unpackedUserOperation.paymaster,
        pad(
          toHex(
            unpackedUserOperation.paymasterVerificationGasLimit || BigInt(0),
          ),
          {
            size: 16,
          },
        ),
        pad(toHex(unpackedUserOperation.paymasterPostOpGasLimit || BigInt(0)), {
          size: 16,
        }),
        unpackedUserOperation.paymasterData || ("0x" as Hex),
      ])
    : "0x";
}

export async function hashUserOperation<
  entryPointVersion extends "0.6" | "0.7",
  TErc7579 extends Address | undefined,
>(
  safeAccountParams: ToSafeSmartAccountParameters<entryPointVersion, TErc7579>,
  parameters: UnionPartialBy<UserOperation, "sender"> & {
    chainId: number;
  },
) {
  const {
    version,
    safe4337ModuleAddress: _safe4337ModuleAddress,
    validAfter = 0,
    validUntil = 0,
  } = safeAccountParams;
  const entryPoint = {
    address: safeAccountParams.entryPoint?.address ?? entryPoint07Address,
    abi:
      (safeAccountParams.entryPoint?.version ?? "0.7") === "0.6"
        ? entryPoint06Abi
        : entryPoint07Abi,
    version: safeAccountParams.entryPoint?.version ?? "0.7",
  } as const;
  const { safe4337ModuleAddress } = getDefaultAddresses(
    version,
    entryPoint.version,
    {
      safe4337ModuleAddress: _safe4337ModuleAddress,
    },
  );
  const { chainId, ...userOperation } = parameters;
  const message = {
    safe: userOperation.sender,
    callData: userOperation.callData,
    nonce: userOperation.nonce,
    initCode: userOperation.initCode ?? "0x",
    maxFeePerGas: userOperation.maxFeePerGas,
    maxPriorityFeePerGas: userOperation.maxPriorityFeePerGas,
    preVerificationGas: userOperation.preVerificationGas,
    verificationGasLimit: userOperation.verificationGasLimit,
    callGasLimit: userOperation.callGasLimit,
    paymasterAndData: userOperation.paymasterAndData ?? "0x",
    validAfter: validAfter,
    validUntil: validUntil,
    entryPoint: entryPoint.address,
  };

  if ("initCode" in userOperation) {
    message.paymasterAndData = userOperation.paymasterAndData ?? "0x";
  }

  if ("factory" in userOperation) {
    if (userOperation.factory && userOperation.factoryData) {
      message.initCode = concatHex([
        userOperation.factory,
        userOperation.factoryData,
      ]);
    }

    if (!userOperation.sender) {
      throw new Error("Sender is required");
    }

    message.paymasterAndData = getPaymasterAndData({
      ...userOperation,
      sender: userOperation.sender,
    });
  }

  const hash = hashTypedData({
    domain: {
      chainId,
      verifyingContract: safe4337ModuleAddress,
    },
    types:
      entryPoint.version === "0.6"
        ? EIP712_SAFE_OPERATION_TYPE_V06
        : EIP712_SAFE_OPERATION_TYPE_V07,
    primaryType: "SafeOp",
    message: message,
  });

  return hash;
}
