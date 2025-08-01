import { createSmartAccountClient, toOwner } from "permissionless";
import { createPimlicoClient } from "permissionless/clients/pimlico";
import {
  Account,
  AccountSource,
  Address,
  encodePacked,
  extractChain,
  concat,
  concatHex,
  createPublicClient,
  CustomSource,
  EIP1193Provider,
  fromHex,
  getContract,
  Hex,
  http,
  InvalidAddressError,
  isAddress,
  JsonRpcAccount,
  LocalAccount,
  numberToHex,
  OneOf,
  pad,
  parseEther,
  recoverPublicKey,
  serializeSignature,
  toHex,
  Transport,
  UnionPartialBy,
  WalletClient,
  zeroAddress,
} from "viem";
import {
  entryPoint06Abi,
  entryPoint07Abi,
  entryPoint07Address,
  PrepareUserOperationRequest,
  PrepareUserOperationReturnType,
  SmartAccount,
  UserOperation,
  WaitForUserOperationReceiptReturnType,
} from "viem/account-abstraction";
import { privateKeyToAccount, publicKeyToAddress } from "viem/accounts";
import {
  SafeVersion,
  toSafeSmartAccount,
  ToSafeSmartAccountParameters,
} from "permissionless/accounts";
import { getChainId } from "viem/actions";
import { Chain } from "viem/chains";
import * as allChains from "viem/chains";
import { getAction, hashTypedData } from "viem/utils";
import express, { Request, Response } from "express";
import { Query } from "express-serve-static-core";
import cors from "cors";
import SSE from "express-sse";
import morgan from "morgan";
import { bech32 } from "bech32";
import { webcrypto } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import "dotenv/config";
import { isNone, none, Option, some } from "fp-ts/lib/Option";
import { unsafeUnwrap } from "fp-ts-std/Option";

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

const getDefaultAddresses = (
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

let chainIdMemoized: number;

async function getMemoizedChainId() {
  if (chainId) return chainId;
  chainIdMemoized = publicClient.chain
    ? publicClient.chain.id
    : await getAction(publicClient, getChainId, "getChainId")({});
  return chainIdMemoized;
}

async function hashUserOperation<
  entryPointVersion extends "0.6" | "0.7",
  TErc7579 extends Address | undefined,
>(
  safeAccountParams: ToSafeSmartAccountParameters<entryPointVersion, TErc7579>,
  parameters: UnionPartialBy<UserOperation, "sender"> & {
    chainId?: number | undefined;
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
  const { chainId = await getMemoizedChainId(), ...userOperation } = parameters;

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

type GetAccountReturnType<accountSource extends AccountSource> =
  | (accountSource extends Address ? JsonRpcAccount : never)
  | (accountSource extends CustomSource ? LocalAccount : never);

function toAccount<accountSource extends AccountSource>(
  source: accountSource,
  type: string,
): GetAccountReturnType<accountSource> {
  if (typeof source === "string") {
    if (!isAddress(source, { strict: false }))
      throw new InvalidAddressError({ address: source });
    return {
      address: source,
      type: "json-rpc",
    } as GetAccountReturnType<accountSource>;
  }

  if (!isAddress(source.address, { strict: false }))
    throw new InvalidAddressError({ address: source.address });
  return {
    address: source.address,
    nonceManager: source.nonceManager,
    sign: source.sign,
    signAuthorization: source.signAuthorization,
    signMessage: source.signMessage,
    signTransaction: source.signTransaction,
    signTypedData: source.signTypedData,
    source: "custom",
    type,
  } as GetAccountReturnType<accountSource>;
}

type EthereumProvider = OneOf<
  { request(...args: any): Promise<any> } | EIP1193Provider
>;

export interface TypedRequest<T extends Query> extends Request {
  query: T;
}

type State<
  entryPointVersion extends "0.6" | "0.7",
  TErc7579 extends Address | undefined,
  calls extends unknown[],
  request extends PrepareUserOperationRequest<account, accountOverride, calls>,
  account extends SmartAccount | undefined = SmartAccount | undefined,
  accountOverride extends SmartAccount | undefined = undefined,
> = {
  [sessionK1: string]: {
    sse: SSE;
    counterpartyKey?: string;
    userOps: {
      [userOpK1: string]: {
        safeAccountParams: ToSafeSmartAccountParameters<
          entryPointVersion,
          TErc7579
        >;
        userOp: PrepareUserOperationReturnType<
          account,
          accountOverride,
          calls,
          request
        >;
      };
    };
  };
};

function toLnurl(url: string) {
  return bech32
    .encode("LNURL", bech32.toWords(Buffer.from(url, "utf8")), 1023)
    .toUpperCase();
}

function traverse(
  obj: object,
  filter: (path: string) => boolean,
  transform: (value: unknown) => unknown,
  path: string = "",
): object {
  const newObj = {};

  for (const key in obj) {
    let keyPath: string;

    if (path === "") {
      keyPath = key;
    } else {
      keyPath = `${path}.${key}`;
    }

    if (!filter(keyPath)) {
      continue;
    }

    const child = obj[key];

    if (typeof child === "object") {
      newObj[key] = traverse(child, filter, transform, keyPath);
    } else if (typeof child !== "function") {
      newObj[key] = transform(child);
    }
  }

  return newObj;
}

function safeAccountParamsTransform<
  entryPointVersion extends "0.6" | "0.7",
  TErc7579 extends Address | undefined,
>(
  safeAccountParams: ToSafeSmartAccountParameters<entryPointVersion, TErc7579>,
): object {
  return traverse(
    safeAccountParams,
    (path) => {
      if (path === "client") {
        return false;
      }

      return true;
    },
    (value) => {
      if (typeof value === "bigint") {
        return value.toString() + "n";
      }

      return value;
    },
  );
}

const entryPointVersion = "0.7";
const state: State<
  typeof entryPointVersion,
  undefined,
  unknown[],
  any,
  undefined
> = {};
const serviceOwner = privateKeyToAccount(`0x${process.env.SERVICE_KEY!}`);
const ownersThreshold = 2n;
const chainId = 11155111;
const safeVersion = "1.4.1";
const chain = extractChain({
  chains: Object.values(allChains),
  id: chainId,
});
const publicClient = createPublicClient({
  chain,
  transport: http(`https://${chainId}.rpc.thirdweb.com`),
});
const apiKey = process.env.PIMLICO_API_KEY!;
const paymasterClient = createPimlicoClient({
  entryPoint: {
    address: entryPoint07Address,
    version: entryPointVersion,
  },
  transport: http(`https://api.pimlico.io/v2/${chainId}/rpc?apikey=${apiKey}`),
});

const app = express();

app.use(cors());

app.get(
  "/vault/userOp",
  (
    req: TypedRequest<{
      prepare?: "yes" | "no" | string | any;
      calls?: string | any;
    }>,
    res,
  ) => {
    let { prepare: isPrepareUserOp, calls } = req.query;

    if (isPrepareUserOp !== undefined && typeof isPrepareUserOp !== "string") {
      res
        .status(422)
        .send({ status: "ERROR", reason: "Invalid prepare query type" });

      return;
    }

    if (
      typeof isPrepareUserOp === "string" &&
      isPrepareUserOp !== "yes" &&
      isPrepareUserOp !== "no"
    ) {
      res
        .status(422)
        .send({ status: "ERROR", reason: "Unknown prepare query value" });

      return;
    }

    if (calls !== undefined && isPrepareUserOp === "no") {
      res.status(422).send({
        status: "ERROR",
        reason: "Query calls and prepare=no incompatible",
      });
    }

    if (calls !== undefined && typeof calls !== "string") {
      res
        .status(422)
        .send({ status: "ERROR", reason: "Invalid calls query type" });

      return;
    }

    const sessionK1Material = new Uint8Array(32);

    webcrypto.getRandomValues(sessionK1Material);

    const sessionK1 = toHex(sessionK1Material).slice(2);

    if (sessionK1 in state) {
      res
        .status(500)
        .send({ status: "ERROR", reason: "Internal server error" });

      throw new Error("Session exist");
    }

    const baseUrl = `${process.env.PROTO ?? req.protocol}://${process.env.HOST ?? req.host}/vault/userOp`;
    let url: URL;

    if (isPrepareUserOp === undefined || isPrepareUserOp === "yes") {
      if (isPrepareUserOp === undefined) {
        isPrepareUserOp = "yes";
      }

      if (calls === undefined) {
        url = new URL(
          `${baseUrl}/login?tag=login&k1=${sessionK1}&action=register&_ext_sb_prepare=${isPrepareUserOp}`,
        );
      } else {
        url = new URL(
          `${baseUrl}/login?tag=login&k1=${sessionK1}&action=register&_ext_sb_prepare=${isPrepareUserOp}&_ext_sb_calls=${calls}`,
        );
      }
    } else if (isPrepareUserOp === "no") {
      url = new URL(
        `${baseUrl}/login?tag=login&k1=${sessionK1}&action=register&_ext_sb_prepare=${isPrepareUserOp}`,
      );
    } else {
      throw new Error("Unreachable"); // make TypeScript linter happy
    }

    const lnurl = toLnurl(url.toString());
    const sse = new SSE();

    state[sessionK1] = { sse, userOps: {} };

    req.on("close", () => {
      delete state[sessionK1];
    });
    sse.init(req, res);
    sse.send({ type: "init", sessionK1: sessionK1, lnurl });
  },
);

async function prepareUserOp(
  sessionK1: string,
  counterpartyAddress: Address,
  calls: unknown[],
  req: Request,
  res: Response,
): Promise<{
  userOpK1: string;
  safeAccountParams: ToSafeSmartAccountParameters<
    typeof entryPointVersion,
    undefined
  >;
  address: string;
  lnurl: string;
}> {
  const counterpartyOwner = toAccount(
    {
      address: counterpartyAddress,

      async signMessage(_message) {
        throw new Error("Not supported");
      },

      async signTransaction(_transaction, _options) {
        throw new Error("Not supported");
      },

      async signTypedData(_typedData) {
        throw new Error("Not supported");
      },
    },

    "public",
  );
  const owners = [serviceOwner, counterpartyOwner];
  const {
    safeModuleSetupAddress,
    safe4337ModuleAddress,
    safeProxyFactoryAddress,
    safeSingletonAddress,
    multiSendAddress,
    multiSendCallOnlyAddress,
  } = getDefaultAddresses(safeVersion, entryPointVersion, {});
  const safeAccountParams = {
    client: publicClient,
    entryPoint: {
      address: entryPoint07Address,
      version: entryPointVersion,
    },
    owners,
    saltNonce: 0n,
    threshold: ownersThreshold,
    version: safeVersion,
    safeModuleSetupAddress,
    safe4337ModuleAddress,
    safeProxyFactoryAddress,
    safeSingletonAddress,
    multiSendAddress,
    multiSendCallOnlyAddress,
  } as ToSafeSmartAccountParameters<typeof entryPointVersion, undefined>;
  const safeAccount = await toSafeSmartAccount(safeAccountParams);
  const smartAccountClient = createSmartAccountClient({
    account: safeAccount,
    bundlerTransport: http(
      `https://api.pimlico.io/v2/${chainId}/rpc?apikey=${apiKey}`,
    ),
    chain,
    paymaster: paymasterClient,
    userOperation: {
      estimateFeesPerGas: async () =>
        (await paymasterClient.getUserOperationGasPrice()).fast,
    },
  });
  const userOp = await smartAccountClient.prepareUserOperation({
    calls,
  });
  const userOpHash = await hashUserOperation(safeAccountParams, userOp);
  const userOpK1 = userOpHash.slice(2);
  const { userOps } = state[sessionK1];

  if (userOpK1 in userOps) {
    res.status(500).json({ status: "ERROR", reason: "Internal server error" });

    throw new Error("UserOp exist");
  }

  userOps[userOpK1] = {
    safeAccountParams,
    userOp,
  };

  const url = new URL(
    `${process.env.PROTO ?? req.protocol}://${process.env.HOST ?? req.host}/vault/userOp/commit/${sessionK1}?tag=login&k1=${userOpK1}&action=auth`,
  );
  const lnurl = toLnurl(url.toString());

  return { userOpK1, safeAccountParams, address: safeAccount.address, lnurl };
}

function parseCalls(
  encodedCalls: string | undefined,
  res: Response,
): Option<unknown[]> {
  if (encodedCalls !== undefined && typeof encodedCalls !== "string") {
    res
      .status(422)
      .send({ status: "ERROR", reason: "Invalid _ext_sb_calls query type" });

    return none;
  }

  let calls: unknown[];

  if (encodedCalls !== undefined) {
    let decodedCalls: string;

    try {
      decodedCalls = decodeURIComponent(encodedCalls);
    } catch (e) {
      if (e instanceof URIError) {
        res.status(422).send({
          status: "ERROR",
          reason: `Can't decode _ext_sb_calls: ${e.toString()}`,
        });

        return none;
      }

      res
        .status(500)
        .json({ status: "ERROR", reason: "Internal server error" });

      throw e;
    }

    try {
      calls = JSON.parse(decodedCalls);
    } catch (e) {
      if (e instanceof SyntaxError) {
        res.status(422).send({
          status: "ERROR",
          reason: `Can't deserialize _ext_sb_calls: ${e.toString()}`,
        });

        return none;
      }

      res
        .status(500)
        .json({ status: "ERROR", reason: "Internal server error" });

      throw e;
    }

    if (!Array.isArray(calls)) {
      return none;
    }
  } else {
    calls = [
      {
        to: zeroAddress,
        value: 0,
        data: "0x",
      },
    ];
  }

  return some(calls);
}

app.get(
  "/vault/userOp/login",
  async (
    req: TypedRequest<{
      k1?: string | any;
      key?: string | any;
      sig?: string | any;
      _ext_sb_prepare?: "yes" | "no" | string | any;
      _ext_sb_calls?: string | any;
    }>,
    res,
  ) => {
    const {
      k1: sessionK1,
      key: counterpartyKey,
      sig: signature,
      _ext_sb_prepare: isPrepareUserOp,
      _ext_sb_calls: encodedCalls,
    } = req.query;

    if (sessionK1 === undefined) {
      res.status(422).json({ status: "ERROR", reason: "Missing k1" });

      return;
    }

    if (typeof sessionK1 !== "string") {
      res.status(422).json({
        status: "ERROR",
        reason: "Invalid k1 query type",
      });

      return;
    }

    if (counterpartyKey === undefined) {
      res.status(422).json({ status: "ERROR", reason: "Missing key" });

      return;
    }

    if (typeof counterpartyKey !== "string") {
      res.status(422).json({
        status: "ERROR",
        reason: "Invalid key query type",
      });

      return;
    }

    if (signature === undefined) {
      res.status(422).json({ status: "ERROR", reason: "Missing sig" });

      return;
    }

    if (typeof signature !== "string") {
      res.status(422).json({
        status: "ERROR",
        reason: "Invalid sig query type",
      });

      return;
    }

    if (isPrepareUserOp !== undefined && typeof isPrepareUserOp !== "string") {
      res.status(422).json({
        status: "ERROR",
        reason: "Invalid _ext_sb_prepare query type",
      });

      return;
    }

    if (
      typeof isPrepareUserOp === "string" &&
      isPrepareUserOp !== "yes" &&
      isPrepareUserOp !== "no"
    ) {
      res.status(422).json({
        status: "ERROR",
        reason: "Unknown _ext_sb_prepare query value",
      });

      return;
    }

    if (encodedCalls !== undefined && isPrepareUserOp === "no") {
      res.status(422).send({
        status: "ERROR",
        reason: "Query _ext_sb_calls and _ext_sb_prepare=no incompatible",
      });
    }

    const maybeCalls = parseCalls(encodedCalls, res);

    if (isNone(maybeCalls)) {
      return;
    }

    const calls = unsafeUnwrap(maybeCalls);

    let counterpartyAddress: Address;

    try {
      const uncompressedCounterpartyKey =
        secp256k1.Point.fromHex(counterpartyKey).toHex(false);

      counterpartyAddress = publicKeyToAddress(
        `0x${uncompressedCounterpartyKey}`,
      );
    } catch (_) {
      res.status(422).json({ status: "ERROR", reason: "Invalid key" });

      return;
    }

    if (
      !secp256k1.verify(
        fromHex(`0x${signature}`, "bytes"),
        fromHex(`0x${sessionK1}`, "bytes"),
        fromHex(`0x${counterpartyKey}`, "bytes"),
        {
          prehash: false,
          format: "der",
        },
      )
    ) {
      res.status(422).json({ status: "ERROR", reason: "Invalid sig" });

      return;
    }

    if (!(sessionK1 in state)) {
      res.status(422).json({ status: "ERROR", reason: "Session dont't exist" });

      return;
    }

    const { sse, counterpartyKey: counterpartyKeyInSession } = state[sessionK1];

    if (
      counterpartyKeyInSession !== undefined &&
      counterpartyKey !== counterpartyKeyInSession
    ) {
      res
        .status(422)
        .json({ status: "ERROR", reason: "Incorrect target session" });

      return;
    }

    const notification = {};
    const prepareUrl = new URL(
      `${process.env.PROTO ?? req.protocol}://${process.env.HOST ?? req.host}/vault/userOp/prepare/${sessionK1}`,
    );

    if (isPrepareUserOp === undefined || isPrepareUserOp === "yes") {
      const { userOpK1, safeAccountParams, address, lnurl } =
        await prepareUserOp(sessionK1, counterpartyAddress, calls, req, res);
      const safeAccountParamsTrans =
        safeAccountParamsTransform(safeAccountParams);

      Object.assign(notification, {
        type: "loginedAndPrepare",
        userOpK1,
        counterpartyKey,
        safeAccountParams: safeAccountParamsTrans,
        address,
        prepareUrl,
        lnurl,
      });
    } else if (isPrepareUserOp === "no") {
      Object.assign(notification, {
        type: "logined",
        counterpartyKey,
        prepareUrl,
      });
    } else {
      throw new Error("Unreachable"); // make TypeScript linter happy
    }

    Object.assign(state[sessionK1], {
      counterpartyKey,
    });
    sse.send(notification);
    res.json({ status: "OK" });
  },
);

app.get(
  "/vault/userOp/prepare/:sessionK1",
  async (
    req: TypedRequest<{
      calls?: string | any;
    }>,
    res,
  ) => {
    const { sessionK1 } = req.params;
    const { calls: encodedCalls } = req.query;

    if (!(sessionK1 in state)) {
      res.status(422).json({ status: "ERROR", reason: "Session dont't exist" });

      return;
    }

    const { counterpartyKey } = state[sessionK1];

    if (counterpartyKey === undefined) {
      res.status(422).json({ status: "ERROR", reason: "Key don't revealed" });

      return;
    }

    const maybeCalls = parseCalls(encodedCalls, res);

    if (isNone(maybeCalls)) {
      return;
    }

    const calls = unsafeUnwrap(maybeCalls);

    let counterpartyAddress: Address;

    try {
      const uncompressedCounterpartyKey =
        secp256k1.Point.fromHex(counterpartyKey).toHex(false);

      counterpartyAddress = publicKeyToAddress(
        `0x${uncompressedCounterpartyKey}`,
      );
    } catch (_) {
      res.status(422).json({ status: "ERROR", reason: "Invalid key" });

      return;
    }

    const { userOpK1, safeAccountParams, address, lnurl } = await prepareUserOp(
      sessionK1,
      counterpartyAddress,
      calls,
      req,
      res,
    );
    const safeAccountParamsTrans =
      safeAccountParamsTransform(safeAccountParams);

    res.json({
      userOpK1,
      safeAccountParams: safeAccountParamsTrans,
      address,
      lnurl,
    });
  },
);

app.get(
  "/vault/userOp/commit/:sessionK1",
  async (
    req: TypedRequest<{
      k1?: string | any;
      key?: string | any;
      sig?: string | any;
    }>,
    res,
  ) => {
    const { sessionK1 } = req.params;
    const { k1: userOpK1, key: counterpartyKey, sig: signature } = req.query;

    if (userOpK1 === undefined) {
      res.status(422).json({ status: "ERROR", reason: "Missing k1" });

      return;
    }

    if (typeof userOpK1 !== "string") {
      res.status(422).json({
        status: "ERROR",
        reason: "Invalid k1 query type",
      });

      return;
    }

    if (counterpartyKey === undefined) {
      res.status(422).json({ status: "ERROR", reason: "Missing key" });

      return;
    }

    if (typeof counterpartyKey !== "string") {
      res.status(422).json({
        status: "ERROR",
        reason: "Invalid key query type",
      });

      return;
    }

    if (signature === undefined) {
      res.status(422).json({ status: "ERROR", reason: "Missing sig" });

      return;
    }

    if (typeof signature !== "string") {
      res.status(422).json({
        status: "ERROR",
        reason: "Invalid sig query type",
      });

      return;
    }

    let uncompressedCounterpartyKey: string;
    let counterpartyAddress: Address;

    try {
      uncompressedCounterpartyKey =
        secp256k1.Point.fromHex(counterpartyKey).toHex(false);

      counterpartyAddress = publicKeyToAddress(
        `0x${uncompressedCounterpartyKey}`,
      );
    } catch (_) {
      res.status(422).json({ status: "ERROR", reason: "Invalid key" });

      return;
    }

    if (
      !secp256k1.verify(
        fromHex(`0x${signature}`, "bytes"),
        fromHex(`0x${userOpK1}`, "bytes"),
        fromHex(`0x${counterpartyKey}`, "bytes"),
        {
          prehash: false,
          format: "der",
        },
      )
    ) {
      res.status(422).json({ status: "ERROR", reason: "Invalid sig" });

      return;
    }

    if (!(sessionK1 in state)) {
      res.status(422).json({ status: "ERROR", reason: "Session dont't exist" });

      return;
    }

    const {
      sse,
      counterpartyKey: counterpartyKeyInSession,
      userOps,
    } = state[sessionK1];

    if (counterpartyKey !== counterpartyKeyInSession) {
      res
        .status(422)
        .json({ status: "ERROR", reason: "Incorrect target session" });

      return;
    }

    if (!(userOpK1 in userOps)) {
      res.status(422).json({ status: "ERROR", reason: "UserOp dont't exist" });

      return;
    }

    const { safeAccountParams, userOp } = userOps[userOpK1];
    const { owners } = safeAccountParams;
    const localOwners = await Promise.all(
      owners
        .filter((owner) => {
          if ("type" in owner && owner.type === "local") {
            return true;
          }

          if ("request" in owner) {
            return true;
          }

          if ("account" in owner) {
            // walletClient
            return true;
          }

          return false;
        })
        .map((owner) =>
          toOwner({
            owner: owner as OneOf<
              | LocalAccount
              | EthereumProvider
              | WalletClient<Transport, Chain | undefined, Account>
            >,
          }),
        ),
    );
    const safeAccount = await toSafeSmartAccount(safeAccountParams);
    const smartAccountClient = createSmartAccountClient({
      account: safeAccount,
      bundlerTransport: http(
        `https://api.pimlico.io/v2/${chainId}/rpc?apikey=${apiKey}`,
      ),
      chain,
      paymaster: paymasterClient,
      userOperation: {
        estimateFeesPerGas: async () =>
          (await paymasterClient.getUserOperationGasPrice()).fast,
      },
    });

    if (localOwners.length < ownersThreshold - 1n) {
      res
        .status(500)
        .json({ status: "ERROR", reason: "Internal server error" });

      throw new Error(
        "Owners length mismatch use SafeSmartAccount.signUserOperation from `permissionless/accounts/safe`",
      );
    }

    const { r, s } = secp256k1.Signature.fromHex(signature, "der");
    let ethSignature: Hex;

    for (let yParity = 0; yParity <= 1; yParity++) {
      ethSignature = serializeSignature({
        r: numberToHex(r, { size: 32 }),
        s: numberToHex(s, { size: 32 }),
        yParity,
        to: "hex",
      });

      const recoveredCounterpartyKey = (
        await recoverPublicKey({
          hash: `0x${userOpK1}`,
          signature: ethSignature,
        })
      ).slice(2);

      if (recoveredCounterpartyKey === uncompressedCounterpartyKey) {
        break;
      } else if (yParity === 1) {
        res
          .status(500)
          .json({ status: "ERROR", reason: "Internal server error" });

        throw new Error("No valid signature");
      }
    }

    const { validAfter = 0, validUntil = 0 } = safeAccountParams;
    let unPackedSignatures = [
      {
        signer: counterpartyAddress,
        data: ethSignature!,
      },
    ];

    if (unPackedSignatures.length < ownersThreshold) {
      for (const owner of localOwners) {
        if (owner.sign === undefined) {
          continue;
        }

        unPackedSignatures.push({
          signer: owner.address,
          data: await owner.sign({ hash: `0x${userOpK1}` }),
        });

        if (BigInt(unPackedSignatures.length) === ownersThreshold) {
          break;
        }
      }
    }

    unPackedSignatures.sort((left, right) =>
      left.signer.toLowerCase().localeCompare(right.signer.toLowerCase()),
    );

    const signatures = encodePacked(
      ["uint48", "uint48", "bytes"],
      [
        validAfter,
        validUntil,
        concat(unPackedSignatures.map((signature) => signature.data)),
      ],
    );

    console.log(`Signature: ${signatures}`);

    const userOpHash = await smartAccountClient.sendUserOperation({
      ...userOp,
      signature: signatures,
    });

    console.log(`User operation hash: ${userOpHash}`);

    setTimeout(async () => {
      let txHash: WaitForUserOperationReceiptReturnType;

      try {
        txHash = await smartAccountClient.waitForUserOperationReceipt({
          hash: userOpHash,
        });
      } catch (_) {
        sse.send({ type: "error", action: "commit", userOpK1 });

        return;
      }

      console.log(`Transaction hash: ${txHash.receipt.transactionHash}`);

      sse.send({ type: "commited", userOpK1 });
    });
    setTimeout(() => {
      delete userOps[userOpK1];
    }, 1_800_000); // clear after 30 min
    res.json({ status: "OK" });
  },
);

app.use(morgan("combined"));

app.set("trust proxy", true);

app.listen(process.env.PORT ?? 8000);
