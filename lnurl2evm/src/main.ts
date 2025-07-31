import { createSmartAccountClient, toOwner } from "permissionless";
import { createPimlicoClient } from "permissionless/clients/pimlico";
import {
  extractChain,
  concatHex,
  createPublicClient,
  getContract,
  http,
  parseEther,
  zeroAddress,
  Hex,
  toHex,
  pad,
  concat,
  Address,
  UnionPartialBy,
  OneOf,
  EIP1193Provider,
  LocalAccount,
  WalletClient,
  Transport,
  Account,
  decodeAbiParameters,
  encodeAbiParameters,
  encodePacked,
  fromHex,
  AccountSource,
  JsonRpcAccount,
  CustomSource,
  InvalidAddressError,
  isAddress,
} from "viem";
import {
  entryPoint06Abi,
  entryPoint07Abi,
  entryPoint07Address,
  PrepareUserOperationRequest,
  PrepareUserOperationReturnType,
  SmartAccount,
  UserOperation,
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
  [k1_session: string]: {
    sse: SSE;
    key?: string;
    txs: {
      [k1: string]: {
        safeAccountParams: ToSafeSmartAccountParameters<
          entryPointVersion,
          TErc7579
        >;
        userop: PrepareUserOperationReturnType<
          account,
          accountOverride,
          calls,
          request
        >;
      };
    };
  };
};

function toLnurl(url: String) {
  return bech32
    .encode("LNURL", bech32.toWords(Buffer.from(url, "utf8")), 1023)
    .toUpperCase();
}

let state: State<"0.7", undefined, unknown[], any, undefined> = {};
const serviceOwner = privateKeyToAccount(`0x${process.env.SERVICE_KEY!}`);
//const ownersThreshold = 2n;
const ownersThreshold = 1n;
const entryPointVersion = "0.7";
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

app.get("/vault/tx", (req, res) => {
  const random = new Uint8Array(32);

  webcrypto.getRandomValues(random);

  const k1_session = toHex(random).slice(2);
  const url = new URL(
    `${req.protocol}://${process.env.HOST ?? req.host}/vault/tx/login_and_prepare?tag=login&k1=${k1_session}&action=register`,
  );
  const lnurl = toLnurl(url.toString());
  const sse = new SSE();

  state[k1_session] = { sse, txs: {} };

  req.on("close", () => {
    delete state[k1_session];
  });
  sse.init(req, res);
  sse.send({ k1_session, lnurl });
});

async function prepare_tx(
  k1_session: string,
  key: string,
  address: Address,
  req: Request,
  res: Response,
): Promise<{
  k1_tx: string;
  lnurl: string;
}> {
  const counterparty = toAccount(
    {
      address,

      async signMessage(_message) {
        throw Error("Not supported");
      },

      async signTransaction(_transaction, _options) {
        throw Error("Not supported");
      },

      async signTypedData(_typedData) {
        throw Error("Not supported");
      },
    },

    "public",
  );
  //const owners = [serviceOwner, counterparty];
  const owners = [counterparty];
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
  const userop = await smartAccountClient.prepareUserOperation({
    calls: [
      {
        to: zeroAddress,
        value: 0,
        data: "0x",
      },
    ],
  });
  const hash = await hashUserOperation(safeAccountParams, userop);
  const k1_tx = hash.slice(2);

  Object.assign(state[k1_session], {
    key,
  });
  state[k1_session].txs[k1_tx] = {
    safeAccountParams,
    userop,
  };

  const url = new URL(
    `${req.protocol}://${process.env.HOST ?? req.host}/vault/tx/commit/${k1_session}?tag=login&k1=${k1_tx}&action=auth`,
  );
  const lnurl = toLnurl(url.toString());

  return { k1_tx, lnurl };
}

app.get(
  "/vault/tx/login_and_prepare",
  async (
    req: TypedRequest<{ k1?: string; key?: string; sig?: string }>,
    res,
  ) => {
    const { k1: k1_session, key, sig } = req.query;

    if (k1_session === undefined) {
      res.status(400).send({ status: "ERROR", reason: "Missing k1" });

      return;
    }

    if (key === undefined) {
      res.status(400).send({ status: "ERROR", reason: "Missing key" });

      return;
    }

    if (sig === undefined) {
      res.status(400).send({ status: "ERROR", reason: "Missing sig" });

      return;
    }

    let address: Address;

    try {
      address = publicKeyToAddress(`0x${key}`);
    } catch (_) {
      res.status(422).send({ status: "ERROR", reason: "Invalid key" });

      return;
    }

    if (
      secp256k1.verify(
        fromHex(`0x${sig}`, "bytes"),
        fromHex(`0x${k1_session}`, "bytes"),
        fromHex(`0x${key}`, "bytes"),
        {
          prehash: false,
          format: "der",
        },
      )
    ) {
      const { k1_tx, lnurl } = await prepare_tx(
        k1_session,
        key,
        address,
        req,
        res,
      );

      if (k1_session in state) {
        state[k1_session].sse.send({
          type: "login_and_prepare",
          k1_tx,
          key,
          lnurl,
        });
      } else {
        res
          .status(422)
          .send({ status: "ERROR", reason: "Session dont't exist" });

        return;
      }

      res.send({ status: "OK" });
    } else {
      res.status(422).send({ status: "ERROR", reason: "Invalid sig 2" });
    }
  },
);

app.get("/vault/tx/prepare/:k1_session", async (req, res) => {
  const { k1_session } = req.params;

  if (!(k1_session in state)) {
    res.status(422).send({ status: "ERROR", reason: "Session dont't exist" });

    return;
  }

  const { key, txs } = state[k1_session];

  if (key === undefined) {
    res.status(422).send({ status: "ERROR", reason: "Key don't revealed" });

    return;
  }

  let address: Address;

  try {
    address = publicKeyToAddress(`0x${key}`);
  } catch (_) {
    res.status(422).send({ status: "ERROR", reason: "Invalid key" });

    return;
  }

  const { k1_tx, lnurl } = await prepare_tx(k1_session, key, address, req, res);

  res.send({ k1_tx, lnurl });
});

app.get(
  "/vault/tx/commit/:k1_session",
  async (
    req: TypedRequest<{ k1?: string; key?: string; sig?: string }>,
    res,
  ) => {
    const { k1_session } = req.params;
    const { k1: k1_tx, key, sig } = req.query;

    if (k1_tx === undefined) {
      res.status(400).send({ status: "ERROR", reason: "Missing k1" });

      return;
    }

    if (key === undefined) {
      res.status(400).send({ status: "ERROR", reason: "Missing key" });

      return;
    }

    if (sig === undefined) {
      res.status(400).send({ status: "ERROR", reason: "Missing sig" });

      return;
    }

    if (!(k1_session in state)) {
      res.status(422).send({ status: "ERROR", reason: "Session dont't exist" });

      return;
    }

    const { key: session_key, txs } = state[k1_session];

    if (key !== session_key) {
      res
        .status(422)
        .send({ status: "ERROR", reason: "Incorrect target session" });

      return;
    }

    let address: Address;

    try {
      address = publicKeyToAddress(`0x${key}`);
    } catch (_) {
      res.status(422).send({ status: "ERROR", reason: "Invalid key" });

      return;
    }

    if (
      secp256k1.verify(
        fromHex(`0x${sig}`, "bytes"),
        fromHex(`0x${k1_tx}`, "bytes"),
        fromHex(`0x${key}`, "bytes"),
        {
          prehash: false,
          format: "der",
        },
      )
    ) {
      if (!(k1_tx in txs)) {
        res.status(422).send({ status: "ERROR", reason: "Tx dont't exist" });

        return;
      }

      const { safeAccountParams, userop } = txs[k1_tx];
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
      const safeAccount = await toSafeSmartAccount(safeAccountParams);\
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

      if (localOwners.length < Number(ownersThreshold) - 1) {
        res
          .status(500)
          .send({ status: "ERROR", reason: "Internal server error" });

        throw new Error(
          "Owners length mismatch use SafeSmartAccount.signUserOperation from `permissionless/accounts/safe`",
        );
      }

      const signature = secp256k1.Signature.fromBytes(
        fromHex(`0x${sig}`, "bytes"),
        "der",
      ).toHex("compact");

      let signatures: Hex = encodeAbiParameters(
        [
          {
            components: [
              { type: "address", name: "signer" },
              { type: "bytes", name: "data" },
            ],
            name: "signatures",
            type: "tuple[]",
          },
        ],
        [
          [
            {
              signer: address,
              data: `0x${signature}`,
            },
          ],
        ],
      );

      for (const owner of localOwners) {
        const { validAfter = 0, validUntil = 0 } = safeAccountParams;
        const existingSignatures = signatures;
        const localOwnersForSig = [
          await toOwner({
            owner: owner as OneOf<LocalAccount | EthereumProvider>,
          }),
        ];

        let unPackedSignatures: readonly { signer: Address; data: Hex }[] = [];

        if (existingSignatures) {
          const decoded = decodeAbiParameters(
            [
              {
                components: [
                  { type: "address", name: "signer" },
                  { type: "bytes", name: "data" },
                ],
                name: "signatures",
                type: "tuple[]",
              },
            ],
            existingSignatures,
          );

          unPackedSignatures = decoded[0];
        }

        const newSignatures: { signer: Address; data: Hex }[] = [
          ...unPackedSignatures,
          ...(await Promise.all(
            localOwnersForSig.map(async (localOwner) => ({
              signer: localOwner.address,
              data: await localOwner.sign!({ hash: `0x${k1_tx}` }),
            })),
          )),
        ];

        if (newSignatures.length !== owners.length) {
          signatures = encodeAbiParameters(
            [
              {
                components: [
                  { type: "address", name: "signer" },
                  { type: "bytes", name: "data" },
                ],
                name: "signatures",
                type: "tuple[]",
              },
            ],
            [newSignatures],
          );
        } else {
          newSignatures.sort((left, right) =>
            left.signer.toLowerCase().localeCompare(right.signer.toLowerCase()),
          );
          const signatureBytes = concat(newSignatures.map((sig) => sig.data));

          signatures = encodePacked(
            ["uint48", "uint48", "bytes"],
            [validAfter, validUntil, signatureBytes],
          );
        }
      }

      if (!signatures) {
        res
          .status(500)
          .send({ status: "ERROR", reason: "Internal server error" });

        throw new Error("No signatures found");
      }

      console.log(`Signature: ${signatures}`);

      const userOphash = await smartAccountClient.sendUserOperation({
        ...userop,
        signature: signatures,
      });

      console.log(`User operation hash: ${userOphash}`);

      const txHash = await smartAccountClient.waitForUserOperationReceipt({
        hash: userOphash,
      });

      console.log(`Transaction hash: ${txHash.receipt.transactionHash}`);

      if (k1_session in state) {
        state[k1_session].sse.send({ type: "commit", k1_tx });

        delete state[k1_session].txs[k1_tx];
      } else {
        res
          .status(422)
          .send({ status: "ERROR", reason: "Session dont't exist" });

        return;
      }

      res.send({ status: "OK" });
    } else {
      res.status(422).send({ status: "ERROR", reason: "Invalid sig" });
    }
  },
);

app.use(morgan("combined"));

app.listen(process.env.PORT ?? 8000);
