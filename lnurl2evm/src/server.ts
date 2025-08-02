import { createSmartAccountClient, toOwner } from "permissionless";
import { createPimlicoClient } from "permissionless/clients/pimlico";
import {
  Account,
  AccountSource,
  Address,
  encodePacked,
  extractChain,
  concat,
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
  parseEther,
  recoverPublicKey,
  serializeSignature,
  toHex,
  Transport,
  WalletClient,
  zeroAddress,
} from "viem";
import {
  entryPoint07Address,
  PrepareUserOperationRequest,
  PrepareUserOperationReturnType,
  SmartAccount,
  WaitForUserOperationReceiptReturnType,
} from "viem/account-abstraction";
import { privateKeyToAccount, publicKeyToAddress } from "viem/accounts";
import {
  toSafeSmartAccount,
  ToSafeSmartAccountParameters,
  ToSafeSmartAccountReturnType,
} from "permissionless/accounts";
import { Chain } from "viem/chains";
import * as allChains from "viem/chains";
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

import { getDefaultAddresses, hashUserOperation } from "./lib.ts";

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
  if (Array.isArray(obj)) {
    const newObj: unknown[] = [];

    for (const [key, child] of obj.entries()) {
      let keyPath: string;

      if (path === "") {
        keyPath = `${key}`;
      } else {
        keyPath = `${path}.${key}`;
      }

      if (typeof child === "object") {
        newObj.push(traverse(child, filter, transform, keyPath));
      } else if (typeof child !== "function") {
        newObj.push(transform(child));
      }
    }

    return newObj;
  } else {
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
}

function bigIntToSting(value: unknown): unknown {
  if (typeof value === "bigint") {
    return value.toString() + "n";
  }

  return value;
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
    bigIntToSting,
  );
}

function userOpTransform<
  const calls extends readonly unknown[],
  const request extends PrepareUserOperationRequest<
    account,
    accountOverride,
    calls
  >,
  account extends SmartAccount | undefined = SmartAccount | undefined,
  accountOverride extends SmartAccount | undefined = undefined,
>(
  userOp: PrepareUserOperationReturnType<
    account,
    accountOverride,
    calls,
    request
  >,
): object {
  return traverse(
    userOp,
    (_) => {
      return true;
    },
    bigIntToSting,
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

async function prepareUserOp<const calls extends readonly unknown[]>(
  sessionK1: string,
  counterpartyAddress: Address,
  calls: calls,
  req: Request,
  res: Response,
): Promise<{
  userOpK1: string;
  safeAccountParams: ToSafeSmartAccountParameters<
    typeof entryPointVersion,
    undefined
  >;
  address: string;
  chainId: number;
  userOp: PrepareUserOperationReturnType<
    ToSafeSmartAccountReturnType<typeof entryPointVersion>,
    undefined,
    calls,
    PrepareUserOperationRequest<
      ToSafeSmartAccountReturnType<typeof entryPointVersion>,
      undefined,
      calls
    >
  >;
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
  // https://docs.pimlico.io/guides/how-to/accounts/use-erc7579-account ???
  const safeAccountParams = {
    client: publicClient,
    entryPoint: {
      address: entryPoint07Address,
      version: entryPointVersion,
    },
    saltNonce: 0n,
    version: safeVersion,
    owners,
    threshold: ownersThreshold,
    safeModuleSetupAddress,
    safe4337ModuleAddress,
    safeProxyFactoryAddress,
    safeSingletonAddress,
    safeModules: [],
    validators: [],
    executors: [],
    fallbacks: [],
    hooks: [],
    attesters: [],
    attestersThreshold: 0,
    multiSendAddress,
    multiSendCallOnlyAddress,
    paymentToken: zeroAddress,
    payment: 0n,
    paymentReceiver: zeroAddress,
    setupTransactions: [],
    validUntil: 0,
    validAfter: 0,
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
  const userOpK1 = (await hashUserOperation(safeAccountParams, {
    ...userOp,
    chainId,
  })).slice(2);
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

  return {
    userOpK1,
    safeAccountParams,
    address: safeAccount.address,
    chainId,
    userOp,
    lnurl,
  };
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
      const { userOpK1, safeAccountParams, address, chainId, userOp, lnurl } =
        await prepareUserOp(sessionK1, counterpartyAddress, calls, req, res);
      const safeAccountParamsTrans =
        safeAccountParamsTransform(safeAccountParams);
      const userOpTrans = userOpTransform(userOp);

      Object.assign(notification, {
        type: "loginedAndPrepare",
        userOpK1,
        counterpartyKey,
        safeAccountParams: safeAccountParamsTrans,
        address,
        chainId,
        userOp: userOpTrans,
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

    const { userOpK1, safeAccountParams, address, chainId, userOp, lnurl } =
      await prepareUserOp(sessionK1, counterpartyAddress, calls, req, res);
    const safeAccountParamsTrans =
      safeAccountParamsTransform(safeAccountParams);
    const userOpTrans = userOpTransform(userOp);

    res.json({
      userOpK1,
      safeAccountParams: safeAccountParamsTrans,
      address,
      chainId,
      userOp: userOpTrans,
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
