import { EventSource } from "eventsource";
import { bech32 } from "bech32";
import "dotenv/config";
import { secp256k1 } from "@noble/curves/secp256k1";
import { toSafeSmartAccount } from "permissionless/accounts";
import {
  createPublicClient,
  encodeFunctionData,
  extractChain,
  getContract,
  http,
  parseAbi,
  prepareEncodeFunctionData,
} from "viem";
import * as allChains from "viem/chains";

import { hashUserOperation } from "./lib.ts";

function fromLnurl(url: string): string {
  return Buffer.from(
    bech32.fromWords(bech32.decode(url.toLowerCase(), 1023).words),
  ).toString("utf-8");
}

function paramsReviver(_: string, value: unknown): unknown {
  if (typeof value === "string" && /^\d+n$/.test(value)) {
    return BigInt(value.slice(0, -1));
  }

  return value;
}

const state = {
  stage: "init",
  sessionK1: null,
  counterpartyKey: null,
  userOps: {},
};
const chainId = 11155111;
const chain = extractChain({
  chains: Object.values(allChains),
  id: chainId,
});
const publicClient = createPublicClient({
  batch: { multicall: true },
  chain,
  transport: http(`https://${chainId}.rpc.thirdweb.com`),
});

if (chainId !== (await publicClient.getChainId())) {
  throw new Error("Unexpected chainId");
}

const contract = getContract({
  address: "0x779877A7B0D9E8603169DdbD7836e478b4624789", // LINK token
  abi: parseAbi([
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.4.0/contracts/token/ERC20/extensions/IERC20Metadata.sol
    "function name() external view returns (string memory)",
    "function symbol() external view returns (string memory)",
    "function decimals() external view returns (uint8)",
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.4.0/contracts/token/ERC20/IERC20.sol
    "event Transfer(address indexed from, address indexed to, uint256 value)",
    "event Approval(address indexed owner, address indexed spender, uint256 value)",
    "function totalSupply() external view returns (uint256)",
    "function balanceOf(address account) external view returns (uint256)",
    "function transfer(address to, uint256 value) external returns (bool)",
    "function allowance(address owner, address spender) external view returns (uint256)",
    "function approve(address spender, uint256 value) external returns (bool)",
    "function transferFrom(address from, address to, uint256 value) external returns (bool)",
  ]),
  client: publicClient,
});
const transfer = prepareEncodeFunctionData({
  abi: contract.abi,
  functionName: "transfer",
});
const secretKey = process.env.COUNTERPARTY_KEY!;
const publicKey = secp256k1.getPublicKey(secretKey, true);
const key = secp256k1.Point.fromBytes(publicKey).toHex(true);
const prepareUserOp: "yes" | "no" = "no";
const es = new EventSource(
  `http://localhost:8091/vault/userOp?prepare=${prepareUserOp}`,
);

es.addEventListener("message", async (event) => {
  const { stage } = state;
  const notify = JSON.parse(event.data);

  switch (notify.type) {
    case "init": {
      const { sessionK1, chainId: chainIdFromService, lnurl } = notify;

      if (stage !== "init") {
        throw Error("Invalid state transition");
      }

      if (chainIdFromService !== chainId) {
        throw Error("Unexpected chainId");
      }

      const url = fromLnurl(lnurl);
      const signature = secp256k1
        .sign(sessionK1, secretKey, {
          prehash: false,
          lowS: true,
          extraEntropy: true,
        })
        .toHex("der");
      const { status, reason } = await (
        await fetch(`${url}&key=${key}&sig=${signature}`)
      ).json();

      if (status === "ERROR") {
        throw Error(reason);
      } else if (status !== "OK") {
        throw Error("Unknown status");
      }

      // @ts-expect-error: TS2367
      if (prepareUserOp === "yes") {
        Object.assign(state, { stage: "loginAndPrepare", sessionK1 });
      } else if (prepareUserOp === "no") {
        Object.assign(state, { stage: "login", sessionK1 });
      }

      break;
    }
    case "logined": {
      const { counterpartyKey, safeAccountParams, address, prepareUserOpUrl } =
        JSON.parse(event.data, paramsReviver);

      if (stage !== "login") {
        throw Error("Invalid state transition");
      }

      // Validate safeAccountParams there

      const safeAccount = await toSafeSmartAccount({
        ...safeAccountParams,
        client: publicClient,
      });

      if (address !== safeAccount.address) {
        throw Error("Invalid Safe address");
      }

      Object.assign(state, { stage: "logined", counterpartyKey });

      const amount = 1n * 10n ** BigInt(await contract.read.decimals());
      const {
        address: sendMsgTo,
        args,
        value,
      } = (
        await contract.simulate.transfer(
          [
            "0x...", // transfer to address
            amount,
          ],
          { account: address },
        )
      ).request;
      const callData = encodeFunctionData({ ...transfer, args });
      const calls = [
        {
          to: sendMsgTo,
          value,
          data: callData,
        },
      ];
      const encodedCalls = encodeURIComponent(JSON.stringify(calls));
      const {
        userOpK1,
        userOp: userOpParams,
        lnurl,
      } = await fetch(`${prepareUserOpUrl}?calls=${encodedCalls}`)
        .then((response) => response.text())
        .then((text) => JSON.parse(text, paramsReviver));

      const { userOps } = state;

      if (userOpK1 in userOps) {
        throw Error("UserOp exist");
      }

      // Validate userOpParams there

      // Hack
      if (!("factory" in userOpParams)) {
        userOpParams.factory = undefined;
      }

      if (!("factoryData" in userOpParams)) {
        userOpParams.factoryData = undefined;
      }

      const gotUserOpK1 = (
        await hashUserOperation(safeAccountParams, {
          ...userOpParams,
          chainId,
        })
      ).slice(2);

      if (userOpK1 !== gotUserOpK1) {
        throw Error("Invalid UserOp address");
      }

      userOps[userOpK1] = { stage: "prepare" };

      const userOp = userOps[userOpK1];
      const url = fromLnurl(lnurl);
      const signature = secp256k1
        .sign(userOpK1, secretKey, {
          prehash: false,
          lowS: true,
          extraEntropy: true,
        })
        .toHex("der");

      const { status, reason } = await (
        await fetch(`${url}&key=${key}&sig=${signature}`)
      ).json();

      if (status === "ERROR") {
        throw Error(reason);
      } else if (status !== "OK") {
        throw Error("Unknown status");
      }

      userOp.stage = "commit";

      break;
    }
    case "loginedAndPrepare": {
      const {
        userOpK1,
        counterpartyKey,
        safeAccountParams,
        address,
        userOp: userOpParams,
        lnurl,
      } = JSON.parse(event.data, paramsReviver);

      if (stage !== "loginAndPrepare") {
        throw Error("Invalid state transition");
      }

      const { userOps } = state;

      if (userOpK1 in userOps) {
        throw Error("UserOp exist");
      }

      // Validate safeAccountParams and userOpParams there

      const safeAccount = await toSafeSmartAccount({
        ...safeAccountParams,
        client: publicClient,
      });

      if (address !== safeAccount.address) {
        throw Error("Invalid Safe address");
      }

      Object.assign(state, { stage: "logined", counterpartyKey });

      // Hack
      if (!("factory" in userOpParams)) {
        userOpParams.factory = undefined;
      }

      if (!("factoryData" in userOpParams)) {
        userOpParams.factoryData = undefined;
      }

      const gotUserOpK1 = (
        await hashUserOperation(safeAccountParams, {
          ...userOpParams,
          chainId,
        })
      ).slice(2);

      if (userOpK1 !== gotUserOpK1) {
        throw Error("Invalid UserOp address");
      }

      userOps[userOpK1] = { stage: "prepare" };

      const userOp = userOps[userOpK1];
      const url = fromLnurl(lnurl);
      const signature = secp256k1
        .sign(userOpK1, secretKey, {
          prehash: false,
          lowS: true,
          extraEntropy: true,
        })
        .toHex("der");

      const { status, reason } = await (
        await fetch(`${url}&key=${key}&sig=${signature}`)
      ).json();

      if (status === "ERROR") {
        throw Error(reason);
      } else if (status !== "OK") {
        throw Error("Unknown status");
      }

      userOp.stage = "commit";

      break;
    }
    case "commited": {
      const { userOpK1 } = notify;
      const userOp = state.userOps[userOpK1];

      if (stage !== "logined") {
        throw Error("Invalid state transition");
      }

      if (userOp.stage !== "commit") {
        throw Error("Invalid state transition");
      }

      userOp.stage = "commited";

      break;
    }
    case "error": {
      switch (notify.action) {
        case "commit": {
          const { userOpK1 } = notify;
          const userOp = state.userOps[userOpK1];

          if (stage !== "logined") {
            throw Error("Invalid state transition");
          }

          if (userOp.stage !== "commit") {
            throw Error("Invalid state transition");
          }

          userOp.stage = "error";

          break;
        }
      }
    }
  }
});
