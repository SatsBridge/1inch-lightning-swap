import { EventSource } from "eventsource";
import { bech32 } from "bech32";
import "dotenv/config";
import { secp256k1 } from "@noble/curves/secp256k1";
import { randomBytes } from "node:crypto";
import {
  HashLock,
  NetworkEnum,
  OrderStatus,
  PresetEnum,
  RelayerRequest,
  SDK,
} from "@1inch/cross-chain-sdk";

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
  orders: {},
};
const secretKey = process.env.COUNTERPARTY_KEY!;
const publicKey = secp256k1.getPublicKey(secretKey, true);
const key = secp256k1.Point.fromBytes(publicKey).toHex(true);
const sdk = new SDK({
  url: "https://api.1inch.dev/fusion-plus",
  authKey: process.env.ONE_INCH_API_KEY!,
});

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const es = new EventSource(`http://localhost:8091/vault?type=custom`);

es.addEventListener("message", async (event) => {
  const { stage } = state;
  const notify = JSON.parse(event.data);

  switch (notify.type) {
    case "init": {
      const { sessionK1, lnurl } = notify;

      if (stage !== "init") {
        throw Error("Invalid state transition");
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

      Object.assign(state, { stage: "login", sessionK1 });

      break;
    }
    case "logined": {
      const { counterpartyKey, counterpartyAddress, prepareCustomUrl } =
        JSON.parse(event.data);

      if (stage !== "login") {
        throw Error("Invalid state transition");
      }

      Object.assign(state, { stage: "logined", counterpartyKey });

      const quote = await sdk.getQuote({
        srcChainId: NetworkEnum.ETHEREUM,
        dstChainId: NetworkEnum.POLYGON,
        srcTokenAddress: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", // USDT
        dstTokenAddress: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
        amount: "1",
        walletAddress: counterpartyAddress,
        enableEstimate: true,
      });
      const preset = PresetEnum.fast;
      const secrets = Array.from({
        length: quote.presets[preset].secretsCount,
      }).map(() => "0x" + randomBytes(32).toString("hex"));
      const hashLock =
        secrets.length === 1
          ? HashLock.forSingleFill(secrets[0])
          : HashLock.forMultipleFills(HashLock.getMerkleLeaves(secrets));
      const secretHashes = secrets.map((s) => HashLock.hashSecret(s));
      const {
        order,
        hash: orderHash,
        quoteId,
      } = await sdk.createOrder(quote, {
        walletAddress: counterpartyAddress,
        hashLock,
        secretHashes,
        preset,
      });

      console.log({ orderHash }, "Order created");

      const orderK1 = orderHash.slice(2);
      const { lnurl } = await fetch(`${prepareCustomUrl}?k1=${orderK1}`)
        .then((response) => response.text())
        .then((text) => JSON.parse(text, paramsReviver));

      const { orders } = state;

      if (orderK1 in orders) {
        throw Error("Order exist");
      }

      orders[orderK1] = { stage: "prepare" };

      const orderState = orders[orderK1];
      const url = fromLnurl(lnurl);
      const signature = secp256k1
        .sign(orderK1, secretKey, {
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

      Object.assign(orderState, {
        stage: "commit",
        quote,
        order,
        quoteId,
        secrets,
        secretHashes,
      });

      break;
    }
    case "commited": {
      const { customK1: orderK1, ethSignature } = notify;
      const orderState = state.orders[orderK1];
      const orderHash = `0x${orderK1}`;
      const { quote, order, quoteId, secrets, secretHashes } = orderState;

      if (stage !== "logined") {
        throw Error("Invalid state transition");
      }

      if (orderState.stage !== "commit") {
        throw Error("Invalid state transition");
      }

      if (!order.multipleFillsAllowed && secretHashes.length > 1) {
        throw new Error(
          "with disabled multiple fills you provided secretHashes > 1",
        );
      } else if (order.multipleFillsAllowed && secretHashes) {
        const secretCount =
          order.escrowExtension.hashLockInfo.getPartsCount() + 1n;

        if (secretHashes.length !== Number(secretCount)) {
          throw new Error(
            "secretHashes length should be equal to number of secrets",
          );
        }
      }

      const orderStruct = order.build();
      const relayerRequest = new RelayerRequest({
        srcChainId: quote.srcChainId,
        order: orderStruct,
        signature: ethSignature,
        quoteId,
        extension: order.extension.encode(),
        secretHashes: secretHashes.length === 1 ? undefined : secretHashes,
      });

      await sdk.api.submitOrder(relayerRequest);

      console.log({ orderHash }, "Order submitted");

      while (true) {
        const secretsToShare = await sdk.getReadyToAcceptSecretFills(orderHash);

        if (secretsToShare.fills.length) {
          for (const { idx } of secretsToShare.fills) {
            await sdk.submitSecret(orderHash, secrets[idx]);

            console.log({ idx }, "Shared secret");
          }
        }

        const { status } = await sdk.getOrderStatus(orderHash);

        if (
          status === OrderStatus.Executed ||
          status === OrderStatus.Expired ||
          status === OrderStatus.Refunded ||
          status === OrderStatus.Cancelled
        ) {
          break;
        }

        await sleep(1000);
      }

      const statusResponse = await sdk.getOrderStatus(orderHash);

      console.log(statusResponse);

      orderState.stage = "commited";

      break;
    }
  }
});
