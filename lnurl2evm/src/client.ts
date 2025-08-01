import { EventSource } from "eventsource";
import { bech32 } from "bech32";
import { secp256k1 } from "@noble/curves/secp256k1";

function fromLnurl(url: string): string {
  return Buffer.from(
    bech32.fromWords(bech32.decode(url.toLowerCase(), 1023).words),
  ).toString("utf-8");
}

function bigIntReviver(key: string, value: unknown): unknown {
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
const { secretKey, publicKey } = secp256k1.keygen();
const key = secp256k1.Point.fromBytes(publicKey).toHex(true);
const es = new EventSource("http://localhost:8091/vault/userOp");

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

      Object.assign(state, { stage: "loginAndPrepare", sessionK1 });

      break;
    }
    case "loginedAndPrepare": {
      const { userOpK1, counterpartyKey, safeAccountParams, lnurl } =
        JSON.parse(event.data, bigIntReviver);

      console.log(safeAccountParams);

      if (stage !== "loginAndPrepare") {
        throw Error("Invalid state transition");
      }

      Object.assign(state, { stage: "logined", counterpartyKey });

      const { userOps } = state;

      if (userOpK1 in userOps) {
        throw Error("UserOp exist");
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
