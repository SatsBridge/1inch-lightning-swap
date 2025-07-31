import { EventSource } from "eventsource";
import { bech32 } from "bech32";
import { secp256k1 } from "@noble/curves/secp256k1";

function fromLnurl(url: string): string {
  return Buffer.from(
    bech32.fromWords(bech32.decode(url.toLowerCase(), 1023).words),
  ).toString("utf-8");
}

let state = "init";
const { secretKey, publicKey } = secp256k1.keygen();
const key = secp256k1.Point.fromBytes(publicKey).toHex(true);
const es = new EventSource("http://localhost:8091/vault/userOp");

es.addEventListener("message", async (event) => {
  switch (state) {
    case "init": {
      const { sessionK1, lnurl } = JSON.parse(event.data);
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

      state = "loginAndPrepare";

      break;
    }
    case "loginAndPrepare": {
      const { type, userOpK1, lnurl } = JSON.parse(event.data);

      if (type !== "loginAndPrepare") {
        throw Error("Invalid state");
      }

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

      state = "commit";

      break;
    }
    case "commit": {
      const { type, userOpK1 } = JSON.parse(event.data);

      if (type !== "commit") {
        throw Error("Invalid state");
      }

      state = "final";
    }
  }
});
