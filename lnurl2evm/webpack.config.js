import { fileURLToPath } from "url";
import * as path from "path";

import { TransformAsyncModulesPlugin } from "transform-async-modules-webpack-plugin";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default {
  context: path.resolve(__dirname, "src"),
  entry: {
    server: "./server.ts",
    client: "./client.ts",
  },
  experiments: {
    outputModule: true,
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        exclude: /node_modules/,
        use: {
          loader: "babel-loader",
        },
      },
    ],
  },
  output: {
    module: true,
    path: path.resolve(__dirname, "dist"),
  },
  plugins: [new TransformAsyncModulesPlugin()],
  target: "node20.19",
};
