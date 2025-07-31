export const plugins = [
  [
    "@babel/plugin-transform-runtime",
    { regenerator: false, version: "^7.28.2" },
  ],
  [
    "polyfill-corejs3",
    { method: "usage-pure", proposals: true, version: "^3.43.0" },
  ],
];

export const presets = [
  ["@babel/preset-typescript"],
  ["@babel/preset-env", { bugfixes: true }],
];
