/**
 * Module hook for plain-node runners (scripts/, harness) that need to load
 * the TypeScript sources without jest.
 *
 * - maps the unpublished `cfd-js` package to the standard BIP-340 shim in
 *   tests/shims/ (test-only scaffolding)
 * - registers ts-node in transpile-only mode (the repo has pre-existing type
 *   errors; behavioral tests must not depend on them)
 */
"use strict";

const Module = require("module");
const path = require("path");

const origResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request, ...args) {
  if (request === "cfd-js") {
    return path.join(__dirname, "..", "shims", "cfd-js.js");
  }
  return origResolveFilename.call(this, request, ...args);
};

require("ts-node").register({
  transpileOnly: true,
  compilerOptions: { module: "commonjs" },
});

module.exports = {};
