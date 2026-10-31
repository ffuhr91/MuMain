#!/usr/bin/env node
// Generates the launcher update manifest (update.json) for a release.
//
// Usage:
//   SEMANTIC_RELEASE_VERSION=1.2.3 \
//     node tools/generate-update-manifest.mjs \
//       MuMain-windows-native-x64-release-editor-off-no-data.tar.gz \
//       MuMain-linux-native-x64-release-editor-off-no-data.tar.gz \
//       MuMain-macos-native-arm64-release-editor-off-no-data.tar.gz \
//       [data.json]
//
// The three runtime archives are required. data.json is optional: when the
// file is absent the data artifact is omitted instead of failing the release.
//
// The emitted document matches the schema documented in launcher/main.go:
//   {
//     "version", "channel", "publishedAt", "signature"?,
//     "artifacts": [{ "kind", "os", "arch", "url", "hash", "size", "zsync"? }]
//   }
//
// Output is deterministic: keys are written in schema order, JSON is indented
// with two spaces, encoded as UTF-8 without a BOM and terminated by one newline.
//
// TODO(minisign): sign via @semantic-release/exec with LAUNCHER_SIGNING_KEY secret
// and add the base64 Ed25519 signature to the "signature" field once the
// launcher's LAUNCHER_SIGNING_PUBKEY is configured.

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const RELEASE_BASE_URL = "https://github.com/ffuhr91/MuMain/releases/download";

const RUNTIME_TARGETS = [
  { os: "windows", arch: "x64" },
  { os: "linux", arch: "x64" },
  { os: "macos", arch: "arm64" },
];

function fail(message) {
  console.error(`generate-update-manifest: ${message}`);
  process.exit(1);
}

function resolveVersion() {
  const candidates = [
    process.env.SEMANTIC_RELEASE_VERSION,
    process.env.NEXT_RELEASE_VERSION,
  ];
  for (const candidate of candidates) {
    const value = (candidate ?? "").trim().replace(/^v/, "");
    if (value) {
      return value;
    }
  }
  fail(
    "release version is missing; set SEMANTIC_RELEASE_VERSION (or NEXT_RELEASE_VERSION)",
  );
}

function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    createReadStream(filePath)
      .on("error", reject)
      .on("data", (chunk) => hash.update(chunk))
      .on("end", () => resolve(hash.digest("hex")));
  });
}

async function fileSize(filePath) {
  const info = await stat(filePath);
  if (!info.isFile()) {
    fail(`not a regular file: ${filePath}`);
  }
  return info.size;
}

async function runtimeArtifact(target, filePath, version) {
  let size;
  let hash;
  try {
    [size, hash] = await Promise.all([fileSize(filePath), hashFile(filePath)]);
  } catch (error) {
    fail(`cannot read runtime archive ${filePath}: ${error.message}`);
  }
  const fileName = path.basename(filePath);
  return {
    kind: "runtime",
    os: target.os,
    arch: target.arch,
    url: `${RELEASE_BASE_URL}/v${version}/${fileName}`,
    hash,
    size,
  };
}

async function dataArtifact(dataJsonPath) {
  if (!dataJsonPath) {
    console.log("generate-update-manifest: no data.json supplied; skipping data artifact");
    return null;
  }

  let raw;
  try {
    raw = await readFile(dataJsonPath, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") {
      console.log(
        `generate-update-manifest: ${dataJsonPath} not found; skipping data artifact`,
      );
      return null;
    }
    fail(`cannot read ${dataJsonPath}: ${error.message}`);
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch (error) {
    fail(`cannot parse ${dataJsonPath}: ${error.message}`);
  }

  for (const field of ["url", "sha256", "size"]) {
    if (data[field] === undefined || data[field] === null || data[field] === "") {
      fail(`${dataJsonPath} is missing "${field}"`);
    }
  }
  if (!/^[0-9a-fA-F]{64}$/.test(String(data.sha256))) {
    fail(`${dataJsonPath} has an invalid sha256 value`);
  }
  if (!Number.isInteger(data.size) || data.size < 0) {
    fail(`${dataJsonPath} has an invalid size value`);
  }

  const artifact = {
    kind: "data",
    os: "any",
    arch: "any",
    url: String(data.url),
    hash: String(data.sha256).toLowerCase(),
    size: data.size,
  };
  if (artifact.url.endsWith(".tar.gz")) {
    artifact.zsync = `${artifact.url}.zsync`;
  }
  return artifact;
}

async function main() {
  const [windowsTar, linuxTar, macosTar, dataJsonPath] = process.argv.slice(2);
  const runtimePaths = [windowsTar, linuxTar, macosTar];

  if (runtimePaths.some((value) => !value)) {
    fail(
      "usage: generate-update-manifest.mjs <windows.tar.gz> <linux.tar.gz> <macos.tar.gz> [data.json]",
    );
  }

  const version = resolveVersion();
  const artifacts = [];
  for (let i = 0; i < RUNTIME_TARGETS.length; i += 1) {
    artifacts.push(await runtimeArtifact(RUNTIME_TARGETS[i], runtimePaths[i], version));
  }

  const data = await dataArtifact(dataJsonPath);
  if (data) {
    artifacts.push(data);
  }

  const manifest = {
    version,
    channel: "stable",
    publishedAt: new Date().toISOString(),
    // "signature" is intentionally omitted until signing is enabled.
    artifacts,
  };

  const outputPath = process.env.UPDATE_MANIFEST_OUT || "update.json";
  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  console.log(
    `generate-update-manifest: wrote ${outputPath} for v${version} with ${artifacts.length} artifact(s)`,
  );
}

main().catch((error) => {
  fail(error instanceof Error ? error.message : String(error));
});
