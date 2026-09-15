#!/usr/bin/env node

// @ts-check

import { execFileSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { styleText } from "node:util"

/** @typedef {"low" | "moderate" | "high" | "critical"} Severity */

/**
 * @typedef {object} Advisory
 * @property {string} title
 * @property {string} url
 */

/**
 * @typedef {object} FixAvailable
 * @property {string} [name]
 * @property {string} [version]
 * @property {boolean} [isSemVerMajor]
 */

/**
 * @typedef {object} Vulnerability
 * @property {Severity} severity
 * @property {string} [range]
 * @property {Array<string | Advisory>} [via]
 * @property {string[]} [nodes]
 * @property {boolean | FixAvailable} [fixAvailable]
 */

/**
 * @typedef {object} AuditResult
 * @property {Record<string, Vulnerability>} [vulnerabilities]
 */

/**
 * @typedef {object} FixChange
 * @property {string} name
 * @property {string} [from]
 * @property {string} [to]
 */

const packageJson = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
)

const HELP = `npm-audit-trace v${packageJson.version}

Trace npm audit vulnerabilities through the dependency tree.

Usage:
  npm-audit-trace
  npx npm-audit-trace

Options:
  -h, --help     Show help
  -v, --version  Show version
`

/**
 * Execute npm and return stdout even when npm exits with a non-zero status.
 *
 * @param {string[]} args
 * @returns {string}
 */
function execNpm(args) {
  try {
    return execFileSync("npm", args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        FORCE_COLOR: "1",
      },
    })
  } catch (error) {
    if (typeof error === "object" && error !== null && "stdout" in error) {
      return String(error.stdout)
    }

    throw error
  }
}

/**
 * Execute npm quietly and return trimmed stdout, or null on failure.
 *
 * @param {string[]} args
 * @returns {string | null}
 */
function execNpmQuiet(args) {
  try {
    return execFileSync("npm", args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim()
  } catch {
    return null
  }
}

/**
 * @param {string} text
 * @returns {string}
 */
function bold(text) {
  return styleText("bold", text)
}

/**
 * @param {Severity} severity
 * @returns {string}
 */
function colorSeverity(severity) {
  switch (severity) {
    case "critical":
    case "high":
      return styleText(["bold", "red"], severity)
    case "moderate":
      return styleText(["bold", "yellow"], severity)
    case "low":
      return styleText(["bold", "blue"], severity)
  }
}

/**
 * @param {string} name
 * @returns {string | null}
 */
function getLatestVersion(name) {
  return execNpmQuiet(["view", name, "version"])
}

/**
 * @param {Vulnerability} vuln
 * @returns {string | null}
 */
function getFixVersion(vuln) {
  if (typeof vuln.fixAvailable === "object" && vuln.fixAvailable !== null) {
    return vuln.fixAvailable.version ?? null
  }

  return null
}

/**
 * @param {Vulnerability} vuln
 * @returns {string}
 */
function getFixLabel(vuln) {
  if (vuln.fixAvailable === false) {
    return "No fix available"
  }

  if (
    typeof vuln.fixAvailable === "object" &&
    vuln.fixAvailable !== null &&
    vuln.fixAvailable.isSemVerMajor
  ) {
    return "Available via `npm audit fix --force`"
  }

  return "Available via `npm audit fix`"
}

/**
 * @param {string} name
 * @returns {void}
 */
function printDependencyTree(name) {
  const tree = execNpmQuiet(["ls", name, "--depth=20", "--color=always"])

  if (!tree) {
    return
  }

  console.log(tree.split("\n").slice(1).join("\n").trim())
}

/**
 * @returns {FixChange[]}
 */
function collectFixChanges() {
  const raw = execNpm(["audit", "fix", "--dry-run", "--json"])

  try {
    /** @type {any} */
    const json = JSON.parse(raw)
    /** @type {FixChange[]} */
    const changes = []

    const candidates = [
      json?.change,
      json?.actions,
      json?.changed,
      json?.updated,
      json?.auditReport?.actions,
    ].filter(Array.isArray)

    for (const list of candidates) {
      for (const item of list) {
        if (item?.from?.name && item?.to?.version) {
          changes.push({
            name: String(item.from.name),
            from: String(item.from.version),
            to: String(item.to.version),
          })
          continue
        }

        const name = item?.module ?? item?.name ?? item?.package
        const from = item?.from ?? item?.oldVersion ?? item?.current
        const to = item?.to ?? item?.version ?? item?.newVersion

        if (name && (from || to)) {
          changes.push({
            name: String(name),
            from: from ? String(from).replace(`${name}@`, "") : undefined,
            to: to ? String(to).replace(`${name}@`, "") : undefined,
          })
        }
      }
    }

    return changes
  } catch {
    return []
  }
}

/**
 * @returns {void}
 */
function main() {
  const args = process.argv.slice(2)

  if (args.includes("-h") || args.includes("--help")) {
    console.log(HELP.trimEnd())
    return
  }

  if (args.includes("-v") || args.includes("--version")) {
    console.log(packageJson.version)
    return
  }

  if (args.length > 0) {
    console.error(`Unknown option: ${args[0]}`)
    console.error("Run `npm-audit-trace --help` for usage.")
    process.exitCode = 1
    return
  }

  /** @type {AuditResult} */
  const audit = JSON.parse(execNpm(["audit", "--json"]))
  const vulnerabilities = Object.entries(audit.vulnerabilities ?? {})

  if (vulnerabilities.length === 0) {
    console.log(`found ${styleText(["bold", "green"], "0")} vulnerabilities`)
    return
  }

  const fixChanges = collectFixChanges()

  for (const [name, vuln] of vulnerabilities) {
    const latestVersion = getLatestVersion(name)
    const fixVersion = getFixVersion(vuln)
    const changes = fixChanges.filter((change) => change.name === name)

    console.log(`${bold(name)}  ${vuln.range ?? ""}`)
    console.log(`Severity: ${colorSeverity(vuln.severity)}`)

    for (const via of vuln.via ?? []) {
      if (typeof via === "object") {
        console.log(`${via.title} - ${via.url}`)
      }
    }

    for (const node of vuln.nodes ?? [`node_modules/${name}`]) {
      console.log(node)
    }

    printDependencyTree(name)

    if (latestVersion) {
      console.log(`Latest: ${latestVersion}`)
    }

    if (fixVersion) {
      console.log(`Fixed by: ${fixVersion}`)
    }

    console.log(getFixLabel(vuln))

    for (const change of changes) {
      console.log(`└─from: ${change.from ?? "?"} - to: ${change.to ?? "?"}`)
    }

    console.log("")
  }
}

main()
