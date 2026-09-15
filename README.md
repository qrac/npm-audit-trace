# npm-audit-trace

Trace `npm audit` vulnerabilities through the dependency tree.

`npm-audit-trace` combines the vulnerability information from `npm audit` with the installed dependency tree from `npm ls`, making it easier to see why a vulnerable package is present and what npm can do to fix it.

## Usage

Run it from an npm project with a lockfile:

```sh
npx npm-audit-trace
```

Or install it globally:

```sh
npm install --global npm-audit-trace
npm-audit-trace
```

## Output

For each vulnerability, the command shows:

- affected package and version range
- severity
- advisory title and URL
- installed node path
- dependency tree from `npm ls`
- latest published package version
- version reported by npm as the available fix
- whether `npm audit fix` or `npm audit fix --force` is required
- version changes reported by `npm audit fix --dry-run`

If no vulnerabilities are found, it prints:

```text
found 0 vulnerabilities
```

## Requirements

- Node.js 22 or later
- npm
- an npm project with a lockfile

## Options

```text
-h, --help     Show help
-v, --version  Show version
```

## How it works

The command uses npm itself and does not modify your project. It runs commands equivalent to:

```sh
npm audit --json
npm audit fix --dry-run --json
npm ls <package> --depth=20
npm view <package> version
```

`npm audit fix` is always run with `--dry-run`; no dependency changes are applied.

## License

MIT

## Credit

- Author: [Qrac](https://qrac.jp)
- Organization: [QRANOKO](https://qranoko.jp)
