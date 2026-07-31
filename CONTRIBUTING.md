# Contributing to UoPFuzz

Thanks for your interest. This is a security research tool for finding
prototype-pollution gadgets in JavaScript libraries. Contributions of any size
are welcome — bug fixes, new gadget/sink coverage, corpus additions, and docs.

## Ground rules (please read)

UoPFuzz **executes untrusted code and generates real exploits**. Only run it
against packages you are authorized to test, and prefer the containerized
workflow (see below). See [`SECURITY.md`](SECURITY.md) for the disclosure policy
and the README's "Safety model" for what is and isn't isolated.

## Development setup

Requires Node.js **>= 18**.

```bash
git clone https://github.com/acuciureanu/uopfuzz.git
cd uopfuzz
npm install
```

## Everyday commands

```bash
npm run lint     # eslint over src/ and tests/
npm test         # node --test over the hermetic fixture suite
npm run benchmark        # full ground-truth benchmark (installs real packages)
npm run benchmark:self-test   # benchmark scoring logic only, installs nothing
```

The test suite is hermetic (purpose-built fixtures under `tests/fixtures/`, no
network). The **benchmark** installs and executes real npm packages — run it
inside the container:

```bash
./run-sandboxed.sh --help          # builds the hardened image on first run
# then run the benchmark inside that image (see docs/usage.md)
```

## Before opening a PR

- `npm run lint` and `npm test` must pass.
- Add or update a fixture/test for any behaviour change to the detection or
  reproduction path. A finding is only ever reported when it is **reproduced in
  fresh child processes** — keep that invariant; don't add heuristics that report
  a vulnerability without reproduction.
- Keep commits focused and descriptive.

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the pipeline overview and
[`docs/configuration.md`](docs/configuration.md) for the YAML target format.
