# assets

Media used in the project README.

- `demo.gif` — the README hero: a tightened, faithful recording of a real
  `node src/cli.js --target lodash@4.17.4` run (discovery → reproduction-proven
  finding). Distilled from the tool's actual output.
- `demo.cast` — the [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/)
  source the GIF is rendered from.

## Regenerating

Requires [`agg`](https://github.com/asciinema/agg) (the asciinema GIF generator):

```bash
npm run demo
```

That runs `scripts/gen-demo-cast.mjs` to (re)write `demo.cast`, then renders
`demo.gif`. Edit the script to change the narrative or timing.
