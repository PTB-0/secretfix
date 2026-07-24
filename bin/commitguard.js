#!/usr/bin/env node
import('../dist/cli.js')
  .then((mod) => mod.run(process.argv))
  .catch((err) => {
    console.error(`commitguard: failed to start — ${err.message}`);
    process.exitCode = 1;
  });
