#!/usr/bin/env node
import('../dist/cli.js').then((mod) => mod.run(process.argv));
