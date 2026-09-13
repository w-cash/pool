#!/usr/bin/env python3
"""Mine more real ZIP301 blocks into an already-running full-pool harness."""
import argparse
import json
from pathlib import Path
import time
from types import SimpleNamespace
from run import Harness, private

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--runtime', required=True, type=Path)
parser.add_argument('--miner', required=True, type=Path)
parser.add_argument('--blocks', type=int, required=True)
args = parser.parse_args()
if not 1 <= args.blocks <= 1000:
    parser.error('--blocks must be in 1..1000')
h = Harness(SimpleNamespace(runtime=args.runtime))
session = json.loads((h.root / 'portal-session.json').read_text())
worker = session['worker']
for index in range(args.blocks):
    previous = {name: h.rpc(name, 'getblockcount') for name in ('wec', 'zec')}
    started = time.monotonic()
    h.mine_winner(f'continuation-proof-{previous["wec"]+1:04}', args.miner, worker)
    for name in ('wec', 'zec'):
        h.until(name + ' chain advancement', lambda n=name: h.rpc(n, 'getblockcount') > previous[n])
    if index == 0 or (index + 1) % 10 == 0 or index + 1 == args.blocks:
        print(f'Real continuation wins: Wcash {previous["wec"]+1}, Zcash {previous["zec"]+1}; last proof {time.monotonic()-started:.1f}s', flush=True)
