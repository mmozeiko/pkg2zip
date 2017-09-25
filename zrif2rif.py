#!/usr/bin/env python3

import sys
import zlib
import base64

zrif_dict = list(zlib.decompress(base64.b64decode(
  b"eNpjYBgFo2AU0AsYAIElGt8MRJiDCAsw3xhEmIAIU4N4AwNdRxcXZ3+/EJCAkW6Ac7C7ARwYgviuQAaIdoPSzlDaBUo7QmknIM3ACIZM78+u7kx3VWYEAGJ9HV0=")))

if len(sys.argv) != 2 and len(sys.argv) != 3:
  exit("Usage: %s zRIF [path/to/work.bin]" % sys.argv[0])

bin = base64.b64decode(sys.argv[1].encode("ascii"))

d = zlib.decompressobj(wbits=10, zdict=bytes(zrif_dict))
rif = d.decompress(bin)
rif += d.flush()

output = sys.argv[2] if len(sys.argv) == 3 else "work.bin"
open(output, "wb").write(rif)
