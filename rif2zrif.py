#!/usr/bin/env python3

import sys
import zlib
import base64

zrif_dict = list(zlib.decompress(base64.b64decode(
  b"eNpjYBgFo2AU0AsYAIElGt8MRJiDCAsw3xhEmIAIU4N4AwNdRxcXZ3+/EJCAkW6Ac7C7ARwYgviuQAaIdoPSzlDaBUo7QmknIM3ACIZM78+u7kx3VWYEAGJ9HV0=")))

if len(sys.argv) != 2:
  exit("Usage: %s path/to/file.rif" % sys.argv[0])

rif = open(sys.argv[1], "rb").read()

c = zlib.compressobj(level=9, wbits=10, memLevel=8, zdict=bytes(zrif_dict))
bin = c.compress(rif)
bin += c.flush()

if len(bin) % 3 != 0:
  bin += b"\0" * (3 - len(bin) % 3)

content = rif[0x10:0x40].rstrip(b"\0").decode("ascii")

print(content, base64.b64encode(bin).decode("ascii"))
