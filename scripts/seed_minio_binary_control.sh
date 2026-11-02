#!/bin/sh
# Run only inside the dedicated QA MinIO container after its corpus is seeded.
# Golden negatives must not acquire random token/XML-looking fragments.
set -eu
head -c 4096 /dev/zero | mc pipe local/secrets-corpus/misc/blob.bin
