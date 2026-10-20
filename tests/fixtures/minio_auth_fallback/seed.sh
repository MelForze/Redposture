#!/bin/sh
set -eu
mc alias set local http://minio:9000 minioadmin minioadmin
mc mb --ignore-existing local/restricted
mc mb --ignore-existing local/public
mc anonymous set download local/public
cat >/tmp/location.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetBucketLocation"],"Resource":["arn:aws:s3:::restricted"]}]}
JSON
mc admin policy create local location-only /tmp/location.json
mc admin user add local restricted-user restricted-secret
mc admin policy attach local location-only --user restricted-user
