#!/bin/sh
set -e
set -x
DIR="$(dirname "$0")"
PROTO_DIR="$DIR/../jaas/src/main/proto"
# See https://grpc.io/docs/languages/go/quickstart/ for dependencies
protoc \
  --proto_path="${PROTO_DIR}" \
  --go_out="$DIR" --go_opt=module=go.mkw.re/ghidra-panel \
  --go-grpc_out="$DIR" --go-grpc_opt=module=go.mkw.re/ghidra-panel \
  "$PROTO_DIR"/*.proto
