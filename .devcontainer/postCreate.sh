#!/bin/bash
set -euo pipefail

go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.30
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3
