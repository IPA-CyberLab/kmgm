#!/bin/bash
PREFIX="/usr/local" && \
VERSION="1.27.2" && \
curl -sSL \
"https://github.com/bufbuild/buf/releases/download/v${VERSION}/buf-$(uname -s)-$(uname -m).tar.gz" | \
sudo tar -xvzf - -C "${PREFIX}" --strip-components 1

go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
