ARG VARIANT="1-bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/go:0-${VARIANT}

RUN mkdir /opt/protoc && cd /opt/protoc && \
  curl -L -O https://github.com/protocolbuffers/protobuf/releases/download/v22.2/protoc-22.2-linux-x86_64.zip && \
  unzip *.zip
