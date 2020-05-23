#!/bin/bash
cd $(dirname $0)
docker run --rm -v `pwd`/tls:/etc/tls:ro -v `pwd`/conf:/etc/nginx:ro -v `pwd`/pub:/pub:ro -p 443:443 nginx
