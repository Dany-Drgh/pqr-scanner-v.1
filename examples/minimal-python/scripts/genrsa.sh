#!/usr/bin/env bash
openssl genrsa -out key.pem 2048
openssl dgst -sha256 -sign key.pem -out sig.bin payload.bin
