# should_match.sh
openssl dgst -sha256 -sign key.pem -out sig.bin payload.bin
