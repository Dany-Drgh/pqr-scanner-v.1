# should_not_match.sh
openssl dgst -sha256 -verify pub.pem -signature sig.bin payload.bin
