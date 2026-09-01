#!/usr/bin/env bash
set -e

openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650 \
    -subj '/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=foobar.com'
openssl x509 -in test/cert.pem -outform der -out test/cert.der
