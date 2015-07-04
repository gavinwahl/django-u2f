#!/bin/sh

# Create a self signed certificate and matching private key for localhost
openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -keyout localhost.key -out localhost.crt -subj /CN=localhost
