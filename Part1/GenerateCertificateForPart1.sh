#!/bin/bash 

echo "Generating root key using RSA"
openssl genrsa -aes256 -out root.key 2048



