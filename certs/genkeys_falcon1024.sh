#!/bin/bash
set -x
set -e
openssl genpkey -algorithm falcon1024 -out ca_privkey.pem  -provider oqsprovider 
openssl req -x509 -new -nodes -key ca_privkey.pem -sha512 -days 5000 -out ca_root.pem -provider oqsprovider
openssl genpkey -algorithm falcon1024  -out server_privkey.pem -provider oqsprovider 
openssl req -new -key server_privkey.pem -out server_privkey.csr -provider oqsprovider
openssl x509 -req -in server_privkey.csr -CA ca_root.pem -CAkey ca_privkey.pem -CAcreateserial -out cert.pem -days 5000 -sha512 -provider oqsprovider

printf '\0' >> ca_root.pem
printf '\0' >> cert.pem
printf '\0' >> server_privkey.pem


if test -z $CC; then
        export CC=cc
fi

$CC -std=gnu99 -o file2header file2header.c

./file2header ca_root.pem tests_rootcert.h QualiaTest_RootCert
./file2header cert.pem tests_servercert.h QualiaTest_ServerCert
./file2header server_privkey.pem tests_serverprivkey.h QualiaTest_ServerPrivKey
