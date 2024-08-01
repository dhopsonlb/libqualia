#!/bin/sh
set -x
set -e
openssl genpkey -algorithm ed25519 -out ca_privkey.pem
openssl req -x509 -new -nodes -key ca_privkey.pem -sha512 -days 5000 -out ca_root.pem
openssl genpkey -algorithm ed25519 -out privkey.pem
openssl req -new -key privkey.pem -out privkey.csr
openssl x509 -req -in privkey.csr -CA ca_root.pem -CAkey ca_privkey.pem -CAcreateserial -out cert.pem -days 5000 -sha512
printf '\0' >> ca_root.pem
printf '\0' >> cert.pem
printf '\0' >> privkey.pem

if test -z $CC; then
	export CC=cc
fi

$CC -std=gnu99 -o file2header file2header.c

./file2header ca_root.pem tests_rootcert.h QualiaTest_RootCert
./file2header cert.pem tests_servercert.h QualiaTest_ServerCert
./file2header privkey.pem tests_serverprivkey.h QualiaTest_ServerPrivKey


mkdir -p ../tests/keys
cp *.h ../tests/keys/
