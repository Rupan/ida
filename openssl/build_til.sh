#!/bin/bash

IDA="${HOME}/ida-6.4"
if [ ! -d "${IDA}" ]
then
  echo "Edit the IDA path in this script."
  exit 1
fi

if [ ! -d "openssl-1.0.1e" ]
then
  echo "Download OpenSSL 1.0.1e and decompress it here."
  exit 1
fi

tilib -v -z -c @gcc-openssl.cfg -hopenssl_all.h -t'OpenSSL 1.0.1e' -b${IDA}/til/gnucmn.til openssl_101e.til
