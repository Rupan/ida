#!/bin/bash

IDA="/opt/ida-7.0"
if [ ! -d "${IDA}" ]
then
  echo "Edit the IDA path in this script."
  exit 1
fi

rm -f openssl_101e_gcc_x86.til openssl_101e_gcc_x64.til

rm -f openssl_all.i
${IDA}/tilib -Gn -v -z -c @gcc32.cfg -I. -Iempty -b${IDA}/til/gnucmn.til \
	-Iopenssl-1.0.1e/include -hopenssl_all.h -t'OpenSSL 1.0.1e (gcc/x86)' \
	openssl_101e_gcc_x86.til
rm -f openssl_all.i
${IDA}/tilib64 -Gn -v -z -c @gcc64.cfg -I. -Iempty -b${IDA}/til/gnucmn.til \
	-Iopenssl-1.0.1e/include -hopenssl_all.h -t'OpenSSL 1.0.1e (gcc/x64)' \
	openssl_101e_gcc_x64.til
rm -f openssl_all.i
