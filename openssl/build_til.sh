#!/bin/bash

IDA="/opt/ida-6.95"
if [ ! -d "${IDA}" ]
then
  echo "Edit the IDA path in this script."
  exit 1
fi

rm -f openssl_102h_gcc_x86.til openssl_102h_gcc_x64.til

rm -f openssl_all.i
${IDA}/tilib -Gn -v -z -c @gcc32.cfg -I. -Iempty -b${IDA}/til/gnucmn.til \
	-hopenssl_all.h -t'OpenSSL 1.0.2h (gcc/x86)' openssl_102h_gcc_x86.til
rm -f openssl_all.i
${IDA}/tilib64 -Gn -v -z -c @gcc64.cfg -I. -Iempty -b${IDA}/til/gnucmn.til \
	-hopenssl_all.h -t'OpenSSL 1.0.2h (gcc/x64)' openssl_102h_gcc_x64.til
rm -f openssl_all.i
