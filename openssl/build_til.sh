#!/bin/bash

IDA="/opt/ida-7.0"
if [ ! -d "${IDA}" ]
then
  echo "Edit the IDA path in this script."
  exit 1
fi

rm -f openssl_*.til openssl_all.i

OSSL_VER="1.0.2m"
OSSL_INC_DIR="openssl-${OSSL_VER}/include"
OSSL_TIL_BASE="openssl_${OSSL_VER//.}_gcc"

if [ ! -d "${OSSL_INC_DIR}" ]
then
  echo "Download and configure OpenSSL ${OSSL_VER}."
  exit 1
fi

${IDA}/tilib -Gn -v -z -c @gcc32.cfg -I${OSSL_INC_DIR} -Iempty -b${IDA}/til/gnucmn.til -hopenssl_all.h \
	-t"OpenSSL ${OSSL_VER} (gcc/x86, without leading underscore)" ${OSSL_TIL_BASE}_x86_nlu.til
rm -f openssl_all.i
${IDA}/tilib64 -Gn -v -z -c @gcc64.cfg -I${OSSL_INC_DIR} -Iempty -b${IDA}/til/gnucmn.til -hopenssl_all.h \
	-t"OpenSSL ${OSSL_VER} (gcc/x64, without leading underscore)" ${OSSL_TIL_BASE}_x64_nlu.til
rm -f openssl_all.i


${IDA}/tilib -v -z -c @gcc32.cfg -I${OSSL_INC_DIR} -Iempty -b${IDA}/til/gnucmn.til -hopenssl_all.h \
	-t"OpenSSL ${OSSL_VER} (gcc/x86, with leading underscore)" ${OSSL_TIL_BASE}_x86_wlu.til
rm -f openssl_all.i
${IDA}/tilib64 -v -z -c @gcc64.cfg -I${OSSL_INC_DIR} -Iempty -b${IDA}/til/gnucmn.til -hopenssl_all.h \
	-t"OpenSSL ${OSSL_VER} (gcc/x64, with leading underscore)" ${OSSL_TIL_BASE}_x64_wlu.til
rm -f openssl_all.i
