#!/bin/bash

IDA="${HOME}/ida-6.9"
if [ ! -d "${IDA}" ]
then
  echo "Edit the IDA path in this script."
  exit 1
fi

${IDA}/tilib -v -z -c @${IDA}/til-cfg/gcc.cfg -I. -Iempty -b${IDA}/til/gnucmn.til -hopenssl_all.h -t'OpenSSL 1.0.2g (gcc/x86)' openssl_102g_gcc_x86.til
