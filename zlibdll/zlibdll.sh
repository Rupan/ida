#!/bin/bash

IDA="${HOME}/ida-6.4"
if [ ! -d "${IDA}" ]
then
echo "Edit the IDA path in this script."
  exit 1
fi

if [ ! -f "unzip.h" ]
then
  echo "Download zlib114dll.zip and unzip it here."
  echo "http://www.winimage.com/zLibDll/zlib114dll.zip"
  exit 1
fi

${IDA}/tilib -v -z -c @${IDA}/til-cfg/vc32.cfg -b${IDA}/til/pc/vc6win.til -hzlib114all.h -t'zlib 1.1.4 (WinImage, x86 VC6)' -Izlib114dll zlib114_x86_vc6.til

pcf static32/zlibstat.lib zlib114_x86_vc6.pat
sigmake -nzlib114dll zlib114_x86_vc6.pat zlib114_x86_vc6.sig
./bin/linux/sigmake -n'zlib dll 1.1.4 (WinImage, x86 static VC6)' -o2 zlibstat.pat zlib114_x86_vc6.sig
