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

tilib -v -c @zlibdll-vc32.cfg -hzlibdll.h -t'zlib 1.1.4 DLL' -b${IDA}/til/pc/vc6win.til zlib114dll.til
pcf static32/zlibstat.lib zlib114dll.pat
sigmake -nzlib114dll zlib114dll.pat zlib114dll.sig
