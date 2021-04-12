"""
Quick-and-dirty IDA loader for Mac OS classic (System 7) resource forks
Copyright (c) 2021 - Michael Mohr
Licence: GPLv3

Useful links:
 * https://github.com/fuzziqersoftware/resource_dasm
 * https://github.com/MacPaw/XADMaster/wiki/Disassembling68KMacExecutables
 * https://code.google.com/archive/p/theunarchiver/wikis/Disassembling68KMacExecutables.wiki
 * https://github.com/dgelessus/python-rsrcfork
 * https://github.com/topics/classic-mac-os?o=asc&s=stars
 * https://github.com/csnover/ida-misc/tree/master/mac
 * https://github.com/ubuntor/m68k_mac_reversing_tools
"""

import io
import struct

# https://github.com/dgelessus/python-rsrcfork
import rsrcfork

import idaapi
import idc
import idc_bc695
import ida_nalt


def accept_file(li, filename):
    file_size = li.size()
    header = li.read(16)
    if len(header) != 16:
        return 0
    data_offset, map_offset, data_size, map_size = struct.unpack(">IIII", header)
    if (data_offset + data_size + map_size) != file_size:
        return 0
    return {"format": "Mac OS Classic resource fork", "processor": "68K"}


class DataValidationError(Exception):
    pass


def build_data_segs(li):
    li.seek(0)
    rsrc_bytes = li.read(li.size())
    if len(rsrc_bytes) != li.size():
        raise DataValidationError("Unable to read resource fork data")
    rf = rsrcfork.ResourceFile(io.BytesIO(rsrc_bytes))
    resource_info = []
    for resource_name, resource_map in rf.items():
        for resource_obj in resource_map.values():
            # Some resources nave names like "TUT#" "STR#" "ics#' "ICN#" which aren't valid names
            seg_name_prefix = resource_name.decode('ascii').replace("#", "_pound")
            if resource_obj.id < 0:
                # Some resource IDs are < 0, special-case then for segment naming
                seg_name = f"{seg_name_prefix}_negative{abs(resource_obj.id)}"
            else:
                seg_name = f"{seg_name_prefix}_{resource_obj.id}"
            start_ea = rf.data_offset + resource_obj.data_raw_offset
            # rsrcfork doesn't consider the resource data (size 4) part of the data length
            # However, we load it as part of the entire resource file so add it back here
            end_ea = start_ea + resource_obj.length_raw + 4
            resource_info.append((start_ea, end_ea, seg_name))
    resource_info.sort()  # yes, unstable
    if resource_info[0][0] != rf.data_offset:
        raise DataValidationError("First resource doesn't start after header")
    for resource_idx in range(len(resource_info)-1):
        _, cur_end_ea, _ = resource_info[resource_idx]
        next_start_ea, _, _ = resource_info[resource_idx+1]
        if cur_end_ea != next_start_ea:
            raise DataValidationError("start/end mismatch")
    if resource_info[-1][1] != rf.map_offset:
        raise DataValidationError("Last resource doesn't end at map")
    # We've got relatively decent looking segment definitions, let's create them!
    for start_ea, end_ea, seg_name in resource_info:
        print(f"{seg_name}: start_ea = {hex(start_ea)}; end_ea = {hex(end_ea)}")
        if seg_name.startswith("CODE") and seg_name != "CODE_0":
            add_seg(start_ea, end_ea, seg_name, "CODE")
        else:
            add_seg(start_ea, end_ea, seg_name, "DATA")


def load_file(li, neflags, format):
    li.file2base(0, 0, li.size(), False)

    data_start_ea = idc_bc695.Dword(0)
    data_end_ea = data_start_ea + idc_bc695.Dword(8)
    try:
        # Be a bit more intelligent: split resources into segments
        build_data_segs(li)
    except DataValidationError:
        # Something failed, just create a giant single CODE segment
        # The disassembly won't be quite as good, but still passable
        add_seg(data_start_ea, data_end_ea, "ResourceData", "CODE")

    map_start_ea = idc_bc695.Dword(4)
    map_end_ea = map_start_ea + idc_bc695.Dword(12)
    add_seg(map_start_ea, map_end_ea, "ResourceMap", "DATA")

    header_start_ea = 0
    header_end_ea = data_start_ea
    add_seg(header_start_ea, header_end_ea, "ResourceHeader", "DATA")

    process_metadata()
    return 1


def add_seg(start_ea, end_ea, name, sclass):
    seg = idaapi.segment_t()
    seg.start_ea = start_ea
    seg.end_ea = end_ea
    seg.bitness = 1  # 32-bit
    idaapi.add_segm_ex(seg, name, sclass, 0)


def process_metadata():
    """
    Nearly a carbon copy of mac_os_resource.idc found here:
        https://github.com/MacPaw/XADMaster/wiki/Disassembling68KMacExecutables
    """
    idc_bc695.MakeDword(0)
    idc_bc695.OpOff(0, 0, 0)
    idc_bc695.MakeComm(0, "Offset to resource data")

    idc_bc695.MakeDword(4)
    idc_bc695.OpOff(4, 0, 0)
    idc_bc695.MakeComm(4, "Offset to resource map")

    idc_bc695.MakeDword(8)
    idc_bc695.OpNumber(8, 0)
    idc_bc695.MakeComm(8, "Length of resource data")

    idc_bc695.MakeDword(12)
    idc_bc695.OpNumber(12, 0)
    idc_bc695.MakeComm(12, "Length of resource map")

    resdata = idc_bc695.Dword(0)
    resmap = idc_bc695.Dword(4)

    idc_bc695.MakeNameEx(resdata, "ResourceData", 0)
    idc_bc695.MakeNameEx(resmap, "ResourceMap", 0)

    idc_bc695.MakeDword(resmap)
    idc_bc695.OpOff(resmap, 0, 0)
    idc_bc695.MakeComm(resmap, "Offset to resource data")

    idc_bc695.MakeDword(resmap + 4)
    idc_bc695.OpOff(resmap + 4, 0, 0)
    idc_bc695.MakeComm(resmap + 4, "Offset to resource map")

    idc_bc695.MakeDword(resmap + 8)
    idc_bc695.OpNumber(resmap + 8, 0)
    idc_bc695.MakeComm(resmap + 8, "Length of resource data")

    idc_bc695.MakeDword(resmap + 12)
    idc_bc695.OpNumber(resmap + 12, 0)
    idc_bc695.MakeComm(resmap + 12, "Length of resource map")

    idc_bc695.MakeDword(resmap + 16)
    idc_bc695.OpNumber(resmap + 16, 0)
    idc_bc695.MakeComm(resmap + 16, "Reserved for handle to next resource map")

    idc_bc695.MakeWord(resmap + 20)
    idc_bc695.OpNumber(resmap + 20, 0)
    idc_bc695.MakeComm(resmap + 20, "Reserved for file reference number")

    idc_bc695.MakeWord(resmap + 22)
    idc_bc695.OpNumber(resmap + 22, 0)
    idc_bc695.MakeComm(resmap + 22, "Resource fork attributes")

    idc_bc695.MakeWord(resmap + 24)
    idc_bc695.OpOffEx(resmap + 24, 0, idc.REF_OFF32, -1, resmap, -2)
    idc_bc695.MakeComm(resmap + 24, "Offset to type list")

    idc_bc695.MakeWord(resmap + 26)
    idc_bc695.OpOffEx(resmap + 26, 0, idc.REF_OFF32, -1, resmap, -2)
    idc_bc695.MakeComm(resmap + 26, "Offset to name list")

    idc_bc695.MakeWord(resmap + 28)
    idc_bc695.OpNumber(resmap + 28, 0)
    idc_bc695.MakeComm(resmap + 28, "Number of types minus one")

    restypelist = resmap + idc_bc695.Word(resmap + 24) + 2
    resnamelist = resmap + idc_bc695.Word(resmap + 26) + 2

    idc_bc695.MakeNameEx(restypelist, "ResourceTypeList", 0)
    idc_bc695.MakeNameEx(resnamelist, "ResourceNameList", 0)

    numtypes = idc_bc695.Word(resmap + 28) + 1

    for i in range(numtypes):
        entry = restypelist + i * 8

        # idc_bc695.MakeStr(entry + 0, entry + 4)
        idc.create_strlit(entry + 0, entry + 4)
        idc_bc695.MakeComm(entry + 0, "Resource type")

        idc_bc695.MakeWord(entry + 4)
        idc_bc695.OpNumber(entry + 4, 0)
        idc_bc695.MakeComm(entry + 4, "Number of resource of this type minus one")

        idc_bc695.MakeWord(entry + 6)
        idc_bc695.OpOffEx(entry + 6, 0, idc.REF_OFF32, -1, restypelist, 2)
        idc_bc695.MakeComm(entry + 6, "Offset of reference list for this type")

        reflist = restypelist + idc_bc695.Word(entry + 6) - 2

        # resname = idc_bc695.GetString(entry + 0, 4, idc.ASCSTR_C)
        # FIXME: some resources have # in their names
        resname = idc.get_strlit_contents(entry + 0, 4, ida_nalt.STRTYPE_C).decode("utf-8").replace("#", "")
        idc_bc695.MakeNameEx(reflist, "ReferenceList" + resname, 0)

        numrefs = idc_bc695.Word(entry + 4) + 1

        for j in range(numrefs):
            ref = reflist + j * 12

            idc_bc695.MakeWord(ref + 0)
            idc_bc695.OpNumber(ref + 0, 0)
            idc_bc695.MakeComm(ref + 0, "Resource ID")

            idc_bc695.MakeWord(ref + 2)
            idc_bc695.OpOffEx(ref + 2, 0, idc.REF_OFF32, -1, resnamelist, 0)
            idc_bc695.MakeComm(ref + 2, "Offset to resource name")

            idc_bc695.MakeDword(ref + 4)
            attrs = idc_bc695.Byte(ref + 4)
            idc_bc695.OpOffEx(ref + 4, 0, idc.REF_OFF32, -1, resdata, attrs << 24)
            idc_bc695.MakeComm(ref + 4, "Offset to resource data plus attributes")

            idc_bc695.MakeDword(ref + 8)
            idc_bc695.OpNumber(ref + 8, 0)
            idc_bc695.MakeComm(ref + 8, "Reserved for handle to resource")

            resid = str(idc_bc695.Word(ref + 0))
            data = resdata + idc_bc695.Dword(ref + 4) - (attrs << 24)
            idc_bc695.MakeNameEx(data, resname + "Resource" + resid, 0)

            idc_bc695.MakeDword(data)
            idc_bc695.OpNumber(data, 0)
            idc_bc695.MakeComm(data, "Length of resource data")

            if resname == "CODE" and resid != "0":
                idc_bc695.MakeWord(data + 4)
                idc_bc695.OpNumber(data + 4, 0)
                idc_bc695.MakeComm(data + 4, "Offset of first entry in jump table")

                idc_bc695.MakeWord(data + 6)
                idc_bc695.OpNumber(data + 6, 0)
                idc_bc695.MakeComm(data + 6, "Number of entries in jump table")

    code0 = idc_bc695.LocByName("CODEResource0")

    idc_bc695.MakeDword(code0 + 4)
    idc_bc695.OpNumber(code0 + 4, 0)
    idc_bc695.MakeComm(code0 + 4, "Size above A5")

    idc_bc695.MakeDword(code0 + 8)
    idc_bc695.OpNumber(code0 + 8, 0)
    idc_bc695.MakeComm(code0 + 8, "Size of globals")

    idc_bc695.MakeDword(code0 + 12)
    idc_bc695.OpNumber(code0 + 12, 0)
    idc_bc695.MakeComm(code0 + 12, "Length of jump table")

    idc_bc695.MakeDword(code0 + 16)
    idc_bc695.OpNumber(code0 + 16, 0)
    idc_bc695.MakeComm(code0 + 16, "A5 offset of jump table")

    idc_bc695.MakeNameEx(code0 + 20, "JumpTable", 0)

    length = idc_bc695.Dword(code0 + 12)

    for i in range(0, length, 8):
        jumpentry = code0 + 20 + i

        jumpresid = str(idc_bc695.Word(jumpentry + 4))
        resoffs = idc_bc695.LocByName("CODEResource" + jumpresid)

        idc_bc695.MakeWord(jumpentry + 0)
        idc_bc695.OpOffEx(jumpentry + 0, 0, idc.REF_OFF32, -1, resoffs, -8)
        idc_bc695.MakeComm(jumpentry + 0, "Offset of function")

        idc_bc695.MakeWord(jumpentry + 2)
        idc_bc695.OpNumber(jumpentry + 2, 0)
        idc_bc695.MakeComm(jumpentry + 2, "Push instruction")

        idc_bc695.MakeWord(jumpentry + 4)
        idc_bc695.OpNumber(jumpentry + 4, 0)
        idc_bc695.MakeComm(jumpentry + 4, "Resource ID to push")

        idc_bc695.MakeWord(jumpentry + 6)
        idc_bc695.OpNumber(jumpentry + 6, 0)
        idc_bc695.MakeComm(jumpentry + 6, "LoadSeg instruction")

        funcoffs = resoffs + 8 + idc_bc695.Word(jumpentry + 0)
        idc_bc695.AutoMark(funcoffs, idc.AU_PROC)