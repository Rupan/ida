/*
  An IDA loader for LG Blu-Ray drive firmware based on the Renesas H8.

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../idaldr.h"
// for ntohl and ntohs
#if defined(__NT__)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif


// Firmware header size is 1024 (0x400) bytes
#define HEADER_SIZE 0x400
// arbitrary firmware file size limit ... we don't
// expect drive firmware to be very large.
#define MAX_FIRMWARE_SIZE 10000000

// segment bitness flags
#define SEGMENT_16BIT 0
#define SEGMENT_32BIT 1
#define SEGMENT_64BIT 2

// firmware types (UNKNOWN/CORE/MAIN)
#define FW_TYPE_UNKNOWN 0
#define FW_TYPE_MAIN 1
#define FW_TYPE_CORE 2

static unsigned short calc_firmware_checksum(linput_t *li) {
    size_t i;
    ssize_t bytes_read;
    uint32 file_size;
    uint16 buf[8192];
    uint16 chksum = 0x00;
    uint32 bytes_processed;

    qlseek(li, 0, SEEK_SET);
    bytes_read = qlread(li, buf, sizeof(buf));  // FIXME: can return -1
    // checksum is stored in first two bytes - skip
    for(i = 1; i < (bytes_read/2); i++)
        chksum += ntohs(buf[i]);
    bytes_processed = bytes_read;

    file_size = (uint32)qlsize(li);
    while(bytes_processed < file_size) {
        bytes_read = qlread(li, buf, sizeof(buf));  // FIXME: can return -1
        for(i = 0; i < (bytes_read/2); i++)
            chksum += ntohs(buf[i]);
        bytes_processed += bytes_read;
    }
    qlseek(li, 0, SEEK_SET);
    return ~chksum;
}


/*
 * check the input file format.
 * - if recognized, return 1 and fill 'fileformatname'.
 *   otherwise return 0
 */
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n) {
    size_t i;
    const char *format_name;
    uint32 file_size, fw_type;
    uint32 load_addr, load_size;
    uint16 checksum_file;
    unsigned char buf[HEADER_SIZE];

    // n is initially 0 for each loader, and is incremented after each call
    if(n != 0) {
        return 0;
    }
    file_size = (uint32)qlsize(li);
    if(file_size > MAX_FIRMWARE_SIZE) {
        return 0;
    }
    if(qlread(li, buf, sizeof(buf)) != sizeof(buf)) {
        return 0;
    }
    qlseek(li, 0, SEEK_SET);
    checksum_file = ntohs(*(uint16 *)(buf+0x00));
    load_addr = ntohl(*(uint32 *)(buf+0x40));
    load_size = ntohl(*(uint32 *)(buf+0x44));
    // the firmware consists of a 0x400-byte header which defines (at least)
    // some strings, the file checksum, the load address, and the load size.
    if((load_size + HEADER_SIZE) != file_size) {
        return 0;
    }
    // compare the calculated checksum with the value from the firmware image
    if(calc_firmware_checksum(li) != checksum_file) {
        return 0;
    }
    // try to identify the firmware type
    fw_type = FW_TYPE_UNKNOWN;
    for(i = 0; i < (HEADER_SIZE-4); i++) {
        if(memcmp(buf, "MAIN", 4) == 0) {
            fw_type = FW_TYPE_MAIN;
            break;
        } else if(memcmp(buf, "CORE", 4) == 0) {
            fw_type = FW_TYPE_CORE;
            break;
        }
    }
    // fill in file format name
    if((load_addr == 0x410000) || fw_type == FW_TYPE_MAIN) {
        format_name = "LG Renesas Blu-Ray drive firmware (MAIN)";
    } else if(load_addr == 0x400000 || fw_type == FW_TYPE_CORE) {
        format_name = "LG Renesas Blu-Ray drive firmware (CORE)";
    } else {
        format_name = "LG Renesas Blu-Ray drive firmware (UNKNOWN)";
    }
    qstrncpy(fileformatname, format_name, MAX_FILE_FORMAT_NAME);
    return 1;
}


/*
 * load the file into the database
 */
void idaapi load_file(linput_t *li, ushort _neflag, const char *fileformatname) {
    refinfo_t rom_ri;
    unsigned char *fw_base, *fw_curr;
    uint32 load_addr, load_size, i, file_size;
    ea_t startEA, endEA, sjtEA, putative_addr;
    uint32 current_offset, increment_by, putative_count;

    if(ph.id != PLFM_H8)
        set_processor_type("h8300a", SETPROC_ALL|SETPROC_FATAL);
    // read in the firmware into memory
    file_size = qlsize(li);
    fw_base = (unsigned char *)qalloc(file_size);
    if(!fw_base) {
        loader_failure();
    }
    qlseek(li, 0, SEEK_SET);
    if(qlread(li, fw_base, file_size) != file_size) {
        qfree(fw_base);
        loader_failure();
    }
    qlseek(li, 0, SEEK_SET);
    // The following three segments represent what appear to be private
    // code/data segments, available only to the drive's OS at runtime.
    if(!add_segm(0, 0x100000, 0x107000, "PRIVATE", CLASS_CODE)) {
        qfree(fw_base);
        loader_failure();
    }
    // This address space may be hardware registers and/or
    // subroutines implemented in hardware
    if(!add_segm(0, 0, 0x7000, "HARDWARE", CLASS_CODE)) {
        qfree(fw_base);
        loader_failure();
    }
    // RAM (possibly)
    if(!add_segm(0, 0xFFE000, 0xFFFFFF, "RAM", CLASS_DATA)) {
        qfree(fw_base);
        loader_failure();
    }
    // identify the start and end EA based
    // on values in the firmware header
    load_addr = ntohl(*(uint32 *)(fw_base+0x40));
    load_size = ntohl(*(uint32 *)(fw_base+0x44));
    startEA = load_addr;
    endEA = load_addr + load_size;
    // init refinfo for the ROM
    rom_ri.init(REF_OFF32, startEA);
    msg("LGE: load addr = 0x%06X\n", load_addr);
    msg("LGE: load size = 0x%06X\n", load_size);
    // load the ROM firmware into the database
    mem2base((fw_base+HEADER_SIZE), startEA, endEA, HEADER_SIZE);
    // create a segment around the ROM section
    if(!add_segm(0, startEA, endEA, "ROM", CLASS_CODE)) {
        qfree(fw_base);
        loader_failure();
    }
    // The firmware appears to reference some kind of permanent
    // storage, likely a small flash chip.  Not sure what size
    // this is; use 128K for now.
    if(!add_segm(0, 0x800000, 0x820000, "FLASH", CLASS_DATA)) {
        qfree(fw_base);
        loader_failure();
    }
    // use 32-bit addressing
    segment_t *s = getseg(startEA);
    set_segm_addressing(s, SEGMENT_32BIT);
    // Special handling for the MAIN firmware image
    if(strstr(fileformatname, "MAIN") != NULL) {
        // Search for the SCSI jump table
        sjtEA = BADADDR;
        putative_count = 0;
        current_offset = HEADER_SIZE;
        fw_curr = fw_base + current_offset;
        while(current_offset < file_size) {
            putative_addr = ntohl(*(uint32 *)(fw_curr));
            if(putative_addr >= startEA && putative_addr <= endEA) {
                increment_by = 4;
                putative_count++;
            } else {
                if(putative_count > 0) {
                    if(putative_count == 256) {
                        sjtEA = (startEA-HEADER_SIZE)+(current_offset-(4*putative_count));
                        break;
                    }
                    putative_count = 0;
                }
                increment_by = 1;
            }
            fw_curr += increment_by;
            current_offset += increment_by;
        }
        if(sjtEA != BADADDR) {
            msg("LGE: SCSI jump table found @ 0x%06X\n", sjtEA);
            for(i=0; i<256; i++) {
                op_offset_ex(sjtEA, 1, &rom_ri);
                sjtEA += 4;
            }
        }
    }
    // free the allocated memory
    qfree(fw_base);
    // create the file header comment
    if((_neflag & NEF_RELOAD) == 0)
        create_filename_cmt();
}


loader_t LDSC = {
    IDP_INTERFACE_VERSION,  // api version
    0,                      // loader flags
    accept_file,            // accept_file callback
    load_file,              // load_file callback
    NULL,                   // save_file callback
    NULL,                   // move_segm callback
    NULL                    // unused
};
