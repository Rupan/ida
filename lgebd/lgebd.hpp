#ifndef LGEBD_HPP
#define LGEBD_HPP

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

// offsets for data in the firmware header
#define HEADER_OFFSET_LOAD_ADDR 0x40
#define HEADER_OFFSET_LOAD_SIZE 0x44

#endif // LGEBD_HPP
