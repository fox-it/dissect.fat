from dissect import cstruct

c_exfat_def = """
enum entry_types : uint8 {
    allocation_bitmap   = 0x81,
    upcase_table        = 0x82,
    volume_label        = 0x83,
    file_directory      = 0x85,
    stream_directory    = 0xC0,
    filename_directory  = 0xC1
};

typedef struct TIMESTAMP {
    uint32 seconds:5;
    uint32 minutes:6;
    uint32 hours:5;
    uint32 day:5;
    uint32 month:4;
    uint32 year:7;
};

typedef struct ENTRY_TYPE {
    uint8 in_use:1;
    uint8 category:1;
    uint8 importance:1;
    uint8 type_code:5;
};

typedef struct ATTRIBUTES {
    uint16 read_only:1;
    uint16 hidden:1;
    uint16 system:1;
    uint16 reserved_1:1;
    uint16 directory:1;
    uint16 archive:1;
    uint16 reserved:10;
};

typedef struct FILE_FLAGS {
    uint8 allocation_possible:1;
    uint8 not_fragmented:1;
    uint8 reserved_1:6;
};

typedef struct EXFAT_HEADER {
    uint8   jump_boot[3];               // 0x00 jmp and nop instructions
    char    fs_name[8];			        // 0x03 "EXFAT   "
    uint8   fat32[53];			        // 0x0B always 0 to avoid accidental mounting as FAT32
    uint64  volume_offset;			    // 0x40 first sector of exFAT volume
    uint64  volume_sector_count;	    // 0x48 sectors count of whole volume
    uint32  fat_sector;		            // 0x50 FAT first sector
    uint32  fat_sector_count;		    // 0x54 FAT sectors count
    uint32  cluster_heap_sector;	    // 0x58 first cluster sector
    uint32  cluster_heap_count;			// 0x5C total clusters count
    uint32  root_dir_cluster;			// 0x60 first cluster of the root dir
    uint32  volume_serial;			    // 0x64 volume serial number
    uint8   fs_version_min;             // 0x68 minor portion of FS version
    uint8   fs_version_maj;             // 0x69 major portion of FS version
    uint16  volume_flags;		    	// 0x6A volume state flags
    uint8   bytes_per_sector_exp;	    // 0x6C sector size as (1 << n)
    uint8   sectors_per_cluster_exp;	// 0x6D sectors per cluster as (1 << n)
    uint8   number_of_fats;  		    // 0x6E always 1
    uint8   drive_select;			    // 0x6F always 0x80
    uint8   percent_inuse;		        // 0x70 percentage of allocated space
    uint8   zeros_2[7];                 // 0x71 always 0
    uint8   boot_code[390];			    // 0x78 code containing bootloader for non-*nix systems
    uint16  boot_signature; 			// 0x1FE boot sector signature 0xAA55
};

typedef struct STREAM_DIRECTORY_ENTRY {
    uint8 entry_type;                  // 0x00 type of directory entry should be 0xC0 0x40
    FILE_FLAGS flags;                  // 0x01 only first 2 bits get used and only bit 1 is relevant True equals
                                       // notfragmented
    uint8 reserved_1;                  // 0x02 actually part of is_fragmented but does not get used in
                                       // current exFAT version
    uint8 filename_length;             // 0x03 length of filename In filename directory entry
    uint16 filename_hash;              // 0x04 hash of filename used to speed up lookups within exFAT
    uint16 protected;                  // 0x06 indicates whether file is protected by EFS
    uint64 valid_data_length;          // 0x08 allocated size of data in bytes only counts for files and is used for
                                       // pre-allocation zero if directory
    uint8 reserved_2[4];               // 0x10 no clue always zero
    uint32 location;                   // 0x15 starting cluster of data
    uint64 data_length;                // 0x18 actual size of data if directory always multiples of sector size
};

typedef struct FILENAME_DIRECTORY_ENTRY {
    uint8 entry_type;                  // 0x00 type of directory entry should be 0xC1 or 0x41
    uint8 flags;                       // 0x01 always zero for filename directory entry
    wchar filename[15];                // 0x02 filename of dir or file each char is represented as 16 bit unicode
};

typedef struct FILE_DIRECTORY_ENTRY {
    uint8  entry_type;                 // 0x00 type of directory entry should be 0x85 or 0x05
    uint8  subentry_count;             // 0x01 amount of secondary directory entries (minimal 2) stream and filename
    uint16 checksum;                   // 0x02 checksum off whole set File dir entries and subentry_count
    ATTRIBUTES attributes;             // 0x04 Microsoft file attrib exFAT uses only the first 5 bits
    uint8  zeros_1[2];                 // 0x06 always zero. checksum gets calculated over it
    uint32 create_time;                // 0x08 MS-DOS Timestamp format for created time
    uint32 modified_time;              // 0x0C MS-DOS Timestamp format for last modified time
    uint32 access_time;                // 0x10 MS-DOS Timestamp format for last access time
    uint8  create_offset;              // 0x14 centisecond offset of create time
    uint8  modified_offset;            // 0x15 centisecond offset of modified time
    uint8  create_timezone;            // 0x16 timezone offset to UTC of Create time
    uint8  modified_timezone;          // 0x17 timezone offset to UTC of Modified time
    uint8  access_timezone;            // 0x18 timezone offset to UTC of Access time
    uint8  zeros_2[7];                 // 0x19 always zero. Checksum gets calculated over it
};

typedef struct FILE {
    FILE_DIRECTORY_ENTRY     metadata; // collection of entries that define a file or directory
    STREAM_DIRECTORY_ENTRY   stream;
    FILENAME_DIRECTORY_ENTRY fn_entries[];
};

typedef struct VOLUME_DIRECTORY_ENTRY {
    uint8 entry_type;                  // 0x00 type of directory entry should be 0x83 or 0x03
    uint8 label_length;                // 0x01 length of volume label string
    wchar volume_label[11];            // 0x02 volume label string max 11 chars
    uint8 zeros_1[8];                  // 0x17 no clue always zero maybe volume label overflow chars
};

typedef struct BITMAP_DIRECTORY_ENTRY {
    uint8 entry_type;                 // 0x00 type of directory entry should be 0x81
    uint8 flags;                      // 0x01 indicates how many bitmaps are used always 0
                                      // which indicates 1 bitmaps is used
    uint8 reserved_1[18];             // 0x02 always zero reserved for later use
    uint32 bitmap_start_cluster;      // 0x0 cluster addr of the bitmap
    uint64 bitmap_length;             // 0x0 length of bitmap in bytes
};

typedef struct UPCASE_DIRECTORY_ENTRY {
    uint8 entry_type;                 // 0x00 type of directory entry should be 0x82
    uint8 reserved_1[3];              // 0x02 always zero reserved for later use
    uint32 upcase_checksum;           // 0x04 checksum of upcase tabel should always be 0DD319E6
    uint8 reserved_2[12];             // 0x08 always zero
    uint32 upcase_start_cluster;      // 0x0C cluster addr of upcase tabel
    uint64 upcase_length;             // 0x12 length of upcase tabel in bytes
};
"""

# default endianess is LE so we keep it that way.
c_exfat = cstruct.cstruct()
c_exfat.load(c_exfat_def)

EOC = 0xFFFFFFFF  # indicates end of cluster chain
FID = 0xFFFFFFF8  # indicates start of FAT

VOLUME_LABEL_ENTRY = c_exfat.entry_types.volume_label.value
FILE_ENTRY = c_exfat.entry_types.file_directory.value
FILENAME_ENTRY = c_exfat.entry_types.filename_directory.value
UPCASE_TABLE_ENTRY = c_exfat.entry_types.upcase_table.value
STREAM_ENTRY = c_exfat.entry_types.stream_directory.value
BITMAP_ENTRY = c_exfat.entry_types.allocation_bitmap.value

NO_VOLUME_LABEL_ENTRY = 0x03
FAT_ENTRY_SIZE = 4
DIR_ENTRY_SIZE = 32
