from dissect import cstruct

# https://ogris.de/fatrepair/fat.c
c_fat_def = """
#define ATTR_READ_ONLY 0x01
#define ATTR_HIDDEN    0x02
#define ATTR_SYSTEM    0x04
#define ATTR_VOLUME_ID 0x08
#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE   0x20
#define ATTR_LONG_NAME (ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID)
#define ATTR_LONG_NAME_MASK (ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID | ATTR_DIRECTORY | ATTR_ARCHIVE)

#define LAST_LONG_ENTRY 0x40

enum Fattype {
    FATunknown,
    FAT12,
    FAT16,
    FAT32
};

struct Bpb {
    uint8_t  BS_jmpBoot[3];    /* jump instruction to boot code */
    uint8_t  BS_OEMName[8];    /* "MSWIN4.1" */
    uint16_t BPB_BytsPerSec;   /* bytes per sector (512, 1k, 2k, 4k) */
    uint8_t  BPB_SecPerClus;   /* sectors per cluster (2^n, 0<=n<=7) */
    uint16_t BPB_RsvdSecCnt;   /* number of reserved sectors */
    uint8_t  BPB_NumFATs;      /* count of FATs on the volume (usually 2) */
    uint16_t BPB_RootEntCnt;   /* count of root directory entries (0 if FAT32) */
    uint16_t BPB_TotSec16;     /* total count of sectors (0 if FAT32) */
    uint8_t  BPB_Media;        /* media type, usally 0xf8 */
    uint16_t BPB_FATSz16;      /* sectors occupied by one fat (FAT12 / FAT16) */
    uint16_t BPB_SecPerTrk;    /* sectors per track for Int 0x13 */
    uint16_t BPB_NumHeads;     /* numbers of heads for Int 0x13 */
    uint32_t BPB_HiddSec;      /* count of sectors preceding the partition */
    uint32_t BPB_TotSec32;     /* total count of all sectors of the volume */
};

struct Bpb16 {
    uint8_t  BS_DrvNum;        /* Int 0x13 drive number, eg. 0x80 */
    uint8_t  BS_Reserved1;     /* reserved for WinNT (usually 0) */
    uint8_t  BS_BootSig;       /* extended boot signature (0x29) */
    uint32_t BS_VolID;         /* volume serial number (date + time) */
    uint8_t  BS_VolLab[11];    /* volume label as stored in the root directory */
    uint8_t  BS_FilSysType[8]; /* informational! */
};

struct Bpb32 {
    uint32_t BPB_FATSz32;      /* sectors occupied by one fat (FAT32) */
    uint16_t BPB_ExtFlags;     /* FAT mirrored? */
    uint16_t BPB_FSVer;        /* version number of FAT filesystem type */
    uint32_t BPB_RootClus;     /* cluster number of first cluster of root dir */
    uint16_t BPB_FSInfo;       /* sector number of FSINFO (usually 1) */
    uint16_t BPB_BkBootSec;    /* sector number of copy of boot sector */
    uint8_t  BPB_Reserved[12]; /* reserved for future use */

    uint8_t  BS_DrvNum;        /* Int 0x13 drive number, eg. 0x80 */
    uint8_t  BS_Reserved1;     /* reserved for WinNT (usually 0) */
    uint8_t  BS_BootSig;       /* extended boot signature (0x29) */
    uint32_t BS_VolID;         /* volume serial number (date + time) */
    uint8_t  BS_VolLab[11];    /* volume label as stored in the root directory */
    uint8_t  BS_FilSysType[8]; /* informational! */
};

struct Dirent {
    uint8_t  DIR_Name[11];
    uint8_t  DIR_Attr;
    uint8_t  DIR_NTRes;
    uint8_t  DIR_CrtTimeTenth;
    uint16_t DIR_CrtTime;
    uint16_t DIR_CrtDate;
    uint16_t DIR_LstAccDate;
    uint16_t DIR_FstClusHI;
    uint16_t DIR_WrtTime;
    uint16_t DIR_WrtDate;
    uint16_t DIR_FstClusLO;
    uint32_t DIR_FileSize;
};

struct Ldirent {
    uint8_t  LDIR_Ord;
    uint8_t  LDIR_Name1[10];
    uint8_t  LDIR_Attr;
    uint8_t  LDIR_Type;
    uint8_t  LDIR_Chksum;
    uint8_t  LDIR_Name2[12];
    uint16_t LDIR_FstClusLO;
    uint8_t  LDIR_Name3[4];
};
"""  # noqa: E501

c_fat = cstruct.cstruct()
c_fat.load(c_fat_def)

Fattype = c_fat.Fattype

VALID_BPB_MEDIA = {0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF}

DATA_CLUSTER_MIN = 0x2
DATA_CLUSTER_MAX = 0x0FFFFFEF
END_OF_CLUSTER_MIN = 0x0FFFFFF8
END_OF_CLUSTER_MAX = 0x0FFFFFFF

FAT12_EOC = 0xFF0
BAD_CLUSTER = 0x0FFFFFF7
FREE_CLUSTER = 0x0
