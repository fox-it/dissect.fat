from __future__ import annotations

from dissect.cstruct import cstruct

# fastfat/fat.h, fastfat/lfn.h
fat_def = """
typedef struct _BIOS_PARAMETER_BLOCK {
    USHORT  BytesPerSector;             /* bytes per sector (512, 1k, 2k, 4k) */
    INT8    SectorsPerCluster;          /* sectors per cluster (2^n, 0<=n<=7) */
    USHORT  ReservedSectors;            /* number of reserved sectors */
    UCHAR   Fats;                       /* count of FATs on the volume (usually 2) */
    USHORT  RootEntries;                /* count of root directory entries (0 if FAT32) */
    USHORT  Sectors;                    /* total count of sectors (0 if FAT32) */
    UCHAR   Media;                      /* media type, usally 0xf8 */
    USHORT  SectorsPerFat;              /* sectors occupied by one fat (FAT12 / FAT16) */
    USHORT  SectorsPerTrack;            /* sectors per track for Int 0x13 */
    USHORT  Heads;                      /* numbers of heads for Int 0x13 */
    ULONG   HiddenSectors;              /* count of sectors preceding the partition */
    ULONG   LargeSectors;               /* total count of all sectors of the volume */
} BIOS_PARAMETER_BLOCK;

typedef struct _BIOS_PARAMETER_BLOCK_EX {
    USHORT  BytesPerSector;             /* bytes per sector (512, 1k, 2k, 4k) */
    INT8    SectorsPerCluster;          /* sectors per cluster (2^n, 0<=n<=7) */
    USHORT  ReservedSectors;            /* number of reserved sectors */
    UCHAR   Fats;                       /* count of FATs on the volume (usually 2) */
    USHORT  RootEntries;                /* count of root directory entries (0 if FAT32) */
    USHORT  Sectors;                    /* total count of sectors (0 if FAT32) */
    UCHAR   Media;                      /* media type, usally 0xf8 */
    USHORT  SectorsPerFat;              /* sectors occupied by one fat (FAT12 / FAT16) */
    USHORT  SectorsPerTrack;            /* sectors per track for Int 0x13 */
    USHORT  Heads;                      /* numbers of heads for Int 0x13 */
    ULONG   HiddenSectors;              /* count of sectors preceding the partition */
    ULONG   LargeSectors;               /* total count of all sectors of the volume */
    ULONG   LargeSectorsPerFat;         /* sectors occupied by one fat (FAT32) */
    USHORT  ExtendedFlags;              /* FAT mirrored? */
    USHORT  FsVersion;                  /* version number of FAT filesystem type */
    ULONG   RootDirFirstCluster;        /* cluster number of first cluster of root dir */
    USHORT  FsInfoSector;               /* sector number of FSINFO (usually 1) */
    USHORT  BackupBootSector;           /* sector number of copy of boot sector */
    UCHAR   Reserved[12];               /* reserved for future use */
} BIOS_PARAMETER_BLOCK_EX;

typedef struct _BOOT_SECTOR {
    UCHAR   Jump[3];                    /* jump instruction to boot code */
    UCHAR   Oem[8];                     /* "MSWIN4.1" */
    BIOS_PARAMETER_BLOCK Bpb;           /* BIOS Parameter Block */
    UCHAR   PhysicalDriveNumber;        /* Int 0x13 drive number, eg. 0x80 */
    UCHAR   CurrentHead;                /* reserved for WinNT (usually 0) */
    UCHAR   Signature;                  /* extended boot signature (0x29) */
    ULONG   Id;                         /* volume serial number (date + time) */
    UCHAR   VolumeLabel[11];            /* volume label as stored in the root directory */
    UCHAR   SystemId[8];                /* informational! */
} BOOT_SECTOR;

typedef struct _BOOT_SECTOR_EX {
    UCHAR   Jump[3];                    /* jump instruction to boot code */
    UCHAR   Oem[8];                     /* "MSWIN4.1" */
    BIOS_PARAMETER_BLOCK_EX Bpb;        /* BIOS Parameter Block */
    UCHAR   PhysicalDriveNumber;        /* Int 0x13 drive number, eg. 0x80 */
    UCHAR   CurrentHead;                /* reserved for WinNT (usually 0) */
    UCHAR   Signature;                  /* extended boot signature (0x29) */
    ULONG   Id;                         /* volume serial number (date + time) */
    UCHAR   VolumeLabel[11];            /* volume label as stored in the root directory */
    UCHAR   SystemId[8];                /* informational! */
} BOOT_SECTOR_EX;

//
//  The directory entry record exists for every file/directory on the
//  disk except for the root directory.
//

typedef struct _DIRENT {
    UCHAR          FileName[11];
    UCHAR          Attributes;
    UCHAR          NtByte;
    UCHAR          CreationMSec;
    USHORT         CreationTime;
    USHORT         CreationDate;
    USHORT         LastAccessDate;
    union {
        USHORT     ExtendedAttributes;
        USHORT     FirstClusterOfFileHi;
    };
    USHORT         LastWriteTime;
    USHORT         LastWriteDate;
    USHORT         FirstClusterOfFile;
    ULONG          FileSize;
} DIRENT;

//
//  The first byte of a dirent describes the dirent.  There is also a routine
//  to help in deciding how to interpret the dirent.
//

#define FAT_DIRENT_NEVER_USED           0x00
#define FAT_DIRENT_REALLY_0E5           0x05
#define FAT_DIRENT_DIRECTORY_ALIAS      0x2e
#define FAT_DIRENT_DELETED              0xe5

//
//  Define the various dirent attributes
//

#define FAT_DIRENT_ATTR_READ_ONLY       0x01
#define FAT_DIRENT_ATTR_HIDDEN          0x02
#define FAT_DIRENT_ATTR_SYSTEM          0x04
#define FAT_DIRENT_ATTR_VOLUME_ID       0x08
#define FAT_DIRENT_ATTR_DIRECTORY       0x10
#define FAT_DIRENT_ATTR_ARCHIVE         0x20
#define FAT_DIRENT_ATTR_DEVICE          0x40
#define FAT_DIRENT_ATTR_LFN             (FAT_DIRENT_ATTR_READ_ONLY | \
                                         FAT_DIRENT_ATTR_HIDDEN |    \
                                         FAT_DIRENT_ATTR_SYSTEM |    \
                                         FAT_DIRENT_ATTR_VOLUME_ID)

//
//  This structure defines the on disk format on long file name dirents.
//

typedef struct _LFN_DIRENT {
    UCHAR     Ordinal;
    UCHAR     Name1[10];
    UCHAR     Attributes;
    UCHAR     Type;
    UCHAR     Checksum;
    UCHAR     Name2[12];
    USHORT    MustBeZero;
    UCHAR     Name3[4];
} LFN_DIRENT;

#define FAT_LAST_LONG_ENTRY             0x40    // Ordinal field
"""

c_fat = cstruct(fat_def)
