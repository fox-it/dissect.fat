# References:
# - https://github.com/mborgerson/fatx
# - https://aerosoul94.github.io/blog/2020/02/25/fatx-reading-and-recovery.html
# - https://github.com/MrMilenko/Theseus
# With some creative naming liberty taken from the other FAT implementations
from __future__ import annotations

from dissect.cstruct import cstruct

fatx_def = """
/* FATX filesystem signature ('FATX') */
#define FAT_VOLUME_SIGNATURE            0x58544146

/* Size of the metadata block, in bytes. */
#define FAT_METADATA_BLOCK_SIZE         4096

/* Number of reserved entries in the FAT. */
#define FAT_RESERVED_FAT_ENTRIES        1

#define FAT_VOLUME_NAME_LENGTH          64
#define FAT_ONLINE_DATA_LENGTH          2048

/*
 * The FATX superblock as it appears on disk.
 */
struct _FAT_VOLUME_METADATA {
    ULONG   Signature;
    ULONG   SerialNumber;
    ULONG   SectorsPerCluster;
    ULONG   RootDirFirstCluster;
    UCHAR   VolumeName[FAT_VOLUME_NAME_LENGTH];
    UCHAR   OnlineData[FAT_ONLINE_DATA_LENGTH];
} FAT_VOLUME_METADATA;

/*
 * The directory entry as it appears on disk.
 */
struct _DIRENT {
    UCHAR   FileNameLength;
    UCHAR   FileAttributes;
    UCHAR   FileName[42];
    ULONG   FirstCluster;
    ULONG   FileSize;
    ULONG   CreationTime;
    ULONG   LastWriteTime;
    ULONG   LastAccessTime;
} DIRENT;

#define FAT_DIRENT_NEVER_USED           0x00
#define FAT_DIRENT_DELETED              0xe5
#define FAT_DIRENT_NEVER_USED2          0xff
"""

c_fatx = cstruct().load(fatx_def)
