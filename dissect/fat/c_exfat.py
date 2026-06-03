# Resources:
# - https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification

from __future__ import annotations

from dissect.cstruct import cstruct

exfat_def = """
typedef struct _BOOT_SECTOR {
    UCHAR       JumpBoot[3];
    UCHAR       FileSystemName[8];
    UCHAR       MustBeZero[53];
    ULONGLONG   PartitionOffset;
    ULONGLONG   VolumeLength;
    ULONG       FatOffset;
    ULONG       FatLength;
    ULONG       ClusterHeapOffset;
    ULONG       ClusterCount;
    ULONG       FirstClusterOfRootDirectory;
    ULONG       VolumeSerialNumber;
    USHORT      FileSystemRevision;
    USHORT      VolumeFlags;
    UCHAR       BytesPerSectorShift;
    UCHAR       SectorsPerClusterShift;
    UCHAR       NumberOfFats;
    UCHAR       DriveSelect;
    UCHAR       PercentInUse;
    UCHAR       Reserved[7];
    UCHAR       BootCode[390];
    USHORT      BootSignature;
} BOOT_SECTOR;

#define EXFAT_DIRENT_SIZE           32

#define EXFAT_DIRENT_TYPE_END            0x00
#define EXFAT_DIRENT_TYPE_UNUSED         0x80
#define EXFAT_DIRENT_TYPE_ALLOC_BITMAP   0x81
#define EXFAT_DIRENT_TYPE_UPCASE         0x82
#define EXFAT_DIRENT_TYPE_VOLUME_LABEL   0x83
#define EXFAT_DIRENT_TYPE_FILE           0x85
#define EXFAT_DIRENT_TYPE_VOLUME_GUID    0xA0
#define EXFAT_DIRENT_TYPE_TEXFAT_PADDING 0xA1
#define EXFAT_DIRENT_TYPE_STREAM_EXT     0xC0
#define EXFAT_DIRENT_TYPE_FILE_NAME      0xC1
#define EXFAT_DIRENT_TYPE_VENDOR_EXT     0xE0
#define EXFAT_DIRENT_TYPE_VENDOR_ALLOC   0xE1

#define EXFAT_DIRENT_FLAG_ALLOC_POSSIBLE 0x01
#define EXFAT_DIRENT_FLAG_NO_FAT_CHAIN   0x02

typedef struct _DIRENT {
    UCHAR       EntryType;
    UCHAR       CustomDefined[31];
} DIRENT;

typedef struct _GENERIC_PRIMARY_DIRENT {
    UCHAR       EntryType;
    UCHAR       SecondaryCount;
    USHORT      SetChecksum;
    USHORT      GeneralPrimaryFlags;
    UCHAR       CustomDefined[14];
    ULONG       FirstCluster;
    ULONGLONG   DataLength;
} GENERIC_PRIMARY_DIRENT;

typedef struct _GENERIC_SECONDARY_DIRENT {
    UCHAR       EntryType;
    UCHAR       GeneralSecondaryFlags;
    UCHAR       CustomDefined[18];
    ULONG       FirstCluster;
    ULONGLONG   DataLength;
} GENERIC_SECONDARY_DIRENT;

typedef struct _ALLOC_BITMAP_DIRENT {
    UCHAR       EntryType;
    UCHAR       BitmapFlags;
    UCHAR       Reserved[18];
    ULONG       FirstCluster;
    ULONGLONG   DataLength;
} ALLOC_BITMAP_DIRENT;

typedef struct _UPCASE_DIRENT {
    UCHAR       EntryType;
    UCHAR       Reserved1[3];
    ULONG       TableChecksum;
    UCHAR       Reserved2[12];
    ULONG       FirstCluster;
    ULONGLONG   DataLength;
} UPCASE_DIRENT;

typedef struct _VOLUME_LABEL_DIRENT {
    UCHAR       EntryType;
    UCHAR       CharacterCount;
    UCHAR       VolumeLabel[22];
    UCHAR       Reserved[8];
} VOLUME_LABEL_DIRENT;

typedef struct _FILE_DIRENT {
    UCHAR       EntryType;
    UCHAR       SecondaryCount;
    USHORT      SetChecksum;
    USHORT      FileAttributes;
    UCHAR       Reserved1[2];
    ULONG       CreateTimestamp;
    ULONG       LastModifiedTimestamp;
    ULONG       LastAccessedTimestamp;
    UCHAR       Create10msIncrement;
    UCHAR       LastModified10msIncrement;
    UCHAR       CreateUtcOffset;
    UCHAR       LastModifiedUtcOffset;
    UCHAR       LastAccessedUtcOffset;
    UCHAR       Reserved2[7];
} FILE_DIRENT;

typedef struct _VOLUME_GUID_DIRENT {
    UCHAR       EntryType;
    UCHAR       SecondaryCount;
    USHORT      SetChecksum;
    USHORT      GeneralPrimaryFlags;
    UCHAR       VolumeGuid[16];
    UCHAR       Reserved[10];
} VOLUME_GUID_DIRENT;

typedef struct _STREAM_EXT_DIRENT {
    UCHAR       EntryType;
    UCHAR       GeneralSecondaryFlags;
    UCHAR       Reserved1;
    UCHAR       NameLength;
    USHORT      NameHash;
    UCHAR       Reserved2[2];
    ULONGLONG   ValidDataLength;
    UCHAR       Reserved3[4];
    ULONG       FirstCluster;
    ULONGLONG   DataLength;
} STREAM_EXT_DIRENT;

typedef struct _FILE_NAME_DIRENT {
    UCHAR       EntryType;
    UCHAR       GeneralSecondaryFlags;
    UCHAR       FileName[30];
} FILE_NAME_DIRENT;

typedef struct _VENDOR_EXT_DIRENT {
    UCHAR       EntryType;
    UCHAR       GeneralSecondaryFlags;
    UCHAR       VendorGuid[16];
    UCHAR       VendorDefined[14];
} VENDOR_EXT_DIRENT;

typedef struct _VENDOR_ALLOC_DIRENT {
    UCHAR       EntryType;
    UCHAR       GeneralSecondaryFlags;
    UCHAR       VendorGuid[16];
    UCHAR       VendorDefined[2];
    ULONG       FirstCluster;
    ULONGLONG   DataLength;
} VENDOR_ALLOC_DIRENT;
"""

c_exfat = cstruct().load(exfat_def)

PRIMARY_DIRENT = (
    c_exfat.ALLOC_BITMAP_DIRENT
    | c_exfat.UPCASE_DIRENT
    | c_exfat.VOLUME_LABEL_DIRENT
    | c_exfat.FILE_DIRENT
    | c_exfat.VOLUME_GUID_DIRENT
    | c_exfat.GENERIC_PRIMARY_DIRENT
)
SECONDARY_DIRENT = (
    c_exfat.STREAM_EXT_DIRENT
    | c_exfat.FILE_NAME_DIRENT
    | c_exfat.VENDOR_EXT_DIRENT
    | c_exfat.VENDOR_ALLOC_DIRENT
    | c_exfat.GENERIC_SECONDARY_DIRENT
)
