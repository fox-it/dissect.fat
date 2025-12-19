# Resources:
# - https://github.com/torvalds/linux/blob/master/fs/exfat/exfat_raw.h

from __future__ import annotations

from dissect.cstruct import cstruct

exfat_def = """
#define BOOT_SIGNATURE		0xAA55
#define EXBOOT_SIGNATURE	0xAA550000
#define STR_EXFAT		    "EXFAT   "	/* size should be 8 */

#define EXFAT_MAX_FILE_LEN	255

#define VOLUME_DIRTY		0x0002
#define MEDIA_FAILURE		0x0004

#define EXFAT_EOF_CLUSTER	0xFFFFFFFFu
#define EXFAT_BAD_CLUSTER	0xFFFFFFF7u
#define EXFAT_FREE_CLUSTER	0
/* Cluster 0, 1 are reserved, the first cluster is 2 in the cluster heap. */
#define EXFAT_RESERVED_CLUSTERS	2
#define EXFAT_FIRST_CLUSTER	2

/* AllocationPossible and NoFatChain field in GeneralSecondaryFlags Field */
#define ALLOC_POSSIBLE		0x01
#define ALLOC_FAT_CHAIN		0x01
#define ALLOC_NO_FAT_CHAIN	0x03

#define DENTRY_SIZE         32 /* directory entry size */
#define DENTRY_SIZE_BITS    5

/* exFAT allows 8388608(256MB) directory entries */
#define MAX_EXFAT_DENTRIES	8388608

#define IS_EXFAT_DELETED(x)	((x) < 0x80) /* deleted file (0x01~0x7F) */
/* dentry types */
#define EXFAT_UNUSED		0x00	/* end of directory */
#define EXFAT_DELETE		(~0x80)

#define EXFAT_INVAL         0x80	/* invalid value */
#define EXFAT_BITMAP		0x81	/* allocation bitmap */
#define EXFAT_UPCASE		0x82	/* upcase table */
#define EXFAT_VOLUME		0x83	/* volume label */
#define EXFAT_FILE          0x85	/* file or dir */
#define EXFAT_GUID		    0xA0
#define EXFAT_PADDING		0xA1
#define EXFAT_ACLTAB		0xA2
#define EXFAT_STREAM		0xC0	/* stream entry */
#define EXFAT_NAME		    0xC1	/* file name entry */
#define EXFAT_ACL		    0xC2	/* stream entry */
#define EXFAT_VENDOR_EXT	0xE0	/* vendor extension entry */
#define EXFAT_VENDOR_ALLOC	0xE1	/* vendor allocation entry */

/* checksum types */
#define CS_DIR_ENTRY    0
#define CS_BOOT_SECTOR  1
#define CS_DEFAULT      2

/* file attributes */
#define EXFAT_ATTR_READONLY	0x0001
#define EXFAT_ATTR_HIDDEN	0x0002
#define EXFAT_ATTR_SYSTEM	0x0004
#define EXFAT_ATTR_VOLUME	0x0008
#define EXFAT_ATTR_SUBDIR	0x0010
#define EXFAT_ATTR_ARCHIVE	0x0020

#define EXFAT_ATTR_RWMASK	(EXFAT_ATTR_HIDDEN | EXFAT_ATTR_SYSTEM | \
                EXFAT_ATTR_VOLUME | EXFAT_ATTR_SUBDIR | \
                EXFAT_ATTR_ARCHIVE)

#define BOOTSEC_JUMP_BOOT_LEN	3
#define BOOTSEC_FS_NAME_LEN     8
#define BOOTSEC_OLDBPB_LEN      53
#define EXFAT_FILE_NAME_LEN     15

/* EXFAT: Main and Backup Boot Sector (512 bytes) */
struct boot_sector {
	__u8	jmp_boot[BOOTSEC_JUMP_BOOT_LEN];
	__u8	fs_name[BOOTSEC_FS_NAME_LEN];
	__u8	must_be_zero[BOOTSEC_OLDBPB_LEN];
	__u64	partition_offset;
	__u64	vol_length;
	__u32	fat_offset;
	__u32	fat_length;
	__u32	clu_offset;
	__u32	clu_count;
	__u32	root_cluster;
	__u32	vol_serial;
	__u8	fs_revision[2];
	__u16	vol_flags;
	__u8	sect_size_bits;
	__u8	sect_per_clus_bits;
	__u8	num_fats;
	__u8	drv_sel;
	__u8	percent_in_use;
	__u8	reserved[7];
	__u8	boot_code[390];
	__u16	signature;
}


struct exfat_dentry {
	__u8 type;
	union dentry {
		struct {
			__u8 char_count;
			char vol_label[char_count * 2];
			__u8 reserved2[8];
		} volume; /* volume label directory entry */
		struct {
			__u8 num_ext;
			__u16 checksum;
			__u16 attr;
			__u16 reserved1;
			__u16 create_time;
			__u16 create_date;
			__u16 modify_time;
			__u16 modify_date;
			__u16 access_time;
			__u16 access_date;
			__u8 create_time_cs;
			__u8 modify_time_cs;
			__u8 create_tz;
			__u8 modify_tz;
			__u8 access_tz;
			__u8 reserved2[7];
		} file; /* file directory entry */
		struct {
			__u8 flags;
			__u8 reserved1;
			__u8 name_len;
			__u16 name_hash;
			__u16 reserved2;
			__u64 valid_size;
			__u32 reserved3;
			__u32 start_clu;
			__u64 size;
		} stream; /* stream extension directory entry */
		struct {
			__u8 flags;
			__u16 unicode_0_14[EXFAT_FILE_NAME_LEN];
		} name; /* file name directory entry */
		struct {
			__u8 flags;
			__u8 reserved[18];
			__u32 start_clu;
			__u64 size;
		} bitmap; /* allocation bitmap directory entry */
		struct {
			__u8 reserved1[3];
			__u32 checksum;
			__u8 reserved2[12];
			__u32 start_clu;
			__u64 size;
		} upcase; /* up-case table directory entry */
		struct {
			__u8 flags;
			__u8 vendor_guid[16];
			__u8 vendor_defined[14];
		} vendor_ext; /* vendor extension directory entry */
		struct {
			__u8 flags;
			__u8 vendor_guid[16];
			__u8 vendor_defined[2];
			__u32 start_clu;
			__u64 size;
		} vendor_alloc; /* vendor allocation directory entry */
		struct {
			__u8 flags;
			__u8 custom_defined[18];
			__u32 start_clu;
			__u64 size;
		} generic_secondary; /* generic secondary directory entry */
	};
};

#define EXFAT_TZ_VALID		(1 << 7)

/* Jan 1 GMT 00:00:00 1980 */
#define EXFAT_MIN_TIMESTAMP_SECS    315532800LL
/* Dec 31 GMT 23:59:59 2107 */
#define EXFAT_MAX_TIMESTAMP_SECS    4354819199LL
"""

c_exfat = cstruct().load(exfat_def)

BOOT_REGION_SIZE = 512 * 12  # 12 sectors of 512 bytes
