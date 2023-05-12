#include "mkfs.h"

int parse_arguments(int argc, char *argv[], FormatOptions *options)
{
	int opt;
	while ((opt = getopt(argc, argv, "b:g:L:d:")) != -1)
	{
		switch (opt)
		{
		case 'b':
			options->block_size = atoi(optarg);
			break;
		case 'g':
			options->blocks_per_group = atoi(optarg);
			break;
		case 'L':
			options->volume_label = optarg;
			break;
		case 'd':
			options->device_path = optarg;
			break;
		default:
			printf("Usage: %s -d <device_path> [-b <block_size>] [-i <inode_size>]\n", argv[0]);
			return -1;
		}
	}
	return options->device_path == NULL ? -1 : 0;
}

int filled_block_calculation(int gdt_blocksize, struct ext2_super_block super_block, int block_size)
{
	return (gdt_blocksize - super_block.s_reserved_gdt_blocks - ((super_block.s_inodes_per_group * super_block.s_inode_size) / block_size));
}

int toPower(int num1, int num2)
{
	do
	{
		if (num1 % num2 != 0)
			return 0;
		num1 /= num2;
	} while (num1 != 1);

	return 1;
}

void block_group_descriptor_0s(struct ext2_group_desc block_group_descriptor)
{
	block_group_descriptor.bg_flags = 0;
	block_group_descriptor.bg_checksum = 0;
	block_group_descriptor.bg_block_bitmap_csum_lo = 0;
	block_group_descriptor.bg_exclude_bitmap_lo = 0;
	block_group_descriptor.bg_inode_bitmap_csum_lo = 0;
	block_group_descriptor.bg_itable_unused = 0;
}

void inode_value_setting(struct ext2_inode *inode)
{
	inode->i_atime = time(NULL);
	inode->i_ctime = time(NULL);
	inode->i_mtime = time(NULL);
	inode->i_uid = 0;
	inode->i_dtime = 0;
	inode->i_gid = 0;
	inode->i_flags = 0;

	inode->osd1.linux1.l_i_version = 0;
	inode->osd1.hurd1.h_i_translator = 0;

	inode->i_generation = 0;
	inode->i_file_acl = 0;
	inode->i_size_high = 0;
	inode->i_faddr = 0;

	inode->osd2.linux2.l_i_blocks_hi = 0;
	inode->osd2.linux2.l_i_file_acl_high = 0;
	inode->osd2.linux2.l_i_uid_high = 0;
	inode->osd2.linux2.l_i_gid_high = 0;
	inode->osd2.linux2.l_i_checksum_lo = 0;
	inode->osd2.linux2.l_i_reserved = 0;

	inode->osd2.hurd2.h_i_frag = 0;
	inode->osd2.hurd2.h_i_fsize = 0;
	inode->osd2.hurd2.h_i_mode_high = 0;
	inode->osd2.hurd2.h_i_uid_high = 0;
	inode->osd2.hurd2.h_i_gid_high = 0;
	inode->osd2.hurd2.h_i_author = 0;
}

int directory_entry(struct ext2_dir_entry_2 *dirent, int inode, int name_length, int ftype, char *str, int record_length)
{

	dirent->inode = inode;
	dirent->rec_len = record_length;
	dirent->name_len = name_length;
	dirent->file_type = ftype;
	strcpy(dirent->name, str);
	return 0;
}

void super_blockf(struct ext2_super_block super_block, int block_size, long long int physical_block_size, int total_no_of_blockGroups, long long int freebl_usingbgdesc, char *volume_label)
{

	super_block.s_blocks_count = (physical_block_size / block_size);
	super_block.s_blocks_per_group = block_size * 8;
	unsigned int no_of_inodes_perBlockGroup = block_size / 8;
	total_no_of_blockGroups = ceil((float)super_block.s_blocks_count / super_block.s_blocks_per_group);

	super_block.s_inode_size = 256;							 /* size of inode structure */
	super_block.s_inodes_per_group = no_of_inodes_perBlockGroup * block_size / super_block.s_inode_size; /* # Inodes per group */
	super_block.s_inodes_count = super_block.s_inodes_per_group * total_no_of_blockGroups;
	super_block.s_free_inodes_count = super_block.s_inodes_count - 11;	 /* Free inodes count */
	super_block.s_free_blocks_count = freebl_usingbgdesc;		 /* Free blocks count */
	super_block.s_log_block_size = block_size >> 11; /* Block size */	 // blocksize = 1024 << s_log_block_size
	super_block.s_log_cluster_size = block_size >> 11;		 /* Allocation cluster size */
	super_block.s_r_blocks_count = (5 * super_block.s_blocks_count) / 100; /* Reserved blocks count */
	super_block.s_clusters_per_group = super_block.s_blocks_per_group;	 /* # Fragments per group */

	if (super_block.s_log_block_size)
		super_block.s_first_data_block = 0; // 	/* First Data Block */
	else
		super_block.s_first_data_block = 1; // 	/* First Data Block */

	super_block.s_mtime = 0;		     /* Mount time */
	super_block.s_wtime = time(NULL);	     /* Write time */
	super_block.s_mnt_count = 0;		     /* Mount count */
	super_block.s_max_mnt_count = -1;	     /* Maximal mount count */
	super_block.s_magic = EXT2_SUPER_MAGIC;	     /* Magic signature */
	super_block.s_state = EXT2_VALID_FS;	     /* File system state */
	super_block.s_errors = EXT2_ERRORS_CONTINUE; /* Behaviour when detecting errors */
	super_block.s_minor_rev_level = 0;	     /* minor revision level */
	super_block.s_lastcheck = time(NULL);	     /* time of last check */
	super_block.s_checkinterval = 0;	     /* max. time between checks */
	super_block.s_creator_os = EXT2_OS_LINUX;    /* OS */
	super_block.s_rev_level = EXT2_DYNAMIC_REV;  /* Revision level */
	super_block.s_def_resuid = 0;		     /* Default uid for reserved blocks */
	super_block.s_def_resgid = 0;		     /* Default gid for reserved blocks */
	super_block.s_first_ino = 11;		     /* First non-reserved inode */
	super_block.s_block_group_nr = 0;	     /* block group # of this superblock */
	uuid_generate(super_block.s_uuid);	     /* 128-bit uuid for volume */
	super_block.s_volume_name[0] = volume_label; /* volume name */
	super_block.s_last_mounted[0] = '\0';	     /* directory where last mounted */
	super_block.s_algorithm_usage_bitmap = 0;    /* For compression */
	super_block.s_prealloc_blocks = 0;	     /* Nr of blocks to try to preallocate*/
	super_block.s_prealloc_dir_blocks = 0;	     /* Nr to preallocate for dirs */

	if (block_size == 4096)
		super_block.s_reserved_gdt_blocks = 127; /* Per group table for online growth */
	else if (block_size == 2048)
		super_block.s_reserved_gdt_blocks = 512;
	else
		super_block.s_reserved_gdt_blocks = 256;
	for (int i = 0; i < 17; i++)
		super_block.s_journal_uuid[i] = 0; /* uuid of journal superblock */

	super_block.s_journal_inum = 0;	        /* inode number of journal file */
	super_block.s_journal_dev = 0;	        /* device number of journal file */
	super_block.s_last_orphan = 0;	        /* start of list of inodes to delete */
	uuid_generate((char *)super_block.s_hash_seed); /* HTREE hash seed */
	super_block.s_def_hash_version = 1;	        /* Default hash version to use */
	super_block.s_jnl_backup_type = 0;	        /* Default type of journal backup */
	super_block.s_desc_size = 0;		        /* Group desc. size: INCOMPAT_64BIT */
	super_block.s_default_mount_opts = 12;
	super_block.s_first_meta_bg = 0;      /* First metablock group */
	super_block.s_mkfs_time = time(NULL); /* When the filesystem was created */

	for (int i = 0; i < 18; i++)
	{
		super_block.s_jnl_blocks[i] = 0; /* Backup of the journal inode */
	}

	super_block.s_blocks_count_hi = 0;				     /* Blocks count high 32bits */
	super_block.s_r_blocks_count_hi = 0;				     /* Reserved blocks count high 32 bits*/
	super_block.s_free_blocks_hi = 0;				     /* Free blocks count */
	super_block.s_min_extra_isize = 32; /* All inodes have at least # bytes */ // 256
	super_block.s_want_extra_isize = 32;				     /* New inodes should reserve # bytes */
	super_block.s_flags = 1;					     /* Miscellaneous flags */
	super_block.s_raid_stride = 0;				     /* RAID stride */
	super_block.s_mmp_update_interval = 0;				     /* # seconds to wait in MMP checking */
	super_block.s_mmp_block = 0;					     /* Block for multi-mount protection */
	super_block.s_raid_stripe_width = 0;				     /* blocks on all data disks (N*stride)*/
	super_block.s_log_groups_per_flex = 0;				     /* FLEX_BG group size */
	super_block.s_checksum_type = 0;				     /* metadata checksum algorithm */
	super_block.s_encryption_level = 0;				     /* versioning level for encryption */
	super_block.s_reserved_pad = 0;				     /* Padding to next 32bits */
	super_block.s_kbytes_written = 0;				     /* nr of lifetime kilobytes written */
	super_block.s_snapshot_inum = 0;				     /* Inode number of active snapshot */
	super_block.s_snapshot_id = 0;				     /* sequential ID of active snapshot */
	super_block.s_snapshot_r_blocks_count = 0;			     /* reserved blocks for active snapshot's future use */
	super_block.s_snapshot_list = 0;				     /* inode number of the head of the on-disk snapshot list */
	super_block.s_error_count = 0;				     /* number of fs errors */
	super_block.s_first_error_time = 0;				     /* first time an error happened */
	super_block.s_first_error_ino = 0;				     /* inode involved in first error */
	super_block.s_first_error_block = 0;				     /* block involved of first error */

	for (int i = 0; i < 32; i++)
	{
		super_block.s_first_error_func[i] = 0; /* function where the error happened */
	}

	super_block.s_first_error_line = 0;    /* line number where error happened */
	super_block.s_last_error_time = 0;     /* most recent time of an error */
	super_block.s_last_error_ino = 0;      /* inode involved in last error */
	super_block.s_last_error_line = 0;     /* line number where error happened */
	super_block.s_last_error_block = 0;    /* block involved of last error */
	super_block.s_last_error_func[32] = 0; /* function where the error happened */

	super_block.s_mount_opts[64] = 0;
	super_block.s_usr_quota_inum = 0;      /* inode number of user quota file */
	super_block.s_grp_quota_inum = 0;      /* inode number of group quota file */
	super_block.s_overhead_blocks = 0;     /* overhead blocks/clusters in fs */
	super_block.s_backup_bgs[2] = 0;       /* If sparse_super2 enabled */
	super_block.s_encrypt_algos[4] = 0;    /* Encryption algorithms in use  */
	super_block.s_encrypt_pw_salt[16] = 0; /* Salt used for string2key algorithm */
	super_block.s_lpf_ino = 0;	         /* Location of the lost+found inode */
	super_block.s_prj_quota_inum = 0;      /* inode for tracking project quota */
	super_block.s_checksum_seed = 0;       /* crc32c(orig_uuid) if csum_seed set */
	super_block.s_reserved[98] = 0;        /* Padding to the end of the block */
	super_block.s_checksum = 0;	         /* crc32c(superblock) */
}
void block_group_descriptor_table(struct ext2_super_block super_block, int block_group, struct ext2_group_desc block_group_descriptor, int total_no_of_blockGroups, int gdt_blocksize, long long int freebl_usingbgdesc, int block_size, int fd)
{

	// printf("The Size of block_group_descriptor is: %ld\n", sizeof(block_group_descriptor));
	int reqsize_gdt = total_no_of_blockGroups * sizeof(block_group_descriptor);
	gdt_blocksize = (reqsize_gdt + block_size - 1) / block_size;
	freebl_usingbgdesc = 0;
	long long int tb = 0; /* to store the number of free blocks in a block group*/

	for (block_group = 0; block_group < total_no_of_blockGroups; block_group++)
	{
		long long int initial = 0;
		for (int i = 0; i < block_group; i++)
		{
			initial += super_block.s_blocks_per_group;
		}

		bool is_special_group = (block_group == 0 ||
				     block_group == 1 ||
				     toPower(block_group, 3) ||
				     toPower(block_group, 5) ||
				     toPower(block_group, 7));
		if (is_special_group)
		{
			block_group_descriptor.bg_block_bitmap = (block_size == 1024) ? (initial + 1 + 1 + gdt_blocksize + super_block.s_reserved_gdt_blocks) : (initial + 1 + gdt_blocksize + super_block.s_reserved_gdt_blocks);
		}
		else
		{
			block_group_descriptor.bg_block_bitmap = (block_size == 1024) ? (initial + 1) : (initial);
		}

		long long int bg_inode_bitmap_offset = 1;
		long long int bg_inode_table_offset = bg_inode_bitmap_offset + 1;

		block_group_descriptor.bg_inode_bitmap = block_group_descriptor.bg_block_bitmap + bg_inode_bitmap_offset;
		block_group_descriptor.bg_inode_table = block_group_descriptor.bg_inode_bitmap + bg_inode_table_offset;

		if (block_group == 0)
		{

			tb = (block_group == total_no_of_blockGroups - 1) ? ((super_block.s_blocks_count % super_block.s_blocks_per_group == 0) ? super_block.s_blocks_per_group : super_block.s_blocks_count % super_block.s_blocks_per_group) : super_block.s_blocks_per_group;

			block_group_descriptor.bg_free_blocks_count = tb - filled_block_calculation(gdt_blocksize, super_block, block_size) - 9;

			int blockCount;

			switch (block_size)
			{
			case 1024:
				blockCount = 9;
				break;
			case 2048:
				blockCount = 4;
				break;
			default:
				blockCount = 0;
			}

			if (blockCount > 0)
			{
				block_group_descriptor.bg_free_blocks_count -= blockCount;
			}

			else if (block_group == 1 || toPower(block_group, 3) || toPower(block_group, 5) || toPower(block_group, 7))
			{
				int tb = block_group == total_no_of_blockGroups - 1 ? (super_block.s_blocks_count % super_block.s_blocks_per_group == 0 ? super_block.s_blocks_per_group : super_block.s_blocks_count % super_block.s_blocks_per_group)
									  : super_block.s_blocks_per_group;
				block_group_descriptor.bg_free_blocks_count = tb - filled_block_calculation(gdt_blocksize, super_block, block_size) - 3;
			}

			else
			{

				tb = (block_group == total_no_of_blockGroups - 1) ? super_block.s_blocks_count % super_block.s_blocks_per_group : super_block.s_blocks_per_group;
				tb = (tb == 0) ? super_block.s_blocks_per_group : tb;

				block_group_descriptor.bg_free_blocks_count = tb - filled_block_calculation(gdt_blocksize, super_block, block_size) - 2;
			}

			freebl_usingbgdesc = freebl_usingbgdesc + block_group_descriptor.bg_free_blocks_count;

			switch (block_group)
			{
			case 0:
				block_group_descriptor.bg_used_dirs_count = 2;
				block_group_descriptor.bg_free_inodes_count = super_block.s_inodes_per_group - 11;
				break;
			default:
				block_group_descriptor.bg_used_dirs_count = 0;
				block_group_descriptor.bg_free_inodes_count = super_block.s_inodes_per_group;
				break;
			}

			block_group_descriptor_0s(block_group_descriptor);

			write(fd, &block_group_descriptor, sizeof(struct ext2_group_desc));
		}
	}
}
int read_block_group_descriptor(int group_number, int block_size, int fd, struct ext2_group_desc *block_group_descriptor)
{

	off_t offset;

	if (block_size == 1024)
		offset = 2 * block_size + group_number * sizeof(struct ext2_group_desc);
	else if (block_size == 2048 || block_size == 4096)
	{
		offset = block_size + group_number * sizeof(struct ext2_group_desc);
	}
	if (lseek(fd, offset, SEEK_SET) == -1)
	{
		perror("lseek error");
		return -1;
	}
	if (read(fd, block_group_descriptor, sizeof(struct ext2_group_desc)) == -1)
	{
		perror("read error");
		return -1;
	}
	return 0;
}
int replicate_superGDT(int total_no_of_blockGroups, int block_size, int fd, struct ext2_super_block super_block, struct ext2_group_desc block_group_descriptor)
{
	off_t offset;
	for (int block_group = 1; block_group < total_no_of_blockGroups; block_group++)
	{
		if (block_group == 1 || toPower(block_group, 3) || toPower(block_group, 5) || toPower(block_group, 7))
		{
			offset = block_group * super_block.s_blocks_per_group * block_size;
			if (lseek(fd, offset, SEEK_SET) == -1)
			{
				perror("lseek error");
				return -1;
			}
			if (write(fd, &super_block, sizeof(struct ext2_super_block)) == -1)
			{
				perror("write error");
				return -1;
			}
			for (int i = 0; i < total_no_of_blockGroups; i++)
			{
				if (read_block_group_descriptor(i, block_size, fd, &block_group_descriptor) == -1)
				{
					return -1;
				}
				offset = block_group * super_block.s_blocks_per_group * block_size + block_size + i * sizeof(struct ext2_group_desc);
				if (lseek(fd, offset, SEEK_SET) == -1)
				{
					perror("lseek error");
					return -1;
				}
				offset = i * sizeof(struct ext2_group_desc);
				if (lseek(fd, offset, SEEK_CUR) == -1)
				{
					perror("lseek error");
					return -1;
				}
				if (write(fd, &block_group_descriptor, sizeof(struct ext2_group_desc)) == -1)
				{
					perror("write error");
					return -1;
				}
			}
		}
	}
	return 0;
}

int value_datablock_bitmap(int gdt_blocksize, struct ext2_super_block super_block, int block_size)
{
	int result = (int)(1 + gdt_blocksize + super_block.s_reserved_gdt_blocks + 1 + 1 + ((super_block.s_inodes_per_group * super_block.s_inode_size) / block_size));
	return result;
}

void data_block_bitmap(int total_no_of_blockGroups, int block_size, int gdt_blocksize, int fd, struct ext2_super_block super_block, struct ext2_group_desc block_group_descriptor)
{
	int no_of_bits_for_blockBitmap = super_block.s_blocks_per_group / 32;
	int raw;
	for (int block_group = 0; block_group < total_no_of_blockGroups; block_group++)
	{
		read_block_group_descriptor(block_group, block_size, fd, &block_group_descriptor);
		lseek(fd, block_group_descriptor.bg_block_bitmap * block_size, SEEK_SET);
		bool is_special_group = (block_group == 1 ||
				     toPower(block_group, 3) ||
				     toPower(block_group, 5) ||
				     toPower(block_group, 7));
		if (block_group == 0)
		{
			raw = value_datablock_bitmap + 5;
			if (block_size == 1024)
				raw += 1;
		}
		else if (is_special_group)
		{
			raw = value_datablock_bitmap;
			if (block_size == 1024)
				raw += 1;
		}
		else
		{
			raw = 1 + 1 + ((super_block.s_inodes_per_group * super_block.s_inode_size) / block_size);
			if (block_size == 1024)
				raw += 1;
		}
		int filled1 = raw / 32;
		unsigned int ones = 0xFFFFFFFF;
		for (int i = 0; i < filled1; i++)
		{
			write(fd, &ones, sizeof(ones));
		}
		int remaining1 = raw % 32;
		if (remaining1)
		{
			int result, i = 0;
			while (remaining1 != 0)
			{
				result += pow(2, i);
				++i;
				--remaining1;
			}
			int decimal = result;
			write(fd, &decimal, sizeof(decimal));
		}

		int number_of_zeros = (no_of_bits_for_blockBitmap - ceil((float)raw / 32));
		int v = 0;

		while (v < number_of_zeros)
		{
			write(fd, &number_of_zeros, sizeof(number_of_zeros));
			v++;
		}
	}
}

int inode_bitmap(int fd, struct ext2_super_block super_block, struct ext2_group_desc block_group_descriptor, int block_size, int total_no_of_blockGroups)
{
	int no_of_bits_for_blockBitmap = super_block.s_blocks_per_group / 32;
	read_block_group_descriptor(0, block_size, fd, &block_group_descriptor);
	lseek(fd, block_group_descriptor.bg_inode_bitmap * block_size, SEEK_SET);
	int raw = 0x000007FF;
	write(fd, &raw, sizeof(raw));
	raw = 0x00000000;

	int v = 0;
	while (v < no_of_bits_for_blockBitmap - 1)
	{
		write(fd, &raw, sizeof(raw));
		v++;
	}
	for (int i = 1; i < total_no_of_blockGroups; i++)
	{
		read_block_group_descriptor(i, block_size, fd, &block_group_descriptor);
		lseek(fd, block_group_descriptor.bg_inode_bitmap * block_size, SEEK_SET);

		int v = 0;
		while (v < no_of_bits_for_blockBitmap)
		{
			write(fd, &raw, sizeof(raw));
			v++;
		}
	}
	return 0;
}

void write_inodetable(int fd, int inode_no, struct ext2_super_block super_block, struct ext2_group_desc block_group_descriptor, struct ext2_inode *inode, int block_size, int gdt_blocksize)
{

	switch (inode_no)
	{
	case 2:
		inode->i_size = block_size;
		inode->i_mode = 0x4000;
		inode->i_links_count = 2;

		inode->i_block[0] = (block_size == 1024) ? 2 + gdt_blocksize + super_block.s_reserved_gdt_blocks + 1 + 1 + ((super_block.s_inodes_per_group * super_block.s_inode_size) / block_size) : 1 + gdt_blocksize + super_block.s_reserved_gdt_blocks + 1 + 1 + ((super_block.s_inodes_per_group * super_block.s_inode_size) / block_size);
		break;

	case 11:
		inode->i_size = 4 * block_size;
		inode->i_mode = 0x4000;
		inode->i_links_count = 2;

		int inode_block_count = (super_block.s_inodes_per_group * super_block.s_inode_size) / block_size;
		int base_block_count = 2 + gdt_blocksize + super_block.s_reserved_gdt_blocks + 1 + 1 + inode_block_count;

		inode->i_block[0] = block_size == 1024 ? base_block_count + 1 : base_block_count;
		for (int i = 1; i < 4; i++)
		{
			inode->i_block[i] = inode->i_block[i - 1] + 1;
		}
		break;

	default:
		break;
	}

	inode->i_blocks = inode->i_size / block_size;
	inode_value_setting(inode); 
	read_block_group_descriptor(0, block_size, fd, &block_group_descriptor);

	off_t offset = (block_group_descriptor.bg_inode_table * block_size + (inode_no - 1) * 256);

	lseek(fd, offset, SEEK_SET);
	write(fd, inode, sizeof(struct ext2_inode));
}

int WriteDBlocks(int fd, struct ext2_super_block super_block, struct ext2_group_desc block_group_descriptor, struct ext2_inode inode, struct ext2_dir_entry_2 *dirent, int block_size)
{

	read_block_group_descriptor(0, block_size, fd, &block_group_descriptor);

	off_t offset1 = block_group_descriptor.bg_inode_table * block_size + 2 * sizeof(struct ext2_inode);
	lseek(fd, offset1, SEEK_SET);
	read(fd, &inode, sizeof(struct ext2_inode));

	off_t offset2 = inode.i_block[0] * block_size;
	lseek(fd, offset2, SEEK_SET);
	directory_entry(dirent, 2, 5, 2, ".\0\0\0", 14);
	write(fd, dirent, sizeof(struct ext2_dir_entry_2));

	off_t offset3 = dirent->rec_len - sizeof(struct ext2_dir_entry_2);
	lseek(fd, offset3, SEEK_CUR);
	directory_entry(dirent, 2, 2, 2, "..\0\0", 14);
	write(fd, dirent, sizeof(struct ext2_dir_entry_2));

	off_t offset4 = dirent->rec_len - sizeof(struct ext2_dir_entry_2);
	lseek(fd, offset4, SEEK_CUR);
	directory_entry(dirent, 2, 11, 2, "lost+found\0\0", 25);
	write(fd, dirent, sizeof(struct ext2_dir_entry_2));

	off_t offset5 = block_group_descriptor.bg_inode_table * block_size + 10 * 2 * sizeof(struct ext2_inode);
	lseek(fd, offset5, SEEK_SET);
	read(fd, &inode, sizeof(struct ext2_inode));

	off_t offset6 = inode.i_block[0] * block_size;
	lseek(fd, offset6, SEEK_SET);
	directory_entry(dirent, 11, 2, 2, ".\0\0\0", 14);
	write(fd, dirent, sizeof(struct ext2_dir_entry_2));

	off_t offset7 = dirent->rec_len - sizeof(struct ext2_dir_entry_2);
	lseek(fd, offset7, SEEK_CUR);
	directory_entry(dirent, 11, 2, 2, "..\0\0", 14);
	write(fd, dirent, sizeof(struct ext2_dir_entry_2));

	return 0;
}
