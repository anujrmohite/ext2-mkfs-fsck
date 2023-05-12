#include "fsck.h"
#include "mkfs.h"

int block_size;
int total_no_of_blockGroups;
int gdt_blocksize;
long long int freebl_usingbgdesc;

int main(int argc, char *argv[])
{

	block_size = 4096;
	int block_group;
	struct ext2_inode inode;
	struct ext2_super_block super_block;
	struct ext2_group_desc block_group_descriptor;
	struct ext2_dir_entry_2 dirent;

	FormatOptions options = {.block_size = 4096, .blocks_per_group = 500};
	if (parse_arguments(argc, argv, &options) != 0)
	{
		perror("Error: device path is required\n");
		return 1;
	}
	block_size = options.block_size;
	char *volume_label = options.volume_label;

	if ((block_size == 1024) || (block_size == 2048) || (block_size == 4096))
	{
		// Do nothing
	}
	else
	{
		if (block_size > 4096)
		{
			block_size = 4096;
		}
		else if (2048 < block_size && block_size < 4096)
		{
			block_size = 2048;
		}
		else if (1024 < block_size && block_size < 2048)
		{
			block_size = 1024;
		}
		else
		{
			perror("error : block size not valid");
			exit(errno);
		}
	}

	int fd = open(options.device_path, O_RDWR);

	if (fd == -1)
	{
		perror("error:");
		exit(errno);
	}

	long long int physical_block_size = lseek(fd, 0, SEEK_END);

	super_blockf(super_block, block_size, physical_block_size, total_no_of_blockGroups, freebl_usingbgdesc, volume_label);

	if (block_size == 1024)
		lseek(fd, 2048, SEEK_SET);
	else
		lseek(fd, block_size, SEEK_SET);

	// bgdt 
	block_group_descriptor_table(super_block, block_group, block_group_descriptor, total_no_of_blockGroups, gdt_blocksize, freebl_usingbgdesc, block_size, fd);
	super_block.s_free_blocks_count = freebl_usingbgdesc;
	lseek(fd, 1024, SEEK_SET);
	write(fd, &super_block, sizeof(struct ext2_super_block));
	replicate_superGDT(total_no_of_blockGroups, block_size, fd, super_block, block_group_descriptor);
	data_block_bitmap(total_no_of_blockGroups, block_size, gdt_blocksize, fd, super_block, block_group_descriptor);
	inode_bitmap(fd, super_block, block_group_descriptor, block_size, total_no_of_blockGroups);
	write_inodetable(fd, 2, super_block, block_group_descriptor, &inode, block_size, gdt_blocksize);
	write_inodetable(fd, 11, super_block, block_group_descriptor, &inode, block_size, gdt_blocksize);
	WriteDBlocks(fd, super_block, block_group_descriptor, inode, &dirent, block_size);
	close(fd);
	return 0;
}
