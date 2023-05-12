#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/fs.h>
#include <ext2fs/ext2_fs.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <uuid/uuid.h>
#include <math.h>
#include <getopt.h>
#include <stdbool.h>

typedef struct{

    char *device_path;
    int block_size;
    int blocks_per_group;
    char *volume_label;
     
} FormatOptions;
 
int parse_arguments(int argc, char *argv[], FormatOptions *options);
int filled_block_calculation(int gdt_blocksize, struct ext2_super_block super_block, int block_size);
int toPower(int num1, int num2);
void block_group_descriptor_0s(struct ext2_group_desc block_group_descriptor);
void inode_value_setting(struct ext2_inode* inode);
int directory_entry(struct ext2_dir_entry_2* dirent, int inode, int name_length, int ftype, char * str, int record_length);
void super_blockf(struct ext2_super_block super_block, int block_size, long long int physical_block_size, int total_no_of_blockGroups, long long int freebl_usingbgdesc, char *volume_label);
void block_group_descriptor_table(struct ext2_super_block super_block, int block_group, struct ext2_group_desc block_group_descriptor, int total_no_of_blockGroups, int gdt_blocksize, long long int freebl_usingbgdesc, int block_size, int fd);
int read_block_group_descriptor(int group_number, int block_size, int fd, struct ext2_group_desc* block_group_descriptor);
int replicate_superGDT(int total_no_of_blockGroups, int block_size, int fd, struct ext2_super_block super_block, struct ext2_group_desc block_group_descriptor);
int value_datablock_bitmap(int gdt_blocksize, struct ext2_super_block super_block, int block_size);
void data_block_bitmap(int total_no_of_blockGroups, int block_size, int gdt_blocksize, int fd, struct ext2_super_block super_block, struct ext2_group_desc block_group_descriptor);
int inode_bitmap(int fd, struct ext2_super_block super_block, struct ext2_group_desc block_group_descriptor, int block_size, int total_no_of_blockGroups);
void write_inodetable(int fd, int inode_no, struct ext2_super_block super_block, struct ext2_group_desc block_group_descriptor, struct ext2_inode* inode, int block_size, int gdt_blocksize);
int WriteDBlocks(int fd, struct ext2_super_block super_block, struct ext2_group_desc block_group_descriptor, struct ext2_inode inode, struct ext2_dir_entry_2* dirent, int block_size);

