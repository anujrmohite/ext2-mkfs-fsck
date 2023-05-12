#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sysexits.h>
#include <ext2fs/ext2_fs.h>
#include <getopt.h>
#include <sys/types.h>
#include <errno.h>
#define _LARGEFILE64_SOURCE

#define int32 32
#define prime_partition 4
#define first_common_inode 11

const unsigned int SectorSizeinBytes = 512;
static int device_path;
typedef enum
{
    DIRECTORY_DATA_BLOCK,
    FILE_DATA_BLOCK
} data_block_type;

typedef struct
{
    unsigned char part_type;
    uint32_t part_length;
    uint32_t part_start;
} part_mdata;

unsigned int division_roundoff(unsigned int dividend, unsigned int divisor);
void partition_checking();
void part_info(int partition_no, part_mdata *data);
int partition_length(unsigned char *sector, int part_num);
int partition_start(unsigned char *sector, int part_num);
int ByteRead(unsigned char *actual_sector, int offset, int number_of_bytes);
void sectorRead(int64_t sectorStart, unsigned int sector_no, void *pointer_into);
void readSuperblock(int partition_no, struct ext2_super_block *sb);
void readGroupDescriptor(int partition_no, struct ext2_group_desc *group_desc);
unsigned char partition_type(unsigned char *actual_sector, int part_num);
void readInode(uint32_t inode_number, struct ext2_inode *inode_i);
bool isinodeallocated(uint32_t inode_number, char **bitmap);
void read_data_block(uint32_t block_num, data_block_type type);
void read_gdt();
void directory_traversal(int inode_number, bool fix_blocks, bool link_counts);
void setting_directory_pointers(int inode_number, int parent_number);
void not_connected_danglingNodes();
void indirected_block_traverse(int block_number, int current_level, bool fix_blocks, int max_indirection);
struct ext2_dir_entry_2 *directory_block_reading(int block_number, int *no_dir_entries);
void sectorWrite(int64_t sectorStart, unsigned int sector_no, void *from);
void print_sector(unsigned char *buf);
void print_disk_bitmap(int block_group_num);
void print_actual_bitmap(int block_group_num);
void real_inode_marking(int inode_number);
void real_block_marking(int block_number);
void lostplusfound_addition(int inode_number);
void directory_entry_setting(int data_block, int dir_number, struct ext2_dir_entry_2 new_directory_entry);
void dis_subtree_marking(int inode_number);
void modify_linkCount(int inode_number);
void WriteInode(int inode_number, struct ext2_inode inode_i);
uint32_t InodeSectorOffset(uint32_t inode_size, uint32_t inode_index);
void write_blockBitmap();
void free_allocated_mem();