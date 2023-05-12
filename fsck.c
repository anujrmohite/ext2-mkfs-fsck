#include "fsck.h"

bool check_all = false;
bool confirm_action = true;
bool non_interactive = false;
int PARTITION_START_OFFSET = 446;
int PARTITION_ENTRY_SIZE = 16;
int PARTITION_START_FIELD_OFFSET = 8;
int MAGIC_NUMBER_OFFSET = 56;
int block_size;
int sectors_in_each_block;
uint32_t part_start;
struct ext2_super_block superb;
char *gdt;
int lost_found;
char **inode_bitmap_real;
int blockGroup_numbers;
int *total_links;
char **block_bitmap_real;

int main(int argc, char **argv)
{
    char *imagep;
    int partition_no;
    int option;
    int check_part = -1;
    int partition_iterator;
    bool check_for_all = false;

    while ((option = getopt(argc, argv, ":p:d:f:y")) != -1)
    {
        switch (option)
        {
        case 'p':
            partition_no = atoi(optarg);
            if (partition_no <= 0)
            {
                fprintf(stderr, "Requires_positive integer");
                exit(EXIT_FAILURE);
            }
            break;
        case 'f':
            check_part = atoi(optarg);
            check_for_all = false;
            break;
        case 'y':
            confirm_action = true;
            break;
        case 'd':
            imagep = optarg;
            strncpy(imagep, optarg, 100);
            break;
        case '?':
            if (optopt == 'p' || optopt == 'd')
                fprintf(stderr, "Argument not given %c\n", optopt);
            else
                fprintf(stderr, "Unknown option  `\\x%x'.\n", optopt);
            exit(EX_USAGE);
            break;
        default:
            break;
        }
    }
    part_mdata partition_info;
    if ((device_path = open(imagep, O_RDWR)) == -1)
    {
        perror("error opening device file");
        exit(EX_NOINPUT);
    }

    if (!check_for_all && confirm_action)
    {
        part_info(partition_no, &partition_info);
        part_start = partition_info.part_start;
        if (partition_info.part_type != 0xFF)
        {
            char output_string[50];
            sprintf(output_string, "0x%02X %d %d\n", partition_info.part_type, partition_info.part_start, partition_info.part_length);
            fputs(output_string, stdout);
        }
        else
        {
            fputs("-1\n", stdout);
        }
    }
    else if (check_part == 0)
    { // Check errors of check_for_all partitions
        partition_iterator = 1;
        while (true)
        {
            bool found_partition = false;
            memset(&partition_info, 0, sizeof(part_mdata));
            part_info(partition_iterator, &partition_info);

            while (!found_partition)
            {
                switch (partition_info.part_type)
                {
                case 0xFF:
                    exit(EX_OK);
                case 0x83:
                    found_partition = true;
                    break;
                default:
                    partition_iterator++;
                    break;
                }
            }

            int block_start;
            part_start = partition_info.part_start;
            block_size = 1024 << superb.s_log_block_size;
            total_links = (int *)malloc((superb.s_inodes_count + 1) * sizeof(int));
            readSuperblock(partition_iterator, &superb);
            sectors_in_each_block = block_size / SectorSizeinBytes;
            char buff[SectorSizeinBytes * sectors_in_each_block];

            gdt = (char *)malloc(sectors_in_each_block * SectorSizeinBytes);
            read_gdt();
            blockGroup_numbers = division_roundoff(superb.s_blocks_count, superb.s_blocks_per_group);

            inode_bitmap_real = (char **)malloc(blockGroup_numbers * sizeof(char *));
            for (int i = 0; i < blockGroup_numbers; i++)
            {
                inode_bitmap_real[i] = (char *)calloc(sectors_in_each_block * SectorSizeinBytes, sizeof(char));
            }
            block_bitmap_real = (char **)malloc(blockGroup_numbers * sizeof(char *));
            for (int i = 0; i < blockGroup_numbers; i++)
            {
                block_bitmap_real[i] = (char *)calloc(sectors_in_each_block * SectorSizeinBytes, sizeof(char));
                block_start = ByteRead(gdt, int32 * i, 4);
                sectorRead(part_start + (block_start * sectors_in_each_block), sectors_in_each_block, buff);
                memcpy(block_bitmap_real[i], buff, sectors_in_each_block * SectorSizeinBytes);
            }
            memset(total_links, 0, (superb.s_inodes_count + 1));

            for (int i = 1; i <= 255; i++)
                real_block_marking(i);
            partition_checking();
            partition_iterator++;
        }
    }
    else
    { // Check for errors on a single partition
        memset(&partition_info, 0, sizeof(part_mdata));
        part_info(check_part, &partition_info);
        if (partition_info.part_type != 0x83)
        {
            printf("Partition Type wrong\n");
            exit(EX_DATAERR);
        }
        printf("Checking partition %d\n", check_part);
        part_start = partition_info.part_start;
        int block_start;
        block_size = 1024 << superb.s_log_block_size;
        total_links = (int *)malloc((superb.s_inodes_count + 1) * sizeof(int));
        readSuperblock(check_part, &superb);
        sectors_in_each_block = block_size / SectorSizeinBytes;
        char buff[SectorSizeinBytes * sectors_in_each_block];
        gdt = (char *)malloc(sectors_in_each_block * SectorSizeinBytes);
        read_gdt();
        blockGroup_numbers = division_roundoff(superb.s_blocks_count, superb.s_blocks_per_group);
        inode_bitmap_real = (char **)malloc(sizeof(char *) * blockGroup_numbers);
        for (int i = 0; i < blockGroup_numbers; i++)
        {
            inode_bitmap_real[i] = (char *)calloc(sectors_in_each_block * SectorSizeinBytes, sizeof(char));
        }
        block_bitmap_real = (char **)malloc(blockGroup_numbers * sizeof(char *));
        for (int i = 0; i < blockGroup_numbers; i++)
        {
            block_bitmap_real[i] = (char *)calloc(sectors_in_each_block * SectorSizeinBytes, sizeof(char));
            block_start = ByteRead(gdt, int32 * i, 4);
            sectorRead(part_start + (block_start * sectors_in_each_block), sectors_in_each_block, buff);
            memcpy(block_bitmap_real[i], buff, sectors_in_each_block * SectorSizeinBytes);
        }
        memset(total_links, 0, (superb.s_inodes_count + 1));

        for (int i = 1; i <= 255; i++)
            real_block_marking(i);
        partition_checking();
    }
    free_allocated_mem();
    exit(EX_OK);
}

unsigned int division_roundoff(unsigned int dividend, unsigned int divisor)
{
    unsigned int quotient = dividend / divisor;
    unsigned int remainder = dividend % divisor;
    if (remainder >= divisor / 2)
    {
        quotient++;
    }
    return quotient;
}

void free_allocated_mem()
{
    free(total_links);
    for (int i = 0; i < blockGroup_numbers; i++)
    {
        free(block_bitmap_real[i]);
    }
    for (int i = 0; i < blockGroup_numbers; i++)
    {
        free(inode_bitmap_real[i]);
    }
    free(block_bitmap_real);

    free(inode_bitmap_real);
    free(gdt);
}

void partition_checking()
{
    setting_directory_pointers(2, 2);     // Pass 1
    directory_traversal(2, false, false); // Pass 2
    not_connected_danglingNodes();
    setting_directory_pointers(2, 2);
    directory_traversal(2, false, true); // Pass 3
    directory_traversal(2, true, false);
    write_blockBitmap(); // Pass 4
}

void not_connected_danglingNodes() // finding disconnected inodes
{
    struct ext2_inode inode_i;

    // Add branches to our bitmap
    int inode_iterator = first_common_inode;
    while (inode_iterator <= superb.s_inodes_count)
    {
        if (isinodeallocated(inode_iterator, NULL))
        {
            readInode(inode_iterator, &inode_i);
            if ((inode_i.i_mode & 0xf000) == 0x4000)
            {
                dis_subtree_marking(inode_iterator);
            }
        }
        inode_iterator++;
    }

    // Add to lost+found
    inode_iterator = first_common_inode;
    while (inode_iterator <= superb.s_inodes_count)
    {
        bool inode_allocated = isinodeallocated(inode_iterator, (char **)NULL);
        bool inode_not_in_bitmap = !isinodeallocated(inode_iterator, inode_bitmap_real);

        if (inode_allocated && inode_not_in_bitmap)
        {
            lostplusfound_addition(inode_iterator);
        }
        inode_iterator++;
    }
}

void WriteInode(int inode_number, struct ext2_inode inode_i)
{
    unsigned char buff[SectorSizeinBytes * sectors_in_each_block];
    int inodes_pg = superb.s_inodes_per_group;
    int block_group_number = (inode_number - 1) / inodes_pg;
    int offset = block_group_number * int32;
    int inode_index = (inode_number - 1) % inodes_pg;

    int starting_of_inode_table = ByteRead(gdt, offset + 8, 4);

    uint32_t inode_size = superb.s_inode_size;
    int size_of_inode = superb.s_inode_size;
    uint32_t sector_size = SectorSizeinBytes / inode_size;
    uint32_t inode_within_sector = SectorSizeinBytes / size_of_inode;
    uint32_t inodesectoroffset = inode_index / sector_size;

    int starting_addr = part_start + (starting_of_inode_table * sectors_in_each_block);
    sectorRead(starting_addr + inodesectoroffset, 1, buff);

    offset = ((inode_index % inode_within_sector)) * size_of_inode;

    struct ext2_inode *new_inode_i = (struct ext2_inode *)(buff + offset);
    new_inode_i->i_links_count = inode_i.i_links_count;
    sectorWrite(starting_addr + inodesectoroffset, 1, buff);
}

void new_directory(struct ext2_dir_entry_2 new_dir_entry, int inode_number) // adding new directory entry to a data block
{
    int direct_blocks = 12;
    struct ext2_inode inode_i;
    struct ext2_dir_entry_2 prev_dir_entry;
    bool allocate_new_block = false;
    readInode(lost_found, &inode_i);

    for (int i = 0; i < direct_blocks; i++)
    {
        if (inode_i.i_block[i] == 0)
        {
            allocate_new_block = true;
            break;
        }
        int no_dir_entries; // in a directory block
        struct ext2_dir_entry_2 *dir_entries;
        int directory_free_block = SectorSizeinBytes * sectors_in_each_block;
        dir_entries = directory_block_reading(inode_i.i_block[i], &no_dir_entries);

        int dir_entry_size = sizeof(struct ext2_dir_entry_2);
        int total_entries_size = 0;

        for (int j = 0; j < no_dir_entries; j++)
        {
            total_entries_size += ((dir_entry_size + dir_entries[j].name_len + 3) & 0xFC);
        }

        directory_free_block = SectorSizeinBytes * sectors_in_each_block - total_entries_size;

        if (directory_free_block >= ((((__u16)8 + new_dir_entry.name_len) + 3) & 0xFC))
        {
            prev_dir_entry = dir_entries[no_dir_entries - 1];
            prev_dir_entry.rec_len = ((((__u16)8 + prev_dir_entry.name_len) + 3) & 0xFC);
            directory_entry_setting(inode_i.i_block[i], no_dir_entries - 1, prev_dir_entry);

            // Adding new entry of directory
            new_dir_entry.rec_len = (((directory_free_block) + 3) & 0xFC);
            directory_entry_setting(inode_i.i_block[i], no_dir_entries, new_dir_entry);
            break;
        }
    }
}

void lostplusfound_addition(int inode_number) // Adding an inode to lost+found directory
{
    char name_of_inode[255];
    int name_length = sprintf(name_of_inode, "%d", inode_number);

    struct ext2_dir_entry_2 lost_found_entry;

    lost_found_entry.rec_len = name_length + 8;
    lost_found_entry.inode = inode_number;
    lost_found_entry.name_len = name_length;
    struct ext2_inode inode_i;
    readInode(inode_number, &inode_i);

    int v = 0;
    while (v < name_length)
    {
        lost_found_entry.name[v] = name_of_inode[v];
        v++;
    }
    switch (inode_i.i_mode & 0xf000)
    {
    case 0x8000:
        lost_found_entry.file_type = 1;
        break;
    case 0x4000:
        lost_found_entry.file_type = 2;
        break;
    case 0x2000:
        lost_found_entry.file_type = 3;
        break;
    case 0x6000:
        lost_found_entry.file_type = 4;
        break;
    case 0x1000:
        lost_found_entry.file_type = 5;
        break;
    case 0xC000:
        lost_found_entry.file_type = 6;
        break;
    case 0xA000:
        lost_found_entry.file_type = 7;
        break;
    default:
        lost_found_entry.file_type = 0;
        break;
    }

    new_directory(lost_found_entry, lost_found);
}

void read_gdt()
{
    int64_t starting_address = part_start + (sectors_in_each_block * 2);
    sectorRead(starting_address, sectors_in_each_block, gdt);
}

void modify_linkCount(int inode_number)
{
    total_links[inode_number]++;
}

void indirected_block_traverse(int block_number, int current_level, bool fix_blocks, int max_indirection) // Traversing indirected blocks
{
    int offset = 0;
    unsigned char buff[SectorSizeinBytes * sectors_in_each_block];
    if (fix_blocks)
        real_block_marking(block_number);
    if (current_level == max_indirection)
    {
        return;
    }
    int64_t starting_addr = part_start + (sectors_in_each_block * block_number);
    sectorRead(starting_addr, sectors_in_each_block, buff);

    for (int offset = 0; offset < (sectors_in_each_block * SectorSizeinBytes); offset += 4)
    {
        int current_block = ByteRead(buff, offset, 4);
        if (current_block != 0)
            indirected_block_traverse(current_block, current_level + 1, fix_blocks, max_indirection);
        offset = offset + 4;
    }
}

void real_inode_marking(int inode_number) // Marking allocated inode num.
{
    int inodes_pg = superb.s_inodes_per_group;
    int inode_index = (inode_number - 1) % inodes_pg;
    int inode_index_in_bytes = inode_index / 8;
    int block_group_number = (inode_number - 1) / inodes_pg;
    int inode_offset_in_bytes = inode_index % 8;
    int mask = 1;
    mask <<= inode_offset_in_bytes;
    inode_bitmap_real[block_group_number][inode_index_in_bytes] |= mask;
}

void directory_entry_setting(int data_block, int dir_number, struct ext2_dir_entry_2 new_directory_entry) // Set a dir entry
{
    int offset = 0;
    int offt = 4;
    unsigned char buff[SectorSizeinBytes * sectors_in_each_block];
    int directory_length;
    int64_t starting_address = part_start + (sectors_in_each_block * data_block);
    struct ext2_dir_entry_2 *old_dir_entry;

    sectorRead(starting_address, sectors_in_each_block, buff);

    for (int i = 0; i < dir_number; i++)
    {
        directory_length = ByteRead(buff, offset + offt, 2);
        offset += directory_length;
    }

    old_dir_entry = (struct ext2_dir_entry_2 *)(buff + offset);
    int new_dir_entry_ptr = &new_directory_entry;

    for (int i = 0; i < sizeof(struct ext2_dir_entry_2); i++)
    {
        ((char *)old_dir_entry)[i] = ((char *)new_dir_entry_ptr)[i];
    }

    int k = 0;
    while (k < new_directory_entry.name_len)
    {
        old_dir_entry->name[k] = new_directory_entry.name[k];
        k++;
    }
    sectorWrite(part_start + (sectors_in_each_block * data_block), sectors_in_each_block, buff);
}

void setting_directory_pointers(int inode_number, int parent_number)
{
    struct ext2_inode inode_i;
    readInode(inode_number, &inode_i);
    int number_of_direct_blocks = 12;
    int is_dir = (inode_i.i_mode & 0xf000);
    if (is_dir == 0x4000)
    {
        int v;
        int num_entries;
        int i = 0;
        while (i < number_of_direct_blocks)
        {
            struct ext2_dir_entry_2 *dir_entry;
            int no_dir_entries;

            dir_entry = directory_block_reading(inode_i.i_block[i], &no_dir_entries);

            while (v < no_dir_entries)
            {
                struct ext2_inode directory_inode;
                char names_of_dir[255];
                int to_make_string;
                if (dir_entry[v].inode == 0)
                    continue;

                for (int k = 0; k < dir_entry[v].name_len; k++)
                {
                    names_of_dir[k] = dir_entry[v].name[k];
                    to_make_string = k;
                }
                names_of_dir[to_make_string] = '\0';

                // Fix any directory pointer issues
                if (!strcmp(names_of_dir, "."))
                {
                    if (!(dir_entry[v].inode == inode_number))
                    {
                        dir_entry[v].inode = inode_number;
                        directory_entry_setting(inode_i.i_block[i], v, dir_entry[v]);
                    }
                    else
                    {
                        continue;
                    }
                }
                if (!strcmp(names_of_dir, ".."))
                {
                    if (!(dir_entry[v].inode == parent_number))
                    {
                        dir_entry[v].inode = parent_number;
                        directory_entry_setting(inode_i.i_block[i], v, dir_entry[v]);
                    }
                    else
                    {
                        continue;
                    }
                }

                if (!strncmp(names_of_dir, "lost+found", dir_entry[v].name_len))
                {
                    lost_found = dir_entry[v].inode;
                }

                readInode(dir_entry[v].inode, &directory_inode);
                int is_dir2 = (directory_inode.i_mode & 0xf000);

                if (is_dir2 == 0x4000 && strncmp(names_of_dir, "..", 2) && strncmp(names_of_dir, ".", 1))
                    setting_directory_pointers(dir_entry[v].inode, inode_number);
                v++;
            }
            i++;
        }
    }
    return;
}

void dis_subtree_marking(int inode_number)
{
    struct ext2_inode inode_i;
    int is_dir = (inode_i.i_mode & 0xf000);
    readInode(inode_number, &inode_i);
    struct ext2_dir_entry_2 *dir_entry;
    if (is_dir == 0x4000)
    {
        int no_of_entries;
        int i = 0;
        while (i < 12 && inode_i.i_block[i] != 0) // doing only for direct blocks
        {
            dir_entry = directory_block_reading(inode_i.i_block[i], &no_of_entries);
            for (int j = 0; j < no_of_entries; j++)
            {
                if (dir_entry[j].inode != 0)
                {
                    char dir_names[255];
                    int v;
                    while (v < dir_entry[j].name_len)
                    {
                        dir_names[v] = dir_entry[j].name[v];
                        v++;
                    }
                    dir_names[v] = '\0';
                    if (strncmp(dir_names, "..", 2) && strncmp(dir_names, ".", 1))
                        real_inode_marking(dir_entry[j].inode);
                }
            }
            free(dir_entry);
            i++;
        }
    }
}

void real_block_marking(int block_number) // Checking whether block is allocated otherwise mark it allocated
{
    int group_size = superb.s_blocks_per_group;

    int block_group_number = (block_number - 1) / group_size;
    int block_index = (block_number - 1) % group_size;

    int block_offset_in_bytes = (block_index % 8);
    int block_index_in_bytes = block_index / 8;

    int mask = 1 << block_offset_in_bytes;

    int byte_val = (block_bitmap_real[block_group_number][block_index_in_bytes] & mask);

    if (byte_val == 0)
    {
        if (block_number > 255)
            printf("allocated block error       %d \n", block_number);
        block_bitmap_real[block_group_number][block_index_in_bytes] |= mask;
    }
}

void write_blockBitmap()
{ // Writing to disk the block bitmap
    int starting_of_block;
    int starting_addr = part_start + (starting_of_block * sectors_in_each_block);
    int v = 0;
    while (v < blockGroup_numbers)
    {
        starting_of_block = ByteRead(gdt, v * int32, 4);
        sectorWrite(starting_addr, sectors_in_each_block, block_bitmap_real[v]);
        v++;
    }
}

void directory_traversal(int inode_number, bool fix_blocks, bool link_counts) // traversing directory tree
{
    int i = 0;
    int no_of_direct_blocks = 12;
    struct ext2_inode inode_i;
    // track of reachable inodes
    real_inode_marking(inode_number);
    readInode(inode_number, &inode_i);
    int is_dir_or_file = (inode_i.i_mode & 0xf000);

    if (total_links[inode_number] != 0)
    {
        if (!link_counts)
        {
            if (total_links[inode_number] != inode_i.i_links_count)
            {
                printf("incorrect count of links");
                inode_i.i_links_count = total_links[inode_number];
                WriteInode(inode_number, inode_i);
            }
            else
            {
                ;
            }
        }
        else
        {
            ;
        }
    }
    if (is_dir_or_file == 0x4000)
    {
        int j;
        int num_entries;
        while (i < no_of_direct_blocks)
        {
            struct ext2_dir_entry_2 *dir_entry;
            int no_dir_entries;

            if (inode_i.i_block[i] == 0)
                continue;
            if (fix_blocks)
                real_block_marking(inode_i.i_block[i]);

            dir_entry = directory_block_reading(inode_i.i_block[i], &no_dir_entries);

            for (j = 0; j < no_dir_entries; j++)
            {
                if (dir_entry[j].inode == 0)
                    continue;
                struct ext2_inode dir_inode;
                char dir_names[255];

                real_inode_marking(dir_entry[j].inode);
                if (link_counts)
                    modify_linkCount(dir_entry[j].inode);
                readInode(dir_entry[j].inode, &dir_inode);

                int k;

                int to_make_string;
                for (k = 0; k < dir_entry[j].name_len; k++)
                {
                    dir_names[k] = dir_entry[j].name[k];
                }
                to_make_string = k;

                dir_names[to_make_string] = '\0';
                if (strncmp(dir_names, "..", 2) && strncmp(dir_names, ".", 1))
                {
                    directory_traversal(dir_entry[j].inode, fix_blocks, link_counts);
                }
                else
                {
                    ;
                }
            }
            i++;
        }
    }
    else if (is_dir_or_file == 0x8000)
    {
        int single_indirect_block = inode_i.i_block[12];
        int double_indirect_block = inode_i.i_block[13];
        int triple_indirect_block = inode_i.i_block[14];

        real_inode_marking(inode_number);
        int r;
        while (r < 12)
        {
            if (fix_blocks)
                real_block_marking(inode_i.i_block[r]);
            else
            {
                ;
            }
            if (inode_i.i_block[r] == 0)
                continue;
            r++;
        }
        // single indirect block
        if (single_indirect_block != 0)
        {
            real_block_marking(single_indirect_block);
            indirected_block_traverse(single_indirect_block, 0, fix_blocks, 1);
        }
        else
        {
            ;
        }

        // double indirect block
        if (double_indirect_block != 0)
        {
            real_block_marking(double_indirect_block);
            indirected_block_traverse(double_indirect_block, 0, fix_blocks, 2);
        }
        else
        {
            ;
        }

        // triple indirect block
        if (triple_indirect_block != 0)
        {
            real_block_marking(triple_indirect_block);
            indirected_block_traverse(triple_indirect_block, 0, fix_blocks, 3);
        }
        else
        {
            ;
        }
    }
}

struct ext2_dir_entry_2 *directory_block_reading(int block_number, int *no_dir_entries) // Reading directory blocks from block num and store num. of entries
{
    unsigned char buff[SectorSizeinBytes * sectors_in_each_block];
    int64_t starting_addr = part_start + (sectors_in_each_block * block_number);
    sectorRead(starting_addr, sectors_in_each_block, buff);
    struct ext2_dir_entry_2 *directories = (struct ext2_dir_entry_2 *)malloc(sizeof(struct ext2_dir_entry_2));
    int offset = 0;
    int total_size_of_block = (SectorSizeinBytes * sectors_in_each_block);
    char file_type;
    uint32_t inode_number;
    uint16_t directory_length;
    char length_of_name; // name of length of directory entry in bytes
    char names_of_dir[255];
    int v = 0;
    int i = 0;
    int curr_size = 0;

    while (offset < total_size_of_block)
    {
        struct ext2_dir_entry_2 *dir_that_is_being_read = (struct ext2_dir_entry_2 *)malloc(sizeof(struct ext2_dir_entry_2));
        inode_number = ByteRead(buff, offset, 4);
        dir_that_is_being_read->inode = inode_number;
        directory_length = ByteRead(buff, offset + 4, 2);
        dir_that_is_being_read->rec_len = directory_length;
        length_of_name = ByteRead(buff, offset + 6, 1);
        dir_that_is_being_read->name_len = length_of_name;
        file_type = ByteRead(buff, offset + 7, 1);
        dir_that_is_being_read->file_type = file_type;

        while (i < length_of_name)
        {

            names_of_dir[i] = *(buff + offset + 8 + i);
            dir_that_is_being_read->name[i] = *(buff + offset + 8 + i);
            i++;
        }
        int to_make_string = i;
        names_of_dir[to_make_string] = '\0';
        offset += directory_length;
        directories = realloc(directories, sizeof(struct ext2_dir_entry_2) * (curr_size + 1));
        directories[v++] = *dir_that_is_being_read;
        curr_size++;
    }
    *no_dir_entries = v;
    return directories;
}

void sectorRead(int64_t sectorStart, unsigned int sector_no, void *pointer_into)
{
    int64_t offset_of_sector = sectorStart * SectorSizeinBytes;
    int64_t total_bytes = sector_no * SectorSizeinBytes;
    int64_t readBytes = 0;

    while (readBytes < total_bytes)
    {
        int64_t remaining_bytes = total_bytes - readBytes;
        ssize_t return_value = pread(device_path, (char *)pointer_into + readBytes, remaining_bytes, offset_of_sector + readBytes);

        if (return_value < 0)
        {
            exit(EX_IOERR);
        }

        readBytes += return_value;
    }
}

void sectorWrite(int64_t sectorStart, unsigned int sector_no, void *from)
{
    ssize_t ret;
    int32_t lret;
    int32_t offset_of_sector;
    ssize_t bytes_tobe_written;

    offset_of_sector = sectorStart * SectorSizeinBytes;

    if ((lret = lseek(device_path, offset_of_sector, SEEK_SET)) != offset_of_sector)
    {
        char errbuf[256];
        strerror_r(errno, errbuf, sizeof(errbuf));
        fprintf(stderr, "lseek failed: %s\n", errbuf);
        exit(EX_IOERR);
    }
    bytes_tobe_written = SectorSizeinBytes * sector_no;

    if ((ret = write(device_path, from, bytes_tobe_written)) != bytes_tobe_written)
    {
        fprintf(stderr, "write failed: %s\n", strerror(errno));
        exit(EX_IOERR);
    }
}

void part_info(int partition_no, part_mdata *intodata)
{
    char buff[SectorSizeinBytes];
    int current_partition_number = 0;
    int current_sector = 0;
    int previous_sector = 0;
    int part_start;
    int part_length;
    char part_type;

    if (partition_no < 0)
    {
        intodata->part_type = -1;
        return;
    }
    int previous_EBR_block_adsress = 0;
    int start_EBR_block_address = 0;
    while (current_partition_number <= partition_no)
    {
        sectorRead(current_sector, 1, buff);
        previous_sector = current_sector;
        for (int i = 0; i < prime_partition; i++)
        {
            part_type = partition_type(buff, i);
            if (current_sector != 0 && part_type != 0x05 && i == 1)
            {
                break;
            }
            if (current_partition_number == partition_no)
            {
                if (previous_sector == 0)
                {
                    part_start = 0 + partition_start(buff, i);
                }
                else
                {

                    part_start = current_sector + partition_start(buff, i);
                }
                part_length = partition_length(buff, i);
                intodata->part_type = part_type;
                intodata->part_length = part_length;
                intodata->part_start = part_start;
                return;
            }
            if (part_type != 0x05 && current_sector == 0)
            { // Increment counter if not EBR in sector 0
                current_partition_number++;
                if (current_partition_number > partition_no)
                {
                    intodata->part_type = -1;
                    return;
                }
            }

            if (part_type == 0x05)
            {
                if (current_sector == 0)
                {
                    start_EBR_block_address = partition_start(buff, i);
                    previous_sector = current_sector;
                }
                else
                {
                    previous_EBR_block_adsress = partition_start(buff, i);
                    previous_sector = current_sector;
                    start_EBR_block_address = current_sector - previous_EBR_block_adsress;
                }
                current_sector = start_EBR_block_address + previous_EBR_block_adsress;
            }
        }
        if (current_sector == previous_sector)
            break;
    }

    (current_partition_number < partition_no) ? (intodata->part_type = -1, (void)0) : (void)0;
    return;
}

int BytesTouint32(unsigned char *buff)
{
    return buff[3] + (buff[1] << 16) + (buff[2] << 8) + (buff[0] << 24);
}

int BytesTouint16(unsigned char *buff)
{
    return (buff[0] << 8) + buff[1];
}

unsigned char bytesTobyte(unsigned char *buff)
{
    return buff[0];
}

int ByteRead(unsigned char *actual_sector, int offset, int number_of_bytes)
{
    unsigned char buff[4];
    for (int i = number_of_bytes - 1; i >= 0; i--)
    {
        buff[i] = actual_sector[offset++];
    }
    switch (number_of_bytes)
    {
    case 2:
        return BytesTouint16(buff);
    case 4:
        return BytesTouint32(buff);
    default:
        return bytesTobyte(buff);
    }
}

int partition_length(unsigned char *sector, int part_num)
{
    return ByteRead(sector, (446 + (part_num)*16 + 12), 4);
}

int partition_start(unsigned char *sector, int part_num)
{
    return ByteRead(sector, (PARTITION_START_OFFSET + part_num * PARTITION_ENTRY_SIZE + PARTITION_START_FIELD_OFFSET), 4);
}

int magic_number(unsigned char *sector)
{
    return ByteRead(sector, MAGIC_NUMBER_OFFSET, 2);
}

unsigned char partition_type(unsigned char *actual_sector, int part_num)
{
    return actual_sector[446 + (part_num)*16 + 4];
}

void readSuperblock(int partition_no, struct ext2_super_block *sb)
{
    char buff[SectorSizeinBytes];
    part_mdata partition_info;
    part_info(partition_no, &partition_info);
    sectorRead(partition_info.part_start + 2, 1, (unsigned char *)buff);

    int offset = 0;
    sb->s_inodes_count = ByteRead(buff, offset, 4); // 0
    offset += 4;
    sb->s_blocks_count = ByteRead(buff, offset, 4); // 4
    offset += 8;
    sb->s_free_blocks_count = ByteRead(buff, offset, 4); // 12
    offset += 4;
    sb->s_free_inodes_count = ByteRead(buff, offset, 4); // 16
    offset += 8;
    sb->s_log_block_size = ByteRead(buff, offset, 4); // 24
    offset += 8;
    sb->s_blocks_per_group = ByteRead(buff, offset, 4); // 32
    offset += 8;
    sb->s_inodes_per_group = ByteRead(buff, offset, 4); // 40
    offset += 16;
    sb->s_magic = ByteRead(buff, offset, 4); // 56
    offset += 32;
    sb->s_inode_size = ByteRead(buff, offset, 2); // 88
    return;
}

void readGroupDescriptor(int block_group, struct ext2_group_desc *group_desc)
{
    int offset = block_group * int32;
    group_desc->bg_block_bitmap = ByteRead(gdt, offset, 4);
    offset += 4;
    group_desc->bg_inode_bitmap = ByteRead(gdt, offset, 4);
    offset += 4;
    group_desc->bg_inode_table = ByteRead(gdt, offset, 4);
    offset += 4;
    group_desc->bg_free_blocks_count = ByteRead(gdt, offset, 2);
    offset += 2;
    group_desc->bg_free_inodes_count = ByteRead(gdt, offset, 2);
    return;
}

uint32_t InodeSectorOffset(uint32_t inode_size, uint32_t inode_index)
{
    uint32_t sector_size = SectorSizeinBytes / inode_size;
    return inode_index / sector_size;
}

void readInode(uint32_t inode_number, struct ext2_inode *inode_i)
{

    struct ext2_group_desc group_desc;
    int block_group_number = (inode_number - 1) / superb.s_inodes_per_group;
    readGroupDescriptor(block_group_number, &group_desc);
    uint32_t start_of_inode_table = group_desc.bg_inode_table;
    int inode_index = (inode_number - 1) % superb.s_inodes_per_group;
    uint32_t inode_size = superb.s_inode_size;
    uint32_t sector_size = SectorSizeinBytes / inode_size;
    uint32_t inodesectoroffset = inode_index / sector_size;
    unsigned char buff[SectorSizeinBytes];
    sectorRead(part_start + (start_of_inode_table * sectors_in_each_block) + inodesectoroffset, 1, buff);

    uint32_t number_of_inodes_sectors = SectorSizeinBytes / superb.s_inode_size;
    uint32_t ptr = buff + ((inode_index % number_of_inodes_sectors) * superb.s_inode_size);

    inode_i->i_mode = ByteRead(buff, ptr+ 0, 2);
    inode_i->i_size = ByteRead(buff, ptr+4, 4);
    inode_i->i_links_count = ByteRead(buff, ptr+ 26, 2);

    int i = 0;
    while (i < 15)
    {
        inode_i->i_block[i] = ByteRead(buff, ptr + 40 + (i * 4), 4);
        i++;
    }
}

bool isinodeallocated(uint32_t inode_number, char **bitmap) // Checking whether inode is allocated or not
{

    unsigned char buff[SectorSizeinBytes * sectors_in_each_block];

    int block_group_number = (inode_number - 1) / superb.s_inodes_per_group;
    int offset = block_group_number * int32;

    int inode_index = (inode_number - 1) % superb.s_inodes_per_group;
    int inode_index_in_bytes = inode_index / 8;
    int inode_offset_in_bytes = inode_index % 8;

    int block_bitmapl_to_be_read = 4;
    offset += 4;
    uint32_t block_bitmapl = ByteRead(gdt, offset, block_bitmapl_to_be_read);
    int64_t starting_addr = part_start + (block_bitmapl * sectors_in_each_block);

    if (bitmap)
    {
        memcpy(buff, bitmap[block_group_number], SectorSizeinBytes * sectors_in_each_block);
        unsigned char byteBitmap = ByteRead(buff, inode_index_in_bytes, 1);
        return byteBitmap;
    }
    sectorRead(starting_addr, sectors_in_each_block, buff);
    unsigned char byteBitmap = ByteRead(buff, inode_index_in_bytes, 1);

    return (byteBitmap & (1 << inode_offset_in_bytes)) ? true : false;
}
