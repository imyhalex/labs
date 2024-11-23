#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/sha.h>

// boot sector
#pragma pack(push,1)
typedef struct BootEntry {
    unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
    unsigned char  BS_OEMName[8];     // OEM Name in ASCII
    unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
    unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
    unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
    unsigned char  BPB_NumFATs;       // Number of FATs
    unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
    unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
    unsigned char  BPB_Media;         // Media type
    unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
    unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
    unsigned short BPB_NumHeads;      // Number of heads in storage device
    unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
    unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
    unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
    unsigned short BPB_ExtFlags;      // A flag for FAT
    unsigned short BPB_FSVer;         // The major and minor version number
    unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
    unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
    unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
    unsigned char  BPB_Reserved[12];  // Reserved
    unsigned char  BS_DrvNum;         // BIOS INT13h drive number
    unsigned char  BS_Reserved1;      // Not used
    unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
    unsigned int   BS_VolID;          // Volume serial number
    unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
    unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

// directory entry
#pragma pack(push,1)
typedef struct DirEntry {
    unsigned char  DIR_Name[11];      // File name
    unsigned char  DIR_Attr;          // File attributes
    unsigned char  DIR_NTRes;         // Reserved
    unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
    unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
    unsigned short DIR_CrtDate;       // Created day
    unsigned short DIR_LstAccDate;    // Accessed day
    unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
    unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
    unsigned short DIR_WrtDate;       // Written day
    unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
    unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

typedef struct {
    unsigned int bytes_per_sector;
    unsigned int sectors_per_cluster;
    unsigned int reserved_sector_count;
    unsigned int num_fats;
    unsigned int fat_size;
    unsigned int root_cluster;
    unsigned int fat_region_size;
    unsigned int cluster_size;
    unsigned int data_region_offset;
    unsigned int root_dir_offset;
    unsigned int total_sectors;
    unsigned int total_clusters;
} FileSystemInfo;

void display_info() 
{
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

void print_file_sys_info(FileSystemInfo *fs_info)
{
    printf("Number of FATs = %u\n", fs_info->num_fats);
    printf("Number of bytes per sector = %u\n", fs_info->bytes_per_sector);
    printf("Number of sectors per cluster = %u\n", fs_info->sectors_per_cluster);
    printf("Number of reserved sectors = %u\n", fs_info->reserved_sector_count);
}

void trim_file(char *filename, DirEntry *dir_entry) 
{
    char name[9]; 
    memcpy(name, dir_entry->DIR_Name, 8);
    name[8] = '\0';

    // Trim trailing spaces from the name
    int i;
    for (i = 7; i >= 0 && name[i] == ' '; i--)
        name[i] = '\0';

    char ext[4]; 
    memcpy(ext, dir_entry->DIR_Name + 8, 3);
    ext[3] = '\0';

    int j;
    for (j = 2; j >= 0 && ext[j] == ' '; j--)
        ext[j] = '\0';

    if (ext[0] != '\0')
        sprintf(filename, "%s.%s", name, ext);
    else
        sprintf(filename, "%s", name);
}

void display_root_directory(char *file_mem, FileSystemInfo *fs_info)
{
    unsigned int current_cluster = fs_info->root_cluster;
    unsigned int cluster_size = fs_info->cluster_size;
    unsigned int entries_per_cluster = cluster_size / sizeof(DirEntry);
    unsigned int fat_start = fs_info->reserved_sector_count * fs_info->bytes_per_sector;

    int entries_cnt = 0;

    while (current_cluster >= 2 && current_cluster < 0x0FFFFFF8)
    {
        unsigned int cluster_offset = fs_info->data_region_offset + (current_cluster - 2) * cluster_size;

        DirEntry *dir_entry = (DirEntry *)(file_mem + cluster_offset);

        unsigned int i;
        for (i = 0; i < entries_per_cluster; i++)
        {
            if (dir_entry->DIR_Name[0] == 0x00)
                break;
            

            if (dir_entry->DIR_Name[0] == 0xE5 || dir_entry->DIR_Attr == 0x0F)
            {
                dir_entry++;
                continue;
            }

            char filename[13];
            trim_file(filename, dir_entry);

            unsigned int starting_cluster = (dir_entry->DIR_FstClusHI << 16) | dir_entry->DIR_FstClusLO;

            if (dir_entry->DIR_Attr & 0x10)
                printf("%s/ (starting cluster = %u)\n", filename, starting_cluster);
            else
            {
                unsigned int file_size = dir_entry->DIR_FileSize;
                if (file_size > 0)
                    printf("%s (size = %u, starting cluster = %u)\n", filename, file_size, starting_cluster);
                else
                    printf("%s (size = 0)\n", filename);
            }

            entries_cnt++;
            dir_entry++;
        }

        // get the next cluster in the chain from the FAT
        unsigned int fat_entry_offset = fat_start + current_cluster * 4;
        unsigned int *fat_entry = (unsigned int *)(file_mem + fat_entry_offset);
        // mask to get 28 bits
        current_cluster = *fat_entry & 0x0FFFFFFF; 

        // check for end-of-cluster chain
        if (current_cluster >= 0x0FFFFFF8)
            break;
    }

    printf("Total number of entries = %d\n", entries_cnt);
}

void recover_small_file(char *file_mem, char *filename, FileSystemInfo *fs_info)
{
    DirEntry *dir_entry = (DirEntry *) (file_mem + fs_info->root_dir_offset);
    int found = 0;
    DirEntry *target_entry = NULL;
    while (1) 
    {
        if (dir_entry->DIR_Name[0] == 0x00)
            break;
        
        if (dir_entry->DIR_Name[0] == 0xe5)
        {
            char entry_name[13];
            trim_file(entry_name, dir_entry);
            // replace the first character
            entry_name[0] = filename[0];
            if (strcasecmp(entry_name, filename) == 0)
            {
                found++;
                if (found == 1)
                    target_entry = dir_entry;
                else 
                {
                    printf("%s: multiple candidates found\n", filename);
                    return;
                }
            }
        }
        dir_entry++;
    }

    if (found == 0)
    {
        printf("%s: file not found\n", filename);
        return;
    }

    // perform file recovery
    unsigned int starting_cluster = (target_entry->DIR_FstClusHI << 16) | target_entry->DIR_FstClusLO;
    unsigned int fat_offset = fs_info->reserved_sector_count * fs_info->bytes_per_sector;
    unsigned int fat_entry_offset = fat_offset + starting_cluster * 4; // FAT32 entries are 4 bytes

    // if empty file
    if (starting_cluster == 0) 
    {
        target_entry->DIR_Name[0] = filename[0];
        printf("%s: successfully recovered\n", filename);
        return;
    }

    unsigned int *fat_entry = (unsigned int *) (file_mem + fat_entry_offset);
    if (*fat_entry != 0x00000000)
    {
        printf("%s: cluster in use\n", filename);
        return;
    }

    *fat_entry = 0x0ffffff8;
    target_entry->DIR_Name[0] = filename[0];
    printf("%s: successfully recovered\n", filename);
}

int main(int argc, char **argv) 
{
    if (argc < 2)
    {
        display_info();
        exit(1);
    }

    char *disk_image = argv[1];
    int i_flag = 0, l_flag = 0, r_flag = 0, R_flag = 0, s_flag = 0;
    char *filename = NULL;
    char *sha1_hash = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "ilr:R:s:")) != -1) 
    {
        switch (opt) 
        {
            case 'i': i_flag = 1; break;
            case 'l': l_flag = 1; break;
            case 'r': r_flag = 1; filename = optarg; break;
            case 'R': R_flag = 1; filename = optarg; break;
            case 's': s_flag = 1; sha1_hash = optarg; break;
            default:
                display_info();
                exit(EXIT_FAILURE);
        }
    }

    /**
     * rules:
     * only one of -i, -l, -r, or -R is used
     * if -r or -R is used, filename must be provided
     * if -R is used, -s must be provided
     * if -s is provided, validate the SHA-1 hash length
     */
    int optind_count = i_flag + l_flag + r_flag + R_flag;
    if (optind_count != 1 || ((r_flag || R_flag) && filename == NULL) || (R_flag && !s_flag) || (s_flag && strlen(sha1_hash) != 40))
    {
        display_info();
        exit(1);
    }
    
    struct stat sb;
    char *file_mem;
    int fd = open(disk_image, O_RDWR); // Use O_RDWR because we may need to write
    if (fd < 0)
    {
        display_info();
        exit(1);
    }
    if (fstat(fd, &sb) == -1)
    {
        perror("Error: getting file size");
        close(fd);
        exit(1);
    }

    file_mem = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (file_mem == MAP_FAILED)
    {
        perror("Error: mapping file");
        close(fd);
        exit(1);
    }

    // initialize file system info
    FileSystemInfo fs_info;
    BootEntry *entry = (BootEntry *) file_mem;
    fs_info.bytes_per_sector = entry->BPB_BytsPerSec;
    fs_info.sectors_per_cluster = entry->BPB_SecPerClus;
    fs_info.reserved_sector_count = entry->BPB_RsvdSecCnt;
    fs_info.num_fats = entry->BPB_NumFATs;
    fs_info.fat_size = entry->BPB_FATSz32;
    fs_info.root_cluster = entry->BPB_RootClus;
    fs_info.total_sectors = entry->BPB_TotSec32;

    // calculate derived values
    fs_info.fat_region_size = fs_info.fat_size * fs_info.num_fats * fs_info.bytes_per_sector;
    fs_info.cluster_size = fs_info.bytes_per_sector * fs_info.sectors_per_cluster;
    fs_info.data_region_offset = (fs_info.reserved_sector_count * fs_info.bytes_per_sector) + fs_info.fat_region_size;
    fs_info.root_dir_offset = fs_info.data_region_offset + ((fs_info.root_cluster - 2) * fs_info.cluster_size);
    fs_info.total_clusters = (fs_info.total_sectors - fs_info.reserved_sector_count - (fs_info.num_fats * fs_info.fat_size)) / fs_info.sectors_per_cluster;

    // proceed based on the option used
    if (i_flag) 
        print_file_sys_info(&fs_info);
    else if (l_flag)
        display_root_directory(file_mem, &fs_info);
    else if (r_flag)
        recover_small_file(file_mem, filename, &fs_info);

    return 0;
}