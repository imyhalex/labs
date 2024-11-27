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

    for (i = 2; i >= 0 && ext[i] == ' '; i--)
        ext[i] = '\0';

    if (ext[0] != '\0')
        sprintf(filename, "%s.%s", name, ext);
    else
        sprintf(filename, "%s", name);
}

int is_valid_cluster(unsigned int cluster) 
{
    return cluster >= 2 && cluster < 0x0ffffff8;
}

unsigned int get_next_cluster(char *file_mem, FileSystemInfo *fs_info, unsigned int current_cluster)
{
    unsigned int fat_start = fs_info->reserved_sector_count * fs_info->bytes_per_sector;
    unsigned int fat_entry_offset = fat_start + current_cluster * 4;
    unsigned int *fat_entry = (unsigned int *)(file_mem + fat_entry_offset);
    return *fat_entry & 0x0fffffff;
}

void display_root_directory(char *file_mem, FileSystemInfo *fs_info)
{
    unsigned int current_cluster = fs_info->root_cluster;
    unsigned int cluster_size = fs_info->cluster_size;
    unsigned int entries_per_cluster = cluster_size / sizeof(DirEntry);

    int entries_cnt = 0;

    while (is_valid_cluster(current_cluster))
    {
        unsigned int cluster_offset = fs_info->data_region_offset + (current_cluster - 2) * cluster_size;

        DirEntry *dir_entry = (DirEntry *)(file_mem + cluster_offset);

        unsigned int i;
        for (i = 0; i < entries_per_cluster; i++)
        {
            if (dir_entry->DIR_Name[0] == 0x00)
                break;
            

            if (dir_entry->DIR_Name[0] == 0xe5 || dir_entry->DIR_Attr == 0x0f)
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

        current_cluster = get_next_cluster(file_mem, fs_info, current_cluster);

        // check for end-of-cluster chain
        if (current_cluster >= 0x0ffffff8)
            break;
    }

    printf("Total number of entries = %d\n", entries_cnt);
}

unsigned char *read_file_data(char *file_mem, FileSystemInfo *fs_info, unsigned int starting_cluster, unsigned int file_size)
{
    unsigned char *data = malloc(file_size);
    unsigned int cluster_size = fs_info->cluster_size;
    unsigned int bytes_read = 0;
    unsigned int current_cluster = starting_cluster;

    while (bytes_read < file_size && is_valid_cluster(current_cluster))
    {
        unsigned int offset = fs_info->data_region_offset + (current_cluster - 2) * cluster_size;
        unsigned int to_read = (file_size - bytes_read > cluster_size) ? cluster_size : file_size - bytes_read;
        memcpy(data + bytes_read, file_mem + offset, to_read);
        bytes_read += to_read;
        current_cluster++;
    }

    if (bytes_read != file_size)
    {
        free(data);
        return NULL;
    }
    return data;
}

int is_cluster_free(char *file_mem, FileSystemInfo *fs_info, unsigned int cluster)
{
    unsigned int fat_start = fs_info->reserved_sector_count * fs_info->bytes_per_sector;
    unsigned int fat;
    for (fat = 0; fat < fs_info->num_fats; fat++)
    {
        unsigned int fat_offset = fat_start + fat * fs_info->fat_size * fs_info->bytes_per_sector + cluster * 4;
        unsigned int *fat_entry = (unsigned int *)(file_mem + fat_offset);
        if (*fat_entry != 0x00000000)
            return 0;
    }
    return 1;
}

void update_fat_entry(char *file_mem, FileSystemInfo *fs_info, unsigned int cluster, unsigned int value)
{
    unsigned int fat_start = fs_info->reserved_sector_count * fs_info->bytes_per_sector;
    unsigned int fat;
    for (fat = 0; fat < fs_info->num_fats; fat++) 
    {
        unsigned int fat_offset = fat_start + fat * fs_info->fat_size * fs_info->bytes_per_sector + cluster * 4;
        unsigned int *fat_entry = (unsigned int *)(file_mem + fat_offset);
        *fat_entry = value;
    }
}

DirEntry *get_cluster_entries(char *file_mem, FileSystemInfo *fs_info, unsigned int cluster)
{
    unsigned int offset = fs_info->data_region_offset + (cluster - 2) * fs_info->cluster_size;
    return (DirEntry *)(file_mem + offset);
}

int is_matching_entry(DirEntry *dir_entry, char *filename)
{
    char temp_name[11];
    memcpy(temp_name, dir_entry->DIR_Name, 11);
    temp_name[0] = filename[0];
    DirEntry temp_entry = *dir_entry;
    memcpy(temp_entry.DIR_Name, temp_name, 11);
    char entry_name[13];
    trim_file(entry_name, &temp_entry);
    return strcasecmp(entry_name, filename) == 0;
}

int hex_to_bytes(const char *hex_str, unsigned char *byte_arr)
{
    int i;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        if (sscanf(hex_str + 2 * i, "%2hhx", &byte_arr[i]) != 1)
            return 0;
    }
    return 1;
}

DirEntry *find_target_entry(char *file_mem, FileSystemInfo *fs_info, DirEntry **candidates, int candidate_count, char *sha1_hash)
{
    if (!sha1_hash)
        return candidates[0];
    unsigned char target_hash[SHA_DIGEST_LENGTH];
    if (!hex_to_bytes(sha1_hash, target_hash))
        return NULL;
    int i;
    for (i = 0; i < candidate_count; i++)
    {
        DirEntry *entry = candidates[i];
        unsigned int starting_cluster = (entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
        unsigned int file_size = entry->DIR_FileSize;
        unsigned char *file_data = read_file_data(file_mem, fs_info, starting_cluster, file_size);
        if (!file_data)
            continue;
        unsigned char computed_hash[SHA_DIGEST_LENGTH];
        SHA1(file_data, file_size, computed_hash);
        free(file_data);
        if (memcmp(computed_hash, target_hash, SHA_DIGEST_LENGTH) == 0)
            return entry;
    }
    return NULL;
}

int recover_clusters(char *file_mem, FileSystemInfo *fs_info, DirEntry *entry)
{
    unsigned int starting_cluster = (entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
    unsigned int file_size = entry->DIR_FileSize;
    if (starting_cluster == 0)
        return 1;

    unsigned int cluster_size = fs_info->cluster_size;
    unsigned int cluster_needed = (file_size + cluster_size - 1) / cluster_size;
    unsigned int current_cluster = starting_cluster;
    unsigned int i;
    for (i = 0; i < cluster_needed; i++) 
    {
        if (!is_valid_cluster(current_cluster))
            return 0;
        if (!is_cluster_free(file_mem, fs_info, current_cluster))
            return 0;
        unsigned int next_cluster = (i == cluster_needed - 1) ? 0x0FFFFFF8 : current_cluster + 1;
        update_fat_entry(file_mem, fs_info, current_cluster, next_cluster);
        current_cluster = next_cluster;
    }
    return 1;
}

void update_fat_sequence(char *file_mem, FileSystemInfo *fs_info, unsigned int *sequence, int seq_len)
{
    unsigned int fat_start = fs_info->reserved_sector_count * fs_info->bytes_per_sector;
    int i;
    for (i = 0; i < seq_len; i++)
    {
        unsigned int cluster = sequence[i];
        unsigned int next_cluster = (i == seq_len - 1) ? 0x0FFFFFF8 : sequence[i + 1];
        unsigned int fat;
        for (fat = 0; fat < fs_info->num_fats; fat++) 
        {
            unsigned int fat_offset = fat_start + fat * fs_info->fat_size * fs_info->bytes_per_sector + cluster * 4;
            unsigned int *fat_entry = (unsigned int *)(file_mem + fat_offset);
            *fat_entry = next_cluster;
        }
    }
}

void get_unallocated_clusters(char *file_mem, FileSystemInfo *fs_info, unsigned int *clusters, int *num_clusters)
{
    unsigned int fat_start = fs_info->reserved_sector_count * fs_info->bytes_per_sector;
    int count = 0;
    unsigned int cluster;
    for (cluster = 2; cluster <= 21; cluster++) 
    {
        unsigned int fat_offset = fat_start + cluster * 4;
        unsigned int *fat_entry = (unsigned int *)(file_mem + fat_offset);
        if (*fat_entry == 0x00000000)
            clusters[count++] = cluster;
    }
    *num_clusters = count;
}

int check_sequence(char *file_mem, FileSystemInfo *fs_info, DirEntry *entry, unsigned char *target_hash, unsigned int *sequence, int seq_len)
{
    unsigned int file_size = entry->DIR_FileSize;
    unsigned int cluster_size = fs_info->cluster_size;
    unsigned char *data = malloc(file_size);
    unsigned int bytes_read = 0;
    int i;
    for (i = 0; i < seq_len; i++)
    {
        unsigned int cluster = sequence[i];
        unsigned int offset = fs_info->data_region_offset + (cluster - 2) * cluster_size;
        unsigned int to_read = (file_size - bytes_read > cluster_size) ? cluster_size : (file_size - bytes_read);
        memcpy(data + bytes_read, file_mem + offset, to_read);
        bytes_read += to_read;
    }
    unsigned char computed_hash[SHA_DIGEST_LENGTH];
    SHA1(data, file_size, computed_hash);
    free(data);
    return memcmp(computed_hash, target_hash, SHA_DIGEST_LENGTH) == 0;
}

int search_sequence(char *file_mem, FileSystemInfo *fs_info, DirEntry *entry, unsigned char *target_hash, unsigned int *clusters, 
                        int num_clusters, int clusters_needed, unsigned int *current_sequence, int depth, int *used)
{
    if (depth == clusters_needed)
    {
        if (check_sequence(file_mem, fs_info, entry, target_hash, current_sequence, clusters_needed))
        {
            update_fat_sequence(file_mem, fs_info, current_sequence, clusters_needed);
            return 1;
        }
        return 0;
    }
    int i;
    for (i = 0; i < num_clusters; i++)
    {
        if (!used[i])
        {
            used[i] = 1;
            current_sequence[depth] = clusters[i];
            if (search_sequence(file_mem, fs_info, entry, target_hash, clusters, num_clusters, clusters_needed,
                               current_sequence, depth + 1, used))
                return 1;
            used[i] = 0;
        }
    }
    return 0;
}

int find_matching_sequence(char *file_mem, FileSystemInfo *fs_info, DirEntry *entry,unsigned char *target_hash, 
                            unsigned int *clusters, int num_clusters, int clusters_needed, unsigned int *first_cluster)
{
    unsigned int *sequence = malloc(sizeof(unsigned int) * clusters_needed);
    int *used = calloc(num_clusters, sizeof(int));
    int result = search_sequence(file_mem, fs_info, entry, target_hash, clusters, num_clusters, clusters_needed, sequence, 0, used);
    if (result == 1)
        *first_cluster = sequence[0];
    free(sequence);
    free(used);
    return result;
}

void recover_file(char *file_mem, char *filename, FileSystemInfo *fs_info, char *sha1_hash, int is_not_contiguous)
{
    unsigned int cluster_size = fs_info->cluster_size;
    unsigned int entries_per_cluster = cluster_size / sizeof(DirEntry);
    unsigned int root_cluster = fs_info->root_cluster;

    DirEntry *candidates[100];
    int candidate_count = 0;

    unsigned int current_cluster = root_cluster;
    while (is_valid_cluster(current_cluster))
    {
        DirEntry *dir_entry = get_cluster_entries(file_mem, fs_info, current_cluster);

        unsigned int i;
        for (i = 0; i < entries_per_cluster; i++, dir_entry++)
        {
            if (dir_entry->DIR_Name[0] == 0x00)
                break;

            if (dir_entry->DIR_Name[0] == 0xe5 && !(dir_entry->DIR_Attr & 0x0f))
            {
                if (is_matching_entry(dir_entry, filename))
                {
                    if (candidate_count < 100)
                        candidates[candidate_count++] = dir_entry;
                    else return;
                }
            }
        }

        current_cluster = get_next_cluster(file_mem, fs_info, current_cluster);
    }

    if (candidate_count == 0)
    {
        printf("%s: file not found\n", filename);
        return;
    }

    if (candidate_count > 1 && !sha1_hash)
    {
        printf("%s: multiple candidates found\n", filename);
        return;
    }

    unsigned char target_hash[SHA_DIGEST_LENGTH];
    if (sha1_hash)
    {
        if (!hex_to_bytes(sha1_hash, target_hash))
        {
            printf("%s: file not found\n", filename);
            return;
        }
    }

    if (is_not_contiguous)
    {
        int recovered = 0;
        int i;
        for (i = 0; i < candidate_count; i++)
        {
            DirEntry *target_entry = candidates[i];
            unsigned int clusters[20];
            int num_clusters;
            get_unallocated_clusters(file_mem, fs_info, clusters, &num_clusters);
            int clusters_needed = (target_entry->DIR_FileSize + fs_info->cluster_size - 1) / fs_info->cluster_size;
            if (clusters_needed > 5) 
                clusters_needed = 5;
            unsigned int first_cluster;
            int result = find_matching_sequence(file_mem, fs_info, target_entry, target_hash, clusters, num_clusters, clusters_needed, &first_cluster);
            if (result == 1)
            {
                // Update the starting cluster in the directory entry
                target_entry->DIR_FstClusHI = (first_cluster >> 16) & 0xFFFF;
                target_entry->DIR_FstClusLO = first_cluster & 0xFFFF;
                // Restore the first character of the directory entry
                target_entry->DIR_Name[0] = filename[0];
                // Success message
                printf("%s: successfully recovered with SHA-1\n", filename);
                recovered = 1;
                break;
            }
        }

        if (!recovered)
            printf("%s: file not found\n", filename);
    }
    else
    {
        DirEntry *target_entry = find_target_entry(file_mem, fs_info, candidates, candidate_count, sha1_hash);
        if (!target_entry)
        {
            printf("%s: file not found\n", filename);
            return;
        }

        recover_clusters(file_mem, fs_info, target_entry);
        // restore the first character of the directory entry
        target_entry->DIR_Name[0] = filename[0];
        // success message
        if (sha1_hash)
            printf("%s: successfully recovered with SHA-1\n", filename);
        else
            printf("%s: successfully recovered\n", filename);
    } 
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
                exit(1);
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
    int fd = open(disk_image, O_RDWR);
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

    int is_not_contiguous = 0;
    if (R_flag)
        is_not_contiguous = 1;
    // proceed based on the option used
    if (i_flag) 
        print_file_sys_info(&fs_info);
    else if (l_flag)
        display_root_directory(file_mem, &fs_info);
    else if (r_flag || R_flag)
        recover_file(file_mem, filename, &fs_info, s_flag? sha1_hash : NULL, is_not_contiguous);

    return 0;
}