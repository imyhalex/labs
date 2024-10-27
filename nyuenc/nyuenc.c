#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define BUFFER_SIZE 16384 // define a 16KB buffer

/** some global values here */
int is_first_file = 1;
unsigned char curr_c = 0;
unsigned char buffer[BUFFER_SIZE];
size_t buffer_index = 0;
// 1-byte unsigned integer in binary format
unsigned char count = 0;

void flush_buffer()
{
    // only flush it when having data
    if (buffer_index > 0)
    {
        write(STDOUT_FILENO, buffer, buffer_index);
        // reset buffer index
        buffer_index = 0;
    }
}

void encode_to_rle(char *data, size_t size)
{
    unsigned char *ptr = (unsigned char *) data;
    // find the end of the pointer
    unsigned char *end = ptr + size;

    while (ptr < end)
    {
        // if the first character
        if (is_first_file)
        {   
            count = 1;
            curr_c = *ptr;
            is_first_file = 0;
        }
        // if character appear within 255 times in a row and pointer is equals to current character
        else if (*ptr == curr_c && count < 255)
            count++;
        // write the character and count to the buffer
        else
        {
            buffer[buffer_index++] = curr_c;
            buffer[buffer_index++] = count;

            // if buffer is full, flush the output
            if (buffer_index >= BUFFER_SIZE - 2)
                flush_buffer();

            // reset curr_c and count
            curr_c = *ptr;
            count = 1;
        }
        ptr++;
    }
}

void write_rle(const char *filename)
{
    int fd = open(filename, O_RDONLY);
    if (fd == -1)
    {
        perror("open");
        return;
    }

    // Get file size
    struct stat sb;
    if (fstat(fd, &sb) == -1)
    {
        perror("fstat");
        close(fd);
        return;
    }

    // Map file into memory
    char *addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED)
    {
        perror("mmap");
        close(fd);
        return;
    }

    // do rle encoding
    encode_to_rle(addr, sb.st_size);

    // remove mapping
    munmap(addr, sb.st_size);
    close(fd);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        perror("error");
        exit(1);
    }

    int i;
    for (i = 1; i < argc; i++)
        write_rle(argv[i]);
    
    // write last char and count after writing all files
    if (!is_first_file && count > 0)
    {
        buffer[buffer_index++] = curr_c;
        buffer[buffer_index++] = count;
    }

    // flush the remaining data
    flush_buffer();

    exit(0);
}