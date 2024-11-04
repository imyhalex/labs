#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>
#include <getopt.h>

#define BUFFER_SIZE 32768 // define a 32KB buffer
#define CHUNK_SIZE 4096
#define MAX_FILES 100
#define MAX_CHUNKS 250000

/**
 * All milestone 2 borrowed ideas from:
 * @cite: https://github.com/mathewpan2/Multithreaded-RLE/blob/main/encode.c
 * ideas of 'void parallel_rle(char **files, int num_files_input, int num_threads);' from multi-thread part in 'int main();'
 * ideas of 'void *fetch_task();' are from 'void* worker_encode();'
 */
typedef struct task_node {
    int index;
    size_t start;
    size_t end;
    unsigned char *data; // each node references entire data
    struct task_node *next;
} Node;

typedef struct {
    Node *front;
    Node *end;
} TaskQueue;

/** some global values here */
TaskQueue queue;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

unsigned char **results; 
int chunk_size_arr[MAX_CHUNKS];
int completed_arr[MAX_CHUNKS] = {0}; // flagger array to keep track if each task is completed
pthread_mutex_t results_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t results_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t result_cond = PTHREAD_COND_INITIALIZER;

// file handling
struct stat sb_files[MAX_FILES];
unsigned char *addr_files[MAX_FILES];
int num_files = 0;

// control variables
int all_tasks_created = 0;

int is_first_file = 1;
unsigned char curr_c = 0;
unsigned char buffer[BUFFER_SIZE];
size_t buffer_index = 0;
// 1-byte unsigned integer in binary format
unsigned char count = 0;

// helper function to reduce the number fwrite call
void flush_buffer()
{
    if (buffer_index > 0)
    {
        fwrite(buffer, 1, buffer_index, stdout);
        buffer_index = 0;
    }
}

void init_queue(TaskQueue *queue)
{
    queue->front = queue->end = NULL;
}

void task_enqueue(TaskQueue *queue, Node *node)
{
    node->next = NULL;
    if (queue->end == NULL)
        queue->front = queue->end = node;
    else
    {
        queue->end->next = node;
        queue->end = node; // update tne end pointer point to the new end
    }
}

Node *task_dequeue(TaskQueue *queue)
{
    if (queue->front == NULL)
        return NULL;
    Node *node = queue->front;
    queue->front = queue->front->next;
    if (queue->front == NULL)
        queue->end = NULL;
    node->next = NULL;
    return node;
}

void *fetch_task()
{
    Node *task;
    for (;;)
    {
        pthread_mutex_lock(&queue_mutex);
        while (queue.front == NULL && !all_tasks_created)
            pthread_cond_wait(&queue_cond, &queue_mutex);
        if (queue.front == NULL && all_tasks_created)
        {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }
        task = task_dequeue(&queue);
        pthread_mutex_unlock(&queue_mutex);
        if (task == NULL) continue;
        // do rle
        unsigned char *ptr = task->data + task->start;
        size_t size = task->end - task->start;
        unsigned char local_count = 0;
        unsigned char local_char = 0;
        unsigned char *local_buffer = (unsigned char *) malloc((size * 2) + 1);
        int local_index = 0;

        size_t i;
        for (i = 0; i < size; i++)
        {   
            if (local_count == 0)
            {
                local_char = ptr[i];
                local_count = 1;
            }
            else if (ptr[i] == local_char && local_count < 255)
                local_count++;
            else
            {
                local_buffer[local_index++] = local_char;
                local_buffer[local_index++] = local_count;
                local_char = ptr[i];
                local_count = 1; 
            }
        }
        if (local_count > 0)
        {
            local_buffer[local_index++] = local_char;
            local_buffer[local_index++] = local_count;
        }
        // store the result
        pthread_mutex_lock(&results_mutex);
        results[task->index] = local_buffer;
        chunk_size_arr[task->index] = local_index;
        completed_arr[task->index] = 1;
        pthread_cond_signal(&results_cond);
        pthread_mutex_unlock(&results_mutex);
        free(task);
    }
    return NULL;
}

void parallel_rle(char **files, int num_files_input, int num_threads)
{
    num_files = num_files_input;
    results = (unsigned char **)malloc(MAX_CHUNKS * sizeof(unsigned char *));
    int i;
    for (i = 0; i < num_files; i++)
    {
        int fd = open(files[i], O_RDONLY);
        if (fd == -1) 
        {
            perror("open");
            exit(1);
        }

        if (fstat(fd, &sb_files[i]) == -1)
        {
            perror("fstat");
            close(fd);
            exit(1);
        }

        addr_files[i] = mmap(NULL, sb_files[i].st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (addr_files[i] == MAP_FAILED)
        {
            perror("mmap");
            close(fd);
            exit(1);
        }
        close(fd); 
    }

    init_queue(&queue);
    pthread_t *threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    for (i = 0; i < num_threads; i++)
        pthread_create(&threads[i], NULL, fetch_task, NULL);
    
    // enqueue tasks
    int chunk_idx = 0;
    int total_chunks = 0;
    for (i = 0; i < num_files; i++)
    {
        size_t file_size = sb_files[i].st_size;
        size_t chunks = file_size / CHUNK_SIZE;
        size_t remainder = file_size % CHUNK_SIZE;
        if (remainder != 0)
            chunks++;
        
        size_t j;
        for (j = 0; j < chunks; j++)
        {
            size_t start = j * CHUNK_SIZE;
            size_t end = (j == chunks - 1) ? file_size : (j + 1) * CHUNK_SIZE;
            Node *task = (Node *)malloc(sizeof(Node));
            task->index = chunk_idx;
            task->start = start;
            task->end = end;
            task->data = addr_files[i];
            task->next = NULL;

            pthread_mutex_lock(&queue_mutex);
            task_enqueue(&queue, task);
            pthread_cond_signal(&queue_cond);
            pthread_mutex_unlock(&queue_mutex);

            chunk_idx++;
            total_chunks++;
        }
    }

    // all tasks have been created
    pthread_mutex_lock(&queue_mutex);
    all_tasks_created = 1;
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);

    // main thread processes results as they become avaibale
    int total_tasks = chunk_idx;
    int tasks_processed = 0;
    int curent_task_index = 0;
    unsigned char last_char = 0;
    unsigned char last_count = 0;
    int has_last_run = 0; // flag to indicate if there's a pending run to merge
    while (tasks_processed < total_tasks)
    {
        pthread_mutex_lock(&results_mutex);
        while (!completed_arr[curent_task_index])
            pthread_cond_wait(&results_cond, &results_mutex);
        // process result at current task index
        unsigned char *result = results[curent_task_index];
        int result_size = chunk_size_arr[curent_task_index];
        // merge
        int k;
        for (k = 0; k < result_size; k+=2)
        {
            unsigned char current_char = result[k];
            unsigned char current_count = result[k + 1];
            if (has_last_run && current_char == last_char)
            {
                unsigned int combined_count = (unsigned int)last_count + (unsigned int)current_count;
                if (combined_count <= 255)
                    last_count = (unsigned char)combined_count;
                else
                {
                    // write out the maximum allowed count
                    unsigned char overflow = (unsigned char)(combined_count - 255);
                    buffer[buffer_index++] = last_char;
                    buffer[buffer_index++] = 255;
                    if (buffer_index >= BUFFER_SIZE - 2)
                        flush_buffer();
                    last_count = overflow;
                }
            }
            else 
            {
                if (has_last_run)
                {
                    buffer[buffer_index++] = last_char;
                    buffer[buffer_index++] = last_count;
                    if (buffer_index >= BUFFER_SIZE - 2)
                        flush_buffer();
                }
                last_char = current_char;
                last_count = current_count;
                has_last_run = 1;
            }
        }
        free(result);
        tasks_processed++;
        curent_task_index++;
        pthread_mutex_unlock(&results_mutex);
    }

    if (has_last_run)
    {
        buffer[buffer_index++] = last_char;
        buffer[buffer_index++] = last_count;
        if (buffer_index >= BUFFER_SIZE - 2)
            flush_buffer();
    }
    flush_buffer();

    // wait all threads
    for (i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);

    // clean up
    free(queue.front);
    free(queue.end);
    pthread_mutex_destroy(&queue_mutex); 
    pthread_cond_destroy(&queue_cond);
    pthread_cond_destroy(&results_cond);
    pthread_mutex_destroy(&results_mutex);
    free(threads);
    for (i = 0; i < num_files; i++)
        munmap(addr_files[i], sb_files[i].st_size);
    free(results);
}

/** this part for sequential rle */
void encode_to_rle(char *data, size_t size)
{
    unsigned char *ptr = (unsigned char *) data;
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

/**
 * @cite: https://www.man7.org/linux/man-pages/man3/getopt.3.html
 */
int main (int argc, char **argv)
{
    int opt;
    int num_threads = 0;
    int num_files_input = 0;
    char **file_list = NULL;
    while ((opt = getopt(argc, argv, "j:")) != -1)
    {
        switch (opt)
        {
            case 'j':
                num_threads = atoi(optarg);
                if (num_threads <= 0)
                {
                    fprintf(stderr, "Invalid number of threads: %s\n", optarg);
                    exit(1);
                }
                break;
            default:
                perror("error");
                exit(1);
        }
    }

    num_files_input = argc - optind;
    file_list = &argv[optind];

    if (num_files_input < 1)
    {
        fprintf(stderr, "No input files specified.\n");
        exit(1);
    }

    if (num_threads > 0)
        parallel_rle(file_list, num_files_input, num_threads);
    else
    {
        int i;
        for (i = 0; i < num_files_input; i++)
            write_rle(file_list[i]);
        
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
    return 0;
}