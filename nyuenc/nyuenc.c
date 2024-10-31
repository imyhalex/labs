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
#include <unistd.h>
#include <string.h>

#define BUFFER_SIZE 16384 // define a 16KB buffer
#define CHUNCK_SIZE 4096

/** the info of each thread should contain */
typedef struct {
    int is_first_file;
    unsigned char curr_c;
    unsigned char count;
    unsigned char *buffer;
    size_t buffer_index;
    size_t buffer_size;
} EncoderState;

/** a struct for a task */
typedef struct {
    int task_id;
    char *data;
    size_t size;
} Task;

/** a struct for task queue - blue part of the image */
typedef struct {
    Task *tasks;
    int capacity;               // current capacity of the task queue
    int size;                   // number of tasks currently in the queue       
    int front;                  // index of the front of the queue
    int rear;                   // index of the rear of the queue
    pthread_mutex_t mutex;      // mutex to protect access to the queue
    pthread_cond_t not_empty;   // condition variable to signal when the queue is not empty
} TaskQueue;

/** global variable for write mutex */
pthread_mutex_t write_mutex = PTHREAD_MUTEX_INITIALIZER;

void init_task_queue(TaskQueue *queue)
{
    queue->capacity = 10; // Initial capacity
    queue->tasks = malloc(queue->capacity * sizeof(Task));
    queue->size = 0;
    queue->front = 0;
    queue->rear = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
}

void enqueue_task(TaskQueue *queue, Task task)
{
    pthread_mutex_lock(&queue->mutex);
    if (queue->size == queue->capacity)
    {
        queue->capacity *=2;
        queue->tasks = realloc(queue->tasks, queue->capacity * sizeof(Task));
        if (!queue->tasks) 
        {
            perror("malloc");
            exit(1);
        }
    }
    queue->tasks[queue->rear] = task;
    queue->rear = (queue->rear + 1) % queue->capacity;
    queue->size++;
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
}

int dequeue_task(TaskQueue *queue, Task *task)
{
    pthread_mutex_lock(&queue->mutex);
    while (queue->size == 0) 
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    *task = queue->tasks[queue->front];
    queue->front = (queue->front + 1) % queue->capacity;
    queue->size--;
    pthread_mutex_unlock(&queue->mutex);
    return 1;
}

void destory_queue(TaskQueue *queue)
{
    free(queue->tasks);
    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->not_empty);
}

void flush_buffer(EncoderState *state)
{
    // only flush it when having data
    if (state->buffer_index > 0)
    {
        pthread_mutex_lock(&write_mutex);
        write(STDOUT_FILENO, state->buffer, state->buffer_index);
        pthread_mutex_unlock(&write_mutex);
        // reset buffer index
        state->buffer_index = 0;
    }
}

void encode_to_rle(char *data, size_t size, EncoderState *state)
{
    unsigned char *ptr = (unsigned char *) data;
    // find the end of the pointer
    unsigned char *end = ptr + size;

    while (ptr < end)
    {
        if (state->is_first_file)
        {
            state->count = 1;
            state->curr_c = *ptr;
            state->is_first_file = 0;
        }
        else if (*ptr == state->curr_c && state->count < 255)
            state->count++;
        else
        {
            // Append to buffer
            state->buffer[state->buffer_index++] = state->curr_c;
            state->buffer[state->buffer_index++] = state->count;

            // Flush buffer if necessary
            if (state->buffer_index >= state->buffer_size - 2)
                flush_buffer(state);

            // Reset curr_c and count
            state->curr_c = *ptr;
            state->count = 1;
        }
        ptr++;
    }
}

// worker thread function
void *worker_function(void * arg)
{
    TaskQueue *task_queue = (TaskQueue *) arg;

    // initialize encoder state
    EncoderState state;
    state.is_first_file = 1;
    state.curr_c = 0;
    state.count = 0;
    state.buffer_size = BUFFER_SIZE;
    state.buffer = malloc(BUFFER_SIZE);
    state.buffer_index = 0;
    if (!state.buffer)
    {
        perror("malloc");
        exit(1);
    }

    while(1)
    {
        Task task;
        dequeue_task(task_queue, &task);
        if (task.task_id == -1) 
            break;
        encode_to_rle(task.data, task.size, &state);

        if (state.count > 0)
        {
            state.buffer[state.buffer_index++] = state.curr_c;
            state.buffer[state.buffer_index++] = state.count;
            state.count = 0;
        }
        flush_buffer(&state);
    }

    free(state.buffer);
    return NULL;
}

int map_file(const char *filename, char **data, size_t *size)
{
    int fd = open(filename, O_RDONLY);
    if (fd == -1)
    {
        perror("open");
        return -1;
    }

    // Get file size
    struct stat sb;
    if (fstat(fd, &sb) == -1)
    {
        perror("fstat");
        close(fd);
        return -1;
    }

    // Map file into memory
    *data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (*data == MAP_FAILED)
    {
        perror("mmap");
        close(fd);
        return -1;
    }

    *size = sb.st_size;
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    /** @cite: https://www.man7.org/linux/man-pages/man3/getopt.3.html */
    // default value for thread is 1 (sequential)
    int num_threads = 1;
    int opt;

    while ((opt = getopt(argc, argv, "j:")) != -1)
    {
        switch(opt)
        {
            case 'j':
                num_threads = atoi(optarg);
                if (num_threads <= 0) 
                {
                    fprintf(stderr, "Invalid number of threads.\n");
                    exit(1);
                }
                break;
            default:
                perror("error");
                exit(1);
        }
    }

    if (optind >= argc)
    {
        fprintf(stderr, "Expected argument after options\n");
        exit(1);
    }

    // initialize a task queue (blue section)
    TaskQueue queue;
    init_task_queue(&queue);

    // worker thread pool
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    int i;
    for (i = 0; i < num_threads; i++)
        pthread_create(&threads[i], NULL, worker_function, &queue);
    
    int task_id = 0;
    for (i = optind; i < argc; i++)
    {
        char *data;
        size_t file_size;
        if (map_file(argv[i], &data, &file_size) != 0)
            continue;
        
        // enqueue chunks in 4KB (4096 Bytes)
        size_t offset = 0;
        while (offset < file_size)
        {
            size_t chunck_size = (file_size - offset >= 4096) ? 4096 : (file_size - offset);
            // create a task
            Task task;
            task.task_id = task_id++;
            task.data = data + offset;
            task.size = chunck_size;
            enqueue_task(&queue, task);
            // increment the offset for next chunk condition
            offset += chunck_size;
        }
        // unmap the file
        // munmap(data, file_size);
    }

    // a task for termination - flag for terminate the task queue
    for (i = 0; i < num_threads; i++)
    {
        Task term_task;
        term_task.task_id = -1;
        term_task.data = NULL;
        term_task.size = 0;
        enqueue_task(&queue, term_task);
    }

    // wait for woker pools to finish
    for (i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);
    free(threads);
    destory_queue(&queue);
    pthread_mutex_destroy(&write_mutex);
    exit(0);
}