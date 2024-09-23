#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MAX_INPUT_SIZE 1000
#define ARGS_SLOT 20
#define DELIMITER " \t\r\n\a" //  Delimiters are space, tab, carriage return, newline, and bell character
#define MAX_JOBS 100

/**
 * References for jobs & fg command:
 * @cite https://github.com/solomonw1/basic_shell/blob/master/jobs.c
 * @cite https://github.com/hungys/mysh/blob/master/mysh.c
 * @cite https://github.com/ImaginationZ/Shell/blob/master/exec.c
 * @cite https://www.youtube.com/watch?v=3MZjaZxZYrE&list=PLfqABt5AS4FkW5mOn2Tn9ZZLLDwA3kZUY&index=18
 * @cite https://www.youtube.com/watch?v=7ud2iqu9szk&list=PLfqABt5AS4FkW5mOn2Tn9ZZLLDwA3kZUY&index=19
 * @cite https://www.youtube.com/watch?v=jF-1eFhyz1U&list=PLfqABt5AS4FkW5mOn2Tn9ZZLLDwA3kZUY&index=19
 */
typedef struct job
{
    int index;
    pid_t pid;
    char *command;
} job;

/** Some global variables for jobs*/
int job_cnt = 0;
job job_list[MAX_JOBS];
char *current_command_line = NULL;

void init_jobs()
{
    job_cnt = 0;
    int i;
    for (i = 0; i < MAX_JOBS; i++)
    {
        job_list[i].index = 0;
        job_list[i].pid = 0;
        job_list[i].command = NULL;
    }
}

void add_job(pid_t pid)
{
    if (job_cnt >= MAX_JOBS)
    {
        fprintf(stderr, "Error: job list is full\n");
        return;
    }

    job_list[job_cnt].index = job_cnt + 1;
    job_list[job_cnt].pid = pid;
    job_list[job_cnt].command = strdup(current_command_line);
    job_cnt++;
}

void remove_job(pid_t pid)
{
    int i;
    for (i = 0; i < job_cnt; i++)
    {
        if (job_list[i].pid == pid)
        {
            free(job_list[i].command);
            int j;
            for (j = i; j < job_cnt - 1; j++)
            {
                job_list[j] = job_list[j + 1];
                job_list[j].index = j + 1;
            }
            job_cnt--;
            break;
        }
    }
}

void reap_children_handler(int sig)
{
    (void) sig;
    pid_t pid;
    int status;
    while ((pid = waitpid(-1, &status, WUNTRACED | WNOHANG)) > 0)
    {
        // if child was stopped, add to job list
        if (WIFSTOPPED(status))
            add_job(pid);
        // if child exit or terminated, remove from job list
        else if (WIFEXITED(status) || WIFSIGNALED(status))
            remove_job(pid);
    }
}

void ignore_signals()
{
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGCHLD, reap_children_handler);
}

void reset_signals()
{
    signal(SIGINT, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGTSTP, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);
}

char *get_cwd()
{
    char *cwd, buffer[PATH_MAX];
    cwd = getcwd(buffer, PATH_MAX);

    if (cwd == NULL)
    {
        perror("directory");
        exit(1);
    }

    return cwd;
}

char *get_base_name(char *cwd)
{
    // make a copy of cwd for safty reason
    char cwd_copy[PATH_MAX];
    strncpy(cwd_copy, cwd, PATH_MAX - 1);
    cwd_copy[PATH_MAX - 1] = '\0';

    // get the last token from the cwd
    char *token = strtok(cwd_copy, "/");
    char *last_token = token;

    while (token)
    {
        last_token = token;
        token = strtok(NULL, "/");
    }
    return last_token;
}

void print_prompt(char *token)
{

    printf("[nyush %s]$ ", token);
    fflush(stdout);
}

char **read_parse_line()
{
    /**
     * @cite char *lsh_read_line(void);
     * @cite https://brennan.io/2015/01/16/write-a-shell-in-c/
     * @cite https://www.ibm.com/docs/en/zos/3.1.0?topic=functions-getline-read-entire-line-from-stream
     */
    char *line = NULL;
    size_t buff_size = 0;
    ssize_t result = 0;

    /**
     * @cite char **lsh_split_line(char *line);
     * @cite https://brennan.io/2015/01/16/write-a-shell-in-c/
     */
    char **tokens;
    char *token;
    int size = ARGS_SLOT, i = 0;

    /**
     * @cite https://docs.revenera.com/installshield21helplib/Subsystems/installshield21langref/helplibrary/LangrefGetLine.htm
     * getline() returns <0 indicates that the function failed due to an end-of-file error or another error condition.
     * This condition also indicates GetLine has read all the lines in the file.
     */
    result = getline(&line, &buff_size, stdin);

    // result == -1 indicates either an error or end-of-file(EOF)
    if (result == -1)
    {
        free(line);
        if (feof(stdin))
            exit(0);
        else
        {
            perror("Readline");
            exit(1);
        }
    }

    if (result > MAX_INPUT_SIZE)
    {
        perror("Error");
        free(line);
        return NULL;
    }

    /** for current_command_line global variable */
    char *line_cpy = strdup(line);
    if (line[result -1] == '\n')
        line[result - 1] = '\0';

    // store or update the current command line
    if (current_command_line != NULL)
        free(current_command_line);
    current_command_line = strdup(line_cpy);
    free(line_cpy);
    /** *************************************** */

    tokens = malloc(size * sizeof(char *));
    if (!tokens)
    {
        perror("Error");
        exit(1);
    }

    token = strtok(line, DELIMITER);
    while (token)
    {
        tokens[i] = token;
        i++;

        // if ARGS_SLOT is filled up
        if (i > size)
        {
            size += ARGS_SLOT;
            tokens = realloc(tokens, size * sizeof(char *));
            if (!tokens)
            {
                perror("Error");
                exit(1);
            }
        }

        token = strtok(NULL, DELIMITER);
    }

    tokens[i] = '\0';
    return tokens;
}

int get_tokens_length(char **tokens)
{
    int i, count = 0;
    for (i = 0; tokens[i] != NULL; i++)
        count++;
    return count;
}

void process_commands(char **tokens, int pos, int cmd_num)
{
    int allow_input_redirection = 0, allow_output_redirection = 0;

    // determine whether to allow I/O redirection
    if (cmd_num == 1)
    {
        allow_input_redirection = 1;
        allow_output_redirection = 1;
    }
    else
    {
        if (pos == 0)
            allow_input_redirection = 1;
        if (pos == cmd_num - 1)
            allow_output_redirection = 1;
    }
    /**
     * @cite https://www.youtube.com/watch?v=DiNmwwQWl0g
     * @cite https://www.youtube.com/watch?v=5fnVr-zH-SE&list=PLfqABt5AS4FkW5mOn2Tn9ZZLLDwA3kZUY&index=14
     * google: default file permission in Linux when a file is created is 644, or rw-r--r--.
     * @cite https://www.geeksforgeeks.org/input-output-system-calls-c-create-open-close-read-write/
     */
    int in_redirect = -1, out_redirect = -1, append_redirect = -1; // initial flags, means no redirections are set
    char *in = NULL, *out = NULL;

    // iterate through each tokens, and implement redirection rules
    int i;
    for (i = 0; tokens[i] != NULL; i++)
    {
        if (strcmp(tokens[i], "<") == 0)
        {
            if (allow_input_redirection)
            {
                in_redirect = i;
                if (tokens[i + 1] != NULL)
                    in = tokens[i + 1];
                else
                {
                    fprintf(stderr, "Error: no input file specified\n");
                    exit(1);
                }
            }
            else { }
        }
        else if (strcmp(tokens[i], ">") == 0)
        {
            if (allow_output_redirection)
            {
                out_redirect = i;
                if (tokens[i + 1] != NULL)
                    out = tokens[i + 1];
                else
                {
                    fprintf(stderr, "Error: no output file initialized/specified\n");
                    exit(1);
                }
            }
            else { }
        }
        else if (strcmp(tokens[i], ">>") == 0)
        {
            if (allow_output_redirection)
            {
                append_redirect = i;
                if (tokens[i + 1] != NULL)
                    out = tokens[i + 1];
                else
                {
                    fprintf(stderr, "Error: no output file initialized/specified\n");
                    exit(1);
                }
            }
            else { }
        }
    }

    // read or create files based on redirect instructions
    if (in_redirect != -1)
    {
        // file status value
        int file = open(in, O_RDONLY);
        if (file < 0)
        {
            if (errno == ENOENT)
                fprintf(stderr, "Error: invalid file\n");
            else
                perror("open");
            exit(1);
        }

        // duplicate the file to stdout descriptor
        dup2(file, STDIN_FILENO);
        close(file);
    }

    // for ">" and ">>"
    if (out_redirect != -1 || append_redirect != -1)
    {
        int file2;
        if (append_redirect != -1)
            file2 = open(out, O_WRONLY | O_CREAT | O_APPEND, 0664);
        else
            file2 = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0664); // O_TRUNC: tells the system to truncate the file to zero length if it already exists

        if (file2 < 0)
        {
            perror("error");
            exit(1);
        }

        dup2(file2, STDOUT_FILENO);
        close(file2);
    }

    // execvp answers
    int len = get_tokens_length(tokens), index = 0, j = 0;
    char *commands[len];
    while (tokens[j] != NULL)
    {
        if (strcmp(tokens[j], "<") == 0 || strcmp(tokens[j], ">") == 0 || strcmp(tokens[j], ">>") == 0)
        {
            // skip redirection opeartor
            j++;
            // skip the filename
            if (tokens[j] != NULL)
                j++;
            else
            {
                fprintf(stderr, "Error: no filename specified after %s\n", tokens[j - 1]);
                exit(1);
            }
        }
        else
            commands[index++] = tokens[j++];
    }
    commands[index] = '\0';

    int status_code = execvp(commands[0], commands);
    // if execvp has return value, it means new program is not executed successfully
    if (status_code == -1)
    {
        perror("execvp");
        exit(1);
    }
}

void handle_pipes(char **tokens, int cmd_num)
{
    /**
     * concept fd[0] -> read end of the file, fd[1] -> write end fo the file
     * @cite https://www.youtube.com/watch?v=6xbLgZpOBi8&list=PLfqABt5AS4FkW5mOn2Tn9ZZLLDwA3kZUY&index=23
     * @cite https://www.youtube.com/watch?v=NkfIUo_Qq4c&list=PLfqABt5AS4FkW5mOn2Tn9ZZLLDwA3kZUY&index=24
     * @cite https://stackoverflow.com/questions/19461744/how-to-make-parent-wait-for-all-child-processes-to-finish
     */
    pid_t pid, ppid;
    int status, file = 0;
    int fd[2];

    int i, cmd_start = 0; // cmd_start marks index of the start of the current command in tokens
    for (i = 0; i < cmd_num; i++)
    {
        // build up commands for execvp
        int len = get_tokens_length(tokens), index = 0;
        char *commands[len];

        int j = cmd_start;
        while (tokens[j] != NULL && strcmp(tokens[j], "|") != 0)
            commands[index++] = tokens[j++];
        commands[index] = NULL;

        // check and update cmd_start for more commands tokens
        if (tokens[j] == NULL)
            cmd_start = j;
        else
            cmd_start = j + 1;

        // create a pipe if not the last command
        if (i < cmd_num - 1)
        {
            if (pipe(fd) == -1)
            {
                perror("pipe");
                exit(1);
            }
        }

        /** create process part */
        pid = fork();

        if (pid < 0)
        {
            // if fork failed
            perror("fork");
            exit(1);
        }
        else if (pid == 0)
        {
            reset_signals();

            // redirect input from previous command if not the first command
            if (file != 0)
            {
                dup2(file, STDIN_FILENO);
                close(file);
            }

            // redirect output to the next command if not the last command
            if (i < cmd_num - 1)
            {
                dup2(fd[1], STDOUT_FILENO);
                close(fd[0]);
                close(fd[1]);
            }

            // first command: redirect output to pipe's write end
            if (i == 0)
                dup2(fd[1], STDOUT_FILENO);
            // last command: redirect input to pipe's read end
            else if (i == cmd_num - 1)
                dup2(file, STDIN_FILENO);
            // intermediate command: redirect both input and output
            else
            {
                dup2(file, STDIN_FILENO);
                dup2(fd[1], STDOUT_FILENO);
            }

            // after handling pipes, normally process commands
            process_commands(commands, i, cmd_num);
            exit(1); // eixt if execvp fails
        }
        else
        {
            if (file != 0)
                close(file);

            // if end of the pipe and save the read end of the pipe for the next command
            if (i < cmd_num - 1)
            {
                close(fd[1]);
                file = fd[0];
            }

            waitpid(pid, &status, 0);
            if (WIFEXITED(status))
            {
                int status_code = WEXITSTATUS(status);
                if (status_code != 0)
                    fprintf(stderr, "Error: error child status %d\n", status_code);
            }
        }
    }
    while ((ppid = wait(&status)) > 0);
}

int main()
{
    init_jobs();
    ignore_signals();

    /**
     * Get the current directory
     * @cite https://www.qnx.com/developers/docs/7.1/#com.qnx.doc.neutrino.lib_ref/topic/g/getcwd.html
     */
    pid_t pid;
    int status;
    char *cwd;
    char **tokens;

    while (1)
    {
        cwd = get_cwd();

        // initial shell input
        char *base_name = get_base_name(cwd);
        print_prompt(base_name);

        // read line from stdin
        tokens = read_parse_line();

        // continue if the entered command is empty
        if (tokens == NULL || tokens[0] == NULL)
        {
            free(tokens);
            continue;
        }


        // handle the built-in command: cd
        if (strcmp(tokens[0], "cd") == 0)
        {
            int args_num = 0;
            // if cd is called with 0 or 2+ arguments
            int i;
            for (i = 1; tokens[i] != NULL; i++)
                args_num++;

            if (args_num != 1)
                fprintf(stderr, "Error: invalid command\n");
            else
            {
                // change directory
                int dir_status = chdir(tokens[1]);
                // if failed
                if (dir_status == -1)
                    fprintf(stderr, "Error: invalid directory\n");
            }
            free(tokens);
            // skip the rest of the process
            continue;
        }


        // handle the built-in command: exit
        if (strcmp(tokens[0], "exit") == 0)
        {
            // exit cannot have any following tokens
            if (tokens[1] != NULL)
                fprintf(stderr, "Error: invalid command\n");
            else
            {
                // if there are suspended jobs
                free(tokens);
                // terminate the shell if there no suspended jobs + no invalid arguments
                exit(0);
            }
            free(tokens);
            continue;
        }

        // handle the built-in command: jobs
        if (strcmp(tokens[0], "jobs") == 0)
        {
            if (tokens[1] != NULL)
                fprintf(stderr, "Error: invalid command\n");
            else
            {
                int i;
                for (i = 0; i < job_cnt; i++)
                    printf("[%d] %s\n", job_list[i].index, job_list[i].command);
            }
            free(tokens);
            continue;
        }

        // handle the built-in command: fg
        if (strcmp(tokens[0], "fg") == 0)
        {
            if (tokens[1] == NULL)
                fprintf(stderr, "Error: invalid command\n");
            else
            {
                int job_index = atoi(tokens[1]);
                if (job_index <= 0 || job_index > job_cnt)
                    fprintf(stderr, "Error: invalid job\n");
                else
                {
                    pid_t pid = job_list[job_index - 1].pid;
                    remove_job(pid);

                    int continue_status = kill(pid, SIGCONT);
                    if (continue_status == -1)
                        perror("kill");
                    else
                    {
                        int status;
                        waitpid(pid, &status, WUNTRACED);

                        // if the process stopped again
                        if (WIFSTOPPED(status))
                            add_job(pid);
                    }
                }
            }
        }

        int cmd_num = 1, i;
        for (i = 0; tokens[i] != NULL; i++)
        {
            if (strcmp(tokens[i], "|") == 0)
                cmd_num++;
        }

        if (cmd_num > 1)
            handle_pipes(tokens, cmd_num);
        else
        {
            // start make fork of the program (wait for user entering command)
            pid = fork();

            if (pid < 0)
            {
                // if fork failed
                perror("fork");
                exit(1);
            }
            else if (pid == 0)
            {
                reset_signals();
                process_commands(tokens, 0, 1);
            }
            else
            {
                waitpid(pid, &status, 0);
                /**
                 * It migth be optional but I think this is pretty good so I added it
                 * @cite https://www.youtube.com/watch?v=DiNmwwQWl0g
                 */
                if (WIFEXITED(status))
                {
                    int status_code = WEXITSTATUS(status);
                    if (status_code != 0)
                        fprintf(stderr, "Error: error child status %d\n", status_code);
                }

                // if (WIFSTOPPED(status))
                //     add_job(pid);
                // else if (WIFEXITED(status) || WIFSIGNALED(status))
                //     remove_job(pid);
            }
        }
        free(tokens);
    }
    return 0;
}