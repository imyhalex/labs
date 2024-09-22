#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>

#include "argmanip.h"

char **manipulate_args(int argc, const char *const *argv, int (*const manip)(int))
{
    /**
     * 1. copy argument list
     * 2. malloc each element in argumentlist
     * 3. apply function reference
     */
    char **arg_list = malloc((argc + 1) * sizeof(char *));
    
    // check if arg_list allocation fails
    if (!arg_list)
    {
        fprintf(stderr, "Allocation Failed\n");
        exit(1);
    }

    int i = 0;
    // 1
    while (i != argc)
    {
        // 2
        arg_list[i] = malloc(strlen(argv[i]) + 1);
        // if an element is null, notify user and not doing the conversion
        if (!arg_list[i])
        {
            fprintf(stderr, "An Element Allocation Failed. \n");
            // free all of the elements that have been allocated
            int j;
            for (j = 0; j < i; j++)
                free(arg_list[j]);
            // finally free whole array
            free(arg_list);
            exit(1);
        }

        // 3 
        const char *given = argv[i];
        char *convert = arg_list[i];
        // while *given is not null
        while (*given != 0)
        {
            *convert = manip((char) *given);
            
            // point to the next character position
            convert++;
            given++;
        }
        // fill in the last character null to each converted elements
        *convert = '\0';
        
        i++;
    }

    // Ensure the last pointer is NULL
    arg_list[argc] = NULL;
    return arg_list;
}


void free_copied_args(char **args, ...)
{
    va_list arg_lists;
    va_start(arg_lists, args);


    // create arg_list point to first element of input parameter
    char **arg_list = args;
    while (1)
    {
        // set up a break point
        if (arg_list == NULL) break;

        int i = 0;
        while (arg_list[i] != NULL)
            free(arg_list[i++]);
        free(arg_list);

        // move arg_list to the next pass-in parameter
        arg_list = va_arg(arg_lists, char**);
    }

    va_end(arg_lists);
}