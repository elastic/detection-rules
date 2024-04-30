#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *combine_argv(int argc, char **argv, int start, int end)
{
    int total_size = 0;
    for (int i = start; i < end; i++)
    {
        total_size += strlen(argv[i]);
    }
    // Provides space for ' ' after each argument and a '\0' terminator.
    char *ret = malloc(total_size + end - start + 1);
    if (ret == NULL)
    {
        fprintf(stderr, "Error: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    int j = 0;
    for (int i = start; i < end; i++)
    {
        strcat(ret + j, argv[i]);
        j += strlen(argv[i]);
        ret[j++] = ' ';
    }
    ret[j - 1] = '\0';
    return ret;
}

void spawn_child_processes(int argc, char **argv)
{
    int start = 1;
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "childprocess") == 0)
        {
            char *command = combine_argv(argc, argv, start, i);
            printf("Spawning child process %s\n", command);
            if (system(command) == -1)
            {
                fprintf(stderr, "Error: failed to spawn child process\n");
                free(command);
                exit(EXIT_FAILURE);
            }
            free(command);
            start = i + 1;
        }
    }
    if (start < argc)
    {
        char *command = combine_argv(argc, argv, start, argc);
        printf("Spawning child process %s\n", command);
        if (system(command) == -1)
        {
            fprintf(stderr, "Error: failed to spawn child process\n");
            free(command);
            exit(EXIT_FAILURE);
        }
        free(command);
    }
}

void validate_input(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Error: invalid number of arguments\n");
        exit(EXIT_FAILURE);
    }

    else if (strcmp(argv[1], "childprocess") == 0 && argc < 3)
    {
        fprintf(stderr, "Error: invalid argument format. Expected childprocess <name of command>\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    validate_input(argc, argv);
    spawn_child_processes(argc, argv);
    for (int i = 0; i < argc; i++)
    {
        printf("argv[%2d]: %s\n", i, argv[i]);
    }
    system("/bin/bash");
    return 0;
}
