#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <libgen.h>

// Function to create directories for the given path
int create_directories(char *path) {
    char *dir_path = dirname(strdup(path));  // Get directory name
    char *p = strtok(dir_path, "/");  // Tokenize path
    char current_path[1024] = {0};  // Store the path being created

    // Iterate through path parts and create directories
    while(p != NULL) {
        strcat(current_path, "/");
        strcat(current_path, p);
        mkdir(current_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);  // Create directory with 755 permissions
        p = strtok(NULL, "/");
    }
    free(dir_path);  // Free duplicated string
    return 0;
}

int main(int argc, char *argv[]) {
    // Check if filename is provided
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <filepath>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Attempt to create the directories for the file
    create_directories(argv[1]);

    // Attempt to create the file
    FILE *file = fopen(argv[1], "w");
    if(file == NULL) {
        perror("Error creating file");
        exit(EXIT_FAILURE);
    }

    // Close the file and exit
    fclose(file);
    printf("File '%s' created successfully\n", argv[1]);
    exit(EXIT_SUCCESS);
}
