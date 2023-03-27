#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char *argv[])
{
    if (argc == 2)
    {
        printf("Sleeping for %s seconds.\n", argv[1]);
        sleep(atoi(argv[1]));
    }
    else if (argc > 2)
    {
        printf("Too many arguments supplied.\n");
        return -1;
    }
    else
    {
        printf("One argument expected.\n");
        return -1;
    }
    return 0;
}
