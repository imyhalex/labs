#include <stdio.h>
#include <unistd.h>

int main()
{
    int i;
    for (i = 0;; i++)
    {
        printf("%d\n", i);
        sleep(1);
    }
}