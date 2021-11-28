#include "tcp-block.h"

int main(int argc, char* argv[])
{
    if(argc!=3)
    {
        usage();
        return -1;
    }

    watch(argv[1],argv[2]);

    return 0;
}