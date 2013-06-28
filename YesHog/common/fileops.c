/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

#ifdef _X86_64_

#include "common.h"
#include <stdio.h>
#include <stdlib.h>

#define FILE_NOT_FOUND -1
#define NOMEM          -2
#define READ_ERROR     -3

BYTE* get_file_data(char* filename, SWORD* len)
{
    FILE * pFile;
    long lSize;
    BYTE* buffer;
    size_t result;

    pFile = fopen ( filename , "rb" );
    if (pFile==NULL)
    {
        fputs ("File error",stderr);
        *len = FILE_NOT_FOUND;
        return NULL;
    }

    /* how big art thou */

    fseek (pFile , 0 , SEEK_END);
    lSize = ftell (pFile);
    rewind (pFile);
    *len = lSize;
    /* allocate sufficient space */
    buffer = (BYTE*)calloc (lSize, sizeof(BYTE));

    if (buffer == NULL)
    {
        fputs ("Memory error",stderr);
        *len = NOMEM;
        return NULL;
    }

    /* copy */
    result = fread (buffer,1,lSize,pFile);
    if (result != lSize)
    {
        fputs ("Reading error",stderr);
        fclose(pFile);
        free(buffer);
        *len = READ_ERROR;
        return NULL;
    }
    /* file gobbled up */

    fclose (pFile);
    return buffer;
}

#endif
