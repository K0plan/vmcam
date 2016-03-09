#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <err.h>

#include "log.h"

char * str_realloc_copy(char ** dest, char * src) {
	size_t len;
        char * tmp = *dest;
        
        len = strlen(src);
	if ((*dest = realloc(*dest, len + 1)) == 0) {
		LOG(ERROR, "[VMCAM] Memory allocation error");
                free(tmp);
                *dest = NULL;
                return NULL;
	}
	strncpy(*dest, src, len + 1);
        return *dest;
}
