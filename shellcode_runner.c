#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>

#define UNMAP(ptr, size)	do					\
				{					\
					if (NULL != (ptr))		\
					{				\
						munmap((ptr), (size));	\
						(ptr) = NULL;		\
					}				\
				}					\
				while (0)

#define FCLOSE(fp)		do					\
				{					\
					if (NULL != (fp))		\
					{				\
						fclose(fp);		\
						(fp) = NULL;		\
					}				\
				}					\
				while (0)

static void run_shellcode(char* buffer)
{
	int (*exeshell)() = (int (*)())buffer;
	(int)(*exeshell)();
}

int main(int argc, char** argv)
{
	FILE* fp = NULL;
	long fsize = 0;
	char* buffer = NULL;
	int (*exeshell)() = NULL;

	// Check arguments
	if (2 != argc)
	{
		printf("Invalid number of arguments: %d", argc);
		goto cleanup;
	}

	// Open the file for reading
	fp = fopen(argv[1], "rb");
	if (NULL == fp)
	{
		printf("Error opening file for reading: %s", argv[1]);
		goto cleanup;
	}

	// Get the file size
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// Allocate shellcode buffer
	buffer = mmap(NULL, fsize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (NULL == buffer)
	{
		printf("Error allocating RWX memory of size: %ld", fsize);
		goto cleanup;
	}

	// Read file and close it
	fread(buffer, fsize, 1, fp);
	FCLOSE(fp);

	// Run shellcode
	run_shellcode(buffer);

cleanup:

	// Free resources
	UNMAP(buffer, fsize);
	FCLOSE(fp);

	// Return result
	return 0;
}
