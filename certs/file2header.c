#include <stdio.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
	if (argc < 4) return 1;
	
	struct stat FileStat;
	
	if (stat(argv[1], &FileStat) != 0)
	{
		puts("Bad filename.");
		return 1;
	}
	
	FILE *Desc = fopen(argv[1], "rb");
	FILE *WDesc = fopen(argv[2], "wb");
	
	fprintf(WDesc, "#ifndef __%s_HEADER__\n#define __%s_HEADER__\nunsigned char %s_Data[%u] = { ", argv[3], argv[3], argv[3], (unsigned)FileStat.st_size);
	
	int Char = 0;
	int Count = 0;
	for (; (Char = getc(Desc)) != EOF; ++Count)
	{
		if (Count >= 15) 
		{
			fputs("\n\t", WDesc);
			Count = 0;
		}
		fprintf(WDesc, "0x%x, ", Char);
	}
	
	fputs(" };\n#endif\n", WDesc);
	
	fclose(WDesc);
	fclose(Desc);
	
	return 0;
}

	
	
	
