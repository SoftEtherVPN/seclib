#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <locale.h>
#include <time.h>
#include <errno.h>

#include <seclib.h>

int main(int argc, char *argv[])
{
	//MayaquaMinimalMode();
	InitMayaqua(false, true, argc, argv);
	InitCedar();

	Print("Hello World\n");

	if (false)
	{
		char *src_dir = "@hamcore";
		char *dst_filename = "c:\\tmp\\test.dat";

		Print("Src Dir: '%s'\n", src_dir);
		Print("Dest Filename: '%s'\n", dst_filename);

		Print("\nProcessing...\n");

		BuildHamcore(dst_filename, src_dir, true);

		Print("\nDone.\n");
	}

	FreeCedar();
	FreeMayaqua();
	return 0;
}

