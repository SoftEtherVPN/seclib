#include <stdio.h>
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

	Print("%s\n", _SS("PRODUCT_NAME_ELOGMGR"));

	FreeCedar();
	FreeMayaqua();
	return 0;
}

OPTIONS_LINK_DEBUG=-g -fsigned-char -m64 -lm -ldl -lrt -lpthread -lssl -lcrypto -lreadline -lncurses -lz
