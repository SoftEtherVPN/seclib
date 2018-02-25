#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <locale.h>
#include <time.h>
#include <errno.h>

#include <seclib.h>

#include "dev_temp.h"

int main(int argc, char *argv[])
{
	//MayaquaMinimalMode();
	InitMayaqua(false, true, argc, argv);
	InitCedar();

	Print("Hello World\n");

	DevTempTest();

	FreeCedar();
	FreeMayaqua();
	return 0;
}

