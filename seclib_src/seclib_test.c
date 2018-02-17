#include <stdio.h>
#include <seclib.h>

int main(int argc, char *argv[])
{
	MayaquaMinimalMode();
	InitMayaqua(false, true, argc, argv);
	InitCedar();

	Print("Hello World\n");

	{
		UNI_TOKEN_LIST* w = EnumDirWithSubDirsW(L"c:\\sec\\vpn4");
		
		UINT i;

		for (i = 0;i < w->NumTokens;i++)
		{
			Print("%u %S\n", i, w->Token[i]);
		}

		UniFreeToken(w);
	}

	FreeCedar();
	FreeMayaqua();
	return 0;
}
