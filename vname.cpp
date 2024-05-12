#include <cstdint>

const char* const prefixes[] = {
	"Backdoor","TrojanDownloader","TrojanDropper",
	"Spammer", "DDoS", "DoS", "Joke",
	"PWS", "Worm", "Flooder", "Trojan",
	"Virus","Constructor","Nuker",
	"Spoofer","Tool", "AolPWS","TrojanSpy",
	"VirTool", "Exploit","TrojanClicker",
	"HackTool","TrojanProxy", "Tool",
	"Sniffer", "TrojanNotifier", "Adware",
	"Spyware", "Dialer"
};

const char* const platforms[] = {
	"Win32","Win95","WinNT", "DOS",
	 "Linux","Win16","MacOS", "BAT",
	 "VBS","JS", "Java","IRC",
	 "W97M", "X97M", "PP97M", "FreeBSD",
	  "OS2", "Win98","Win2K", "AutoIt",
	  "WinCE", "SymbOS", "WinHLP", "MSIL",
	   "INF", "SunOS", "Netware","DOS32",
		"MacOS_X","AppleScript"
};

const char* const suffixes[] = {
	".dr", ".intd", ".remnants", "@mm",
	 ".dam", ".plugin", ".pak", ".gen",
	 ".worm", ".dll", "@m", ".ldr",".kit"
};

//Î´ÓÅ»¯
uint64_t   UnpackVirusName(char* cname, char* uname)
{
	char* v2; // r8
	char* v3; // r9
	__int64 v4; // rcx
	char v5; // al
	bool v6; // zf
	unsigned __int8 v8; // r10
	unsigned int v9; // r9d
	__int64 v10; // r11
	char* v11; // r10
	__int64 v12; // r11
	char v13; // al
	__int64 v14; // r10
	char* v15; // r11
	__int64 v16; // r10
	char v17; // al
	char* v18; // rbx
	char* v19; // rdx
	__int64 v20; // rcx
	char v21; // al
	__int64 v22; // r9
	__int64 v23; // rcx
	char v24; // al

	v2 = uname;
	if (!cname || !uname || cname == uname)
		return 0xFFFFFFFFi64;
	*uname = 0;
	if (*cname >= 0 || (v8 = cname[1]) == 0)
	{
		v3 = uname + 64;
		if (uname < uname + 64)
		{
			v4 = cname - uname;
			do
			{
				v5 = v2[v4];
				*v2 = v5;
				if (!v5)
					break;
				++v2;
			} while (v2 < v3);
		}
		v6 = v2 == v3;
		goto LABEL_10;
	}
	v9 = v8 | (unsigned __int16)((unsigned __int8)*cname << 8);
	*uname = 0;
	v10 = (v9 >> 10) & 0x1F;
	if ((unsigned int)(v10 - 1) <= 0x1C)
	{
		v11 = uname + 64;
		if (uname < uname + 64)
		{
			v12 = (uint64_t)prefixes[v10 - 1] - (uint64_t)uname;
			do
			{
				v13 = v2[v12];
				*v2 = v13;
				if (!v13)
					break;
				++v2;
			} while (v2 < v11);
		}
		if (v2 < v11)
			*v2++ = 58;
	}
	v14 = (v9 >> 5) & 0x1F;
	if ((unsigned int)(v14 - 1) <= 0x1D)
	{
		v15 = uname + 64;
		if (v2 < uname + 64)
		{
			v16 = (uint64_t)platforms[v14 - 1] - (uint64_t)v2;
			do
			{
				v17 = v2[v16];
				v18 = v2;
				*v2 = v17;
				if (!v17)
					break;
				++v2;
			} while (v2 < v15);
			v2 = v18 + 1;
			if (!v17)
				v2 = v18;
			if (v2 < v15)
				*v2++ = 47;
		}
	}
	v19 = uname + 64;
	if (v2 < v19)
	{
		v20 = cname - v2;
		do
		{
			v21 = v2[v20 + 2];
			*v2 = v21;
			if (!v21)
				break;
			++v2;
		} while (v2 < v19);
	}
	v22 = (v9 >> 1) & 0xF;
	if ((unsigned int)(v22 - 1) <= 0xC)
	{
		v6 = v2 == v19;
		if (v2 >= v19)
			goto LABEL_10;
		v23 = (uint64_t)suffixes[v22 - 1] - (uint64_t)v2;
		do
		{
			v24 = v2[v23];
			*v2 = v24;
			if (!v24)
				break;
			++v2;
		} while (v2 < v19);
	}
	v6 = v2 == v19;
LABEL_10:
	if (v6)
		*(v2 - 1) = 0;
	return 0i64;
}