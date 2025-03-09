//                    GNU GENERAL PUBLIC LICENSE
//                       Version 3, 29 June 2007
//
// Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
// Everyone is permitted to copy and distribute verbatim copies
// of this license document, but changing it is not allowed.
//
// For more information, please check LICENSE file.

#define APIXEXPORT __declspec(dllexport)
#define APIXIMPORT __declspec(dllimport)

#ifdef APIXDLLFILE
#define APIXAPI APIXEXPORT
#else
#define APIXAPI APIXIMPORT
#endif

#ifndef APIXCONFIG_H
#define APIXCONFIG_H

#include <windows.h>
#include <string>
#include <vector>
#include "../Common/CryptConfig.h"

/* 错误消息（GetLastError查看） */
#define APE_DEBUG_MESSAGE		0x21ffffff
#define APE_BAD_KEY				0x21000001
#define APE_PACK_FAILED			0x21000002
#define APE_UNPACK_FAILED		0x21000003
#define APE_LOAD_FILE_FAILED	0x21000004
#define APE_ENCODE_FAILED		0x21000005
#define APE_DECODE_FAILED		0x21000006
#define APE_BAD_APIXFILE		0x21000007
#define APE_BAD_FILE_WITHIN		0x21000008
#define APE_FILE_NOT_FOUND		0x21000009

#define APS_FAIL				0x00000000
#define APS_SUCCESS				0x00000001

#define FAIL(i) {SetLastError((i)); return APS_FAIL; }
#define FAIL_J(i) {SetLastError((i)); goto EXIT; }

struct FILECONFIG {
	// 导入时只需要设置lpPath
	std::string lpPath;
	std::string lpName;
	ULONG bytes;
	FILECONFIG() : bytes(0) {}
	FILECONFIG(std::string iPath) : lpPath(iPath), bytes(0) {}
};
struct CRACKCONFIG {
	std::string lpDisplayName;
	std::string lpBefoCmdLine;
	std::string lpAfteCmdLine;
	CRACKCONFIG() {}
	CRACKCONFIG(std::string iDName, std::string iBCLine, std::string iACLine)
		: lpDisplayName(iDName)
		, lpBefoCmdLine(iBCLine)
		, lpAfteCmdLine(iACLine)
	{
	}
};
struct INSTALLCONFIG {
	std::string lpDisplayName;
	std::string lpBefoCmdLine;
	std::string lpAfteCmdLine;
	std::string lpWarning;
	INT type;
	std::vector <CRACKCONFIG> Crack;
	INSTALLCONFIG() : type(0) {}
	INSTALLCONFIG(std::string iDName, std::string iBCLine, std::string iACLine, std::string iWarning) 
		: lpDisplayName(iDName)
		, lpBefoCmdLine(iBCLine)
		, lpAfteCmdLine(iACLine)
		, lpWarning(iWarning)
		, type(0)
	{
		Crack.clear();
	}
};

struct APIXCONFIG {
	std::string lpName;
	std::string lpResFileName;
	std::string lpInstruction;
	std::string lpOfficialWeb;
	std::string lpDownloadWeb;
	std::vector <INSTALLCONFIG> Inst;
	std::vector <FILECONFIG> File;
	AESKEY FileKey;
	// 构造
	APIXCONFIG() :
		lpName(""),
		lpResFileName(""),
		lpInstruction(""),
		lpOfficialWeb(""),
		lpDownloadWeb("")
	{
		Inst.clear();
		File.clear();
	}
};

#ifndef APIXDLLFILE
BOOL APIXIMPORT WriteApix(APIXCONFIG Config, std::string lpPath);
BOOL APIXIMPORT ReadApix(APIXCONFIG* lpConfig, std::string lpPath);
BOOL APIXIMPORT ExtractFile(std::string lpPath, APIXCONFIG Config, std::string lpName, std::string lpExtPath);
#endif

#endif
