//                    GNU GENERAL PUBLIC LICENSE
//                       Version 3, 29 June 2007
//
// Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
// Everyone is permitted to copy and distribute verbatim copies
// of this license document, but changing it is not allowed.
//
// For more information, please check LICENSE file.

#define APIXDLLFILE

#include <string>
#include <ctime>
#include <vector>
#include <iostream>
#include "../Common/ApixConfig.h"
#include "MyHeaders/FileBinIO.h"
#include "MyHeaders/Convert.h"

#define RND(l, r) ((rand() % ((r) - (l) + 1)) + (l));
#define NXT512(x) (((x) - 1) / 512 + 1)

std::string GetFileName(std::string lpPath) {
    size_t lastBackslashIndex = lpPath.find_last_of("\\");
    return lpPath.substr(lastBackslashIndex + 1);
}
DWORD NextSector(DWORD dwOrig) {
    DWORD NextSec = (dwOrig / 512) * 512;
    if (NextSec < dwOrig) NextSec += 512;
    return NextSec;
}

BOOL AddStrData(std::string lpPath, std::string Data, ULONG* ptr, DWORD* dwBytesWritten = NULL, BYTE bEncodeKey = 0) {
    if (Data.size() >= 512 || ptr == NULL) return FALSE;
    bEncodeKey ^= 0x3A;
    UCHAR uch[513] = { 0 };
    CH2UCH(Data.c_str(), uch, 512);
    for (UINT indx = 0; indx < Data.size(); indx++) uch[indx] ^= bEncodeKey;
    if (FBWriteFile(lpPath.c_str(), uch, dwBytesWritten, *ptr, Data.size()) != FB_SUCCESS) return FALSE;
    *ptr += Data.size();
    return TRUE;
}
BOOL AddNumData(std::string lpPath, ULONGLONG Data, ULONG* ptr, INT iBytes = 8, DWORD* dwBytesWritten = NULL, BYTE bEncodeKey = 0) {
    if (iBytes > 8 || ptr == NULL) return FALSE;
    bEncodeKey ^= 0x3A;
    BYTE byte[16] = { 0 };
    for (INT indx = iBytes - 1; indx >= 0; indx--) {
        byte[indx] = (Data & 0xff) ^ bEncodeKey;
        Data >>= 8;
    }
    if (FBWriteFile(lpPath.c_str(), byte, dwBytesWritten, *ptr, iBytes) != FB_SUCCESS) return FALSE;
    *ptr += iBytes;
    return TRUE;
}
BOOL ReadStrData(std::string lpPath, std::string* source, ULONG* ptr, size_t size, DWORD* dwBytesRead = NULL, BYTE bEncodeKey = 0) {
    if (size >= 512 || ptr == NULL) return FALSE;
    bEncodeKey ^= 0x3A;
    UCHAR uch[513] = { 0 };
    CHAR buffer[513] = { 0 };
    if (FBReadFile(lpPath.c_str(), uch, dwBytesRead, *ptr, size) != FB_SUCCESS) return FALSE;
    for (UINT indx = 0; indx < size; indx++) uch[indx] ^= bEncodeKey;
    UCH2CH(uch, buffer, 512);
    *source = "";
    for (UINT indx = 0; indx < size; indx++) (*source) += buffer[indx];
    *ptr += size;
    return TRUE;
}
BOOL ReadNumData(std::string lpPath, ULONGLONG* source, ULONG* ptr, INT iBytes = 8, DWORD* dwBytesRead = NULL, BYTE bEncodeKey = 0) {
    if (iBytes > 8 || ptr == NULL) return FALSE;
    bEncodeKey ^= 0x3A;
    BYTE byte[16] = { 0 };
    if (FBReadFile(lpPath.c_str(), byte, dwBytesRead, *ptr, iBytes) != FB_SUCCESS) return FALSE;
    *source = 0;
    for (INT indx = 0; indx < iBytes; indx++) {
        (*source) <<= 8;
        (*source) |= (byte[indx] ^ bEncodeKey);
    }
    *ptr += iBytes;
    return TRUE;
}

BOOL PackConfig(APIXCONFIG* Config, std::string lpPath, ULONG* ptr, DWORD* Bytes = NULL, BYTE key = 0) {
    if (ptr == NULL) return FALSE;
    DWORD bytes = 0, allbytes = 0;
    BOOL bRes = TRUE;
    
    bRes &= AddNumData(lpPath, Config->lpName.size(), ptr, 4, &bytes, key);                          allbytes += bytes;
    bRes &= AddStrData(lpPath, Config->lpName, ptr, &bytes, key);                                    allbytes += bytes;
    
    bRes &= AddNumData(lpPath, Config->lpResFileName.size(), ptr, 4, &bytes, key);                   allbytes += bytes;
    bRes &= AddStrData(lpPath, Config->lpResFileName, ptr, &bytes, key);                             allbytes += bytes;
    
    bRes &= AddNumData(lpPath, Config->lpInstruction.size(), ptr, 4, &bytes, key);                   allbytes += bytes;
    bRes &= AddStrData(lpPath, Config->lpInstruction, ptr, &bytes, key);                             allbytes += bytes;
    
    bRes &= AddNumData(lpPath, Config->lpOfficialWeb.size(), ptr, 4, &bytes, key);                   allbytes += bytes;
    bRes &= AddStrData(lpPath, Config->lpOfficialWeb, ptr, &bytes, key);                             allbytes += bytes;
    
    bRes &= AddNumData(lpPath, Config->lpDownloadWeb.size(), ptr, 4, &bytes, key);                   allbytes += bytes;
    bRes &= AddStrData(lpPath, Config->lpDownloadWeb, ptr, &bytes, key);                             allbytes += bytes;

    bRes &= AddNumData(lpPath, Config->Inst.size(), ptr, 4, &bytes, key);
    for (UINT indx = 0; indx < Config->Inst.size(); indx++) {
        bRes &= AddNumData(lpPath, Config->Inst[indx].lpDisplayName.size(), ptr, 4, &bytes, key);    allbytes += bytes;
        bRes &= AddStrData(lpPath, Config->Inst[indx].lpDisplayName, ptr, &bytes, key);              allbytes += bytes;
        bRes &= AddNumData(lpPath, Config->Inst[indx].lpBefoCmdLine.size(), ptr, 4, &bytes, key);    allbytes += bytes;
        bRes &= AddStrData(lpPath, Config->Inst[indx].lpBefoCmdLine, ptr, &bytes, key);              allbytes += bytes;
        bRes &= AddNumData(lpPath, Config->Inst[indx].lpAfteCmdLine.size(), ptr, 4, &bytes, key);    allbytes += bytes;
        bRes &= AddStrData(lpPath, Config->Inst[indx].lpAfteCmdLine, ptr, &bytes, key);              allbytes += bytes;
        bRes &= AddNumData(lpPath, Config->Inst[indx].lpWarning.size(), ptr, 4, &bytes, key);        allbytes += bytes;
        bRes &= AddStrData(lpPath, Config->Inst[indx].lpWarning, ptr, &bytes, key);                  allbytes += bytes;

        bRes &= AddNumData(lpPath, Config->Inst[indx].type, ptr, 4, &bytes, key);                                   allbytes += bytes;
        bRes &= AddNumData(lpPath, Config->Inst[indx].Crack.size(), ptr, 4, &bytes, key);                           allbytes += bytes;
        for (UINT indxc = 0; indxc < Config->Inst[indx].Crack.size(); indxc++) {
            bRes &= AddNumData(lpPath, Config->Inst[indx].Crack[indxc].lpDisplayName.size(), ptr, 4, &bytes, key);   allbytes += bytes;
            bRes &= AddStrData(lpPath, Config->Inst[indx].Crack[indxc].lpDisplayName, ptr, &bytes, key);             allbytes += bytes;
            bRes &= AddNumData(lpPath, Config->Inst[indx].Crack[indxc].lpBefoCmdLine.size(), ptr, 4, &bytes, key);   allbytes += bytes;
            bRes &= AddStrData(lpPath, Config->Inst[indx].Crack[indxc].lpBefoCmdLine, ptr, &bytes, key);             allbytes += bytes;
            bRes &= AddNumData(lpPath, Config->Inst[indx].Crack[indxc].lpAfteCmdLine.size(), ptr, 4, &bytes, key);   allbytes += bytes;
            bRes &= AddStrData(lpPath, Config->Inst[indx].Crack[indxc].lpAfteCmdLine, ptr, &bytes, key);             allbytes += bytes;
        }
    }
    bRes &= AddNumData(lpPath, Config->File.size(), ptr, 4, &bytes, key);
    for (UINT indx = 0; indx < Config->File.size(); indx++) {
        std::string name = GetFileName(Config->File[indx].lpPath);
        Config->File[indx].lpName = name;
        Config->File[indx].bytes = FBLIntToUl(FBGetFileSize(Config->File[indx].lpPath.c_str()));
        bRes &= AddNumData(lpPath, Config->File[indx].bytes, ptr, 8, &bytes, key);                  allbytes += bytes;
        bRes &= AddNumData(lpPath, name.size(), ptr, 4, &bytes, key);                               allbytes += bytes;
        bRes &= AddStrData(lpPath, name, ptr, &bytes, key);                                         allbytes += bytes;
    }
    if (Bytes != NULL) *Bytes = allbytes;
    return bRes;
}
BOOL UnpackConfig(APIXCONFIG* Config, std::string lpPath, ULONG* ptr, DWORD* Bytes = NULL, BYTE key = 0) {
    if (Config == NULL || ptr == NULL) return FALSE;
    DWORD bytes = 0, allbytes = 0;
    ULONGLONG numd;
    BOOL bRes = TRUE;

    bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                        allbytes += bytes;
    bRes &= ReadStrData(lpPath, &(Config->lpName), ptr, (ULONG)numd, &bytes, key);                  allbytes += bytes;

    bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                        allbytes += bytes;
    bRes &= ReadStrData(lpPath, &(Config->lpResFileName), ptr, (ULONG)numd, &bytes, key);           allbytes += bytes;

    bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                        allbytes += bytes;
    bRes &= ReadStrData(lpPath, &(Config->lpInstruction), ptr, (ULONG)numd, &bytes, key);           allbytes += bytes;

    bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                        allbytes += bytes;
    bRes &= ReadStrData(lpPath, &(Config->lpOfficialWeb), ptr, (ULONG)numd, &bytes, key);           allbytes += bytes;

    bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                        allbytes += bytes;
    bRes &= ReadStrData(lpPath, &(Config->lpDownloadWeb), ptr, (ULONG)numd, &bytes, key);           allbytes += bytes;

    bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                        allbytes += bytes;
    UINT inum = (UINT)numd;
    for (UINT indx = 0; indx < inum; indx++) {
        INSTALLCONFIG icfg;
        bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                    allbytes += bytes;
        bRes &= ReadStrData(lpPath, &(icfg.lpDisplayName), ptr, (ULONG)numd, &bytes, key);          allbytes += bytes;
        bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                    allbytes += bytes;
        bRes &= ReadStrData(lpPath, &(icfg.lpBefoCmdLine), ptr, (ULONG)numd, &bytes, key);          allbytes += bytes;
        bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                    allbytes += bytes;
        bRes &= ReadStrData(lpPath, &(icfg.lpAfteCmdLine), ptr, (ULONG)numd, &bytes, key);          allbytes += bytes;
        bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                    allbytes += bytes;
        bRes &= ReadStrData(lpPath, &(icfg.lpWarning), ptr, (ULONG)numd, &bytes, key);              allbytes += bytes;

        bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                        allbytes += bytes; icfg.type = (INT)numd;
        bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                        allbytes += bytes;
        UINT cnum = (UINT)numd;
        for (UINT indxc = 0; indxc < cnum; indxc++) {
            CRACKCONFIG ccfg;
            bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                    allbytes += bytes;
            bRes &= ReadStrData(lpPath, &ccfg.lpDisplayName, ptr, (ULONG)numd, &bytes, key);            allbytes += bytes;
            bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                    allbytes += bytes;
            bRes &= ReadStrData(lpPath, &ccfg.lpBefoCmdLine, ptr, (ULONG)numd, &bytes, key);            allbytes += bytes;
            bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                    allbytes += bytes;
            bRes &= ReadStrData(lpPath, &ccfg.lpAfteCmdLine, ptr, (ULONG)numd, &bytes, key);            allbytes += bytes;
            icfg.Crack.push_back(ccfg);
        }
        Config->Inst.push_back(icfg);
    }
    bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                        allbytes += bytes;
    UINT fnum = (UINT)numd;
    for (UINT indx = 0; indx < fnum; indx++) {
        FILECONFIG fcfg;
        bRes &= ReadNumData(lpPath, &numd, ptr, 8, &bytes, key);                                    allbytes += bytes; fcfg.bytes = (ULONG)numd;
        bRes &= ReadNumData(lpPath, &numd, ptr, 4, &bytes, key);                                    allbytes += bytes;
        bRes &= ReadStrData(lpPath, &(fcfg.lpName), ptr, (ULONG)numd, &bytes, key);                 allbytes += bytes;
        Config->File.push_back(fcfg);
    }
    if (Bytes != NULL) *Bytes = allbytes;
    return bRes;
}

// 读取Apix文件
BOOL APIXAPI ReadApix(APIXCONFIG* lpConfig, std::string lpPath) {
    // 读取元数据
    std::string header = "";
    DWORD wbytes = 0;
    ULONG ptr = 7, fileNum = 0, mftStart = 0;
    BYTE xorKey = 0;
    ULONGLONG ullTmp = 0;
    ReadNumData(lpPath, &ullTmp, &ptr, 1, NULL, 0x3A); // XOR密钥 07
    xorKey = (BYTE)ullTmp;
    ReadNumData(lpPath, &ullTmp, &ptr, 8, NULL, xorKey); // 文件表起始字节数 08-0F
    mftStart = (ULONG)ullTmp;
    ptr = 0;
    ReadStrData(lpPath, &header, &ptr, 3, NULL, 0x3A); // 文件头 00-06
    if (header != "App") FAIL(APE_BAD_APIXFILE);
    ReadStrData(lpPath, &header, &ptr, 4, NULL, xorKey);
    if (header != "Inst") FAIL(APE_BAD_APIXFILE);

    const BYTE iv[AES_BLOCK_SIZE] = { 0x1f, 0xe6, 0x3b, 0x69, 0x0a, 0x44, 0x26, 0xea, 0x3d, 0x97, 0x9f, 0x20, 0x01, 0xc0, 0x11, 0xcf };
    
    AESKEY ReadKey;
    ptr = 16;
    ReadNumData(lpPath, &ullTmp, &ptr, 4, NULL, xorKey); // AES密钥长度 10-13
    ReadKey.len = (ULONG)ullTmp;
    ReadNumData(lpPath, &ullTmp, &ptr, 4, NULL, xorKey); // 文件总个数 14-17
    fileNum = (ULONG)ullTmp;
    ReadKey.key = (BYTE*)VirtualAlloc(NULL, ReadKey.len + 128, MEM_COMMIT, PAGE_READWRITE);
    FBReadFile(lpPath.c_str(), ReadKey.key, NULL, 24, ReadKey.len); // AES密钥 18-*
    for (UINT indx = 0; indx < ReadKey.len; indx++) ReadKey.key[indx] ^= (xorKey ^ 0x4C);
    ptr = 512;
    if (!UnpackConfig(lpConfig, lpPath, &ptr, &wbytes, xorKey)) FAIL(APE_UNPACK_FAILED); // 主要信息 200-*

    return APS_SUCCESS;
}
// 写入Apix文件
BOOL APIXAPI WriteApix(APIXCONFIG Config, std::string lpPath) {
    DWORD fileAttributes = GetFileAttributesA(lpPath.c_str());
    if (fileAttributes != INVALID_FILE_ATTRIBUTES) DeleteFileA(lpPath.c_str());

    // 写入元数据
    BYTE xorKey = RND(0, 255);
    while (xorKey == 0x3A || xorKey == 0x00) xorKey = RND(0, 255); // 防止巧合直接看到明文
    //BYTE xorKey = 0x3A; // 调试用，显示明文

    DWORD wbytes = 0;
    ULONG ptr = 0;
    const BYTE iv[AES_BLOCK_SIZE] = { 0x1f, 0xe6, 0x3b, 0x69, 0x0a, 0x44, 0x26, 0xea, 0x3d, 0x97, 0x9f, 0x20, 0x01, 0xc0, 0x11, 0xcf };

    AddStrData(lpPath, "App", &ptr, NULL, 0x3A); // 文件头 00-06
    AddStrData(lpPath, "Inst", &ptr, NULL, xorKey);
    AddNumData(lpPath, xorKey, &ptr, 1, NULL, 0x3A); // XOR密钥 07
    if (!AESCreateRandomKey(&Config.FileKey)) FAIL(APE_BAD_KEY);
    AESKEY WriteKey(Config.FileKey);
    ptr = 16;
    AddNumData(lpPath, WriteKey.len, &ptr, 4, NULL, xorKey); // AES密钥长度 10-13
    AddNumData(lpPath, Config.File.size(), &ptr, 4, NULL, xorKey); // 文件总个数 14-17
    for (UINT indx = 0; indx < WriteKey.len; indx++) WriteKey.key[indx] ^= (xorKey ^ 0x4C);
    FBWriteFile(lpPath.c_str(), WriteKey.key, NULL, 24, WriteKey.len); // AES密钥 18-*
    ptr = 512;
    if (!PackConfig(&Config, lpPath, &ptr, &wbytes, xorKey)) FAIL(APE_PACK_FAILED); // 主要信息 200-*
    DWORD NextSec = NextSector(ptr);
    ptr = 8;
    AddNumData(lpPath, NextSec, &ptr, 8, NULL, xorKey); // 文件表起始字节数 08-0F

    // 写入文件内容
    ptr = NextSec;
    for (UINT indx = 0; indx < Config.File.size(); indx++) {
        UINT FileSize = (UINT)Config.File[indx].bytes;
        UINT BufferSize = FileSize + 128;
        PBYTE pBuffer = (PBYTE)VirtualAlloc(NULL, BufferSize, MEM_COMMIT, PAGE_READWRITE);
        if (!pBuffer) FAIL(APE_LOAD_FILE_FAILED);
        ZeroMemory(pBuffer, BufferSize);
        DWORD rbytes = 0, wbytes = 0;
        if (FBReadFile(Config.File[indx].lpPath.c_str(), pBuffer, &rbytes, 0) != FB_SUCCESS) {
            VirtualFree(pBuffer, 0, MEM_RELEASE);
            FAIL(APE_ENCODE_FAILED);
        }
        if (!AESEncryptData(pBuffer, &rbytes, BufferSize, Config.FileKey, iv)) {
            VirtualFree(pBuffer, 0, MEM_RELEASE);
            FAIL(APE_ENCODE_FAILED);
        }
        AddNumData(lpPath, indx, &ptr, 4, NULL, xorKey); // 文件索引 00-03
        AddNumData(lpPath, FileSize, &ptr, 4, NULL, xorKey); // 文件实际大小 04-07
        AddNumData(lpPath, rbytes, &ptr, 8, NULL, xorKey); // 文件加密后大小 08-0F
        ULONG ptrNextFile = ptr;
        ptr += 8;
        if (FBWriteFile(lpPath.c_str(), pBuffer, &wbytes, ptr, rbytes) != FB_SUCCESS) { // 文件加密后数据 18-*
            VirtualFree(pBuffer, 0, MEM_RELEASE);
            FAIL(APE_ENCODE_FAILED);
        }
        ULONG NextFile = NextSector(ptr + rbytes);
        ptr = ptrNextFile;
        if (indx != Config.File.size() - 1) AddNumData(lpPath, NextFile, &ptr, 8, NULL, xorKey); // 下一个文件头字节位置 10-17
        else AddNumData(lpPath, 0xffffffffffffffff, &ptr, 8, NULL, xorKey);
        ptr = NextFile;

        VirtualFree(pBuffer, 0, MEM_RELEASE);
    }
    return APS_SUCCESS;
}
// 释放Apix文件的资源
BOOL APIXAPI ExtractFile(std::string lpPath, APIXCONFIG Config, std::string lpName, std::string lpExtPath) {
    std::string header = "";
    ULONG ptr = 7, fileNum = 0, mftStart = 0;
    ULONG FileSizeae = 0, FileSize = 0;
    BYTE xorKey = 0;
    ULONGLONG ullTmp = 0;
    UINT FileIndx = UINT_MAX;
    ReadNumData(lpPath, &ullTmp, &ptr, 1, NULL, 0x3A); // XOR密钥 07
    xorKey = (BYTE)ullTmp;
    ReadNumData(lpPath, &ullTmp, &ptr, 8, NULL, xorKey); // 文件表起始字节数 08-0F
    mftStart = (ULONG)ullTmp;
    ptr = 0;
    ReadStrData(lpPath, &header, &ptr, 3, NULL, 0x3A); // 文件头 00-06
    if (header != "App") FAIL(APE_BAD_APIXFILE);
    ReadStrData(lpPath, &header, &ptr, 4, NULL, xorKey);
    if (header != "Inst") FAIL(APE_BAD_APIXFILE);

    const BYTE iv[AES_BLOCK_SIZE] = { 0x1f, 0xe6, 0x3b, 0x69, 0x0a, 0x44, 0x26, 0xea, 0x3d, 0x97, 0x9f, 0x20, 0x01, 0xc0, 0x11, 0xcf };

    AESKEY ReadKey;
    ptr = 16;
    ReadNumData(lpPath, &ullTmp, &ptr, 4, NULL, xorKey); // AES密钥长度 10-13
    ReadKey.len = (ULONG)ullTmp;
    ReadNumData(lpPath, &ullTmp, &ptr, 4, NULL, xorKey); // 文件总个数 14-17
    fileNum = (ULONG)ullTmp;
    ReadKey.key = (BYTE*)VirtualAlloc(NULL, ReadKey.len + 128, MEM_COMMIT, PAGE_READWRITE);
    FBReadFile(lpPath.c_str(), ReadKey.key, NULL, 24, ReadKey.len); // AES密钥 18-*
    for (UINT indx = 0; indx < ReadKey.len; indx++) ReadKey.key[indx] ^= (xorKey ^ 0x4C);

    // 读取文件内容
    ptr = mftStart;
    for (UINT indx = 0; indx < fileNum; indx++) {
        UINT index = 0;
        ULONG Size = 0, rBytes = 0, Sizeae = 0, Next = 0;
        ReadNumData(lpPath, &ullTmp, &ptr, 4, NULL, xorKey); // 文件索引 00-03
        index = (UINT)ullTmp;
        ReadNumData(lpPath, &ullTmp, &ptr, 4, NULL, xorKey); // 文件实际大小 04-07
        Size = (ULONG)ullTmp;
        ReadNumData(lpPath, &ullTmp, &ptr, 8, NULL, xorKey); // 文件加密后大小 08-0F
        Sizeae = (ULONG)ullTmp;
        ReadNumData(lpPath, &ullTmp, &ptr, 8, NULL, xorKey); // 下一个文件头字节位置 10-17
        Next = (ULONG)ullTmp;
        if (index != indx) FAIL(APE_BAD_FILE_WITHIN);
        if (Config.File[indx].lpName != lpName) {
            if (Next != ULONG_MAX) ptr = Next;
            else FAIL(APE_FILE_NOT_FOUND);
        }
        else {
            FileIndx = indx;
            FileSizeae = Sizeae;
            FileSize = Size;
            break;
        }
    }
    UINT BufferSize = FileSizeae + 128;

    PBYTE pBuffer = (PBYTE)VirtualAlloc(NULL, BufferSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pBuffer) FAIL(APE_LOAD_FILE_FAILED);
    ZeroMemory(pBuffer, BufferSize);
    DWORD rbytes = 0, wbytes = 0;
    if (FBReadFile(lpPath.c_str(), pBuffer, &rbytes, ptr, FileSizeae) != FB_SUCCESS) {
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        FAIL(APE_DECODE_FAILED);
    }
    if (!AESDecryptData(pBuffer, &rbytes, ReadKey, iv)) {
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        FAIL(APE_DECODE_FAILED);
    }
    DWORD fileAttributes = GetFileAttributesA(lpExtPath.c_str());
    if (fileAttributes != INVALID_FILE_ATTRIBUTES) DeleteFileA(lpExtPath.c_str());
    if (FBWriteFile(lpExtPath.c_str(), pBuffer, &wbytes, 0, rbytes) != FB_SUCCESS) { // 文件加密后数据 18-*
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        FAIL(APE_DECODE_FAILED);
    }
    VirtualFree(pBuffer, 0, MEM_RELEASE);
    return APS_SUCCESS;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH: {
        srand((UINT)time(NULL));
        break;
    }
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH: {
        break;
    }
    }
    return TRUE;
}

