//FileBinIO.h by XMC
#ifndef FILEBINIO_H
#define FILEBINIO_H

#include <windows.h>

enum FB_RESULTS {
    FB_SUCCESS = 0x0, 
    FB_ERROR = 0x1, 
    FB_FILE_NOT_EXIST = 0x2, 
    FB_OUT_OF_RANGE = 0x4, 
    FB_INVAILD_POINTER = 0x8
};

const UINT FB_UI_INF = UINT_MAX;
const ULONG FB_UL_INF = ULONG_MAX;
const ULONGLONG FB_ULL_INF = ULLONG_MAX;

template <typename _Tp>
_Tp FBMax(_Tp x, _Tp y);

template <typename _Tp>
_Tp FBMin(_Tp x, _Tp y);


//LARGE_INTEGER转ULONG
ULONG FBLIntToUl(LARGE_INTEGER x);

//ULONG转LARGE_INTEGER
LARGE_INTEGER FBUlToLInt(ULONG x);

// 获取文件字节数（单位：字节）
LARGE_INTEGER FBGetFileSize(const char* filePath);

// 按字节读文件（磁盘）
DWORD FBReadFile(const char* lpcFilePath, // 文件路径
    UCHAR* lpcData, // 接收数据段指针
    LPDWORD lpdwBytesRead, // 接收读取字节数指针 
    LONG uiRstart, // 读取起始地址
    DWORD uiRsize = FB_UL_INF // 读取总大小（FB_UI_INF表示到末尾）
);

// 按字节写文件（磁盘）
DWORD FBWriteFile(const char* lpcFilePath, // 文件路径
    UCHAR* lpcData, // 写入数据段指针
    LPDWORD lpdwBytesWrite, // 接收写入字节数指针 
    LONG uiWstart, // 写入起始地址
    DWORD uiWsize // 写入总大小
);

#endif
