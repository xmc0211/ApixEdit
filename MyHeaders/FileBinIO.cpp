//FileBinIO.cpp by XMC

#include "FileBinIO.h"

template <typename _Tp>
_Tp FBMax(_Tp x, _Tp y) {return x > y ? x : y; }

template <typename _Tp>
_Tp FBMin(_Tp x, _Tp y) { return x > y ? y : x; }


//LARGE_INTEGER转ULONG
ULONG FBLIntToUl(LARGE_INTEGER x) {
    ULONG ulValue;
    ulValue = (ULONG)x.QuadPart;
    return ulValue;
}

//ULONG转LARGE_INTEGER
LARGE_INTEGER FBUlToLInt(ULONG x) {
    LARGE_INTEGER liValue{};
    liValue.QuadPart = (LONGLONG)x;
    return liValue;
}

// 获取文件字节数（单位：字节）
LARGE_INTEGER FBGetFileSize(const char* filePath) {
    LARGE_INTEGER fileSize;
    fileSize.QuadPart = 0;

    // 打开文件以读取其大小
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) return fileSize;

    // 获取文件大小
    if (!GetFileSizeEx(hFile, &fileSize)) {
        // 关闭文件句柄
        CloseHandle(hFile);
        return fileSize;
    }

    // 关闭文件句柄
    CloseHandle(hFile);
    return fileSize;
}

// 按字节读文件（磁盘）
DWORD FBReadFile(const char* lpcFilePath, // 文件路径
    UCHAR* lpcData, // 接收数据段指针
    LPDWORD lpdwBytesRead, // 接收读取字节数指针 
    LONG uiRstart, // 读取起始地址
    DWORD uiRsize /* = FB_UL_INF */ // 读取总大小（FB_UI_INF表示到末尾）
) {
    LARGE_INTEGER liFileSize = FBGetFileSize(lpcFilePath);

    // 判断溢出的可能并避免
    if (lpcData == NULL) return FB_INVAILD_POINTER;
    if (uiRsize != FB_UL_INF && 1ULL * sizeof(UCHAR) * uiRsize > FBLIntToUl(liFileSize)) return FB_OUT_OF_RANGE;

    // 创建文件对象
    HANDLE hFile = CreateFileA(lpcFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FB_ERROR;

    // 读取的字节数
    DWORD dwBytesRead;

    // 设置起始位置
    if (SetFilePointer(hFile, uiRstart, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(hFile);
        return FB_ERROR;
    }

    // 读取文件并关闭句柄
    BOOL result = ReadFile(hFile, lpcData, FBMin <ULONG> (uiRsize, FBLIntToUl(liFileSize)), &dwBytesRead, NULL);
    CloseHandle(hFile);

    // 处理读取失败
    if (!result) return FB_ERROR;

    if (lpdwBytesRead != NULL) *lpdwBytesRead = dwBytesRead;
    return FB_SUCCESS;
}

// 按字节写文件（磁盘）
DWORD FBWriteFile(const char* lpcFilePath, // 文件路径
    UCHAR* lpcData, // 写入数据段指针
    LPDWORD lpdwBytesWrite, // 接收写入字节数指针 
    LONG uiWstart, // 写入起始地址
    DWORD uiWsize // 写入总大小
) {
    // 判断空指针并避免
    if (lpcData == NULL) return FB_INVAILD_POINTER;

    // 创建文件对象
    HANDLE hFile = CreateFileA(lpcFilePath, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FB_ERROR;

    // 写入的字节数
    DWORD dwBytesWrite;

    // 设置起始位置
    if (SetFilePointer(hFile, uiWstart, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(hFile);
        return FB_ERROR;
    }

    // 写入文件并关闭句柄
    BOOL result = WriteFile(hFile, lpcData, uiWsize, &dwBytesWrite, NULL);
    CloseHandle(hFile);

    // 处理写入失败
    if (!result) return FB_ERROR;

    if (lpdwBytesWrite != NULL) *lpdwBytesWrite = dwBytesWrite;
    return FB_SUCCESS;
}
