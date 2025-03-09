// Convert.h by XMC
#ifndef CONVERT_H
#define CONVERT_H

#include <windows.h>
#include <string>
#include <vector>
#include <iomanip>

// std::string与std::wstring互转（更安全）
std::wstring LPC2LPW(const std::string str);
std::string LPW2LPC(const std::wstring wstr);

// UCHAR*的strlen
size_t ustrlen(const UCHAR* str);

// char*与unsigned char*互转
void CH2UCH(const char* str, UCHAR* res, size_t sz);
void UCH2CH(const UCHAR* str, char* res, size_t sz);

// int与std::string互转（确保在范围内）
std::string INT2STR(const INT res);
INT STR2INT(const std::string str);

// UCHAR*与十六进制字符串互转
void UCH2STR(const UCHAR* data, CHAR* res, size_t sz);
void STR2UCH(const CHAR* hexStr, UCHAR* data, size_t sz);

#endif
