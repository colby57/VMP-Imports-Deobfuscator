#include "StringConversion.h"

#include <atlbase.h> 
#include <atlconv.h>

const char* StringConversion::ToAscii(const wchar_t* str, char* buf, size_t bufsize)
{
	ATL::CW2A str_a = str;

	strncpy_s(buf, bufsize, str_a, bufsize);
	buf[bufsize - 1] = '\0';

	return buf;
}

const wchar_t* StringConversion::ToUtf16(const char* str, wchar_t* buf, size_t bufsize)
{
	ATL::CA2W str_w = str;

	wcsncpy_s(buf, bufsize, str_w, bufsize);
	buf[bufsize - 1] = L'\0';

	return buf;
}
