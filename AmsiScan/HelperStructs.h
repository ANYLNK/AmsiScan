#pragma once
#include <Windows.h>
#include <iostream>

#define EICAR_TEST_STRING "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
#define INVOKEKATZ_TEST_STRING "Invoke-Mimikatz"
#define AMSIFAIL_TEST_STRING "amsiInitFailed"
#define AMSIUTIL_TEST_STRING "AmsiUtils"

struct SampleFile {
	std::wstring wstrFileName;
	LPVOID DataBuffer;
	SIZE_T dwFileSize;
};

struct SampleScanResult {
	HRESULT RiskLevel;
	BOOL IsMalware;
	HRESULT StringRiskLevel;
	BOOL StringIsMalware;
};

struct SampleScanNotifyAntivirusResult {
	HRESULT RiskLevel;
	BOOL IsMalware;
};