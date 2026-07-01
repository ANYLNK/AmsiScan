#pragma once
#include "HelperStructs.h"
#include <iostream>
#include <vector>

using namespace std;

void ReadDirectoryFiles(const wstring path, vector<SampleFile>& OutBuffers);
HRESULT AmsiScan(LPCWSTR FileName, LPVOID SampleData, SIZE_T SampleSize, SampleScanResult* ScanResult);
HRESULT AmsiScanNotifyAV(LPCWSTR ContentName, LPVOID DataBuffer, ULONG length, SampleScanNotifyAntivirusResult* ScanNotifyResult);
BOOL ScanTestStrings();