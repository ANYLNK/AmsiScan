#include "HelperStructs.h"
#include <amsi.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "amsi.lib")

using namespace std;

static BOOL ReadSingleSampleFile(LPCWSTR lpFileName, SampleFile* Sample) {
	HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		cerr << "[-]Failed to Get File Handle " << GetLastError() << endl;
		return FALSE;
	}
	SIZE_T dwSize = GetFileSize(hFile, NULL);
	if (dwSize == 0 || dwSize == INVALID_FILE_SIZE) {
		cerr << "[-]Failed when retrieving FileSize " << GetLastError() << endl;
		CloseHandle(hFile);
		return FALSE;
	}
	LPVOID lpOutBuffer = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (!lpOutBuffer) {
		cerr << "[-]Failed to allocate memory for file " << GetLastError() << endl;
		CloseHandle(hFile);
		return FALSE;
	}
	DWORD dwBytesRead;
	if (!ReadFile(hFile, lpOutBuffer, dwSize, &dwBytesRead, NULL)) {
		cerr << "[-]Failed to Read File into Memory." << GetLastError() << endl;
		CloseHandle(hFile);
		return FALSE;
	}
	CloseHandle(hFile);
	wstring wsfilename(lpFileName);
	Sample->wstrFileName = wsfilename;
	Sample->DataBuffer = lpOutBuffer;
	Sample->dwFileSize = dwSize;
	return TRUE;
}

void ReadDirectoryFiles(const wstring path, vector<SampleFile>& OutBuffers) {
	wstring normalizedpath = path;
	while (normalizedpath.size() > 3 && (normalizedpath.back() == L'\\' || normalizedpath.back() == L'/')) {
		normalizedpath.pop_back();
	}
	LPCWSTR lpFileName = normalizedpath.c_str();
	DWORD FileAttributes = GetFileAttributes(lpFileName);
	if (FileAttributes == INVALID_FILE_ATTRIBUTES) {
		cerr << "[-]Failed to retrieve file attributes " << GetLastError() << endl;
		return ;
	}
	if (!(FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
		SampleFile sf;
		if (ReadSingleSampleFile(lpFileName, &sf)) {
			OutBuffers.push_back(sf);
		}
		return;
	}
	wstring searchPath = normalizedpath + L"\\*";
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(searchPath.c_str(), &fd);
	if (hFind == INVALID_HANDLE_VALUE) {
		cerr << "[-]Cannot Open Directory " << GetLastError() << endl;
		return;
	}
	do {
		wstring name = fd.cFileName;
		if (name == L"." || name == L"..") {
			continue;
		}
		wstring fullpath = normalizedpath + L"\\" + name;
		ReadDirectoryFiles(fullpath, OutBuffers);
	} while (FindNextFile(hFind, &fd));
	FindClose(hFind);
}

HRESULT AmsiScan(LPCWSTR FileName, LPVOID SampleData, SIZE_T SampleSize, SampleScanResult* ScanResult) {
	HRESULT hResult = S_OK;
	HAMSICONTEXT amsiContext;
	HAMSISESSION session = NULL;
	AMSI_RESULT amsiResult = AMSI_RESULT_DETECTED;
	AMSI_RESULT amsiStringScanResult = AMSI_RESULT_DETECTED;
	ZeroMemory(&amsiContext, sizeof(amsiContext));

	hResult = AmsiInitialize(L"Madobe Ann&Mio's AMSI Scanner", &amsiContext);
	if (hResult != S_OK) {
		cerr << "[-]AmsiInitialize Failed, HRESULT = 0x" << hex << hResult << endl;
		return hResult;
	}

	hResult = AmsiOpenSession(amsiContext, &session);
	if (hResult != S_OK || session == NULL) {
		cerr << "[-]AmsiOpenSession Failed, HRESULT = 0x" << hex << hResult << endl;
		AmsiUninitialize(amsiContext);
		return hResult;
	}

	hResult = AmsiScanBuffer(amsiContext, SampleData, SampleSize, FileName, session, &amsiResult);
	if (hResult != S_OK) {
		cerr << "[-]AmsiScanBuffer Failed, HRESULT = 0x" << hex << hResult << endl;
		AmsiCloseSession(amsiContext, session);
		AmsiUninitialize(amsiContext);
		return hResult;
	}

	hResult = AmsiScanString(amsiContext, (LPCWSTR)SampleData, FileName, session, &amsiStringScanResult);
	if (hResult != S_OK) {
		cerr << "[-]AmsiScanString Failed, HRESULT = 0x" << hex << hResult << endl;
		AmsiCloseSession(amsiContext, session);
		AmsiUninitialize(amsiContext);
		return hResult;
	}

	ScanResult->RiskLevel = amsiResult;
	ScanResult->IsMalware = AmsiResultIsMalware(amsiResult);
	ScanResult->StringRiskLevel = amsiStringScanResult;
	ScanResult->StringIsMalware = AmsiResultIsMalware(amsiStringScanResult);

	AmsiCloseSession(amsiContext, session);
	AmsiUninitialize(amsiContext);
	return hResult;
}

HRESULT AmsiScanNotifyAV(LPCWSTR ContentName, LPVOID DataBuffer, ULONG length, SampleScanNotifyAntivirusResult* ScanNotifyResult) {
	HRESULT hResult = S_OK;
	HAMSICONTEXT amsiContext;
	AMSI_RESULT amsiResult = AMSI_RESULT_DETECTED;
	ZeroMemory(&amsiContext, sizeof(amsiContext));

	hResult = AmsiInitialize(L"Madobe Mio&Ann's AMSI Notify AV Scanner", &amsiContext);
	if (hResult != S_OK) {
		cerr << "[-]AmsiInitialize Failed, HRESULT = 0x" << hex << hResult << endl;
		return hResult;
	}

	hResult = AmsiNotifyOperation(amsiContext, DataBuffer, length, ContentName, &amsiResult);
	if (hResult != S_OK) {
		cerr << "[-]AmsiNotifyOperation Failed, HRESULT = 0x" << hex << hResult << endl;
		AmsiUninitialize(amsiContext);
		return hResult;
	}

	ScanNotifyResult->RiskLevel = amsiResult;
	ScanNotifyResult->IsMalware = AmsiResultIsMalware(amsiResult);

	AmsiUninitialize(amsiContext);
	return hResult;
}

BOOL ScanTestStrings() {
	LPCWSTR ScanName = L"Test_Strings";
	SampleFile EICAR, INVKATZ, amsFail, amsUtil;
	SampleScanResult EICARRes, INVKATZRes, amsFailRes, amsUtilRes;
	SampleScanNotifyAntivirusResult EICARNotifyRes, INVKATZNotifyRes, amsFailNotifyRes, amsUtilNotifyRes;
	
	EICAR.DataBuffer = (BYTE*)EICAR_TEST_STRING;
	EICAR.dwFileSize = strlen(EICAR_TEST_STRING);
	EICAR.wstrFileName = L"EICAR_SAMPLE_TEST";
	HRESULT hResEICAR = AmsiScan(ScanName, EICAR.DataBuffer, EICAR.dwFileSize, &EICARRes);
	if (S_OK == hResEICAR) {
		cout << "[+]EICAR String Scan Success. RiskLevel = " << EICARRes.RiskLevel << " StringRiskLevel = " << EICARRes.StringRiskLevel << endl;
		if (EICARRes.IsMalware) {
			cout << "[!]AmsiScanBuffer Malware Detected" << endl;
		}
		if (EICARRes.StringIsMalware) {
			cout << "[!]AmsiScanString Malware Detected" << endl;
		}
		if (S_OK == AmsiScanNotifyAV(EICAR.wstrFileName.c_str(), EICAR.DataBuffer, EICAR.dwFileSize, &EICARNotifyRes)) {
			cout << "[+]Scan EICAR Notify Antivirus Software Success! RiskLevel = " << EICARNotifyRes.RiskLevel << endl;
		}
	}

	INVKATZ.DataBuffer = (BYTE*)INVOKEKATZ_TEST_STRING;
	INVKATZ.dwFileSize = strlen(INVOKEKATZ_TEST_STRING);
	INVKATZ.wstrFileName = L"INVOKEMIMIKATZ_SAMPLE_TEST";
	HRESULT hResINVKATZ = AmsiScan(ScanName, INVKATZ.DataBuffer, INVKATZ.dwFileSize, &INVKATZRes);
	if (S_OK == hResINVKATZ) {
		cout << "[+]Invoke_Mimikatz String Scan Success. RiskLevel = " << INVKATZRes.RiskLevel << " StringRiskLevel = " << INVKATZRes.StringRiskLevel << endl;
		if (INVKATZRes.IsMalware) {
			cout << "[!]AmsiScanBuffer Malware Detected" << endl;
		}
		if (INVKATZRes.StringIsMalware) {
			cout << "[!]AmsiScanString Malware Detected" << endl;
		}
		if (S_OK == AmsiScanNotifyAV(INVKATZ.wstrFileName.c_str(), INVKATZ.DataBuffer, INVKATZ.dwFileSize, &INVKATZNotifyRes)) {
			cout << "[+]Scan Invoke_Mimikatz Notify Antivirus Software Success! RiskLevel = " << INVKATZNotifyRes.RiskLevel << endl;
		}
	}

	amsFail.DataBuffer = (BYTE*)AMSIFAIL_TEST_STRING;
	amsFail.dwFileSize = strlen(AMSIFAIL_TEST_STRING);
	amsFail.wstrFileName = L"AMSIFAIL_SAMPLE_TEST";
	HRESULT hResAmsFail = AmsiScan(ScanName, amsFail.DataBuffer, amsFail.dwFileSize, &amsFailRes);
	if (S_OK == hResAmsFail) {
		cout << "[+]AmsiFail String Scan Success. RiskLevel = " << amsFailRes.RiskLevel << " StringRiskLevel = " << amsFailRes.StringRiskLevel << endl;
		if (amsFailRes.IsMalware) {
			cout << "[!]AmsiScanBuffer Malware Detected" << endl;
		}
		if (amsFailRes.StringIsMalware) {
			cout << "[!]AmsiScanString Malware Detected" << endl;
		}
		if (S_OK == AmsiScanNotifyAV(amsFail.wstrFileName.c_str(), amsFail.DataBuffer, amsFail.dwFileSize, &amsFailNotifyRes)) {
			cout << "[+]Scan AmsiFail Notify Antivirus Software Success! RiskLevel = " << amsFailNotifyRes.RiskLevel << endl;
		}
	}

	amsUtil.DataBuffer = (BYTE*)AMSIUTIL_TEST_STRING;
	amsUtil.dwFileSize = strlen(AMSIUTIL_TEST_STRING);
	amsUtil.wstrFileName = L"AMSIUTIL_SAMPLE_TEST";
	HRESULT hResAmsUtil = AmsiScan(ScanName, amsUtil.DataBuffer, amsUtil.dwFileSize, &amsUtilRes);
	if (S_OK == hResAmsUtil) {
		cout << "[+]AmsiUtil String Scan Success. RiskLevel = " << amsUtilRes.RiskLevel << " StringRiskLevel = " << amsUtilRes.StringRiskLevel << endl;
		if (amsUtilRes.IsMalware) {
			cout << "[!]AmsiScanBuffer Malware Detected" << endl;
		}
		if (amsUtilRes.StringIsMalware) {
			cout << "[!]AmsiScanString Malware Detected" << endl;
		}
		if (S_OK == AmsiScanNotifyAV(amsUtil.wstrFileName.c_str(), amsUtil.DataBuffer, amsUtil.dwFileSize, &amsUtilNotifyRes)) {
			cout << "[+]Scan Invoke_Mimikatz Notify Antivirus Software Success! RiskLevel = " << amsUtilNotifyRes.RiskLevel << endl;
		}
	}

	if (hResEICAR == S_OK && hResAmsFail == S_OK && hResINVKATZ == S_OK && hResAmsUtil == S_OK) {
		return TRUE;
	}
	return FALSE;
}