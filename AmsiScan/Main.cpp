#include "Functions.h"
#include <conio.h>

using namespace std;

int wmain(int argc, wchar_t* argv[]) {
	wcout.imbue(locale(""));
	if (argc < 2) {
		cout << "[!]No Sample Provided, using built-in test strings." << endl;
		if (!ScanTestStrings()) {
			cerr << "[-]Some scan(s) failed." << endl;
			return -1;
		}
		cout << "[+]Scan complete success." << endl;
		return 0;
	}
	if (argc == 2) {
		vector<SampleFile> FilesBuffer;
		ReadDirectoryFiles(argv[1], FilesBuffer);
		if (FilesBuffer.empty()) {
			cerr << "[-]Failed to Read Files" << endl;
			return -2;
		}
		cout << "[!]Read Files Complete, turn on Real-Time Protection of your AV, then press any key to continue..." << endl;
		_getch();

		for (auto& File : FilesBuffer) {
			wcout << L"[!]Scanning " << File.wstrFileName << endl;
			SampleScanResult FileScanResult;
			LPCWSTR lpFileName = File.wstrFileName.c_str();
			if (S_OK != AmsiScan(lpFileName, File.DataBuffer, File.dwFileSize, &FileScanResult)) {
				cerr << "[-]AmsiScan Failed" << endl;
				continue;
			}
			wcout << L"[!]AmsiScan " << File.wstrFileName << " Complete, RiskLevel = " << FileScanResult.RiskLevel << ", StringRiskLevel = " << FileScanResult.StringRiskLevel << endl;
			if (FileScanResult.IsMalware) {
				cout << "[!]AmsiScanBuffer Malware Detected" << endl;
			}
			if (FileScanResult.StringIsMalware) {
				cout << "[!]AmsiScanString Malware Detected" << endl;
			}
			VirtualFree(File.DataBuffer, 0, MEM_RELEASE);
		}
		return 0;
	}
	if (argc == 3 && wcscmp(argv[2], L"-Notify") == 0) {
		vector<SampleFile> FilesBuffer;
		ReadDirectoryFiles(argv[1], FilesBuffer);
		if (FilesBuffer.empty()) {
			cerr << "[-]Failed to Read Files" << endl;
			return -2;
		}
		cout << "[!]Read Files Complete, turn on Real-Time Protection of your AV, then press any key to continue..." << endl;
		_getch();

		for (auto& File : FilesBuffer) {
			wcout << L"[!]Scanning " << File.wstrFileName << endl;
			SampleScanNotifyAntivirusResult FileScanNotifyResult;
			LPCWSTR lpFileName = File.wstrFileName.c_str();
			if (S_OK != AmsiScanNotifyAV(lpFileName, File.DataBuffer, File.dwFileSize, &FileScanNotifyResult)) {
				cerr << "[-]AmsiScanNotifyAV Failed" << endl;
				continue;
			}
			wcout << L"[!]AmsiScan " << File.wstrFileName << " Complete, RiskLevel = " << FileScanNotifyResult.RiskLevel << endl;
			if (FileScanNotifyResult.IsMalware) {
				cout << "[!]AmsiNotifyOperation Malware Detected" << endl;
			}
			VirtualFree(File.DataBuffer, 0, MEM_RELEASE);
		}
		return 0;
	}
	cout << "Usage: Scanner.exe <Directory or File> (-Notify)" << endl;
	cout << "You may need to suspend the Real-time protection of your AV when reading files" << endl;
	return 0;
}