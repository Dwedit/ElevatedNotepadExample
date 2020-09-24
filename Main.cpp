struct IUnknown;
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <comdef.h>

int MainAdmin(PWSTR pCmdLine, int nCmdShow)
{
	STARTUPINFOW startupInfo = {};
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.dwFlags |= STARTF_USESHOWWINDOW;
	startupInfo.wShowWindow = nCmdShow;
	BOOL okay;
	PROCESS_INFORMATION processInformation = {};
	
	wchar_t systemDirectory[MAX_PATH];
	GetSystemDirectoryW(&systemDirectory[0], MAX_PATH);

	_bstr_t path;
	path += "\"";
	path += systemDirectory;
	path += "\\notepad.exe\" ";
	path += pCmdLine;

	okay = CreateProcess(NULL, path, NULL, NULL, false, 0, NULL, NULL, &startupInfo, &processInformation);
	DWORD lastErr = GetLastError();
	if (okay)
	{
		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);
	}
	return !okay;
}
