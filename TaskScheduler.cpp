struct IUnknown;
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Ole2.h>
#include <taskschd.h>
#include <comdef.h>
#include <shellapi.h>
#include <lmaccess.h>
#include <lmapibuf.h>
#include <LMErr.h>
#define SECURITY_WIN32
#include <Security.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "Netapi32.lib")

#define APPNAME L ## "ElevatedNotepadExample"

int MainAdmin(PWSTR pCmdLine, int nCmdShow);

template <class TComObject>
int SafeRelease(TComObject*& obj)
{
	if (obj != NULL)
	{
		int refCount = obj->Release();
		obj = NULL;
		return refCount;
	}
	else
	{
		return 0;
	}
}

//https://www.codeproject.com/articles/320748/elevating-during-runtime
//
BOOL IsAppRunningAsAdminMode()
{
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;

	// Allocate and initialize a SID of the administrators group.
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdministratorsGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Determine whether the SID of administrators group is enabled in 
	// the primary access token of the process.
	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (pAdministratorsGroup)
	{
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}

	return fIsRunAsAdmin;
}
// 

void RunElevated(LPCWSTR commandLine, int cmdShow)
{
	wchar_t szPath[MAX_PATH];
	if (GetModuleFileNameW(NULL, szPath, ARRAYSIZE(szPath)))
	{
		// Launch itself as admin
		SHELLEXECUTEINFO sei = { sizeof(sei) };
		sei.lpVerb = L"runas";
		sei.lpFile = szPath;
		sei.hwnd = NULL;
		sei.nShow = cmdShow;
		sei.lpParameters = commandLine;
		if (!ShellExecuteExW(&sei))
		{
			DWORD dwError = GetLastError();
			if (dwError == ERROR_CANCELLED)
			{
				ExitProcess(1);
			}
		}
		else
		{
			ExitProcess(1);  // Quit itself
		}
	}

}

IRegisteredTask* GetScheduledTask(const wchar_t* taskName)
{
	HRESULT hr;
	ITaskService* taskService = NULL;
	ITaskFolder* rootFolder = NULL;
	IRegisteredTask* registeredTask = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&taskService);
	if (taskService == NULL || !SUCCEEDED(hr))
	{
		goto failed;
	}
	hr = taskService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
	if (!SUCCEEDED(hr))
	{
		goto failed;
	}
	hr = taskService->GetFolder(_bstr_t(L"\\"), &rootFolder);
	if (rootFolder == NULL || !SUCCEEDED(hr))
	{
		goto failed;
	}

	hr = rootFolder->GetTask(_bstr_t(taskName), &registeredTask);
	if (registeredTask == NULL || !SUCCEEDED(hr))
	{
		goto failed;
	}
okay:
	SafeRelease(taskService);
	SafeRelease(rootFolder);
	return registeredTask;
failed:
	SafeRelease(taskService);
	SafeRelease(rootFolder);
	SafeRelease(registeredTask);
	return NULL;
}

//https://stackoverflow.com/questions/562701/best-way-to-determine-if-two-path-reference-to-same-file-in-windows
bool IsSameFile(const wchar_t* path1, const wchar_t* path2)
{
	HANDLE handle1 = INVALID_HANDLE_VALUE;
	HANDLE handle2 = INVALID_HANDLE_VALUE;
	BY_HANDLE_FILE_INFORMATION info1 = {}, info2 = {};
	BOOL okay;

	handle1 = CreateFileW(path1, GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle1 == INVALID_HANDLE_VALUE) goto failed;
	handle2 = CreateFileW(path2, GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle2 == INVALID_HANDLE_VALUE) goto failed;

	okay = GetFileInformationByHandle(handle1, &info1);
	if (!okay) goto failed;
	okay = GetFileInformationByHandle(handle2, &info2);
	if (!okay) goto failed;

	if (info1.dwVolumeSerialNumber == info2.dwVolumeSerialNumber &&
		info1.nFileIndexLow == info2.nFileIndexLow &&
		info1.nFileIndexHigh == info2.nFileIndexHigh)
	{

	}
	else
	{
		goto failed;
	}

okay:
	CloseHandle(handle1);
	CloseHandle(handle2);
	return true;
failed:
	CloseHandle(handle1);
	CloseHandle(handle2);
	return false;

}

_bstr_t GetComputerName()
{
	//computer names are 15 characters max
	const int MAXSIZE = 256;
	DWORD bufferSize = MAXSIZE;
	wchar_t buffer[MAXSIZE];
	BOOL okay = GetComputerNameW(buffer, &bufferSize);
	return buffer;
}

_bstr_t GetUserName()
{
	//usernames are 64 characters max
	const int MAXSIZE = 256;
	DWORD bufferSize = MAXSIZE;
	wchar_t buffer[MAXSIZE];
	BOOL okay = GetUserNameW(buffer, &bufferSize);
	return buffer;
}

_bstr_t GetSamName()
{
	//SAM name should be 80 characters max
	const int MAXSIZE = 256;
	DWORD bufferSize = MAXSIZE;
	wchar_t buffer[MAXSIZE];
	GetUserNameExW(NameSamCompatible, buffer, &bufferSize);
	return buffer;
}

IRegisteredTask* GetThisTask(const _bstr_t &userName)
{
	HRESULT hr = 0;
	_bstr_t taskName = APPNAME L" for " + userName;
	IRegisteredTask* task = GetScheduledTask(taskName);
	ITaskDefinition* taskDefinition = NULL;
	IPrincipal* principal = NULL;
	IActionCollection* actionCollection = NULL;
	IAction* action = NULL;
	IExecAction* execAction = NULL;
	ITaskSettings* taskSettings = NULL;
	_bstr_t actionPath;
	_bstr_t args;
	wchar_t thisPath[MAX_PATH];
	ULONG bufferSize = MAX_PATH;
	_bstr_t userId;
	_bstr_t samName = GetComputerName() + "\\" + userName;
	TASK_RUNLEVEL_TYPE runLevel;
	VARIANT_BOOL allowDemandStart;
	VARIANT_BOOL enabled;
	VARIANT_BOOL stopIfGoingOnBatteries;
	VARIANT_BOOL disallowStartIfOnBatteries;
	VARIANT_BOOL runOnlyIfIdle;

	if (task == NULL) { goto failed; }
	//verify task points to this EXE
	hr = task->get_Definition(&taskDefinition);
	if (!SUCCEEDED(hr) || taskDefinition == NULL) { goto failed; }
	hr = taskDefinition->get_Actions(&actionCollection);
	if (!SUCCEEDED(hr) || actionCollection == NULL) { goto failed; }
	hr = actionCollection->get_Item(1, &action);
	if (!SUCCEEDED(hr) || action == NULL) { goto failed; }
	hr = action->QueryInterface(&execAction);
	if (!SUCCEEDED(hr) || execAction == NULL) { goto failed; }
	hr = execAction->get_Path(actionPath.GetAddress());
	if (!SUCCEEDED(hr)) { goto failed; }
	if (!GetModuleFileNameW(NULL, thisPath, ARRAYSIZE(thisPath))) { goto failed; }
	if (!IsSameFile(actionPath, thisPath)) { goto failed; }
	
	//verify arguments
	hr = execAction->get_Arguments(args.GetAddress());
	if (!SUCCEEDED(hr)) { goto failed; }
	if (0 != wcscmp(args, L"$(Arg0)")) { goto failed; }

	//verify the run mode and user is correct
	hr = taskDefinition->get_Principal(&principal);
	if (principal == NULL || !SUCCEEDED(hr)) { goto failed; }
	hr = principal->get_RunLevel(&runLevel);
	hr = principal->get_UserId(userId.GetAddress());
	if (runLevel != TASK_RUNLEVEL_HIGHEST) { goto failed; }
	if (userId != samName) { goto failed; }

	//verify settings
	hr = taskDefinition->get_Settings(&taskSettings);
	if (taskSettings == NULL || !SUCCEEDED(hr)) { goto failed; }
	taskSettings->get_AllowDemandStart(&allowDemandStart);
	taskSettings->get_Enabled(&enabled);

	hr = taskSettings->get_AllowDemandStart(&allowDemandStart);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->get_Enabled(&enabled);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->get_StopIfGoingOnBatteries(&stopIfGoingOnBatteries);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->get_DisallowStartIfOnBatteries(&disallowStartIfOnBatteries);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->get_RunOnlyIfIdle(&runOnlyIfIdle);
	if (!SUCCEEDED(hr)) { goto failed; }

	if (!(allowDemandStart && enabled && !stopIfGoingOnBatteries && !disallowStartIfOnBatteries && !runOnlyIfIdle)) { goto failed; }

okay:
	SafeRelease(taskDefinition);
	SafeRelease(actionCollection);
	SafeRelease(action);
	SafeRelease(execAction);
	SafeRelease(principal);
	SafeRelease(taskSettings);
	return task;
failed:
	SafeRelease(taskDefinition);
	SafeRelease(actionCollection);
	SafeRelease(action);
	SafeRelease(execAction);
	SafeRelease(task);
	SafeRelease(principal);
	SafeRelease(taskSettings);
	return NULL;
}

IRegisteredTask* GetThisTask()
{
	return GetThisTask(GetUserName());
}

bool CreateThisTask(const _bstr_t &userName)
{
	HRESULT hr;
	ITaskService* taskService = NULL;
	ITaskDefinition* taskDefinition = NULL;
	ITaskFolder* rootFolder = NULL;
	IRegisteredTask* registeredTask = NULL;
	IActionCollection* actionCollection = NULL;
	IAction* action = NULL;
	IExecAction* execAction = NULL;
	IPrincipal* principal = NULL;
	ITaskSettings* taskSettings = NULL;
	_bstr_t path;
	wchar_t thisPath[MAX_PATH];
	_bstr_t userId = GetComputerName() + "\\" + userName;
	_bstr_t taskName = APPNAME L" for " + userName;
	ULONG bufferSize = MAX_PATH;

	if (!GetModuleFileNameW(NULL, thisPath, ARRAYSIZE(thisPath))) { goto failed; }
	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&taskService);
	if (taskService == NULL || !SUCCEEDED(hr)) { goto failed; }
	hr = taskService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskService->GetFolder(_bstr_t(L"\\"), &rootFolder);
	if (rootFolder == NULL || !SUCCEEDED(hr)) { goto failed; }
	hr = taskService->NewTask(0, &taskDefinition);
	if (taskDefinition == NULL || !SUCCEEDED(hr)) { goto failed; }
	hr = taskDefinition->get_Actions(&actionCollection);
	if (actionCollection == NULL || !SUCCEEDED(hr)) { goto failed; }
	hr = actionCollection->Create(TASK_ACTION_EXEC, &action);
	if (action == NULL || !SUCCEEDED(hr)) { goto failed; }
	hr = action->QueryInterface(&execAction);
	if (execAction == NULL || !SUCCEEDED(hr)) { goto failed; }
	path = thisPath;
	hr = execAction->put_Path(path);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = execAction->put_Arguments(_bstr_t(L"$(Arg0)"));
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskDefinition->put_Actions(actionCollection);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskDefinition->get_Principal(&principal);
	if (principal == NULL || !SUCCEEDED(hr)) { goto failed; }
	hr = principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = principal->put_UserId(userId.GetBSTR());
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskDefinition->put_Principal(principal);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskDefinition->get_Settings(&taskSettings);
	if (taskSettings == NULL || !SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->put_AllowDemandStart(true);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->put_AllowHardTerminate(true);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->put_Compatibility(TASK_COMPATIBILITY_V2_1);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->put_DisallowStartIfOnBatteries(false);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->put_Enabled(true);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->put_RunOnlyIfIdle(false);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->put_RunOnlyIfNetworkAvailable(false);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->put_WakeToRun(false);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskSettings->put_StopIfGoingOnBatteries(false);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = taskDefinition->put_Settings(taskSettings);
	if (!SUCCEEDED(hr)) { goto failed; }
	hr = rootFolder->RegisterTaskDefinition(_bstr_t(taskName), taskDefinition, TASK_CREATE_OR_UPDATE, _variant_t(userId), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(), &registeredTask);
	if (registeredTask == NULL || !SUCCEEDED(hr)) { goto failed; }
okay:
	SafeRelease(taskService);
	SafeRelease(taskDefinition);
	SafeRelease(rootFolder);
	SafeRelease(registeredTask);
	SafeRelease(actionCollection);
	SafeRelease(action);
	SafeRelease(execAction);
	SafeRelease(principal);
	SafeRelease(taskSettings);
	return true;
failed:
	SafeRelease(taskService);
	SafeRelease(taskDefinition);
	SafeRelease(rootFolder);
	SafeRelease(registeredTask);
	SafeRelease(actionCollection);
	SafeRelease(action);
	SafeRelease(execAction);
	SafeRelease(principal);
	SafeRelease(taskSettings);
	return false;
}

bool CreateThisTask()
{
	return CreateThisTask(GetUserName());
}

bool CreateThisTaskForAllUsers()
{
	bool success = true;
	BYTE* buffer = NULL;
	DWORD entriesRead, totalEntries;
	DWORD okay;
	okay = NetUserEnum(NULL, 2, FILTER_NORMAL_ACCOUNT, &buffer, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, NULL);
	if (okay == NERR_Success)
	{
		USER_INFO_2* userInfoArray = (USER_INFO_2*)buffer;
		for (int i = 0; i < entriesRead; i++)
		{
			USER_INFO_2& userInfo = userInfoArray[i];
			DWORD flags = userInfo.usri2_flags;
			DWORD priv = userInfo.usri2_priv;

			bool isDisabled = flags & UF_ACCOUNTDISABLE;
			bool isGuest = priv == USER_PRIV_GUEST;

			if (!isDisabled && !isGuest)
			{
				success &= CreateThisTask(userInfo.usri2_name);
			}
		}
	}
	NetApiBufferFree(buffer);
	return success;
}

bool RunTask(IRegisteredTask* task, LPCWSTR commandLine)
{
	HRESULT hr;
	IRunningTask* runningTask = NULL;
	if (task == NULL) goto failed;
	hr = task->Run(_variant_t(_bstr_t(commandLine)), &runningTask);
	if (FAILED(hr) || runningTask == NULL)
	{
		goto failed;
	}
okay:
	SafeRelease(runningTask);
	return true;
failed:
	SafeRelease(runningTask);
	return false;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	bool isAdmin;

	HRESULT hr;
	IRegisteredTask* task;
	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	isAdmin = IsAppRunningAsAdminMode();
	task = GetThisTask();
	if (task && !isAdmin)
	{
		RunTask(task, pCmdLine);
		SafeRelease(task);
		return 0;
	}
	if (task && isAdmin)
	{
		SafeRelease(task);
		return MainAdmin(pCmdLine, nCmdShow);
	}
	SafeRelease(task);
	if (!isAdmin)
	{
		RunElevated(pCmdLine, nCmdShow);
		return 0;
	}
	CreateThisTaskForAllUsers();
	return MainAdmin(pCmdLine, nCmdShow);
}
