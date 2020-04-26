#include "pch.h"
#define NTGETNEXTPROCESS_STR "NtGetNextProcess"
#define NTOPENPROCESS_STR "NtOpenProcess"
#define EXIT_CODE 0
#if defined(_UNICODE) //Unicode
#define PROCESS_LIST { L"firefox.exe", L"sublime_text.exe" }
#define NTDLL L"ntdll.dll"
#else //Multibyte
#define PROCESS_LIST { "firefox.exe", "sublime_text.exe"  }
#define NTDLL "ntdll.dll"
#endif

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING, ** PPUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef std::basic_string<TCHAR> str_t;
typedef std::vector<str_t> vstr_t;
typedef NTSTATUS(NTAPI* NtGetNextProcess_t)(_In_ HANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes, _In_ ULONG Flags, _Out_ PHANDLE NewProcessHandle);
typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

void KillProcesses(vstr_t processNames)
{
	if (processNames.size() == 0) return;

	HMODULE ntdll = GetModuleHandle(NTDLL);
	if (!ntdll) return;
	NtGetNextProcess_t NtGetNextProcess = (NtGetNextProcess_t)GetProcAddress(ntdll, NTGETNEXTPROCESS_STR);
	if (!NtGetNextProcess) return;
	NtOpenProcess_t NtOpenProcess = (NtOpenProcess_t)GetProcAddress(ntdll, NTOPENPROCESS_STR);
	if (!NtOpenProcess) return;

	HANDLE curHandle = 0;
	TCHAR buffer[MAX_PATH];
	while (NtGetNextProcess(curHandle, MAXIMUM_ALLOWED, NULL, NULL, &curHandle) == 0)
	{
		GetModuleFileNameEx(curHandle, 0, buffer, sizeof(buffer) / sizeof(TCHAR));
		str_t strProcPath = buffer;
		for (size_t i = 0; i < processNames.size(); i++)
		{
			str_t strProcName = processNames.at(i);
			size_t size = strProcPath.length() - strProcName.length();
			bool bKill = true;
			for (size_t j = 0; j < strProcName.length(); j++)
			{
				bKill &= strProcPath.c_str()[size + j] == strProcName.c_str()[j];
			}

			if (bKill)
				TerminateProcess(curHandle, EXIT_CODE);
		}
	}

	CloseHandle(ntdll);
}

int main()
{
	KillProcesses(PROCESS_LIST);
	LockWorkStation();
	return 0;
}