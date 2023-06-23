#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

#define IMPORTAPI(DLLFILE, FUNCNAME, RETTYPE, ...)                             \
  typedef RETTYPE(WINAPI *type##FUNCNAME)(__VA_ARGS__);                        \
  type##FUNCNAME FUNCNAME = (type##FUNCNAME)GetProcAddress(                    \
      (LoadLibraryW(DLLFILE), GetModuleHandleW(DLLFILE)), #FUNCNAME);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

HMODULE getModuleHandle(LPCWSTR libraryName) {
  const LIST_ENTRY *head =
      &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
  LIST_ENTRY *next = head->Flink;

  while (next != head) {
    LDR_DATA_TABLE_ENTRY *entry =
        CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    const UNICODE_STRING *basename =
        (UNICODE_STRING *)((BYTE *)&entry->FullDllName +
                           sizeof(UNICODE_STRING));

    if (_wcsicmp(libraryName, basename->Buffer) == 0) {
      return (HMODULE)entry->DllBase;
    }

    next = next->Flink;
  }
  return NULL;
}

HMODULE queueLoadLibrary(WCHAR *libraryName, BOOL swtch) {
  IMPORTAPI(L"NTDLL.dll", NtWaitForSingleObject, NTSTATUS, HANDLE, BOOLEAN,
            PLARGE_INTEGER);

  if (swtch) {
    IMPORTAPI(L"NTDLL.dll", RtlQueueWorkItem, NTSTATUS, PVOID, PVOID, ULONG);

    if (NT_SUCCESS(RtlQueueWorkItem(&LoadLibraryW, (PVOID)libraryName,
                                    WT_EXECUTEDEFAULT))) {
      LARGE_INTEGER timeout;
      timeout.QuadPart = -500000;
      NtWaitForSingleObject(NtCurrentProcess(), FALSE, &timeout);
    }
  } else {
    IMPORTAPI(L"NTDLL.dll", RtlRegisterWait, NTSTATUS, PHANDLE, HANDLE, PVOID,
              PVOID, ULONG, ULONG);
    HANDLE newWaitObject;
    HANDLE eventObject = CreateEventW(NULL, FALSE, FALSE, NULL);

    if (NT_SUCCESS(RtlRegisterWait(&newWaitObject, eventObject, LoadLibraryW,
                                   (PVOID)libraryName, 0, WT_EXECUTEDEFAULT))) {
      WaitForSingleObject(eventObject, 500);
    }
  }

  return getModuleHandle(libraryName);
}

int main(int argc, char ** argv) {
  WCHAR libraryName1[] = L"ws2_32.dll";
  WCHAR libraryName2[] = L"dnsapi.dll";

  HMODULE moduleHandle = queueLoadLibrary(libraryName1, TRUE);
  printf("%ws loaded at 0x%p via RtlQueueWorkItem\n", libraryName1, moduleHandle);
  FreeLibrary(moduleHandle);

  moduleHandle = queueLoadLibrary(libraryName2, FALSE);
  printf("%ws loaded at 0x%p via RtlRegisterWait\n", libraryName2, moduleHandle);
  FreeLibrary(moduleHandle);


}
