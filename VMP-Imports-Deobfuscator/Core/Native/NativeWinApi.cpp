#include "NativeWinApi.h"

// @note: @colby57: This file is not changed.

def_NtCreateThreadEx C_KernelWrapper::NtCreateThreadEx = 0;
def_NtDuplicateObject C_KernelWrapper::NtDuplicateObject = 0;
def_NtOpenProcess C_KernelWrapper::NtOpenProcess = 0;
def_NtOpenThread C_KernelWrapper::NtOpenThread = 0;
def_NtQueryObject C_KernelWrapper::NtQueryObject = 0;
def_NtQueryInformationFile C_KernelWrapper::NtQueryInformationFile = 0;
def_NtQueryInformationProcess C_KernelWrapper::NtQueryInformationProcess = 0;
def_NtQueryInformationThread C_KernelWrapper::NtQueryInformationThread = 0;
def_NtQuerySystemInformation C_KernelWrapper::NtQuerySystemInformation = 0;
def_NtQueryVirtualMemory C_KernelWrapper::NtQueryVirtualMemory = 0;
def_NtResumeProcess C_KernelWrapper::NtResumeProcess = 0;
def_NtResumeThread C_KernelWrapper::NtResumeThread = 0;
def_NtSetInformationThread C_KernelWrapper::NtSetInformationThread = 0;
def_NtSuspendProcess C_KernelWrapper::NtSuspendProcess = 0;
def_NtTerminateProcess C_KernelWrapper::NtTerminateProcess = 0;

def_NtOpenSymbolicLinkObject C_KernelWrapper::NtOpenSymbolicLinkObject = 0;
def_NtQuerySymbolicLinkObject C_KernelWrapper::NtQuerySymbolicLinkObject = 0;

def_RtlNtStatusToDosError C_KernelWrapper::RtlNtStatusToDosError = 0;
def_NtClose C_KernelWrapper::NtClose = 0;

C_KernelWrapper::C_KernelWrapper()
{
	HMODULE hModuleNtdll = GetModuleHandle(L"ntdll.dll");

	NtCreateThreadEx = (def_NtCreateThreadEx)GetProcAddress(hModuleNtdll, "NtCreateThreadEx");
	NtDuplicateObject = (def_NtDuplicateObject)GetProcAddress(hModuleNtdll, "NtDuplicateObject");
	NtOpenProcess = (def_NtOpenProcess)GetProcAddress(hModuleNtdll, "NtOpenProcess");
	NtOpenThread = (def_NtOpenThread)GetProcAddress(hModuleNtdll, "NtOpenThread");
	NtQueryObject = (def_NtQueryObject)GetProcAddress(hModuleNtdll, "NtQueryObject");
	NtQueryInformationFile = (def_NtQueryInformationFile)GetProcAddress(hModuleNtdll, "NtQueryInformationFile");
	NtQueryInformationProcess = (def_NtQueryInformationProcess)GetProcAddress(hModuleNtdll, "NtQueryInformationProcess");
	NtQueryInformationThread = (def_NtQueryInformationThread)GetProcAddress(hModuleNtdll, "NtQueryInformationThread");
	NtQuerySystemInformation = (def_NtQuerySystemInformation)GetProcAddress(hModuleNtdll, "NtQuerySystemInformation");
	NtQueryVirtualMemory = (def_NtQueryVirtualMemory)GetProcAddress(hModuleNtdll, "NtQueryVirtualMemory");
	NtResumeProcess = (def_NtResumeProcess)GetProcAddress(hModuleNtdll, "NtResumeProcess");
	NtResumeThread = (def_NtResumeThread)GetProcAddress(hModuleNtdll, "NtResumeThread");
	NtSetInformationThread = (def_NtSetInformationThread)GetProcAddress(hModuleNtdll, "NtSetInformationThread");
	NtSuspendProcess = (def_NtSuspendProcess)GetProcAddress(hModuleNtdll, "NtSuspendProcess");
	NtTerminateProcess = (def_NtTerminateProcess)GetProcAddress(hModuleNtdll, "NtTerminateProcess");
	NtOpenSymbolicLinkObject = (def_NtOpenSymbolicLinkObject)GetProcAddress(hModuleNtdll, "NtOpenSymbolicLinkObject");
	NtQuerySymbolicLinkObject = (def_NtQuerySymbolicLinkObject)GetProcAddress(hModuleNtdll, "NtQuerySymbolicLinkObject");

	RtlNtStatusToDosError = (def_RtlNtStatusToDosError)GetProcAddress(hModuleNtdll, "RtlNtStatusToDosError");
	NtClose = (def_NtClose)GetProcAddress(hModuleNtdll, "NtClose");
}