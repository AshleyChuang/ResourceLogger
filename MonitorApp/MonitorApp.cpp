#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <commdlg.h>
#include <math.h>
#include <intrin.h>
#include "Shlwapi.h"
#include <xmmintrin.h>
#include <emmintrin.h>

#include <time.h>
#include <pdh.h>
#include <pdhmsg.h>

#include <Iphlpapi.h>

#include <Wbemidl.h>

#include <iostream>
#include <string>
#include <fstream>
#include <wininet.h>
#include <urlmon.h>
#include <string.h>
#include <Assert.h>
using namespace std;

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"pdh.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "wininet")
#pragma warning(default:4265)
#pragma warning(disable:4996)

#define TIMER_ID 431879
#define USE_AAC 1
#define _WIN32_DCOM

int printErrorMessage = 0;
int printResult = 0;
int unit = 1; // 0: Bytes, 1:KB, 2:MB, 3:GB

// ===== ===== ===== ===== GetInformation() Starts ===== ===== ===== =====
// query for virtual and physical memory
MEMORYSTATUSEX memInfo;
double totalVirMem, totalPhyMem;
// ===== ===== Get available disk ===== ===== 
LPCWSTR pszDrive = NULL;
BOOL result;
DWORD dwSectPerClust, dwBytesPerSect, dwFreeClusters, dwTotalClusters;
double freeDiskToCaller, totalDisk, freeDisk, usedDisk;
// ===== ===== Get network information ===== ===== 
DWORD dwSize = 0;
DWORD dwRetVal = 0;
// variables used for GetIfTable and GetIfEntry
MIB_IFTABLE *pIfTable;
MIB_IFROW *pIfRow;
double prevRxData = -1;
double prevTxData = -1;
double prevRxSeg = -1;
double prevTxSeg = -1;
bool upload_info = false;
bool upload_cinebench = false;
char* mac_address;

char* getMAC() {
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(AdapterInfo);
	char *mac_addr = (char*)malloc(17);

	AdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen     variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {

		AdapterInfo = (IP_ADAPTER_INFO *)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;// Contains pointer to current adapter info
		do {
			sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
				pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
			printf("Address: %s, mac: %s\n", pAdapterInfo->IpAddressList.IpAddress.String, mac_addr);
			return mac_addr;

			printf("\n");
			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}
	free(AdapterInfo);
}

void GetInformation(){
	FILE *pFile = fopen("C:\\users\\public\\documents\\info.txt", "w+");
	// ===== ===== Get CPU info and cores ===== =====
	int CPUInfo[4] = { -1 };
	unsigned   nExIds, i = 0;
	char CPUBrandString[0x40];
	// Get the information associated with each extended ID.
	__cpuid(CPUInfo, 0x80000000);
	nExIds = CPUInfo[0];
	for (i = 0x80000000; i <= nExIds; ++i){
		__cpuid(CPUInfo, i);
		// Interpret CPU brand string
		if (i == 0x80000002)
			memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
		else if (i == 0x80000003)
			memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
		else if (i == 0x80000004)
			memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
	}

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	// ===== ===== Get total virtual and physical memory ===== ===== 
	// Total virtual memory
	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
	GlobalMemoryStatusEx(&memInfo);
	switch (unit){
	case 0:	totalVirMem = memInfo.ullTotalPageFile;							break;
	case 1:	totalVirMem = memInfo.ullTotalPageFile / 1024;					break;
	case 2:	totalVirMem = memInfo.ullTotalPageFile / 1024 / 1024;			break;
	case 3:	totalVirMem = memInfo.ullTotalPageFile / 1024 / 1024 / 1024;	break;
	}

	// Total physical memory
	switch (unit){
	case 0:	totalPhyMem = memInfo.ullTotalPhys;							break;
	case 1:	totalPhyMem = memInfo.ullTotalPhys / 1024;					break;
	case 2:	totalPhyMem = memInfo.ullTotalPhys / 1024 / 1024;			break;
	case 3:	totalPhyMem = memInfo.ullTotalPhys / 1024 / 1024 / 1024;	break;
	}

	// ===== ===== Get total disk ===== ===== 
	result = GetDiskFreeSpace(pszDrive, &dwSectPerClust, &dwBytesPerSect, &dwFreeClusters, &dwTotalClusters);
	if (printErrorMessage){
		if (GetLastError() != 0){
			fprintf(stderr, "GetDiskFreeSpace error code: %d\n", GetLastError());
			fflush(stderr);
		}
		else{
			fprintf(stderr, "Successful - GetDiskFreeSpace\n");
		}
	}
	if (result) {
		/* force 64-bit math */
		switch (unit){
		case 0:	totalDisk = (__int64)dwTotalClusters * dwSectPerClust * dwBytesPerSect;							break;
		case 1:	totalDisk = (__int64)dwTotalClusters * dwSectPerClust * dwBytesPerSect / 1024;					break;
		case 2:	totalDisk = (__int64)dwTotalClusters * dwSectPerClust * dwBytesPerSect / 1024 / 1024;			break;
		case 3:	totalDisk = (__int64)dwTotalClusters * dwSectPerClust * dwBytesPerSect / 1024 / 1024 / 1024;	break;
		}
	}

	// ===== ===== Get network adapter information ===== =====
	// Declare and initialize variables
	int index, j;

	// Info to log
	int target_index = -1;
	double max_speed = -1;
	char description[MAXLEN_IFDESCR];
	char type[30];

	// Allocate memory for pointers
	pIfTable = (MIB_IFTABLE *)malloc(sizeof (MIB_IFTABLE));
	if (pIfTable == NULL){
		if (printErrorMessage)	printf("Error allocating memory needed to call GetIfTable()!\n");
		exit(1);
	}
	else{
		if (printErrorMessage)	printf("Memory needed to call GetIfTable() has been allocated!\n");
	}

	// Before calling GetIfEntry, we call GetIfTable to make
	// sure there are entries to get and retrieve the interface index.

	// Make an initial call to GetIfTable to get the necessary size into dwSize
	dwSize = sizeof (MIB_IFTABLE);
	if (GetIfTable(pIfTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER){ // Not enough memory; re-allocation
		free(pIfTable);
		pIfTable = (MIB_IFTABLE *)malloc(dwSize);
		if (pIfTable == NULL){
			if (printErrorMessage)	printf("Error allocating memory!\n");
			exit(1);
		}
		else{
			if (printErrorMessage)	printf("(Dummy) Memory allocated successfully!\n");
		}
	}
	else{
		if (printErrorMessage)	printf("GetIfTable() should be fine!\n");
	}

	// Call GetIfTable() to get data
	if ((dwRetVal = GetIfTable(pIfTable, &dwSize, 0)) == NO_ERROR){
		if (pIfTable->dwNumEntries > 0){
			pIfRow = (MIB_IFROW *)malloc(sizeof (MIB_IFROW));
			if (pIfRow == NULL){
				if (printErrorMessage)	printf("Error allocating memory!\n");
				if (pIfTable != NULL){
					free(pIfTable);
					pIfTable = NULL;
				}
				exit(1);
			}
			else{
				if (printErrorMessage)	printf("Memory allocated successfully for 2nd call!\n");
			}

			// Get the info of the operational adapter with the maximum speed
			for (index = 0; index < (int)pIfTable->dwNumEntries; index++){
				pIfRow->dwIndex = pIfTable->table[index].dwIndex;
				if ((dwRetVal = GetIfEntry(pIfRow)) == NO_ERROR){
					if ((int)pIfRow->dwSpeed > max_speed &&
						pIfRow->dwOperStatus == IF_OPER_STATUS_OPERATIONAL &&
						(pIfRow->dwType == IF_TYPE_ETHERNET_CSMACD ||
						pIfRow->dwType == IF_TYPE_IEEE80211 ||
						pIfRow->dwType == IF_TYPE_IEEE1394 ||
						pIfRow->dwType == IF_TYPE_IEEE80216_WMAN) &&
						pIfRow->dwInOctets > 0){

						for (j = 0; j < (int)pIfRow->dwDescrLen; j++){
							description[j] = pIfRow->bDescr[j];
						}

						switch (pIfRow->dwType){
						case IF_TYPE_ETHERNET_CSMACD:	sprintf(type, "Ethernet");					break;
						case IF_TYPE_IEEE80211:			sprintf(type, "IEEE 802.11 Wireless");		break;
						case IF_TYPE_IEEE1394:			sprintf(type, "IEEE 1394 Firewire");		break;
						case IF_TYPE_IEEE80216_WMAN:	sprintf(type, "IEEE 802.16 WiMax");			break;
						default:						sprintf(type, "Unknown type %ld\n", pIfRow->dwType);	break;
						}
						target_index = index;
						max_speed = pIfRow->dwSpeed; // original dwSpeed is bit/s
						prevRxData = pIfRow->dwInOctets;
						prevTxData = pIfRow->dwOutOctets;
					}
				}
				else {
					if (printErrorMessage)	printf("GetIfEntry failed for index %d with error: %ld\n", index, dwRetVal);
				}
			}
		}
		else {
			if (printErrorMessage)	printf("\tGetIfTable failed with error: %ld\n", dwRetVal);
		}
	}
	
	
	// ===== ===== Output To File ===== =====
	// CPU info, cores, totalVirMem, totalPhyMem, totalDisk, network information
	fprintf(pFile, "%s\n", CPUBrandString); //string includes manufacturer, model and clockspeed
	fprintf(pFile, "%d\n", sysInfo.dwNumberOfProcessors);
	fprintf(pFile, "%.0lf\n", totalVirMem);
	fprintf(pFile, "%.0lf\n", totalPhyMem);
	fprintf(pFile, "%.0lf\n", totalDisk);
	fprintf(pFile, "%s\n", description);
	fprintf(pFile, "%s\n", type);
	
	// Valid file path name (file is there).
	LPCWSTR cinebench_path = (L"C:\\users\\public\\documents\\cinebench.txt");

	// Return value from "PathFileExists".
	int retval;

	// Search for the presence of a file with a true result.
	retval = PathFileExists(cinebench_path);
	if (retval != 1) {
		//system("cinebench.exe -cb_all > C:\\users\\public\\documents\\cinebench.txt");
	}
	
	if (printResult){
		printf("outputformat: CPU info string / cores / totalVirMem / totalPhyMem / totalDisk / network information\n");
		printf("CPU Type: %s\n", CPUBrandString);
		printf("Number of Cores: %d\n", sysInfo.dwNumberOfProcessors);
		printf("===\n");

		switch (unit){
		case 0:	printf("[unit: Bytes]\n");	break;
		case 1:	printf("[unit: KB]\n");		break;
		case 2:	printf("[unit: MB]\n");		break;
		case 3:	printf("[unit: GB]\n");		break;
		}
		
		printf("totalVirMem:\t%.0lf\n", totalVirMem);
		printf("totalPhyMem:\t%.0lf\n", totalPhyMem);
		printf("===\n");

		printf("totalDisk:\t%.0lf\n", totalDisk);
		printf("===\n");

		printf("network adapter:%s\n", description);
		printf("type:\t\t%s\n", type);
		printf("===== ===== ===== =====\n\n");
	}
	fclose(pFile);
}
// ===== ===== ===== ===== GetInformation() Ends ===== ===== ===== =====

// ===== ===== ===== ===== PeriodicalLogging() Starts ===== ===== ===== =====
// query for CPU usage
HQUERY cpu_query;
// query for System wide context switch
HCOUNTER cpu_counter;
PDH_HCOUNTER cpu_pdh_counter;
PDH_FMT_COUNTERVALUE cpu_pdhValue;
DWORD dwValue;
PDH_STATUS status;
HQUERY hQuery = NULL;

// query for virtual and physical memory
double usedVirMem, usedPhyMem;
void PeriodicalLogging() {
	time_t start_time;
	char buff[100];
	cpu_counter = (HCOUNTER *)GlobalAlloc(GPTR, sizeof(HCOUNTER));
	FILE *pFile = fopen("C:\\users\\public\\documents\\log.csv", "a+");

	// Querying CPU usage and context switch
	// ===== ===== Open Query ===== ===== 
	status = PdhOpenQuery(NULL, NULL, &cpu_query);
	if (printErrorMessage) {
		if (status != ERROR_SUCCESS) {
			fprintf(stderr, "CPU PdhOpenQuery error: 0x%x\n\n", status);
			fflush(stderr);
		}
		else {
			fprintf(stderr, "Successful - CPU PdhOpenQuery\n");
		}
	}

	// ===== ===== Add Counter ===== ===== 
	status = PdhAddCounter(cpu_query, L"\\Processor(_Total)\\% Processor Time", NULL, &cpu_counter);
	if (printErrorMessage) {
		if (status != ERROR_SUCCESS) {
			fprintf(stderr, "CPU PdhAddCounter error: 0x%x\n", status);
			if (status == PDH_INVALID_ARGUMENT) fprintf(stderr, "ARGUMENT\n");
			else if (status == PDH_INVALID_DATA) fprintf(stderr, "INVALID_DATA\n");
			else if (status == PDH_INVALID_HANDLE) fprintf(stderr, "INVALID_HANDLE\n");
			fflush(stderr);
		}
		else {
			fprintf(stderr, "Successful - CPU PdhAddCounter\n");
		}
	}

	// ===== ===== Get Data ===== ===== 
	status = PdhCollectQueryData(cpu_query);
	if (printErrorMessage) {
		if (status != ERROR_SUCCESS) {
			fprintf(stderr, "CPU PdhCollectQueryData error: 0x%x\n", status);
			fflush(stderr);
		}
		else {
			fprintf(stderr, "Successful - CPU PdhCollectQueryData\n");
		}
	}

	Sleep(1000); // Pause a moment between data samples

	// ===== ===== Get Data Again ===== =====
	status = PdhCollectQueryData(cpu_query);
	if (printErrorMessage) {
		if (status != ERROR_SUCCESS) {
			fprintf(stderr, "CPU PdhCollectQueryData error: 0x%x\n", status);
			fflush(stderr);
		}
		else {
			fprintf(stderr, "Successful - CPU PdhCollectQueryData\n");
		}
	}

	// ===== ===== Format Counter Value ===== ===== 
	status = PdhGetFormattedCounterValue(cpu_counter, PDH_FMT_DOUBLE, &dwValue, &cpu_pdhValue);
	if (printErrorMessage) {
		if (status != ERROR_SUCCESS) {
			fprintf(stderr, "CPU PdhGetFormattedCounterValue error: 0x%x\n", status);
			if (status == PDH_INVALID_ARGUMENT) fprintf(stderr, "ARGUMENT\n");
			else if (status == PDH_INVALID_DATA) fprintf(stderr, "INVALID_DATA\n");
			else if (status == PDH_INVALID_HANDLE) fprintf(stderr, "INVALID_HANDLE\n");
			fflush(stderr);
		}
		else {
			fprintf(stderr, "Successful - CPU PdhGetFormattedCounterValue\n");
		}
	}

	// ===== ===== Querying used virtual and physical memory ===== ===== 
	// Virtual memory currently used
	switch (unit) {
	case 0:	usedVirMem = (memInfo.ullTotalPageFile - memInfo.ullAvailPageFile);							break;
	case 1:	usedVirMem = (memInfo.ullTotalPageFile - memInfo.ullAvailPageFile) / 1024;					break;
	case 2:	usedVirMem = (memInfo.ullTotalPageFile - memInfo.ullAvailPageFile) / 1024 / 1024;			break;
	case 3:	usedVirMem = (memInfo.ullTotalPageFile - memInfo.ullAvailPageFile) / 1024 / 1024 / 1024;	break;
	}

	// Physical memory currently used
	switch (unit) {
	case 0:	usedPhyMem = (memInfo.ullTotalPhys - memInfo.ullAvailPhys);							break;
	case 1:	usedPhyMem = (memInfo.ullTotalPhys - memInfo.ullAvailPhys) / 1024;					break;
	case 2:	usedPhyMem = (memInfo.ullTotalPhys - memInfo.ullAvailPhys) / 1024 / 1024;			break;
	case 3:	usedPhyMem = (memInfo.ullTotalPhys - memInfo.ullAvailPhys) / 1024 / 1024 / 1024;	break;
	}

	// ===== ===== Get used disk ===== ===== 
	result = GetDiskFreeSpace(pszDrive, &dwSectPerClust, &dwBytesPerSect, &dwFreeClusters, &dwTotalClusters);
	if (printErrorMessage) {
		if (GetLastError() != 0) {
			fprintf(stderr, "GetDiskFreeSpace error code: %d\n", GetLastError());
			fflush(stderr);
		}
		else {
			fprintf(stderr, "Successful - GetDiskFreeSpace\n");
		}
	}
	if (result) {
		/* force 64-bit math */
		switch (unit) {
		case 0:	totalDisk = (__int64)dwTotalClusters * dwSectPerClust * dwBytesPerSect;							break;
		case 1:	totalDisk = (__int64)dwTotalClusters * dwSectPerClust * dwBytesPerSect / 1024;					break;
		case 2:	totalDisk = (__int64)dwTotalClusters * dwSectPerClust * dwBytesPerSect / 1024 / 1024;			break;
		case 3:	totalDisk = (__int64)dwTotalClusters * dwSectPerClust * dwBytesPerSect / 1024 / 1024 / 1024;	break;
		}
		switch (unit) {
		case 0:	freeDisk = (__int64)dwFreeClusters * dwSectPerClust * dwBytesPerSect;							break;
		case 1:	freeDisk = (__int64)dwFreeClusters * dwSectPerClust * dwBytesPerSect / 1024;					break;
		case 2:	freeDisk = (__int64)dwFreeClusters * dwSectPerClust * dwBytesPerSect / 1024 / 1024;			break;
		case 3:	freeDisk = (__int64)dwFreeClusters * dwSectPerClust * dwBytesPerSect / 1024 / 1024 / 1024;	break;
		}
		usedDisk = totalDisk - freeDisk;
	}

	// ===== ===== Get disk read/write speed ===== =====
	// To add error checking,
	// check returned HRESULT below where collected.
	HRESULT                 hr = S_OK;
	IWbemRefresher          *pRefresher = NULL;
	IWbemConfigureRefresher *pConfig = NULL;
	IWbemHiPerfEnum         *pEnum = NULL;
	IWbemServices           *pNameSpace = NULL;
	IWbemLocator            *pWbemLocator = NULL;
	IWbemObjectAccess       **apEnumAccess = NULL;
	BSTR                    bstrNameSpace = NULL;
	long                    lID = 0;
	long					lDiskReadBytesPerSecHandle = 0;
	long					lDiskWriteBytesPerSecHandle = 0;
	DWORD					dwDiskReadBytesPerSec = 0;
	DWORD					dwDiskWriteBytesPerSec = 0;
	DWORD                   dwNumObjects = 0;
	DWORD                   dwNumReturned = 0;
	DWORD                   i = 0;
	int                     x = 0;

	if (FAILED(hr = CoInitializeEx(NULL, COINIT_MULTITHREADED)) ||
		FAILED(hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, 0)) ||
		FAILED(hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&pWbemLocator))) {
		goto CLEANUP;
	}
	// Connect to the desired namespace.
	bstrNameSpace = SysAllocString(L"\\\\.\\root\\cimv2");
	if (NULL == bstrNameSpace) {
		hr = E_OUTOFMEMORY;
		goto CLEANUP;
	}
	if (FAILED(hr = pWbemLocator->ConnectServer(bstrNameSpace,
		NULL, // User name
		NULL, // Password
		NULL, // Locale
		0L,   // Security flags
		NULL, // Authority
		NULL, // Wbem context
		&pNameSpace))) {
		goto CLEANUP;
	}
	pWbemLocator->Release();
	pWbemLocator = NULL;
	SysFreeString(bstrNameSpace);
	bstrNameSpace = NULL;


	if (FAILED(hr = CoCreateInstance(CLSID_WbemRefresher, NULL, CLSCTX_INPROC_SERVER, IID_IWbemRefresher, (void**)&pRefresher))) {
		goto CLEANUP;
	}

	if (FAILED(hr = pRefresher->QueryInterface(IID_IWbemConfigureRefresher, (void **)&pConfig))) {
		goto CLEANUP;
	}

	// Add an enumerator to the refresher.
	if (FAILED(hr = pConfig->AddEnum(pNameSpace, L"Win32_PerfRawData_PerfDisk_PhysicalDisk", 0, NULL, &pEnum, &lID))) {
		goto CLEANUP;
	}
	pConfig->Release();
	pConfig = NULL;
	dwNumReturned = 0;
	dwNumObjects = 0;
	if (FAILED(hr = pRefresher->Refresh(0L))) {
		goto CLEANUP;
	}

	hr = pEnum->GetObjects(0L, dwNumObjects, apEnumAccess, &dwNumReturned);
	// If the buffer was not big enough,
	// allocate a bigger buffer and retry.
	if (hr == WBEM_E_BUFFER_TOO_SMALL && dwNumReturned > dwNumObjects) {
		apEnumAccess = new IWbemObjectAccess*[dwNumReturned];
		if (NULL == apEnumAccess) {
			hr = E_OUTOFMEMORY;
			goto CLEANUP;
		}
		SecureZeroMemory(apEnumAccess, dwNumReturned * sizeof(IWbemObjectAccess*));
		dwNumObjects = dwNumReturned;

		if (FAILED(hr = pEnum->GetObjects(0L, dwNumObjects, apEnumAccess, &dwNumReturned))) {
			goto CLEANUP;
		}
	}
	else {
		if (hr == WBEM_S_NO_ERROR) {
			hr = WBEM_E_NOT_FOUND;
			goto CLEANUP;
		}
	}

	// First time through, get the handles.
	if (0 == x) {
		CIMTYPE DiskReadBytesPerSecType;
		CIMTYPE DiskWriteBytesPerSecType;
		if (FAILED(hr = apEnumAccess[0]->GetPropertyHandle(L"DiskReadBytesPerSec", &DiskReadBytesPerSecType, &lDiskReadBytesPerSecHandle)) ||
			FAILED(hr = apEnumAccess[0]->GetPropertyHandle(L"DiskWriteBytesPerSec", &DiskWriteBytesPerSecType, &lDiskWriteBytesPerSecHandle))) {
			goto CLEANUP;
		}
	}

	if (FAILED(hr = apEnumAccess[0]->ReadDWORD(lDiskReadBytesPerSecHandle, &dwDiskReadBytesPerSec)) ||
		FAILED(hr = apEnumAccess[0]->ReadDWORD(lDiskWriteBytesPerSecHandle, &dwDiskWriteBytesPerSec))) {
		goto CLEANUP;
	}
	switch (unit) {
	case 0:	dwDiskReadBytesPerSec /= 10000;							break;
	case 1:	dwDiskReadBytesPerSec /= 1024 * 10000;					break;
	case 2:	dwDiskReadBytesPerSec /= 1024 * 1024 * 10000;			break;
	case 3:	dwDiskReadBytesPerSec /= 1024 * 1024 * 1024 * 10000;	break;
	}
	switch (unit) {
	case 0:	dwDiskWriteBytesPerSec /= 10000;						break;
	case 1:	dwDiskWriteBytesPerSec /= 1024 * 10000;					break;
	case 2:	dwDiskWriteBytesPerSec /= 1024 * 1024 * 10000;			break;
	case 3:	dwDiskWriteBytesPerSec /= 1024 * 1024 * 1024 * 10000;	break;
	}

	// Done with the object
	apEnumAccess[0]->Release();
	apEnumAccess[0] = NULL;

	if (NULL != apEnumAccess) {
		delete[] apEnumAccess;
		apEnumAccess = NULL;
	}


	// exit loop here
CLEANUP:

	if (NULL != bstrNameSpace) {
		SysFreeString(bstrNameSpace);
	}

	if (NULL != apEnumAccess) {
		for (i = 0; i < dwNumReturned; i++) {
			if (apEnumAccess[i] != NULL) {
				apEnumAccess[i]->Release();
				apEnumAccess[i] = NULL;
			}
		}
		delete[] apEnumAccess;
	}
	if (NULL != pWbemLocator) {
		pWbemLocator->Release();
	}
	if (NULL != pNameSpace) {
		pNameSpace->Release();
	}
	if (NULL != pEnum) {
		pEnum->Release();
	}
	if (NULL != pConfig) {
		pConfig->Release();
	}
	if (NULL != pRefresher) {
		pRefresher->Release();
	}

	CoUninitialize();

	if (FAILED(hr)) {
		if (printErrorMessage)	printf("Error status=%08x\n", hr);
	}

	// ===== ===== Get network usage ===== =====
	// Declare and initialize variables
	int index;
	int target_index = -1;

	// Info to log
	double max_speed = -1;
	double rxData = -1;
	double txData = -1;

	// Allocate memory for pointers
	pIfTable = (MIB_IFTABLE *)malloc(sizeof(MIB_IFTABLE));
	if (pIfTable == NULL) {
		if (printErrorMessage)	printf("Error allocating memory needed to call GetIfTable()!\n");
		exit(1);
	}
	else {
		if (printErrorMessage)	printf("Memory needed to call GetIfTable() has been allocated!\n");
	}

	// Before calling GetIfEntry, we call GetIfTable to make
	// sure there are entries to get and retrieve the interface index.

	// Make an initial call to GetIfTable to get the necessary size into dwSize
	dwSize = sizeof(MIB_IFTABLE);
	if (GetIfTable(pIfTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) { // Not enough memory; re-allocation
		free(pIfTable);
		pIfTable = (MIB_IFTABLE *)malloc(dwSize);
		if (pIfTable == NULL) {
			if (printErrorMessage)	printf("Error allocating memory!\n");
			exit(1);
		}
		else {
			if (printErrorMessage)	printf("(Dummy) Memory allocated successfully!\n");
		}
	}
	else {
		if (printErrorMessage)	printf("GetIfTable() should be fine!\n");
	}

	// Call GetIfTable() to get data
	if ((dwRetVal = GetIfTable(pIfTable, &dwSize, 0)) == NO_ERROR) {
		if (pIfTable->dwNumEntries > 0) {
			pIfRow = (MIB_IFROW *)malloc(sizeof(MIB_IFROW));
			if (pIfRow == NULL) {
				if (printErrorMessage)	printf("Error allocating memory!\n");
				if (pIfTable != NULL) {
					free(pIfTable);
					pIfTable = NULL;
				}
				exit(1);
			}
			else {
				if (printErrorMessage)	printf("Memory allocated successfully for 2nd call!\n");
			}

			// Get the info of the operational adapter with the maximum speed
			for (index = 0; index < (int)pIfTable->dwNumEntries; index++) {
				pIfRow->dwIndex = pIfTable->table[index].dwIndex;
				if ((dwRetVal = GetIfEntry(pIfRow)) == NO_ERROR) {
					if ((int)pIfRow->dwSpeed > max_speed &&
						pIfRow->dwOperStatus == IF_OPER_STATUS_OPERATIONAL &&
						(pIfRow->dwType == IF_TYPE_ETHERNET_CSMACD ||
							pIfRow->dwType == IF_TYPE_IEEE80211 ||
							pIfRow->dwType == IF_TYPE_IEEE1394 ||
							pIfRow->dwType == IF_TYPE_IEEE80216_WMAN) &&
						pIfRow->dwInOctets > 0) {

						target_index = index;
						max_speed = pIfRow->dwSpeed; // original dwSpeed is bit/s
						switch (unit) {
						case 0:	rxData = (pIfRow->dwInOctets - prevRxData);							break;
						case 1:	rxData = (pIfRow->dwInOctets - prevRxData) / 1024;					break;
						case 2:	rxData = (pIfRow->dwInOctets - prevRxData) / 1024 / 1024;			break;
						case 3:	rxData = (pIfRow->dwInOctets - prevRxData) / 1024 / 1024 / 1024;	break;
						}
						switch (unit) {
						case 0:	txData = (pIfRow->dwOutOctets - prevTxData);							break;
						case 1:	txData = (pIfRow->dwOutOctets - prevTxData) / 1024;					break;
						case 2:	txData = (pIfRow->dwOutOctets - prevTxData) / 1024 / 1024;			break;
						case 3:	txData = (pIfRow->dwOutOctets - prevTxData) / 1024 / 1024 / 1024;	break;
						}
						prevRxData = pIfRow->dwInOctets;
						prevTxData = pIfRow->dwOutOctets;
					}
				}
				else {
					if (printErrorMessage)	printf("GetIfEntry failed for index %d with error: %ld\n", index, dwRetVal);
				}
			}
			switch (unit) {
			case 0:	max_speed = (max_speed / 8);							break;
			case 1:	max_speed = (max_speed / 8) / 1024;					break;
			case 2:	max_speed = (max_speed / 8) / 1024 / 1024;			break;
			case 3:	max_speed = (max_speed / 8) / 1024 / 1024 / 1024;	break;
			}
		}
		else {
			if (printErrorMessage)	printf("\tGetIfTable failed with error: %ld\n", dwRetVal);
		}
	}

	// ===== ===== Output To File ===== =====
	start_time = time(0);
	strftime(buff, 100, "%Y-%m-%d-%H-%M-%S", localtime(&start_time));

	fprintf(pFile, "%s, ", buff);
	// ===== ===== Get IP address ===== =====
	/*
	string line;
	ifstream IPFile;
	int offset;
	char* search0 = "IPv4 Address. . . . . . . . . . . :";      // search pattern

	system("ipconfig > ip.txt");

	IPFile.open("ip.txt");
	if (IPFile.is_open())
	{
		while (!IPFile.eof())
		{
			getline(IPFile, line);
			if ((offset = line.find(search0, 0)) != string::npos)
			{
				//   IPv4 Address. . . . . . . . . . . : 1
				//1234567890123456789012345678901234567890
				line.erase(0, 39);
				cout << line << endl;
				const char* IPaddress = line.c_str();
				fprintf(pFile, "%s, ", IPaddress);
				IPFile.close();
			}
		}
	}
	*/
	HINTERNET hInternet = NULL;
	HINTERNET hFile;
	DWORD rSize;
	char buffer[128] = {'\0'};
	char *no_internet = "No Internet";
	char* buffer2 = (char*) malloc(sizeof(char)*128);
	LPCWSTR url = L"http://checkip.dyndns.org/";
	if (InternetCheckConnection(url, FLAG_ICC_FORCE_CONNECTION, 0)) {
		if ((hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0))!= NULL) {
			if ((hFile = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0))!= NULL) {
				if (InternetReadFile(hFile, &buffer, sizeof(buffer), &rSize)) {
					buffer[rSize] = '\0';

					InternetCloseHandle(hFile);
					InternetCloseHandle(hInternet);

					char* Token;
					Token = strrchr(buffer, ':');
					Token = strtok(Token, "<");

					strncpy(buffer, Token + 2, sizeof(buffer));
					fprintf(pFile, "%s, ", buffer);
				}
				else {
					fprintf(pFile, "%s, ", no_internet);
				}
			}
			else {
				fprintf(pFile, "%s, ", no_internet);
			}
		}
		else {
			fprintf(pFile, "%s, ", no_internet);
		}
		
	}
	else {
		fprintf(pFile, "%s, ", no_internet);
	}
	
	//buffer[strlen(Token)] = '\0';
	
	
	fprintf(pFile, "%.2lf, ", (double)cpu_pdhValue.doubleValue);
	fprintf(pFile, "%.0lf, ", usedVirMem);
	fprintf(pFile, "%.0lf, ", usedPhyMem);
	fprintf(pFile, "%.0lf, ", usedDisk);
	fprintf(pFile, "%lu, ", dwDiskReadBytesPerSec);
	fprintf(pFile, "%lu, ", dwDiskWriteBytesPerSec);
	fprintf(pFile, "%.0lf, ", max_speed);
	fprintf(pFile, "%.0lf, ", rxData);
	fprintf(pFile, "%.0lf\n", txData);

	if (printResult){
		printf("outputformat: Time, CPU usage, usedVirMem, usedPhyMem, usedDisk, DiskReadSpeed, DiskWriteSpeed, Network speed, rxData, txData\n");
		printf("%s, ", buff);
		printf("%.2lf, ", (double)cpu_pdhValue.doubleValue);
		printf("%.0lf, ", usedVirMem);
		printf("%.0lf, ", usedPhyMem);
		printf("%.0lf, ", usedDisk);
		printf("%lu, ", dwDiskReadBytesPerSec);
		printf("%lu, ", dwDiskWriteBytesPerSec);
		printf("%.0lf, ", max_speed);
		printf("%.0lf, ", rxData);
		printf("%.0lf\n", txData);
		printf("===\n");
		switch (unit){
		case 0:	printf("[unit: Bytes]\n");	break;
		case 1:	printf("[unit: KB]\n");		break;
		case 2:	printf("[unit: MB]\n");		break;
		case 3:	printf("[unit: GB]\n");		break;
		}
		printf("Time:\t\t\t%s\n", buff);
		printf("CPU usage:\t\t%.2lf\n", (double)cpu_pdhValue.doubleValue);
		printf("usedVirMem:\t\t%.0lf\n", usedVirMem);
		printf("usedPhyMem:\t\t%.0lf\n", usedPhyMem);
		printf("usedDisk:\t\t%.0lf\n", usedDisk);
		printf("Disk read speed:\t%lu\n", dwDiskReadBytesPerSec);
		printf("Disk write speed:\t%lu\n", dwDiskWriteBytesPerSec);
		printf("Network Speed:\t\t%.0lf\n", max_speed);
		printf("rxData:\t\t\t%.0lf\n", rxData);
		printf("txData:\t\t\t%.0lf\n", txData);
		printf("===== ===== ===== =====\n\n");
	}

	// ===== ===== Close Query ===== ===== 
	if (hQuery)
		PdhCloseQuery(hQuery);
	fclose(pFile);
}
// ===== ===== ===== ===== PeriodicalLogging() Ends ===== ===== ===== =====

// ===== ===== ===== ===== Run at startup() Starts ===== ===== ===== =====
BOOL IsMyProgramRegisteredForStartup(PCWSTR pszAppName){
	HKEY hKey = NULL;
	LONG lResult = 0;
	BOOL fSuccess = TRUE;
	DWORD dwRegType = REG_SZ;
	wchar_t szPathToExe[MAX_PATH] = {};
	DWORD dwSize = sizeof(szPathToExe);

	lResult = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hKey);

	fSuccess = (lResult == 0);

	if (fSuccess){
		lResult = RegGetValueW(hKey, NULL, pszAppName, RRF_RT_REG_SZ, &dwRegType, szPathToExe, &dwSize);
		fSuccess = (lResult == 0);
	}

	if (fSuccess){
		fSuccess = (wcslen(szPathToExe) > 0) ? TRUE : FALSE;
	}

	if (hKey != NULL){
		RegCloseKey(hKey);
		hKey = NULL;
	}

	return fSuccess;
}

BOOL RegisterMyProgramForStartup(PCWSTR pszAppName, PCWSTR pathToExe, PCWSTR args){
	HKEY hKey = NULL;
	LONG lResult = 0;
	BOOL fSuccess = TRUE;
	DWORD dwSize;

	const size_t count = MAX_PATH * 2;
	wchar_t szValue[count] = {};


	wcscpy_s(szValue, count, L"\"");
	wcscat_s(szValue, count, pathToExe);
	wcscat_s(szValue, count, L"\" ");

	if (args != NULL){
		// caller should make sure "args" is quoted if any single argument has a space
		// e.g. (L"-name \"Mark Voidale\"");
		wcscat_s(szValue, count, args);
	}

	lResult = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);

	fSuccess = (lResult == 0);

	if (fSuccess){
		dwSize = (wcslen(szValue) + 1) * 2;
		lResult = RegSetValueExW(hKey, pszAppName, 0, REG_SZ, (BYTE*)szValue, dwSize);
		fSuccess = (lResult == 0);
	}

	if (hKey != NULL){
		RegCloseKey(hKey);
		hKey = NULL;
	}

	return fSuccess;
}

void RegisterProgram(){
	wchar_t szPathToExe[MAX_PATH];

	GetModuleFileNameW(NULL, szPathToExe, MAX_PATH);
	RegisterMyProgramForStartup(L"MonitorApp", szPathToExe, L"-foobar");
}
// ===== ===== ===== ===== Run at startup() Ends ===== ===== ===== =====

void UploadInfo(void)
{
	if (!upload_cinebench) {
		string file = "C:\\users\\public\\documents\\cinebench.txt";
		char *str2 = "_cinebench.txt";
		char * output_file = (char *)malloc(1 + strlen(mac_address) + strlen(str2));
		strcpy(output_file, mac_address);
		strcat(output_file, str2);

		WCHAR wsz[64];
		swprintf(wsz, L"%S", output_file);
		LPCWSTR cinebench_filename = wsz;


		if (!ifstream(file))
		{
			cout << "no file\n";
			return;
		}

		HINTERNET hint = InternetOpen(0, INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0);
		HINTERNET hftp = InternetConnect(hint, L"140.114.89.209", INTERNET_DEFAULT_FTP_PORT,
			L"ashley", L"ashley1213", INTERNET_SERVICE_FTP, 0, 0);

		if (FtpSetCurrentDirectory(hftp, L"/home/nmslab/ashley/ResourceLogger_Data"))
		{
			if (!FtpPutFile(hftp, L"C:\\users\\public\\documents\\cinebench.txt", cinebench_filename, FTP_TRANSFER_TYPE_BINARY, 0))
			{
				cout << "FAIL!" << endl;
				cout << GetLastError() << endl;
			}
			else
			{
				cout << "file sended !";
				upload_cinebench = true;
			}

		}
		InternetCloseHandle(hftp);
		InternetCloseHandle(hint);

	}
	if (!upload_info) {
		string file = "C:\\users\\public\\documents\\info.txt";

		char *str2 = "_into.txt";
		char * output_file = (char *)malloc(1 + strlen(mac_address) + strlen(str2));
		strcpy(output_file, mac_address);
		strcat(output_file, str2);

		WCHAR wsz[64];
		swprintf(wsz, L"%S", output_file);
		LPCWSTR info_filename = wsz;

		if (!ifstream(file))
		{
			cout << "no file\n";
			return;
		}

		HINTERNET hint = InternetOpen(0, INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0);
		HINTERNET hftp = InternetConnect(hint, L"140.114.89.209", INTERNET_DEFAULT_FTP_PORT,
			L"ashley", L"ashley1213", INTERNET_SERVICE_FTP, 0, 0);

		if (FtpSetCurrentDirectory(hftp, L"/home/nmslab/ashley/ResourceLogger_Data"))
		{
			if (!FtpPutFile(hftp, L"C:\\users\\public\\documents\\info.txt", info_filename, FTP_TRANSFER_TYPE_BINARY, 0))
			{
				cout << "FAIL!" << endl;
				cout << GetLastError() << endl;
			}
			else
			{
				cout << "file sended !";
				upload_cinebench = true;
			}

		}
		InternetCloseHandle(hftp);
		InternetCloseHandle(hint);
	}
}


void UploadLog(void)
{

		string file = "C:\\users\\public\\documents\\log.csv";
		char *str2 = "_log.csv";
		char * output_file = (char *)malloc(1 + strlen(mac_address) + strlen(str2));
		strcpy(output_file, mac_address);
		strcat(output_file, str2);

		WCHAR wsz[64];
		swprintf(wsz, L"%S", output_file);
		LPCWSTR cinebench_filename = wsz;

		if (!ifstream(file))
		{
			cout << "no file\n";
			return;
		}

		HINTERNET hint = InternetOpen(0, INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0);
		HINTERNET hftp = InternetConnect(hint, L"140.114.89.209", INTERNET_DEFAULT_FTP_PORT,
			L"ashley", L"ashley1213", INTERNET_SERVICE_FTP, 0, 0);

		if (FtpSetCurrentDirectory(hftp, L"/home/nmslab/ashley/ResourceLogger_Data"))
		{
			if (!FtpPutFile(hftp, L"C:\\users\\public\\documents\\log.csv", cinebench_filename, FTP_TRANSFER_TYPE_BINARY, 0))
			{
				cout << "FAIL!" << endl;
				cout << GetLastError() << endl;
			}
			else
			{
				cout << "file sended !";
			}

		}
		InternetCloseHandle(hftp);
		InternetCloseHandle(hint);

}


int _tmain(int argc, _TCHAR* argv[]){
	mac_address = getMAC();
	if (!(printErrorMessage || printResult)){
		// Not printing messages; hide the console
		ShowWindow(GetConsoleWindow(), SW_HIDE);
	}

	if (printErrorMessage)	printf("=== Register for running at startup ===\n");
	if (IsMyProgramRegisteredForStartup(L"MonitorApp")){
		if (printErrorMessage)	printf("Program registered.\n");
	}
	else{
		if (printErrorMessage)	printf("Registering this program...\n");
		RegisterProgram();
		if (printErrorMessage)	printf("Program registered.\n");
	}

	if (printErrorMessage || printResult)	printf("=== Computer Information ===\n");
	GetInformation();

	if (printErrorMessage || printResult)	printf("=== Computer Performance Monitoring ===\n");
	time_t t;
	tm* timePtr;
	
	while (1){
		// Get time
		t = time(0);
		timePtr = localtime(&t);

		// Call FeatureLogging() every 300 seconds
		if ((timePtr->tm_sec) % 300 == 0){
			PeriodicalLogging();
			UploadLog();
			if (upload_info == false && upload_cinebench==false) {
				UploadInfo();
			}
		}
	}

	if (printErrorMessage || printResult){
		system("pause");
	}
	return 0;
}

