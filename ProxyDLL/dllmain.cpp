// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "dllmain.h"





void __declspec(naked) DoJmpEntryPoint(){
	_gfNew = PAGE_READWRITE;
	_glpMovEax = (DWORD*)_lpCode.OldAddr;
	VirtualProtect(_glpMovEax, 2 * sizeof(DWORD), _gfNew, &_gfOld);
	*_glpMovEax = _lpCode.OldCode[0];
	*(_glpMovEax + 1) = _lpCode.OldCode[1];
	VirtualProtect(_glpMovEax, 2 * sizeof(DWORD), _gfOld, &_gfNew);
	__asm{
		_asm popad
		_asm jmp _lpCode.lpEntryPoint
	}
}

BOOL InitHook(){
	HANDLE hMap;
	LPSPY_MEM_SHARE lpMem;
	DWORD dwSize;
	// 取得FileMapping的句柄  
	hMap = OpenFileMapping(FILE_MAP_ALL_ACCESS, 0, "MyDllMapView");
	if (hMap)
	{
		lpMem = (LPSPY_MEM_SHARE)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (lpMem)
		{
			// 恢复目标进程的入口代码  
			WriteProcessMemory(GetCurrentProcess(), lpMem->lpEntryPoint, lpMem->oldcode, sizeof(INJECT_CODE), &dwSize);
			_lpCode.OldAddr = (DWORD)((BYTE*)lpMem->lpEntryPoint + offsetof(INJECT_CODE, jmp_MOVEAX));
			_lpCode.lpEntryPoint = (DWORD)lpMem->lpEntryPoint;
			memcpy(&_lpCode.OldCode, (BYTE*)lpMem->oldcode + offsetof(INJECT_CODE, jmp_MOVEAX), 2 * sizeof(DWORD));
			lpByte = (BYTE*)lpMem->lpEntryPoint + offsetof(INJECT_CODE, jmp_MOVEAX);
			DWORD fNew, fOld;
			fNew = PAGE_READWRITE;
			VirtualProtect(lpByte, 2 * sizeof(DWORD), fNew, &fOld);
			*lpByte = 0xb8;
			*(DWORD*)(lpByte + 1) = (DWORD)DoJmpEntryPoint;
			*(BYTE*)(lpByte + 5) = 0xff;
			*(BYTE*)(lpByte + 6) = 0xe0;
			VirtualProtect(lpByte, 2 * sizeof(DWORD), fOld, &fNew);
			UnmapViewOfFile(lpMem);
		}
		CloseHandle(hMap);
	}
	return TRUE;
}

char szBuffer[MAX_PATH];
void StartThread(){
	if (!Initialize())return ;
	SuperHookDeviceIoControl();   //挂钩内核
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)OLD_connect, myconnect);
	DetourAttach(&(PVOID&)pNtDeviceIoControl, NewNtDeviceIoControlFile);
	DetourTransactionCommit();
	OutputDebugString(TEXT("dbg:Loading.."));
}


BOOL APIENTRY DllMain(HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:{
		InitHook();   //初始化hook
		boost::thread hookthread(StartThread);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}



void GetPath(char *pString, char *pCrrentDir) //解析文件路径
{
	while (*(pCrrentDir++) = *(pString++));     //获取原始文件字符串
	while (*(--pCrrentDir) != '\\');            //从原始字符串尾部向前移到最后一个反斜杠处
	*pCrrentDir = '\0';                        //最后一个反斜杠位置截断，获得当前路径
}



bool Initialize(){


	WSADATA wsadata;
	WSAStartup(MAKEWORD(2, 2), &wsadata);
	char szPath[MAX_PATH];
	char szDLLDir[MAX_PATH];
	char szIniPath[MAX_PATH];
	GetModuleFileName(GetModuleHandle("dll.dll"), szPath, MAX_PATH);
	GetPath(szPath, szDLLDir);
	sprintf_s(szIniPath, "%s\\Config.ini", szDLLDir);



	boost::property_tree::ptree m_pt;
	boost::property_tree::ini_parser::read_ini(szIniPath, m_pt);
	Config.Host = m_pt.get<string>("public.Host");
	if (Config.Host.empty()){ return false; }
	Config.Port = m_pt.get<int>("public.Port");
	Config.hiddenIp = m_pt.get<bool>("public.hiddenIp");
	Config.sslHost = m_pt.get<string>("public.sslHost");
	HOSTENT *pHostent;
	if ((pHostent = gethostbyname(Config.sslHost.c_str())) != NULL){
		strcpy(Config.sslIp, inet_ntoa(*((struct in_addr *)pHostent->h_addr)));
	}
	Config.sslPort = m_pt.get<int>("public.sslPort");
	//	OutputDebugString(Config.Host.c_str());

	if ((pHostent = gethostbyname(Config.Host.c_str())) != NULL){
		strcpy(Config.Ip, inet_ntoa(*((struct in_addr *)pHostent->h_addr)));
	}
	if (strcmp(Config.Ip, "") == 0){
		MessageBox(NULL, "获取IP错误，请检查配置文件是否存在", NULL, MB_OK);
		ExitProcess(0);
		return false;
	}
	WSACleanup();
	//	OutputDebugString(Config.Ip);
	return true;
}
string fileterhttp(string sbuf){
	boost::cmatch mat;
	boost::regex reg("Host: ([^\r\n]+)\r\n");
	if (boost::regex_search(sbuf.c_str(), mat, reg)){
		string sok = (mat[0]);
		string Host = mat[1];
		if (Config.hiddenIp == true){
			boost::replace_first(sbuf, sok, "Host: " + Config.Host + "\r\ngHost: " + mat[1] + "\r\nhiddenIp: true\r\n");
		}
		else{
			boost::replace_first(sbuf, sok, "Host: " + Config.Host + "\r\ngHost: " + mat[1] + "\r\n");
		}
	}
	return sbuf;
}
NTSTATUS WINAPI NewNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event OPTIONAL, PVOID ApcRoutine OPTIONAL, PVOID ApcContext OPTIONAL, PVOID IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer OPTIONAL, ULONG InputBufferLength, PVOID OutputBuffer OPTIONAL, ULONG OutputBufferLength)
{
	if (IoControlCode != AFD_SEND)
	{
		return pNtDeviceIoControl(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
	}
	string text = "";
	PAFD_INFO AfdInfo = NULL;
	char * Buffer = NULL;
	ULONG Len = NULL;
	AfdInfo = (PAFD_INFO)InputBuffer;
	Len = AfdInfo->BufferArray->len;
	text = AfdInfo->BufferArray->buf;
	if (text.find("1.1") == -1){
		OutputDebugString("fileter https!");
		NTSTATUS Ntstatus = pNtDeviceIoControl(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
		return Ntstatus;
	}
	else{
		text = fileterhttp(text);
		AfdInfo->BufferArray->len = text.length();
		AfdInfo->BufferArray->buf = (char*)text.c_str();
		NTSTATUS Ntstatus = pNtDeviceIoControl(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
		PIO_STATUS_BLOCK io_status_block = (PIO_STATUS_BLOCK)IoStatusBlock;
		io_status_block->Status = STATUS_SUCCESS;
		io_status_block->Information = Len;
		return Ntstatus;
	}
}
void OutputDebugPrintf(const char * strOutputString, ...)
{
	char strBuffer[4096] = { 0 };
	va_list vlArgs;
	va_start(vlArgs, strOutputString);
	_vsnprintf(strBuffer, sizeof(strBuffer)-1, strOutputString, vlArgs);
	//vsprintf(strBuffer,strOutputString,vlArgs);
	va_end(vlArgs);
	OutputDebugString(strBuffer);
}
int WINAPI myconnect(int sockfd, struct sockaddr * serv_addr, int addrlen){
	struct sockaddr_in *paddr = (struct sockaddr_in *)serv_addr;
	int nPort = ntohs(paddr->sin_port);
	string sIp;
	if (nPort == 443){
		sIp = Config.sslIp;
		nPort = Config.sslPort;
	}
	else{
		sIp = Config.Ip;
		nPort = Config.Port;
	}
	OutputDebugPrintf("dbg:%d\n", nPort);

	paddr->sin_addr.S_un.S_addr = inet_addr(sIp.c_str());
	paddr->sin_port = htons(nPort);
	return OLD_connect(sockfd, (struct sockaddr*)paddr, sizeof(sockaddr_in));
}
void SuperHookDeviceIoControl()
{
	//得到ws2_32.dll的模块基址
	HMODULE hMod = LoadLibrary("mswsock.dll");
	if (hMod == 0)
	{
		return;
	}

	//得到DOS头

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;

	//如果DOS头无效
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return;
	}

	//得到NT头

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG)hMod + pDosHeader->e_lfanew);

	//如果NT头无效
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return;
	}

	//检查输入表数据目录是否存在
	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
	{
		return;
	}
	//得到输入表描述指针

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG)hMod + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	PIMAGE_THUNK_DATA ThunkData;

	//检查每个输入项
	while (ImportDescriptor->FirstThunk)
	{
		//检查输入表项是否为ntdll.dll

		char* dllname = (char*)((ULONG)hMod + ImportDescriptor->Name);

		//如果不是，则跳到下一个处理

		if (::strcmp(dllname, "ntdll.dll") != 0)
		{
			ImportDescriptor++;
			continue;
		}

		ThunkData = (PIMAGE_THUNK_DATA)((ULONG)hMod + ImportDescriptor->OriginalFirstThunk);

		int no = 1;
		while (ThunkData->u1.Function)
		{
			//检查函数是否为NtDeviceIoControlFile

			char* functionname = (char*)((ULONG)hMod + ThunkData->u1.AddressOfData + 2);
			if (strcmp(functionname, "NtDeviceIoControlFile") == 0)
			{
				//
				//如果是，那么记录原始函数地址
				//HOOK我们的函数地址
				//
				PDWORD lpAddr = (DWORD *)((ULONG)hMod + (DWORD)ImportDescriptor->FirstThunk) + (no - 1);
				pNtDeviceIoControl = (NTSTATUS(__stdcall *)(HANDLE, HANDLE, PVOID, PVOID, PVOID, ULONG, PVOID, ULONG, PVOID, ULONG)) (PVOID)(*(ULONG*)lpAddr);
				return;

			}

			no++;
			ThunkData++;
		}
		ImportDescriptor++;
	}
	return;
}

