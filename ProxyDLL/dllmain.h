#define AFD_RECV 0x12017     //定义接受标识
#define AFD_SEND 0x1201f     //定义发送标识
#define STATUS_SUCCESS 0x00000000
typedef struct AFD_WSABUF{
	UINT  len;
	PCHAR  buf;
}AFD_WSABUF, *PAFD_WSABUF;

typedef struct AFD_INFO {
	PAFD_WSABUF  BufferArray;
	ULONG  BufferCount;
	ULONG  AfdFlags;
	ULONG  TdiFlags;
} AFD_INFO, *PAFD_INFO;
typedef LONG NTSTATUS;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
struct{
	std::string Host;
	int Port;
	bool hiddenIp;
	char Ip[50];
	std::string sslHost;
	int sslPort;
	char sslIp[50];
}Config;


// 监视程序和DLL共用的结构体
#pragma pack (push ,1) // 保证下面的结构体采用BYTE对齐（必须）
typedef struct INJECT_CODE
{
	BYTE      int_PUSHAD;         // pushad        0x60       
	BYTE      int_PUSH;             // push &szDLL     0x68
	DWORD push_Value;           //            &szDLL = "ApiSpy.dll"的path
	BYTE      int_MOVEAX;              //  move eax &LoadLibrary  0xB8
	DWORD eax_Value;             //     &LoadLibrary
	WORD    call_eax;         //     call eax    0xD0FF(FF D0) (LoadLibrary("ApiSpy.dll");
	BYTE      jmp_MOVEAX;             //     move eax &ReplaceOldCode  0xB8       
	DWORD jmp_Value;             //     JMP的参数
	WORD    jmp_eax;        //     jmp eax   0xE0FF(FF E0) jmp ReplaceOldCode;
	char szDLL[MAX_PATH]; //  "ApiSpy.dll"的FullPath
}INJECT_LOADLIBRARY_CODE, *LPINJECT_CODE;
#pragma pack (pop , 1)

typedef struct
{
	LPBYTE  lpEntryPoint;   // 目标进程的入口地址
	BYTE      oldcode[sizeof(INJECT_CODE)];        // 目标进程的代码保存
}SPY_MEM_SHARE, *LPSPY_MEM_SHARE;

typedef struct
{
	DWORD lpEntryPoint;
	DWORD OldAddr;
	DWORD OldCode[4];
}JMP_CODE, *LPJMP_CODE;
static JMP_CODE _lpCode;
BYTE* lpByte;
DWORD _gfNew, _gfOld, *_glpMovEax;


///defline fuc
bool Initialize();
void SuperHookDeviceIoControl();
int WINAPI myconnect(int sockfd, struct sockaddr * serv_addr, int addrlen);
NTSTATUS WINAPI NewNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event OPTIONAL, PVOID ApcRoutine OPTIONAL, PVOID ApcContext OPTIONAL, PVOID IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer OPTIONAL, ULONG InputBufferLength, PVOID OutputBuffer OPTIONAL, ULONG OutputBufferLength);
static NTSTATUS(WINAPI* pNtDeviceIoControl)(HANDLE FileHandle, HANDLE Event OPTIONAL, PVOID ApcRoutine OPTIONAL, PVOID ApcContext OPTIONAL, PVOID IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer OPTIONAL, ULONG InputBufferLength, PVOID OutputBuffer OPTIONAL, ULONG OutputBufferLength);
static  int(WINAPI * OLD_connect)(SOCKET sockfd, const sockaddr * serv_addr, int addrlen)= connect;;
void OutputDebugPrintf(const char * strOutputString, ...);