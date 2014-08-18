
// MainDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Main.h"
#include "MainDlg.h"
#include "afxdialogex.h"
#include <Imagehlp.h>
#pragma comment(lib,"Imagehlp.lib")


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMainDlg 对话框



CMainDlg::CMainDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CMainDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMainDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CMainDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CMainDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CMainDlg 消息处理程序

BOOL CMainDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMainDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMainDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMainDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



typedef struct {
	DWORD ExitStatus;
	DWORD PebBaseAddress;
	DWORD AffinityMask;
	DWORD BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef LONG(WINAPI *PROCNTQSIP)(HANDLE, UINT, PVOID, ULONG, PULONG);

LPBYTE GetExeEntryPointI(HANDLE procHdl, const char* ansiExeFilePath) {
	LPBYTE entryPoint = NULL;

	PROCNTQSIP NtQueryInformationProcess = (PROCNTQSIP)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");

	if (!NtQueryInformationProcess)
		return entryPoint;

	LONG status;
	DWORD dwParentPID = (DWORD)-1;
	PROCESS_BASIC_INFORMATION pbi;

	// Retrieve information
	status = NtQueryInformationProcess(procHdl,
		0,
		(PVOID)&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL
		);

	DWORD bytesRead = 0;
	HINSTANCE baseAddr = NULL;
	ReadProcessMemory(procHdl,
		(PVOID)(pbi.PebBaseAddress + 8),    // 这个8就是 ImageBaseAddress 在 PEB 结构中的偏移
		&baseAddr,
		sizeof(baseAddr),
		&bytesRead);

	PLOADED_IMAGE pImage = ImageLoad(ansiExeFilePath, NULL);    // ImageLoad 只支持ANSI编码。。。
	if (pImage == NULL)
		return entryPoint;
	PIMAGE_NT_HEADERS pNTHeader = pImage->FileHeader;
	entryPoint = (LPBYTE)baseAddr + pNTHeader->OptionalHeader.AddressOfEntryPoint;
	ImageUnload(pImage);

	return entryPoint;
}


LPBYTE GetExeEntryPoint(char *filename)
{
	PIMAGE_NT_HEADERS pNTHeader;
	DWORD pEntryPoint;
	PLOADED_IMAGE pImage;
	pImage = ImageLoad(filename, NULL);
	if (pImage == NULL)
		return NULL;
	pNTHeader = pImage->FileHeader;
	pEntryPoint = pNTHeader->OptionalHeader.AddressOfEntryPoint + pNTHeader->OptionalHeader.ImageBase;
	ImageUnload(pImage);
	return (LPBYTE)pEntryPoint;
}







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




void CMainDlg::OnBnClickedOk()
{
	USES_CONVERSION;
	char szCurrentDir[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, szCurrentDir);
	CString csConfigFile;
	csConfigFile = szCurrentDir;
	csConfigFile.Append(_TEXT("\\config.ini"));
	TCHAR tzChrome[MAX_PATH];
	TCHAR tzParam[MAX_PATH];
	GetPrivateProfileString(_TEXT("public"), _TEXT("chrome"), _TEXT(""), tzChrome, MAX_PATH, csConfigFile.GetString());
	GetPrivateProfileString(_TEXT("public"), _TEXT("param"), _TEXT(""), tzParam, MAX_PATH, csConfigFile.GetString());
	CString sRunFile;
	sRunFile.Format(_TEXT("%s"), tzChrome);
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = {0};
	CString sRunCommandLine;
	sRunCommandLine.Format(_TEXT("%s %s"), sRunFile.GetString(), tzParam);
	BOOL bRet = CreateProcess(NULL, sRunCommandLine.GetBuffer(0), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (bRet){
		LPBYTE  pEntryPoint = GetExeEntryPointI(pi.hProcess,T2A(sRunFile));
		if (pEntryPoint){
			HANDLE hMap = CreateFileMapping((HANDLE)0xFFFFFFFF, NULL, PAGE_READWRITE, 0, sizeof(SPY_MEM_SHARE), TEXT("MyDllMapView"));
			LPSPY_MEM_SHARE lpMap = (LPSPY_MEM_SHARE)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);

			SIZE_T stRead;
			ReadProcessMemory(pi.hProcess, pEntryPoint, &lpMap->oldcode, sizeof(INJECT_CODE),&stRead);
			lpMap->lpEntryPoint = pEntryPoint;
			INJECT_CODE     newCode;
			strcpy_s(newCode.szDLL, szCurrentDir);
			strcat_s(newCode.szDLL, "\\dll.dll");
			// 准备硬代码（汇编代码）  
			newCode.int_PUSHAD = 0x60;
			newCode.int_PUSH = 0x68;
			newCode.int_MOVEAX = 0xB8;
			newCode.call_eax = 0xD0FF;
			newCode.jmp_MOVEAX = 0xB8;
			newCode.jmp_eax = 0xE0FF;
			newCode.eax_Value = (DWORD)&LoadLibraryA;
			newCode.push_Value = (DWORD)(pEntryPoint + offsetof(INJECT_CODE, szDLL));
			DWORD dwNewFlg, dwOldFlg;
			dwNewFlg = PAGE_READWRITE;
			VirtualProtectEx(pi.hProcess, (LPVOID)pEntryPoint, sizeof(DWORD), dwNewFlg, &dwOldFlg);
			WriteProcessMemory(pi.hProcess, pEntryPoint, &newCode, sizeof(newCode), NULL);//&dwWrited);  
			VirtualProtectEx(pi.hProcess, (LPVOID)pEntryPoint, sizeof(DWORD), dwOldFlg, &dwNewFlg);
			UnmapViewOfFile(lpMap);
			ResumeThread(pi.hThread);
		}
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}



	// TODO:  在此添加控件通知处理程序代码
	//CDialogEx::OnOK();
}
