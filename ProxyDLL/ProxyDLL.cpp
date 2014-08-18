// ProxyDLL.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"


EXTERN_C  __declspec(dllexport) int test(){
	return 1;
}