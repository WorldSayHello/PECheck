#include "stdafx.h"
#include "EditProvider.h"


CEditProvider::CEditProvider()
{
}


CEditProvider::~CEditProvider()
{
}
BEGIN_MESSAGE_MAP(CEditProvider, CEdit)
	ON_WM_DROPFILES()
END_MESSAGE_MAP()


void CEditProvider::OnDropFiles(HDROP hDropInfo)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	int nFileCount = DragQueryFile(hDropInfo, -1, NULL, 0);
	if (nFileCount == 1)
	{
		WCHAR wszFilePath[MAX_PATH] = { 0 };
		DragQueryFile(hDropInfo, 0, wszFilePath, MAX_PATH);//获得拖曳的第i个文件的文件名  
		SetWindowText(wszFilePath);
	}
	else
	{
		MessageBox(L"请选择一个文件!", L"警告", MB_OK);
	}

	CEdit::OnDropFiles(hDropInfo);
}
