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
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ
	int nFileCount = DragQueryFile(hDropInfo, -1, NULL, 0);
	if (nFileCount == 1)
	{
		WCHAR wszFilePath[MAX_PATH] = { 0 };
		DragQueryFile(hDropInfo, 0, wszFilePath, MAX_PATH);//�����ҷ�ĵ�i���ļ����ļ���  
		SetWindowText(wszFilePath);
	}
	else
	{
		MessageBox(L"��ѡ��һ���ļ�!", L"����", MB_OK);
	}

	CEdit::OnDropFiles(hDropInfo);
}
