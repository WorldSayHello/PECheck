#pragma once
#include "afxcmn.h"


// COptionHeader �Ի���

class COptionHeader : public CDialogEx
{
	DECLARE_DYNAMIC(COptionHeader)

public:
	COptionHeader(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~COptionHeader();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_OPTION_HEADER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
};
