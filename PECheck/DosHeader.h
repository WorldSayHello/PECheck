#pragma once


// CDosHeader �Ի���

class CDosHeader : public CDialogEx
{
	DECLARE_DYNAMIC(CDosHeader)

public:
	CDosHeader(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CDosHeader();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_DOS_HEADER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
};
