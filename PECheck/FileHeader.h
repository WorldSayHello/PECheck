#pragma once


// CFileHeader �Ի���

class CFileHeader : public CDialogEx
{
	DECLARE_DYNAMIC(CFileHeader)

public:
	CFileHeader(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CFileHeader();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_FILE_HEADER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
};
