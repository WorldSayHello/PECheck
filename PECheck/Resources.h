#pragma once
#include "afxcmn.h"


// CResources �Ի���

class CResources : public CDialogEx
{
	DECLARE_DYNAMIC(CResources)

public:
	CResources(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CResources();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_RESOURCES };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CTreeCtrl m_SectionTree;
	HTREEITEM m_hRoot;     // ���ĸ��ڵ�ľ��   
	HTREEITEM m_hSecondItem; // �ɱ�ʾ��һ����ڵ�ľ��   
	HTREEITEM m_hThirdItem;  // �ɱ�ʾ��һ���½ڵ�ľ��   
};
