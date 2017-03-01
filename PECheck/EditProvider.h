#pragma once
#include "afxwin.h"
class CEditProvider :
	public CEdit
{
public:
	CEditProvider();
	~CEditProvider();
	DECLARE_MESSAGE_MAP()
	afx_msg void OnDropFiles(HDROP hDropInfo);
};

