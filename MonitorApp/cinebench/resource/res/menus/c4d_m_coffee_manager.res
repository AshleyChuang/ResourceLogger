// Menudefinition for COFFEE_MANAGER

MENU M_COFFEE_MANAGER
{
  IDM_CM_DROP;
  SEPARATOR;
  IDM_FULLSCREEN;
  IDM_FULLSCREEN_GROUP;
  SEPARATOR;
  IDM_FULLSCREEN_STICKY;
  IDM_MAINWINDOW_FLAG;
  IDM_CM_SHOWWINDOWTITLE;
  SEPARATOR;
  IDM_CM_GROUPWINDOW;
  IDM_CM_NEWPALETTE;
  PLUGIN_CMD_300000186;
  SEPARATOR;
  IDM_CM_RENAMEWINDOW;
	IDM_CM_MAKETAB;
 	SUBMENU M_CMIP_TABS
	{
		IDM_CM_MAKETAB_TOP;
		IDM_CM_MAKETAB_LEFT;
		IDM_CM_MAKETAB_RIGHT;
	}
	IDM_SHOWONLINEHELP;
  SEPARATOR;
  IDM_CM_CLOSEWINDOW;
}

MENU M_ICON_PALETTE
{
  IDM_CM_DROP;
  IDM_FULLSCREEN_STICKY;
  SEPARATOR;
  SUBMENU IDS_MENU_SHOW
  {
    M_CMIP_ICONS;
    M_CMIP_TEXT;
    M_CMIP_VERTICAL;
  }
  SUBMENU M_CMIP_ICONS
  {
    M_CMIP_ICONS_SMALL;
    M_CMIP_ICONS_MEDIUM;
    M_CMIP_ICONS_BIG;
    SEPARATOR;
    M_CMIP_ICONS_AS_IS;
  }
  SUBMENU IDS_CM_ROWSCOLS
  {
    M_CMIP_NUM1;
    M_CMIP_NUM2;
    M_CMIP_NUM3;
    M_CMIP_NUM4;
    M_CMIP_NUM5;
    SEPARATOR;
		M_CMIP_DONTMIRROR;
  }
  M_CMIP_TRANSPOSE;
  SEPARATOR;
  IDM_CM_GROUPWINDOW;
  IDM_CM_NEWPALETTE;
	SUBMENU M_CMIP_TABS
	{
		IDM_CM_MAKETAB;
	  SEPARATOR;
		IDM_CM_MAKETAB_TOP;
		IDM_CM_MAKETAB_LEFT;
		IDM_CM_MAKETAB_RIGHT;
	}
  SEPARATOR;
  IDM_LOADPALETTE;
  IDM_SAVEPALETTE;
  IDM_CM_RENAMEWINDOW;
  SEPARATOR;
  IDM_FOLDPALETTE;
  IDM_UNFOLDICON;
  IDM_FIX_ICON;
  SEPARATOR;
  IDM_EDIT_SCRIPT;
  IDM_SHOWONLINEHELP;
  SEPARATOR;
  IDM_CM_CUSTOMIZE;
  SEPARATOR;
  IDM_CM_CLOSEWINDOW;
}