MENU M_VIEWPOPUP
{
	IDM_UNDO;
	IDM_SHOWACTIVE;
	IDM_SHOWSCENE;
	SEPARATOR;
	IDM_MAKEFLAECHEN;
	IDM_TAKEANIM;
	PLUGIN_CMD_100004772; //group objects
	IDM_VERBINDEN;
	IDM_CONNECTANDDELETE;
	SEPARATOR;
	SUBMENU IDS_TAGSUBMENU
	{
		PLUGIN_CMD_100004788;
	}
	SUBMENU IDS_RESTORESELECTION
	{
		IDM_LISTSELECTIONS;
	}
  SEPARATOR;
	IDM_SELECTCHILDS;
	IDM_SHOWINTIMELINE;
	IDM_SHOWFCURVES;
	IDM_SHOWINMOTION; // Cat added for show in Motion
  IDM_INFORMATIONOBJEKT;
  SEPARATOR;
	PLUGIN_CMD_200000088;
	PLUGIN_CMD_200000089;
	PLUGIN_CMD_200000090;
  PLUGIN_CMD_200000083;
  PLUGIN_CMD_200000084;
  PLUGIN_CMD_200000085;
}