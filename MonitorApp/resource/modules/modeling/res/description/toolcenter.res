CONTAINER ToolCenter
{
  NAME ToolCenter;
	INCLUDE ToolBase;

  GROUP MDATA_MAINGROUP
  {
		GROUP
		{
			LONG MDATA_CENTER_XAXIS { CYCLE { MDATA_CENTER_NONE; MDATA_CENTER_POS; MDATA_CENTER_CENTER; MDATA_CENTER_NEG; } }
			LONG MDATA_CENTER_YAXIS { CYCLE { MDATA_CENTER_NONE; MDATA_CENTER_POS; MDATA_CENTER_CENTER; MDATA_CENTER_NEG; } }
			LONG MDATA_CENTER_ZAXIS { CYCLE { MDATA_CENTER_NONE; MDATA_CENTER_POS; MDATA_CENTER_CENTER; MDATA_CENTER_NEG; } }
		}
  }
	GROUP MDATA_COMMANDGROUP
	{
		SHOW MDATA_APPLY;
	}
}