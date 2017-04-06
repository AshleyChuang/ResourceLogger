CONTAINER ToolCreatePolygon
{
	NAME ToolCreatePolygon;
	INCLUDE ToolBase;

	HIDE MDATA_COMMANDGROUP;

	GROUP MDATA_MAINGROUP
	{
		BUTTON MDATA_CREATEPOLYGON_BUTTON {NAME MDATA_CREATEPOLYGON_NAME;}
		LONG MDATA_CREATEPOLYGON_CREATE { ALIGN_LEFT; CYCLE { MDATA_CREATEPOLYGON_SET_NGON; MDATA_CREATEPOLYGON_SET_TRI; MDATA_CREATEPOLYGON_SET_QUAD; } }
		LONG MDATA_CREATEPOLYGON_NGON_SUB { ALIGN_LEFT; CYCLE { MDATA_CREATEPOLYGON_NGON_NGON; MDATA_CREATEPOLYGON_NGON_TRI; MDATA_CREATEPOLYGON_NGON_QUAD; } }
		BOOL MDATA_CREATEPOLYGON_SNAPTO {ANIM OFF;}
		BOOL MDATA_CREATEPOLYGON_VISIBLE { ANIM OFF;}
	GROUP
    {
	  COLUMNS 1;
      STATICTEXT MDATA_CREATEPOLYGON_POSITIONX {ANIM OFF;}
      STATICTEXT MDATA_CREATEPOLYGON_POSITIONY {ANIM OFF;}
      STATICTEXT MDATA_CREATEPOLYGON_POSITIONZ {ANIM OFF;}

     }
	}
}