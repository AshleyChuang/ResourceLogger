CONTAINER BPspline
{
	NAME BPspline;
	INCLUDE Obaselist;

	GROUP Obaselist
	{
		DEFAULT 1;
		BITMAPBUTTON ID_PAINTSPLINE_PREVIEW { };
	}

	GROUP ID_PAINTSPLINE_GROUP_COORDS
	{
		LAYOUTGROUP; COLUMNS 3;
		GROUP { VECTOR ID_PAINTSPLINE_POSITION { UNIT METER;  CUSTOMGUI SUBDESCRIPTION; } }
		GROUP { VECTOR ID_PAINTSPLINE_SCALE    { STEP 0.01;   CUSTOMGUI SUBDESCRIPTION; } }
		GROUP { VECTOR ID_PAINTSPLINE_ROTATION { UNIT DEGREE; CUSTOMGUI SUBDESCRIPTION; } }
	}

	GROUP ID_PAINTSPLINE_GROUP
	{
		DEFAULT 1;
	}

	GROUP ID_PAINTSPLINE_INFO_GROUP
	{
		DEFAULT 1;
		STATICTEXT ID_PAINTSPLINE_SEGMENTS { }
		STATICTEXT ID_PAINTSPLINE_POINTS	 { }
	}
}
