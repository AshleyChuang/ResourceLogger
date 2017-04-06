CONTAINER Ooiltank
{
	NAME Ooiltank;
	INCLUDE Obase;

	GROUP ID_OBJECTPROPERTIES
	{
		REAL PRIM_OILTANK_RADIUS { UNIT METER; MIN 0.0; }
		REAL PRIM_OILTANK_HEIGHT { UNIT METER; MIN 0.0; }
		LONG PRIM_OILTANK_HSUB   { MIN 1; MAX 1000; }
		REAL PRIM_OILTANK_CAPHEIGHT { UNIT METER; MIN 0.0; }
		LONG PRIM_OILTANK_FSUB	 { MIN 1; MAX 1000; }
		LONG PRIM_OILTANK_SEG		 { MIN 3; MAX 1000; }

		INCLUDE Oprimitiveaxis;
		INCLUDE Oprimitiveslice;
	}
}