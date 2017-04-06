CONTAINER Olathe
{
	NAME Olathe;
	INCLUDE Obase;
	INCLUDE Onurbscaps;

	GROUP ID_OBJECTPROPERTIES
	{
		REAL LATHEOBJECT_ROTATE { UNIT DEGREE; }
		LONG LATHEOBJECT_SUB    { MIN 1; MAX 4000; }
		LONG LATHEOBJECT_ISOPARM { MIN 2; MAX 4000; }
		REAL LATHEOBJECT_MOVE   { UNIT METER; }
		REAL LATHEOBJECT_SCALE  { UNIT PERCENT; MIN 0.0; }

		BOOL LATHEOBJECT_FLIPNORMALS { }
	}
}