CONTAINER Oboole
{
	NAME Oboole;
	INCLUDE Obase;

	GROUP ID_OBJECTPROPERTIES
	{
		LONG BOOLEOBJECT_TYPE
		{
			CYCLE
			{
				BOOLEOBJECT_TYPE_UNION;
				BOOLEOBJECT_TYPE_SUBTRACT;
				BOOLEOBJECT_TYPE_INTERSECT;
				BOOLEOBJECT_TYPE_WITHOUT;
			}
		}
		BOOL BOOLEOBJECT_HIGHQUALITY { }
		BOOL BOOLEOBJECT_SINGLE_OBJECT { }
		BOOL BOOLEOBJECT_HIDE_NEW_EDGES { }
		BOOL BOOLEOBJECT_BREAK_CUT_EDGES { }
		BOOL BOOLEOBJECT_SEL_CUT_EDGES { }
		REAL BOOLEOBJECT_OPTIMIZE_LEVEL { UNIT METER; MIN 0.0001; STEP .001; }
		//BOOL BOOLEOBJECT_BEVEL { }
		//REAL BOOLEOBJECT_BEVEL_WIDTH { UNIT METER; MIN 0; }
		//LONG BOOLEOBJECT_BEVEL_SUBDIVISION { MIN 0; }
		//LONG BOOLEOBJECT_BEVEL_MODE
		//{
		//	CYCLE
		//	{
		//		BOOLEOBJECT_BEVEL_LINEAR;
		//		BOOLEOBJECT_BEVEL_OUTER_CIRCLE;
		//		BOOLEOBJECT_BEVEL_INNER_CIRCLE;
		//		BOOLEOBJECT_BEVEL_BEZIER;
		//	}
		//}
	}
}