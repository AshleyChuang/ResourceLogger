CONTAINER GVformula
{
	NAME GVformula;
	INCLUDE GVbase;

	GROUP ID_GVPROPERTIES
	{
		STRING GV_FORMULA_STRING { }
		BOOL GV_FORMULA_USE_PORTNAMES { }
		LONG GV_FORMULA_ANGLE 
		{ 
			CYCLE 
			{ 
				GV_FORMULA_ANGLE_DEGREE;
				GV_FORMULA_ANGLE_RAD;
			}
		}
	}

	GROUP ID_GVPORTS
	{
		REAL GV_FORMULA_INPUT		{ INPORT;  MULTIPLE; }
		REAL GV_FORMULA_OUTPUT	{ OUTPORT; STATICPORT; CREATEPORT; }
	}
}
