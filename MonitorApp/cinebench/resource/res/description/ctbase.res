CONTAINER CTbase
{
	NAME CTbase;

	INCLUDE Obaselist;

	GROUP ID_CTRACK_PROPERTIES
	{
		DEFAULT	1;
		COLUMNS 2;

		BOOL ID_CTRACK_ANIMOFF { }
		STATICTEXT { }
		
		BOOL ID_CTRACK_ANIMSOLO { }
		STATICTEXT { }

		BOOL ID_CTRACK_CONSTANTVELOCITY_V {}
		STATICTEXT { JOINENDSCALE; }

		SEPARATOR { LINE; }
		STATICTEXT { JOINENDSCALE; }

		LONG ID_CTRACK_BEFORE
		{
			CYCLE
			{
				ID_CTRACK_OFF;
				ID_CTRACK_CONSTANT;
				ID_CTRACK_CONTINUE;
				ID_CTRACK_REPEAT;
				ID_CTRACK_OFFSETREPEAT;
				ID_CTRACK_OSCILLATE;
			}
		}
		LONG ID_CTRACK_BEFORE_CNT { MIN 1; }

		LONG ID_CTRACK_AFTER
		{
			CYCLE
			{
				ID_CTRACK_OFF;
				ID_CTRACK_CONSTANT;
				ID_CTRACK_CONTINUE;
				ID_CTRACK_REPEAT;
				ID_CTRACK_OFFSETREPEAT;
				ID_CTRACK_OSCILLATE;
			}
		}
		LONG ID_CTRACK_AFTER_CNT { MIN 1; }

		SEPARATOR { }
		STATICTEXT { JOINENDSCALE; }
		
		LINK ID_CTRACK_TIME
		{
			ACCEPT
			{
				5350;
			}
		}
	
		BOOL ID_CTRACK_TIME_RELATIVE {}

		SEPARATOR { LINE; }
		STATICTEXT { JOINENDSCALE; }

		BOOL ID_CTRACK_USE_PREF	{}
		STATICTEXT { }

		COLOR ID_CTRACK_FCURVE_COLOR { }
		STATICTEXT { JOINENDSCALE; }

		SEPARATOR { LINE; }
		STATICTEXT { JOINENDSCALE; }

		REAL ID_CTRACK_FCURVE_OFFSET { }
		STATICTEXT { }

		REAL ID_CTRACK_FCURVE_SCALE { UNIT PERCENT; }
		STATICTEXT { }


		HIDE ID_CTRACK_FCURVE_COLOR;
		HIDE ID_CTRACK_FCURVE_OFFSET;
		HIDE ID_CTRACK_FCURVE_SCALE;
		HIDE ID_CTRACK_BEFORE;
		HIDE ID_CTRACK_AFTER;
		HIDE ID_CTRACK_AFTER_CNT; //ITEM#49977 gui issues with sound track AM
		HIDE ID_CTRACK_BEFORE_CNT;
		HIDE ID_CTRACK_TIME;
		HIDE ID_CTRACK_TIME_RELATIVE;

	}
}