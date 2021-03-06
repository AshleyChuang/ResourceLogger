CONTAINER MGlineararray
{
	NAME		MGlineararray;
	INCLUDE Obase;

	GROUP		ID_OBJECTPROPERTIES
	{
		GROUP
		{
			COLUMNS 1;

			LONG	MG_LINEAR_COUNT
			{
				MIN 0;
				MAXSLIDER 100;
				CUSTOMGUI LONGSLIDER;
			}
			LONG	MG_LINEAR_OFFSET
			{
				MIN 0;
				MAXSLIDER 100;
				CUSTOMGUI LONGSLIDER;
			}
			SEPARATOR
			{
				LINE;
			}
			LONG	MG_LINEAR_MODE
			{
				CYCLE
				{
					MG_LINEAR_MODE_ALL;
					MG_LINEAR_MODE_STEP;
				}
			}
			REAL	MG_LINEAR_OBJECT_AMOUNT
			{
				UNIT	PERCENT;
				MINSLIDER 0.0;
				MAXSLIDER 100.0;
				CUSTOMGUI REALSLIDER;
			}
			GROUP
			{
				LAYOUTGROUP;
				COLUMNS 3;
				GROUP
				{
					VECTOR	MG_LINEAR_OBJECT_POSITION
					{
						UNIT	METER;
						STEP 1.0;
						CUSTOMGUI SUBDESCRIPTION;
					}
				}
				GROUP
				{
					VECTOR	MG_LINEAR_OBJECT_SCALE
					{
						UNIT	PERCENT;
						STEP 1.0;
						CUSTOMGUI SUBDESCRIPTION;
					}
				}
				GROUP
				{
					VECTOR	MG_LINEAR_OBJECT_ROTATION
					{
						UNIT	DEGREE;
						STEP 1.0;
						CUSTOMGUI SUBDESCRIPTION;
					}
				}
			}
			SEPARATOR
			{
				LINE;
			}
			LONG	MG_LINEAR_JOINT_MODE
			{
				CYCLE
				{
					MG_LINEAR_JOINT_MODE_ALL;
					MG_LINEAR_JOINT_MODE_STEP;
				}
			}
			REAL	MG_LINEAR_JOINT_SCALE
			{
				UNIT	PERCENT;
				MIN 0.0;
				MAXSLIDER 100.0;
				CUSTOMGUI REALSLIDER;
			}
			VECTOR	MG_LINEAR_JOINT_ROTATION
			{
				UNIT	DEGREE;
				STEP 0.1;
				OPEN;
				CUSTOMGUI SUBDESCRIPTION;
			}
		}
	}
}
