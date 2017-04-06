CONTAINER Oerandomize
{
	NAME		Oerandomize;

	INCLUDE Obaseeffector;

	GROUP		ID_MG_BASEEFFECTOR_GROUPEFFECTOR
	{
		LONG	MGRANDOMEFFECTOR_MODE
		{
			CYCLE
			{
				MGRANDOMEFFECTOR_MODE_RANDOM;
				MGRANDOMEFFECTOR_MODE_GAUSIAN;
				MGRANDOMEFFECTOR_MODE_NOISE;
				MGRANDOMEFFECTOR_MODE_TURBULENCE;
				MGRANDOMEFFECTOR_MODE_SORT;
			}
			FIT_H;
		}
		SEPARATOR
		{
			LINE;
		}
		GROUP
		{
			COLUMNS 2;
			BOOL	MGRANDOMEFFECTOR_SYNC {}
			BOOL	MGRANDOMEFFECTOR_INDEXED {}
		}
		REAL	MGRANDOMEFFECTOR_SEED
		{
			STEP 1.0;
			MIN 0.0;
		}
		SEPARATOR
		{
			LINE;
		}
		GROUP MGRANDOMEFFECTOR_MODE_NOISE_GRP
		{
			LONG	MGRANDOMEFFECTOR_SPACE
			{
				CYCLE
				{
					MGRANDOMEFFECTOR_SPACE_GLOBAL;
					MGRANDOMEFFECTOR_SPACE_OBJECT;
				}
			}
			REAL	MGRANDOMEFFECTOR_SPEED
			{
				UNIT	PERCENT;
				MIN 0.0;
			}
			REAL	MGRANDOMEFFECTOR_SCALE
			{
				UNIT	PERCENT;
				MIN 0.0;
			}
		}
	}
}