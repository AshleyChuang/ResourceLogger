CONTAINER Prefsproman
{
	NAME Prefsproman;
	GROUP PREF_PM_MAIN_GROUP
	{
	
		DEFAULT 1;
		COLUMNS 2;
		
		
		LONG PREF_PM_WIDTH {ANIM OFF; MIN 1; MAX 100000;}
		STATICTEXT{}
		LONG PREF_PM_HEIGHT {ANIM OFF;  MIN 1; MAX 100000;}
		STATICTEXT{}
		LONG PREF_PM_CHANNEL
		{
			ANIM OFF;
			CYCLE
			{
				PREF_PM_CHANNEL_LA;
				PREF_PM_CHANNEL_CA;
			}
		}
		STATICTEXT{}
		
		FILENAME PREF_PM_PSPATH {ANIM OFF;}
		STATICTEXT {JOINENDSCALE;}
		FILENAME PREF_PM_WPATH {DIRECTORY;  ANIM OFF;}
		STATICTEXT {JOINENDSCALE;}
		
		LONG PREF_PM_MODE
		{
			ANIM OFF;
			CYCLE
			{
				PREF_PM_MODE_PS;
				PREF_PM_MODE_BP3D;
			}
		}
		STATICTEXT{}
	}
}