CONTAINER Odoodle
{
	NAME Odoodle;
	INCLUDE Obase;

	GROUP DOODLEOBJECT_GROUP_OPTIONS
	{
		LINK DOODLEOBJECT_BD				{ HIDDEN; }
		LINK DOODLEOBJECT_IMAGE     { ACCEPT { 1022211; } HIDDEN; }

		GROUP
		{
			COLUMNS 2;
			BUTTON DOODLEOBJECT_ADDIMAGE			{	FIT_H; }
			BUTTON DOODLEOBJECT_DELIMAGE			{	FIT_H; }
			BUTTON DOODLEOBJECT_CLEARFRAME		{ FIT_H; }
			BUTTON DOODLEOBJECT_SETBD					{	FIT_H; }
			BUTTON DOODLEOBJECT_LOAD_BITMAP		{	FIT_H; }
			BUTTON DOODLEOBJECT_REMOVE_UNUSED	{	FIT_H; }
			BUTTON DOODLEOBJECT_EXPORT				{	FIT_H; }
			BUTTON DOODLEOBJECT_IMPORT				{	FIT_H; }
		}
		
		SEPARATOR { LINE; }
		
		LONG DOODLEOBJECT_EXPORT_FORMAT
		{
			CYCLE
			{
				DOODLEOBJECT_EXPORT_FORMAT_PNG;
				DOODLEOBJECT_EXPORT_FORMAT_TIF;
			}
		}
		
		SEPARATOR { LINE; }
				
		GROUP
		{
			COLUMNS 2;
			LONG DOODLEOBJECT_SIZE_X { MIN 100; MAX 1024; }
			LONG DOODLEOBJECT_SIZE_Y { MIN 100; MAX 1024; }
		}
	
		SEPARATOR { LINE; }
		
		GROUP
		{
			COLUMNS 2;
			BOOL DOODLEOBJECT_GHOST_PREV { }
			BOOL DOODLEOBJECT_GHOST_NEXT { }
			BOOL DOODLEOBJECT_SMOOTHVIEW { }
			BOOL DOODLEOBJECT_SAVECOMPRESSED { }
		}
	}
	GROUP ID_OBJECTPROPERTIES
	{
		STRING DOODLEOBJECT_CURRENTVIEW { ANIM OFF;  }

		SEPARATOR { LINE; }
		
		STRING DOODLEOBJECT_TITLE { ANIM OFF; }
		STRING DOODLEOBJECT_BODY { OPEN; CUSTOMGUI MULTISTRING; ANIM OFF; }
	}
}