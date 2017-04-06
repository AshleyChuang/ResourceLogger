CONTAINER OCloudGroup
{
	NAME OCloudGroup;
	INCLUDE Obase;

	GROUP ID_OBJECTPROPERTIES
	{
		LAYOUTGROUP; COLUMNS 2;
		GROUP
		{
			REAL SKY_CLOUD_GROUP_ALTITUDE_MIN { UNIT METER; MIN 0; }
			REAL SKY_CLOUD_GROUP_FALLOFF_MIN { UNIT METER; MIN 0; }
			REAL SKY_CLOUD_GROUP_LUM_FALLOFF_MIN { UNIT METER; MIN 0; }
			REAL SKY_CLOUD_GROUP_TRANS_FALLOFF_MIN { UNIT METER; MIN 0; }
			COLOR SKY_CLOUD_GROUP_COLOR_1 { }
		}
		GROUP
		{
			REAL SKY_CLOUD_GROUP_ALTITUDE_MAX { UNIT METER; MIN 0; }
			REAL SKY_CLOUD_GROUP_FALLOFF_MAX { UNIT METER; MIN 0; }
			REAL SKY_CLOUD_GROUP_LUM_FALLOFF_MAX { UNIT METER; MIN 0; }
			REAL SKY_CLOUD_GROUP_TRANS_FALLOFF_MAX { UNIT METER; MIN 0; }
			COLOR SKY_CLOUD_GROUP_COLOR_2 { }
		}
	}
}