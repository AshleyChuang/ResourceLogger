CONTAINER Xplanet
{
	NAME Xplanet;

	INCLUDE Mpreview;
	INCLUDE Xbase;

	GROUP ID_SHADERPROPERTIES
	{
		LONG PLANETSHADER_TYPE
		{
			CYCLE
			{
				PLANETSHADER_TYPE_SATURN;
				PLANETSHADER_TYPE_SATURNRING;
				PLANETSHADER_TYPE_URANUS;
				PLANETSHADER_TYPE_NEPTUNE;
			}
		}
	}
}