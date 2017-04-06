CONTAINER Xmarble
{
	NAME Xmarble;

	INCLUDE Mpreview;
	INCLUDE Xbase;

	GROUP ID_SHADERPROPERTIES
	{
		GRADIENT MARBLESHADER_COLOR { ICC_BASEDOCUMENT; }
		VECTOR 	MARBLESHADER_SCALE { MIN 0.0; STEP 0.01; }
		REAL  	MARBLESHADER_TURBULENCE { UNIT PERCENT; MIN 0.0; MAX 100.0; }
	}
}