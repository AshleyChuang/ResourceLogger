CONTAINER Xbitmap
{
	NAME Xbitmap;

	INCLUDE Mpreview;
	INCLUDE Xbase;

	GROUP ID_MATERIAL_PREVIEW
	{
		LAYOUTGROUP; COLUMNS 2;
		GROUP
		{
			COLUMNS 1;
			BUTTON BITMAPSHADER_RELOADIMAGE { FIT_H; }
			BUTTON BITMAPSHADER_EDITIMAGE { FIT_H; }
		}
	}

	GROUP ID_SHADERPROPERTIES
	{
		LONG BITMAPSHADER_INTERPOLATION
		{
			CYCLE
			{
				BITMAPSHADER_INTERPOLATION_NONE;
				BITMAPSHADER_INTERPOLATION_CIRCLE;
				BITMAPSHADER_INTERPOLATION_SQUARE;
				BITMAPSHADER_INTERPOLATION_ALIAS1;
				BITMAPSHADER_INTERPOLATION_ALIAS2;
				BITMAPSHADER_INTERPOLATION_ALIAS3;
				BITMAPSHADER_INTERPOLATION_MIP;
				BITMAPSHADER_INTERPOLATION_SAT;
			}
		}

		FILENAME BITMAPSHADER_FILENAME { TEXTURE; }

		LAYERSET BITMAPSHADER_LAYERSET { }

		SEPARATOR { LINE; }

		LONG BITMAPSHADER_COLORPROFILE { CYCLE { BITMAPSHADER_COLORPROFILE_EMBEDDED; BITMAPSHADER_COLORPROFILE_LINEAR; BITMAPSHADER_COLORPROFILE_SRGB; } }

		SEPARATOR { LINE; }

		REAL BITMAPSHADER_EXPOSURE { STEP 0.01; MIN -25.0; MAX 25.0; }
		REAL BITMAPSHADER_GAMMA		 { STEP 0.01; MIN 0.0; MAX 100.0; }
		REAL BITMAPSHADER_BLACKPOINT { STEP 0.01; MIN 0.0; MAX 100.0; }
		REAL BITMAPSHADER_WHITEPOINT { STEP 0.01; MIN 0.0; MAX 100.0; }
		BUTTON BITMAPSHADER_RESETVALUES { }
	}

	GROUP ID_BITMAPDETAILS
	{
		LONG BITMAPSHADER_TIMING_MODE
		{
			CYCLE
			{
				BITMAPSHADER_TIMING_MODE_SIMPLE;
				BITMAPSHADER_TIMING_MODE_LOOP;
				BITMAPSHADER_TIMING_MODE_PINGPONG;
			}
		}

		LONG BITMAPSHADER_TIMING_TIMING
		{
			CYCLE
			{
				BITMAPSHADER_TIMING_TIMING_FRAME;
				BITMAPSHADER_TIMING_TIMING_SECOND;
				BITMAPSHADER_TIMING_TIMING_AREA;
			}
		}

		BASETIME BITMAPSHADER_TIMING_RANGEFROM { MIN 0.0; MAX 1000000.0; }
		BASETIME BITMAPSHADER_TIMING_RANGETO   { MIN 0.0; MAX 1000000.0; }

		LONG BITMAPSHADER_TIMING_LOOPS { MIN 0; MAX 1000; }

		SEPARATOR { LINE; }

		LONG BITMAPSHADER_TIMING_FROM	{ MIN 0; MAX 1000000; }
		LONG BITMAPSHADER_TIMING_TO		{ MIN 0; MAX 1000000; }
		REAL BITMAPSHADER_TIMING_FPS 	{ MIN 1; MAX 100; STEP 1.0; }
		BUTTON BITMAPSHADER_CALCULATE {}
 	}
}