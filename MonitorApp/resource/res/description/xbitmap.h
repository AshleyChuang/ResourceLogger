#ifndef XBITMAP_H__
#define XBITMAP_H__

enum
{
	BITMAPSHADER_FILENAME					= 1000, // FILENAME

	BITMAPSHADER_INTERPOLATION		= 1002,
		BITMAPSHADER_INTERPOLATION_NONE		= 0,
		BITMAPSHADER_INTERPOLATION_CIRCLE	= 1,
		BITMAPSHADER_INTERPOLATION_SQUARE	= 2,
		BITMAPSHADER_INTERPOLATION_ALIAS1	= 3,
		BITMAPSHADER_INTERPOLATION_ALIAS2	= 4,
		BITMAPSHADER_INTERPOLATION_ALIAS3	= 5,
		BITMAPSHADER_INTERPOLATION_MIP	  = 6,
		BITMAPSHADER_INTERPOLATION_SAT	  = 7,

	BITMAPSHADER_EDITIMAGE				= 1003,
	BITMAPSHADER_RELOADIMAGE			= 1004,
	BITMAPSHADER_LAYERSET					= 1005,

	BITMAPSHADER_TIMING_FROM			= 2000,
	BITMAPSHADER_TIMING_TO				= 2001,
	BITMAPSHADER_TIMING_FPS 			= 2002,
	BITMAPSHADER_TIMING_LOOPS 	  = 2003,
	BITMAPSHADER_TIMING_TIMING		= 2004,
		BITMAPSHADER_TIMING_TIMING_FRAME  = 0,
		BITMAPSHADER_TIMING_TIMING_SECOND = 1,
		BITMAPSHADER_TIMING_TIMING_AREA   = 2,
	BITMAPSHADER_TIMING_MODE    	= 2005,
		BITMAPSHADER_TIMING_MODE_SIMPLE   = 0,
		BITMAPSHADER_TIMING_MODE_LOOP     = 1,
		BITMAPSHADER_TIMING_MODE_PINGPONG = 2,
	BITMAPSHADER_TIMING_RANGEFROM	= 2006,
	BITMAPSHADER_TIMING_RANGETO		= 2007,

	BITMAPSHADER_EXPOSURE					= 2010,
	BITMAPSHADER_GAMMA						= 2011,
	BITMAPSHADER_RESETVALUES			= 2012,
	BITMAPSHADER_BLACKPOINT				= 2013,
	BITMAPSHADER_WHITEPOINT				= 2014,

	BITMAPSHADER_COLORPROFILE			= 2017,
		BITMAPSHADER_COLORPROFILE_EMBEDDED	= 0,
		BITMAPSHADER_COLORPROFILE_LINEAR		= 1,
		BITMAPSHADER_COLORPROFILE_SRGB			= 2,

	ID_BITMAPDETAILS				= 8000, // virtual ID
	BITMAPSHADER_CALCULATE	= 8001
};

#endif	// XBITMAP_H__
