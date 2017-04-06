#ifndef GVNOISE_H__
#define GVNOISE_H__

#include "gvbase.h"

enum
{
	GV_NOISE_FUNCTION					= 1000,
		GV_NOISE_NOISE = 0,
		GV_NOISE_TURBULENCE,
		GV_NOISE_FRACTAL,
		GV_NOISE_FBM,
	GV_NOISE_POSITIVE					= 1001,

	GV_NOISE_LEVELS						= 2000,
	GV_NOISE_TIME,
	GV_NOISE_X,
	GV_NOISE_Y,
	GV_NOISE_Z,
	GV_NOISE_VECTOR,
	GV_NOISE_FREQUENCY,
	GV_NOISE_SCALE,
	GV_NOISE_AMPLITUDE,
	GV_NOISE_SEED,

	GV_NOISE_OUTPUT						= 3000,

	GV_NOISE_
};

#endif	// GVNOISE_H__
