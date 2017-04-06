#ifndef DGRADIENT_H__
#define DGRADIENT_H__

enum
{
	GRADIENTSUBCHANNEL_INTERPOLATION	= 1000,
		GRADIENTSUBCHANNEL_INTERPOLATION_CUBICKNOT 	= 0,
		GRADIENTSUBCHANNEL_INTERPOLATION_CUBICBIAS	= 1,
		GRADIENTSUBCHANNEL_INTERPOLATION_SMOOTHKNOT	= 2,
		GRADIENTSUBCHANNEL_INTERPOLATION_LINEARKNOT = 3,
		GRADIENTSUBCHANNEL_INTERPOLATION_LINEAR			= 4,
		GRADIENTSUBCHANNEL_INTERPOLATION_NONE				= 5,
		GRADIENTSUBCHANNEL_INTERPOLATION_EXP_UP			= 6,
		GRADIENTSUBCHANNEL_INTERPOLATION_EXP_DOWN		= 7
};

#endif	// DGRADIENT_H__
