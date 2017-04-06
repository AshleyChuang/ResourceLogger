#ifndef MTERRAIN_H__
#define MTERRAIN_H__

enum
{
	TERRAINSHADER_HEIGHT	= 1005,	// REAL
	TERRAINSHADER_TYPE		= 1006,	// LONG
		TERRAINSHADER_TYPE_CUSTOM		= 0,
		TERRAINSHADER_TYPE_MOUNTAIN	= 1,
		TERRAINSHADER_TYPE_MARS			= 2,
		TERRAINSHADER_TYPE_MOON			= 3,
		TERRAINSHADER_TYPE_DESERT		= 4,
		TERRAINSHADER_TYPE_POLAR		= 5,
	TERRAINSHADER_COLOR		= 1007	// GRADIENT
};

#endif	// MTERRAIN_H__
