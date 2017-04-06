#ifndef XSLAFRESNEL_H__
#define XSLAFRESNEL_H__

enum
{
	XSLAFresnel																= 1000,

	SLA_FRESNEL_USE_BUMP											= 1001,
	SLA_FRESNEL_RENDER												= 1002,
		SLA_FRESNEL_RENDER_FRONT_ONLY							= 2001,
		SLA_FRESNEL_RENDER_FRONT_TRANS						= 2002,
		SLA_FRESNEL_RENDER_BACK_ONLY							= 2003,
		SLA_FRESNEL_RENDER_BACK_TRANS							= 2004,
		SLA_FRESNEL_RENDER_FRONT_BACK							= 2005,
	SLA_FRESNEL_GRADIENT											= 1003,

	SLA_FRESNEL_PHY_ENABLE										= 1010,
	SLA_FRESNEL_PHY_IOR											= 1011,
	SLA_FRESNEL_PHY_INVERT										= 1012,
	SLA_FRESNEL_PHY_IOR_PRESET								= 1013,
		SLA_FRESNEL_PHY_IOR_PRESET_CUSTOM				= 1100,
		SLA_FRESNEL_PHY_IOR_PRESET_ASPHALT				= 1101,
		SLA_FRESNEL_PHY_IOR_PRESET_BEER					= 1102,
		SLA_FRESNEL_PHY_IOR_PRESET_BRONZE				= 1103,
		SLA_FRESNEL_PHY_IOR_PRESET_COPPER				= 1104,
		SLA_FRESNEL_PHY_IOR_PRESET_DIAMOND				= 1105,
		SLA_FRESNEL_PHY_IOR_PRESET_EMERALD				= 1106,
		SLA_FRESNEL_PHY_IOR_PRESET_ETHANOL				= 1107,
		SLA_FRESNEL_PHY_IOR_PRESET_GLASS					= 1108,
		SLA_FRESNEL_PHY_IOR_PRESET_GOLD					= 1109,
		SLA_FRESNEL_PHY_IOR_PRESET_IRON					= 1110,
		SLA_FRESNEL_PHY_IOR_PRESET_JADE					= 1111,
		SLA_FRESNEL_PHY_IOR_PRESET_MILK					= 1112,
		SLA_FRESNEL_PHY_IOR_PRESET_PEARL					= 1113,
		SLA_FRESNEL_PHY_IOR_PRESET_PLEXIGLASS		= 1114,
		SLA_FRESNEL_PHY_IOR_PRESET_RUBY					= 1115,
		SLA_FRESNEL_PHY_IOR_PRESET_SAPPHIRE			= 1116,
		SLA_FRESNEL_PHY_IOR_PRESET_SILVER				= 1117,
		SLA_FRESNEL_PHY_IOR_PRESET_WATER					= 1118,
		SLA_FRESNEL_PHY_IOR_PRESET_WATER_ICE			= 1119,
		SLA_FRESNEL_PHY_IOR_PRESET_WHISKEY				= 1120,
		SLA_FRESNEL_PHY_IOR_PRESET_OIL_VEGETABLE = 1121,
		SLA_FRESNEL_PHY_IOR_PRESET_TITANIUM			= 1122,
		SLA_FRESNEL_PHY_IOR_PRESET_TEFLON				= 1123,
		SLA_FRESNEL_PHY_IOR_PRESET_PET						= 1124,

	SLA_FRESNEL_DUMMY_
};

#endif	// XSLAFRESNEL_H__
