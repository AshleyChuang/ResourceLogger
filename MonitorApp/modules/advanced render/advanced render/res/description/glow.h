#ifndef GLOW_H__
#define GLOW_H__

enum
{
	GW_MAXSIZE		= 1501,
	GW_DENS			= 1502,
	GW_BDENS		= 1503,
	GW_LUM			= 1504,
	GW_GCOL			= 1505,
	GW_GEDGES		= 1506,
	GW_COL			= 1507,
	GW_ZSCALE		= 1509,
	GW_DSCALE		= 1510,
	GW_BAL			= 1511,
	GW_BLUM			= 1512,
	GW_BLUMON		= 1513,

	GW_NC_USE		= 1514,
	GW_NC_MIN		= 1515,
	GW_NC_MAX		= 1516,
	GW_NC_COLON		= 1517,
	GW_NC_COL		= 1518,
	GW_NC_COLVAR	= 1519,
	GW_NC_SIZEON	= 1520,
	GW_NC_GSIZE		= 1521,
	GW_NC_DENSON	= 1522,
	GW_NC_GDENS		= 1523,
	GW_NC_LUMON		= 1524,
	GW_NC_GLUM		= 1525,
	GW_NC_GCOL		= 1526,
	GW_NC_GRAD		= 1527,

	GW_AT_USE		= 1528,
	GW_AT_START		= 1529,
	GW_AT_END		= 1530,
	GW_AT_POS		= 1531,
		GW_AT_ZBUFFER = 0,
		GW_AT_3DPOS   = 1,
	GW_AT_SIZEON	= 1533,
	GW_AT_GSIZE		= 1534,
	GW_AT_DENSON	= 1535,
	GW_AT_GDENS		= 1536,
	GW_AT_LUMON		= 1537,
	GW_AT_GLUM		= 1538,
	GW_AT_GCOL		= 1539,
	GW_AT_GRAD		= 1540,

	GW_AL_USE		= 1541,
	GW_AL_MIN		= 1542,
	GW_AL_MAX		= 1543,
	GW_AL_SIZEON	= 1544,
	GW_AL_GSIZE		= 1545,
	GW_AL_DENSON	= 1546,
	GW_AL_GDENS		= 1547,
	GW_AL_LUMON		= 1548,
	GW_AL_GLUM		= 1549,
	GW_AL_GCOL		= 1550,
	GW_AL_GRAD		= 1551,

	GW_SN_USE		= 1552,
	GW_SN_SH		= 1553,
	GW_SN_SIZEON	= 1554,
	GW_SN_GSIZE		= 1555,
	GW_SN_DENSON	= 1556,
	GW_SN_GDENS		= 1557,
	GW_SN_LUMON		= 1558,
	GW_SN_GLUM		= 1559,
	GW_SN_GCOL		= 1560,
	GW_SN_GRAD		= 1561,

	GW_FF_USE		= 1508,
	GW_FF_TYPE		= 1562,
		GW_FF_TYPE_GAS  = 0,
		GW_FF_TYPE_FIRE	= 1,
		GW_FF_TYPE_ELEC = 2,
	GW_FF_INT		= 1563,
	GW_FF_DENS		= 1564,
	GW_FF_BRIGHT	= 1565,
	GW_FF_LUM		= 1566,
	GW_FF_COLOR		= 1567,
	GW_FF_COLORON	= 1568,
	GW_FF_SCALE		= 1569,
	GW_FF_EXP		= 1570,
	GW_FF_LEVEL		= 1571,
	GW_FF_PHASE		= 1572,
	GW_FF_ANGLE		= 1573,
	GW_FF_SPEED		= 1574,
	GW_FF_PSTATIC	= 1575,
	GW_FF_ADD		= 1576,
	GW_FF_STR		= 1577,

	GW_CH_OBJON		= 1578,
	GW_CH_OBJ		= 1579,

	GW_GLOBALS_GROUP = 1580,
	GW_NC_GROUP		= 1581,
	GW_ATT_GROUP	= 1582,
	GW_AL_GROUP		= 1583,
	GW_SN_GROUP		= 1584,
	GW_FF_GROUP		= 1585
};

#endif	// GLOW_H__
