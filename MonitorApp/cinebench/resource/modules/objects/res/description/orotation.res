CONTAINER Orotation
{
	NAME Orotation;
	INCLUDE Oparticlebase;

	GROUP ID_OBJECTPROPERTIES
	{
		REAL ROTATIONOBJECT_STRENGTH { MIN 0.0; STEP 0.01; }
		//VECTOR ROTATIONOBJECT_SIZE { UNIT METER; MIN 0.0;}
		LONG PARTICLEBASE_MODE {CYCLE {PARTICLEBASE_MODE_ACCELERATION; PARTICLEBASE_MODE_FORCE; PARTICLEBASE_MODE_AERODYNAMICS;} }
	}
}
