CONTAINER Zmultipass
{
	NAME Zmultipass;

	GROUP 
	{
		LONG MULTIPASSOBJECT_OBJECTBUFFER { ANIM OFF; MIN 1; }
	}

	GROUP MULTIPASSOBJECT_BLENDDATA
	{
		BOOL MULTIPASSOBJECT_AMBIENT { ANIM OFF; }
		BOOL MULTIPASSOBJECT_DIFFUSE { ANIM OFF; }
		BOOL MULTIPASSOBJECT_SPECULAR { ANIM OFF; }
		BOOL MULTIPASSOBJECT_SHADOW	{ ANIM OFF; }
		BOOL MULTIPASSOBJECT_REFLECTION { ANIM OFF; }
		BOOL MULTIPASSOBJECT_TRANSPARENCY { ANIM OFF; }
		BOOL MULTIPASSOBJECT_RADIOSITY { ANIM OFF; }
		BOOL MULTIPASSOBJECT_CAUSTICS	{ ANIM OFF; }
		BOOL MULTIPASSOBJECT_ATMOSPHERE { ANIM OFF; }
		BOOL MULTIPASSOBJECT_ATMOSPHERE_MUL	{ ANIM OFF; }
		BOOL MULTIPASSOBJECT_ALLPOSTEFFECTS	{ ANIM OFF; }
	}
}
