CONTAINER Obulge
{
	NAME Obulge;
	INCLUDE Obasedeform;

	SHOW DEFORMOBJECT_SIZE;
	SHOW DEFORMOBJECT_MODE;
	SHOW DEFORMOBJECT_CURVATURE;
	SHOW DEFORMOBJECT_STRENGTH;
	SHOW DEFORMOBJECT_FILLET;
	
	GROUP ID_OBJECTPROPERTIES
	{
		SEPARATOR		{ LINE; }
		BUTTON	DEFORMOBJECT_FITTOPARENT	{  }
	}
}
