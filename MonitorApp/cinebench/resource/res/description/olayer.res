CONTAINER olayer
{
	NAME olayer;
	INCLUDE Obaselist;
	
	HIDE ID_LAYER_LINK;
	GROUP Obaselist
	{
		DEFAULT 1;
		COLOR ID_LAYER_COLOR { ANIM OFF; HIDEINPORT; }
		BOOL ID_LAYER_SOLO { ANIM OFF; HIDEINPORT; }
		BOOL ID_LAYER_VIEW { ANIM OFF; HIDEINPORT; }
		BOOL ID_LAYER_RENDER { ANIM OFF; HIDEINPORT; }
		BOOL ID_LAYER_MANAGER { ANIM OFF; HIDEINPORT; }
		BOOL ID_LAYER_ANIMATION { ANIM OFF; HIDEINPORT; }
		BOOL ID_LAYER_GENERATORS { ANIM OFF; HIDEINPORT; }
		BOOL ID_LAYER_DEFORMERS { ANIM OFF; HIDEINPORT; }
		BOOL ID_LAYER_EXPRESSIONS { ANIM OFF; HIDEINPORT; }
		BOOL ID_LAYER_LOCKED { ANIM OFF; HIDEINPORT; }
		BOOL ID_LAYER_XREF { ANIM OFF; HIDEINPORT; }
	}
}
