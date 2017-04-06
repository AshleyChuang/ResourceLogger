CONTAINER Xmg_color
{
	NAME		Xmg_color;

	INCLUDE Xbase;

	GROUP		ID_SHADERPROPERTIES
	{
		LONG	MGCOLORSHADER_MODE
		{
			CYCLE
			{
				MGCOLORSHADER_MODE_COLOR;
				MGCOLORSHADER_MODE_INDEXRATIO;
			}
		}
		BOOL	MGCOLORSHADER_INVERT {}
		SPLINE	MGCOLORSHADER_SPLINE
		{
			SHOWGRID_H;
			SHOWGRID_V;
			GRIDSIZE_H 8;
			GRIDSIZE_V 8;
			HAS_PRESET_BTN;
			MINSIZE_H 120;
			MINSIZE_V 90;
			EDIT_H;
			EDIT_V;
			LABELS_H;
			LABELS_V;
			HAS_ROUND_SLIDER;
			X_MIN 0;
			X_MAX 100;
			Y_MIN 0;
			Y_MAX 100;
			X_STEPS 1;
			Y_STEPS 1;
		}
	}
}
