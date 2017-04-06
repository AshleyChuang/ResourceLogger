// C4D-DialogResource

DIALOG P_PAINTTOOL_LINE
{
  NAME TITLE;
	SCALE_H; SCALE_V;

	GROUP
	{
		COLUMNS 1;
		RADIOGROUP PGD_POLY_DRAWMODE
		{
			GROUP
			{
				ROWS 1;
				RADIOGADGET PGD_DRAWMODE_FILLED   { NAME TFILLED; }
				RADIOGADGET PGD_DRAWMODE_OUTLINED { NAME TOUTLINE; }
//				RADIOGADGET PGD_DRAWMODE_PATH			{ NAME TPATH; }
			}
		}
	}

  GROUP
  {
		COLUMNS 2;
		SCALE_H; SCALE_V;

		TAB PGD_POLYFILL_BRUSHEDITORTAB
		{
			SELECTION_NONE;
			SCALE_H; SCALE_V;

			GROUP IDC_X1 
			{
				SCALE_H;
				COLUMNS 1;
				GROUP
				{
					SCALE_H;
					STATICTEXT { NAME TENDINGS; }
					GROUP
					{
						ROWS 1;
						COMBOBOX PGD_LINE_BEGIN
						{
							CHILDS
							{
								PGD_CAPS_NONE				, TNONE;
								PGD_CAPS_OUT_CIRCLE	, TROUNDOUT;
								PGD_CAPS_IN_CIRCLE  , TROUNDIN;
								PGD_CAPS_OUT_SPICE  , TSPICEOUT;
								PGD_CAPS_IN_SPICE		, TSPICEIN;
								PGD_CAPS_OUT_BEVEL	, TBEVELOUT;
								PGD_CAPS_IN_BEVEL		, TBEVELIN;
								PGD_CAPS_ARROW			, TARROWS;
							}
						}
						COMBOBOX PGD_LINE_END
						{
							CHILDS
							{
								PGD_CAPS_NONE				, TNONE;
								PGD_CAPS_OUT_CIRCLE	, TROUNDOUT;
								PGD_CAPS_IN_CIRCLE  , TROUNDIN;
								PGD_CAPS_OUT_SPICE  , TSPICEOUT;
								PGD_CAPS_IN_SPICE		, TSPICEIN;
								PGD_CAPS_OUT_BEVEL	, TBEVELOUT;
								PGD_CAPS_IN_BEVEL		, TBEVELIN;
								PGD_CAPS_ARROW			, TARROWS;
							}
						}
					}

					COLUMNS 2;
					STATICTEXT { NAME TLINEWIDTH; }
					EDITSLIDER PGD_LINE_WIDTH { SCALE_H; };

					STATICTEXT { NAME TSMOOTHBORDER; }
					EDITSLIDER PGD_POLYFILL_BORDER { SCALE_H; }

					STATICTEXT {}
					CHECKBOX PGD_POLYFILL_ANTIALIAS { NAME TAA; }
				}
			}
			GROUP PGD_POLYFILL_BRUSHEDITOR 
			{
				SCALE_H; SCALE_V;
				BRUSHEDITOR { SCALE_H; SCALE_V; }
			}
		}
	}
}