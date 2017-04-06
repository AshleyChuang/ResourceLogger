// C4D-DialogResource

DIALOG R_EXPRESSION
{
  NAME T1;
  SCALE_H;
  SCALE_V;

	GROUP
	{
		COLUMNS 1;
		SCALE_H;
		SPACE 4,1;
		GROUP
		{
			ROWS 1; 
			SCALE_H;
			SPACE 1,4;
			WINDOWPIN { ALIGN_LEFT; ALIGN_TOP; };
			BUTTON IDC_LOAD { NAME T2; }
			BUTTON IDC_SAVE { NAME T3; }
			STATICTEXT { SIZE 6,0; }
			BUTTON IDC_COMPILE { NAME T4; }    
			BUTTON IDC_X3      { NAME T10; }    
		}
		SEPARATOR { SCALE_H; }
	}

	GROUP
	{
		COLUMNS 1; 
		SCALE_H;
		SCALE_V;
		BORDERSIZE 4,0,4,4;

		GROUP
		{
			COLUMNS 1; 
			SCALE_H;
			SCALE_V;

			MULTILINEEDIT IDC_TEXT 
			{
				MONOSPACED;
				SYNTAXCOLOR;
				STATUSBAR;
				SCALE_H;SCALE_V; SIZE 600,30; 
			}
		}
		
		STATICTEXT IDC_MESSAGE { SCALE_H; NAME T7; }		

		GROUP
		{
			ROWS 1; 
			
			STATICTEXT IDC_X1 { NAME T8; }
			STATICTEXT IDC_LINE { SIZE 80,0; }
	    
			STATICTEXT IDC_X2 { NAME T9; }
			STATICTEXT IDC_POS { SIZE 80,0; }    
		}
	}
}