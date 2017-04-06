DIALOG IDD_COFFEESCRIPT_DIALOG
{
  NAME T1;
  SCALE_H;
  SCALE_V;

	GROUP
	{
	  SCALE_H;
	  SCALE_V;
		COLUMNS 1;
		BORDERSIZE 4,4,4,4;

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
				
				QUICKTAB IDC_SCRIPTMANAGER_SCRIPTMODE { SCALE_H; SHOWSINGLE; NOLINEBREAK; NOMULTISELECT; }
			}
		}
		SEPARATOR { SCALE_H; }

		GROUP IDD_COFFEESCRIPT_VARIABLEGROUP
		{
			SCALE_H;
			SCALE_V;
			
			GROUP IDD_COFFEESCRIPT_COFFEEMODE
			{
				SCALE_H;
				SCALE_V;
				COLUMNS 1;
				
				GROUP
				{
					COLUMNS 2;
					SCALE_H;

					GROUP
					{
						ROWS 1;
						FIT_H;
						BITMAPBUTTON IDC_COFFEESCRIPT_IMAGE { SIZE -32,-32; BORDER; BUTTON; }
						STATICTEXT { NAME TA; }
					}

					COMBOBOX IDC_COFFEESCRIPT_SCRIPT { SCALE_H; SIZE 300,0; }

					STATICTEXT IDC_STATIC { NAME TR3; }

					GROUP
					{
						COLUMNS 2;
						SCALE_H;
						EDITTEXT IDC_COFFEESCRIPT_SCRIPTNAME { CENTER_V; SCALE_H; SIZE 70, 0; }
						COMBOBOX IDC_COFFEESCRIPT_LANGUAGE { FIT_H; SIZE 100,0; }
					}

					STATICTEXT IDC_STATIC { NAME TR4; }
					EDITTEXT IDC_COFFEESCRIPT_SCRIPTHELP { CENTER_V; SCALE_H; SIZE 70, 0; }
					STATICTEXT IDC_STATIC { NAME TR5; }
					MULTILINEEDIT IDC_COFFEESCRIPT_SCRIPTENABLE { MONOSPACED; SYNTAXCOLOR; HIGHLIGHTLINE; STATUSBAR; SCALE_V; SCALE_H; SIZE 70, 80; }
				}

				GROUP
				{
					COLUMNS 1;
					SCALE_H;
					SCALE_V;

					MULTILINEEDIT IDC_COFFEESCRIPT_TEXT
					{
						MONOSPACED;
						SYNTAXCOLOR;
						HIGHLIGHTLINE;
						STATUSBAR;
						SCALE_H;SCALE_V; SIZE 600,100;
					}
				}

				GROUP
				{
					SCALE_H;
					ROWS 1;
					BORDERSIZE 0, 0, 3, 0;

					GROUP
					{
						COLUMNS 1;
						CHECKBOX IDC_COFFEESCRIPT_SCRIPTSHOW { NAME TR7; }
						CHECKBOX IDC_COFFEESCRIPT_SCRIPTADDEVENT { NAME TR8; }
					}

					STATICTEXT { SCALE_H; }

					BUTTON IDC_COFFEESCRIPT_ASSIGNSHORTCUT { ALIGN_RIGHT; SCALE_V; NAME T13; }
					BUTTON IDC_COFFEESCRIPT_EXECUTE { ALIGN_RIGHT; SCALE_V; NAME T10; }
				}
			}
			
			GROUP IDD_COFFEESCRIPT_PYTHONMODE
			{
				SCALE_H;
				SCALE_V;
				COLUMNS 1;

				
				GROUP
				{
					COLUMNS 2;
					SCALE_H;

					GROUP
					{
						ROWS 1;
						FIT_H;
						BITMAPBUTTON IDC_PYTHONSCRIPT_IMAGE { SIZE -32,-32; BORDER; }
						STATICTEXT { NAME TA; }
					}

					COMBOBOX IDC_PYTHONSCRIPT_SCRIPT { SCALE_H; SIZE 300,0; }
				}
				
				GROUP
				{
					COLUMNS 1;
					SCALE_H;
					SCALE_V;

					MULTILINEEDIT IDC_PYTHONSCRIPT_TEXT
					{
						MONOSPACED;
						PYTHON;
						HIGHLIGHTLINE;
						SYNTAXCOLOR;
						STATUSBAR;
						SCALE_H;SCALE_V; SIZE 600,100;
					}
				}

				GROUP
				{
					SCALE_H;
					ROWS 1;
					BORDERSIZE 0, 0, 3, 0;

					STATICTEXT { SCALE_H; }

					BUTTON IDC_PYTHONSCRIPT_ASSIGNSHORTCUT { ALIGN_RIGHT; SCALE_V; NAME T13; }
					BUTTON IDC_PYTHONSCRIPT_EXECUTE { ALIGN_RIGHT; SCALE_V; NAME T10; }
				}
			}
		}
	}
}