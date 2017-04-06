DIALOG DLG_DEMO
{
  NAME IDS_DIALOG; SCALE_H; SCALE_V;

	GROUP
	{
		COLUMNS 1;
		BORDERSIZE 4,4,4,4;
		SCALE_H; SCALE_V;

		HTMLVIEWER IDC_DEMOHTML
		{
			SCALE_V; SCALE_H; SIZE -750,-600;
		}

		GROUP IDC_DEMOTAB1
		{
			FIT_V; CENTER_H; 
			COLUMNS 2;

			BUTTON IDC_DEMOACTIVATE { NAME IDS_BUTTON; FIT_V; CENTER_H; SIZE 0, 20; }
			BUTTON IDC_DEMOCONTINUE1 { NAME IDS_BUTTONT1; FIT_V; CENTER_H; SIZE 0, 20; }
		}
	}
}