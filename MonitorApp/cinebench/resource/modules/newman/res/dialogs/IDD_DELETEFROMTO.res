// C4D-DialogResource
DIALOG IDD_DELETEFROMTO
{
  NAME IDS_DIALOG; CENTER_V; CENTER_H; 
  
  GROUP IDC_DELETEGROUP
  {
    ALIGN_TOP; ALIGN_LEFT; 
    BORDERSTYLE BORDER_NONE; BORDERSIZE 0, 0, 0, 0; 
    COLUMNS 2;
    
    STATICTEXT IDC_DELETE_TEXT1 { NAME IDS_TEXT1; CENTER_V; ALIGN_LEFT; }
    EDITNUMBERARROWS IDC_DELETE_FROM
    { CENTER_V; CENTER_H; SIZE 70, 0; }
    STATICTEXT IDC_DELETE_TEXT2 { NAME IDS_TEXT2; CENTER_V; ALIGN_LEFT; }
    EDITNUMBERARROWS IDC_DELETE_COUNT
    { CENTER_V; CENTER_H; SIZE 70, 0;}
    CHECKBOX IDC_DELETE_RIPPLE
    {NAME IDS_TEXT3; CENTER_V; CENTER_H; }
  }
	DLGGROUP { OK; CANCEL; }
}