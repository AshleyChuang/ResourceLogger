// C4D-DialogResource
DIALOG IDD_ADDKEYAT
{
  NAME IDS_DIALOG; CENTER_V; CENTER_H; 
  
  GROUP IDC_GROUPADKEYAT
  {
    ALIGN_TOP; ALIGN_LEFT; 
    BORDERSTYLE BORDER_NONE; BORDERSIZE 0, 0, 0, 0; 
    COLUMNS 2;
    
    STATICTEXT IDC_TEXTADDKEAT { NAME IDS_TEXT; CENTER_V; ALIGN_LEFT; }
    EDITNUMBERARROWS IDC_ADDKEY_TIME
    { CENTER_V; CENTER_H; SIZE 70, 0; }
  }
  DLGGROUP { OK; CANCEL; }
}