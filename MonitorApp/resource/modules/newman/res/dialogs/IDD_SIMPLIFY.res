// C4D-DialogResource
DIALOG IDD_SIMPLIFY
{
  NAME IDS_DIALOG; CENTER_V; CENTER_H; 
  
  GROUP IDC_SIMPLIFY_GR1
  {
    ALIGN_TOP; ALIGN_LEFT; 
    BORDERSIZE 0, 0, 0, 0; 
    COLUMNS 2;
    SPACE 4, 4;
    
    STATICTEXT IDC_SIMPLIFY_TXT1 { NAME IDS_TEXT1; CENTER_V; ALIGN_LEFT; }
    EDITNUMBERARROWS IDC_SIMPLIFY_VALUE
    { CENTER_V; CENTER_H; SIZE 70, 0; }
  }
  GROUP IDC_SIMPLIFY_GR1
  {
    ALIGN_TOP; ALIGN_LEFT; 
    BORDERSIZE 0, 0, 0, 0; 
    COLUMNS 2;
    SPACE 4, 4;
    
    STATICTEXT IDC_SIMPLIFY_TXT1 { NAME IDS_TEXT2; CENTER_V; ALIGN_LEFT; }
    EDITNUMBERARROWS IDC_SIMPLIFY_FRAME
    { CENTER_V; CENTER_H; SIZE 70, 0; }
  }
  DLGGROUP { OK; CANCEL; }
}