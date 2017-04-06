// C4D-DialogResource
DIALOG IDD_BAKE_OBJECT_DIALOG
{
  NAME IDS_DIALOG; SCALE_V; SCALE_H; 
  
  GROUP IDC_STATIC
  {
    NAME IDS_STATIC2; ALIGN_TOP; SCALE_H; 
    BORDERSIZE 4, 4, 4, 0; 
    COLUMNS 2;
    SPACE 4, 4;
    
    GROUP IDC_STATIC
    {
      SCALE_V; SCALE_H; 
      BORDERSIZE 0, 0, 0, 0; 
      COLUMNS 1;
      SPACE 4, 4;
      
      GROUP IDC_STATIC
      {
        NAME IDS_STATIC3; FIT_V; SCALE_H; 
        BORDERSIZE 0, 0, 0, 0; 
        COLUMNS 2;
        SPACE 4, 4;
        
        GROUP IDC_STATIC
        {
          NAME IDS_STATIC6; ALIGN_TOP; SCALE_H; 
          BORDERSIZE 0, 0, 0, 0; 
          COLUMNS 1;
          SPACE 4, 4;
          
          CHECKBOX IDC_BAKE_OBJECT_AO_CHK { NAME IDS_BAKE_OBJ_AO; ALIGN_TOP; ALIGN_LEFT;  }
          CHECKBOX IDC_BAKE_OBJECT_NORMAL_CHK { NAME IDS_BAKE_OBJ_NORMALS; ALIGN_TOP; ALIGN_LEFT;  }
          CHECKBOX IDC_BAKE_OBJECT_KEEP_UV_CHK { NAME IDS_KEEP_UV; ALIGN_TOP; ALIGN_LEFT;  }
        }
        GROUP IDC_STATIC
        {
          NAME IDS_STATIC5; ALIGN_TOP; SCALE_H; 
          BORDERSIZE 0, 0, 0, 0; 
          COLUMNS 1;
          SPACE 4, 4;
          
          CHECKBOX IDC_BAKE_OBJECT_ILLUM_CHK { NAME IDS_BAKE_OBJ_ILLUMINATE; ALIGN_TOP; ALIGN_LEFT;  }
          CHECKBOX IDC_BAKE_OBJECT_SINGLE_TEX_CHK { NAME IDS_SINGLE_TEXTURE; ALIGN_TOP; ALIGN_LEFT;  }
          CHECKBOX IDC_BAKE_OBJECT_REPLACE_CHK { NAME IDS_BAKE_OBJ_REPLACE; ALIGN_TOP; ALIGN_LEFT;  }
        }
      }
      GROUP IDC_STATIC
      {
        NAME IDS_STATIC19; ALIGN_TOP; ALIGN_LEFT; 
        BORDERSIZE 0, 0, 0, 0; 
        COLUMNS 4;
        SPACE 4, 4;
        
        STATICTEXT IDC_STATIC { NAME IDS_STATIC20; CENTER_V; ALIGN_LEFT; }
        EDITNUMBERARROWS IDC_BAKE_OBJECT_SUPERSAMPLING_EDIT
        { CENTER_V; CENTER_H; SIZE 70, 0; }
        STATICTEXT IDC_STATIC { NAME IDS_STATIC21; CENTER_V; ALIGN_LEFT; }
        EDITNUMBERARROWS IDC_BAKE_OBJECT_PBORDER_EDIT
        { CENTER_V; CENTER_H; SIZE 70, 0; }
        STATICTEXT IDC_STATIC { NAME IDS_STATIC7; CENTER_V; ALIGN_LEFT; }
        EDITNUMBERARROWS IDC_BAKE_OBJECT_WIDTH_EDIT
        { CENTER_V; CENTER_H; SIZE 70, 0; }
        STATICTEXT IDC_STATIC { NAME IDS_STATIC8; CENTER_V; ALIGN_LEFT; }
        EDITNUMBERARROWS IDC_BAKE_OBJECT_HEIGHT_EDIT
        { CENTER_V; CENTER_H; SIZE 70, 0; }
      }
      GROUP IDC_STATIC
      {
        NAME IDS_STATIC10; ALIGN_TOP; SCALE_H; 
        BORDERSIZE 0, 0, 0, 0; 
        COLUMNS 2;
        SPACE 4, 4;
        
        STATICTEXT IDC_STATIC { NAME IDS_STATIC11; CENTER_V; ALIGN_LEFT; }
        COMBOBOX IDC_BAKE_OBJECT_FORMAT_COMBO
        {
          ALIGN_TOP; SCALE_H; SIZE 150, 0; 
          CHILDS
          {
          }
        }
        STATICTEXT IDC_STATIC { NAME IDS_STATIC16; CENTER_V; ALIGN_LEFT; }
        GROUP IDC_STATIC
        {
          NAME IDS_STATIC12; ALIGN_TOP; SCALE_H; 
          BORDERSIZE 0, 0, 0, 0; 
          COLUMNS 2;
          SPACE 4, 4;
          
          COMBOBOX IDC_BAKE_OBJECT_BPP_COMBO
          {
            ALIGN_TOP; SCALE_H; SIZE 150, 0; 
            CHILDS
            {
            }
          }
          BUTTON IDC_BAKE_OBJECT_OPTIONS_BTN { NAME IDS_BAKE_OBJ_OPTIONS; ALIGN_TOP; ALIGN_LEFT; }
        }
        STATICTEXT IDC_STATIC { NAME IDS_STATIC22; CENTER_V; ALIGN_LEFT; }
        COLORPROFILE IDC_BAKE_OBJECT_COLOR_PROFILE
        {
          ALIGN_TOP; SCALE_H; 
        }
      }
    }
    GROUP IDC_STATIC
    {
      NAME IDS_STATIC1; SCALE_V; ALIGN_LEFT; 
      BORDERSIZE 0, 0, 0, 0; 
      COLUMNS 1;
      SPACE 4, 4;
      
      MATPREVIEW IDC_BAKE_OBJECT_PREVIEW
      {
        SCALE_V; SCALE_H; 
        OPEN; 
        MIN_WIDTH 150; 
        MIN_HEIGHT 150; 
      }
    }
  }
  GROUP IDC_STATIC
  {
    NAME IDS_STATIC15; ALIGN_TOP; SCALE_H; 
    BORDERSIZE 4, 0, 4, 4; 
    COLUMNS 1;
    SPACE 4, 4;
    
    GROUP IDC_STATIC
    {
      NAME IDS_STATIC18; ALIGN_TOP; SCALE_H; 
      BORDERSIZE 0, 0, 0, 0; 
      COLUMNS 2;
      SPACE 4, 4;
      
      STATICTEXT IDC_STATIC { NAME IDS_STATIC17; CENTER_V; ALIGN_LEFT; }
      FILENAME IDC_BAKE_OBJECT_FILENAME_EDIT
      {
        ALIGN_TOP; SCALE_H; 
        DIRECTORY; 
      }
    }
    GROUP IDC_STATIC
    {
      NAME IDS_STATIC4; ALIGN_TOP; CENTER_H; 
      BORDERSIZE 0, 4, 0, 0; 
      COLUMNS 2;
      SPACE 4, 4;
      
      BUTTON IDC_BAKE_OBJECT_BAKE_BTN { NAME IDS_BAKE; ALIGN_TOP; ALIGN_LEFT; }
      BUTTON IDC_BAKE_OBJECT_CANCEL_BTN { NAME IDS_CANCEL; ALIGN_TOP; ALIGN_LEFT; }
    }
  }
}