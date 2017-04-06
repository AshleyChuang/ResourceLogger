// C4D Menu Resource

MENU M_EDITOR
{
  SUBMENU IDS_EDITOR_FILE
  {
    IDM_NEU;
    IDM_OEFFNE;
    IDM_HINZULADEN;
    IDM_REVERTFILE;
    SEPARATOR;
    IDM_CLOSESCENE;
    IDM_CLOSEALL;
    SEPARATOR;
    IDM_SPEICHERN;
    IDM_S_C4D5;
    PLUGIN_ID_SAVE0x0020INCREMENTAL;
    SEPARATOR;
    IDM_SAVEALL;
    IDM_MAKEPROJECT;
    PLUGIN_CMD_100004765;
    PLUGIN_CMD_100004841;
    SEPARATOR;
    SUBMENU IDS_EDITOR_EXPORT
    {
      IDM_FILTER3D;
    }
    SUBMENU IDS_RECENT
    {
      IDM_RECENTFILES;
    }
    SEPARATOR;
    PLUGIN_CMD_200000204;
    IDM_BEENDEN;
  }
  SUBMENU IDS_EDITOR_EDIT
  {
    IDM_UNDO;
    IDM_REDO;
    IDM_MODELING_UNDOLAST;
    SEPARATOR;
    IDM_CUT;
    IDM_COPY;
    IDM_PASTE;
    IDM_DELETE;
    SEPARATOR;
    IDM_SELECTALL;
    IDM_SELECTNONE;
    IDM_SELECTCHILDS;
    SEPARATOR;
    IDM_DOC_PREFS;
    IDM_STATISTICS;
    PLUGIN_CMD_200000277;
    SEPARATOR;
    PLUGIN_CMD_1000474;
  }
  SUBMENU IDS_MENU_CREATE
  {
    SUBMENU IDS_MENU_OBJECT
    {
      PLUGIN_CMD_5140;
      IDM_POLYACHSE2;
      PLUGIN_CMD_1027657;
      SEPARATOR;
      PLUGIN_CMD_5162;
      PLUGIN_CMD_5159;
      PLUGIN_CMD_5170;
      PLUGIN_CMD_5164;
      PLUGIN_CMD_5168;
      PLUGIN_CMD_5174;
      PLUGIN_CMD_5160;
      PLUGIN_CMD_5163;
      SEPARATOR;
      PLUGIN_CMD_5171;
      PLUGIN_CMD_5172;
      PLUGIN_CMD_5165;
      PLUGIN_CMD_5167;
      PLUGIN_CMD_5161;
      SEPARATOR;
      PLUGIN_CMD_5166;
      PLUGIN_CMD_5169;
      PLUGIN_CMD_5173;
    }
    SUBMENU IDS_MENU_SPLINE
    {
      IDM_POLYACHSE;
      SEPARATOR;
      IDM_SPLINE_FREEHAND;
      IDM_SPLINE_BEZIER;
      IDM_SPLINE_BSPLINE;
      IDM_SPLINE_LINEAR;
      IDM_SPLINE_CUBIC;
      IDM_SPLINE_AKIMA;
      SEPARATOR;
      PLUGIN_CMD_5182;
      PLUGIN_CMD_5181;
      PLUGIN_CMD_5185;
      PLUGIN_CMD_5179;
      PLUGIN_CMD_5186;
      PLUGIN_CMD_5187;
      PLUGIN_CMD_5178;
      PLUGIN_CMD_5189;
      SEPARATOR;
      PLUGIN_CMD_5180;
      PLUGIN_CMD_5183;
      PLUGIN_CMD_5188;
      PLUGIN_CMD_5184;
      PLUGIN_CMD_5177;
      PLUGIN_CMD_5176;
      PLUGIN_CMD_5175;
    }
    SEPARATOR;
    SUBMENU IDS_EDITOR_NURBS
    {
      PLUGIN_CMD_1007455;
      SEPARATOR;
      PLUGIN_CMD_5116;
      PLUGIN_CMD_5117;
      PLUGIN_CMD_5107;
      PLUGIN_CMD_5118;
      SEPARATOR;
      PLUGIN_CMD_5120;
    }
    SUBMENU IDS_EDITOR_MODELING
    {
      PLUGIN_CMD_5150;
      PLUGIN_CMD_1001002;
      PLUGIN_CMD_1010865;
      PLUGIN_CMD_1019396;
      PLUGIN_CMD_1011010;
      PLUGIN_CMD_5126;
      PLUGIN_CMD_5125;
      PLUGIN_CMD_5142;
      PLUGIN_CMD_1023866;
      SEPARATOR;
      PLUGIN_CMD_5153;
    }
    SUBMENU IDS_EDITOR_DEFORMATION
    {
      PLUGIN_CMD_5128;
      PLUGIN_CMD_5129;
      PLUGIN_CMD_5131;
      PLUGIN_CMD_5133;
      PLUGIN_CMD_5134;
      SEPARATOR;
      PLUGIN_CMD_5108;
      PLUGIN_CMD_1024543;
      PLUGIN_CMD_1021280;
      PLUGIN_CMD_5147;
      SEPARATOR;
      PLUGIN_CMD_5145;
      PLUGIN_CMD_1002603;
      PLUGIN_CMD_5148;
      SEPARATOR;
      PLUGIN_CMD_1024542;
      PLUGIN_CMD_1021284;
      PLUGIN_CMD_1019768;
      SEPARATOR;
      PLUGIN_CMD_1019774;
      PLUGIN_CMD_1001003;
      PLUGIN_CMD_1024552;
      PLUGIN_CMD_5143;
      SEPARATOR;
      PLUGIN_CMD_1008982;
      PLUGIN_CMD_1008796;
      PLUGIN_CMD_1019221;
      SEPARATOR;
      PLUGIN_CMD_1024476;
      PLUGIN_CMD_1024544;
      PLUGIN_CMD_1018685;
      PLUGIN_CMD_5146;
      PLUGIN_CMD_5149;
      SEPARATOR;
      PLUGIN_CMD_1001253;
      PLUGIN_CMD_1024529;
    }
    SEPARATOR;
    SUBMENU IDS_EDITOR_SCENE
    {
      PLUGIN_CMD_5104;
      PLUGIN_CMD_5105;
      PLUGIN_CMD_1028462;
      SEPARATOR;
      PLUGIN_CMD_5106;
      PLUGIN_CMD_5121;
      PLUGIN_CMD_5122;
      PLUGIN_CMD_5136;
    }
    SUBMENU IDS_MENU_PHYSICALSKY
    {
      PLUGIN_CMD_1011145;
      PLUGIN_CMD_450000023;
      PLUGIN_CMD_450000059;
      PLUGIN_CMD_450000058;
      PLUGIN_CMD_450000057;
    }
    SEPARATOR;
    SUBMENU IDS_MENU_CAMERA
    {
      PLUGIN_CMD_5103;
      IDM_CAMERATARGET;
      IDM_CAMERASTEREO;
      PLUGIN_CMD_1027744;
      PLUGIN_CMD_1027745;
      PLUGIN_CMD_1028271;
    }
    SUBMENU IDS_MENU_LIGHT
    {
      PLUGIN_CMD_5102;
      PLUGIN_ID_NEWSPOTLIGHT;
      IDM_LIGHTTARGET;
      SEPARATOR;
      PLUGIN_ID_NEWAREALIGHT;
      PLUGIN_CMD_300001070;
      SEPARATOR;
      PLUGIN_ID_NEWINFINITELIGHT;
      IDM_LIGHTSUN;
    }
    SUBMENU IDS_MENU_MATERIAL
    {
      IDM_MNEU;
      SEPARATOR;
      IDM_VOLUMESHADER;
    }
    SUBMENU IDS_MENU_TAG
    {
      PLUGIN_CMD_100004788;
    }
    SEPARATOR;
    SUBMENU IDS_MENU_XREF
    {
      PLUGIN_CMD_1025763;
      SEPARATOR;
      PLUGIN_CMD_1025766;
      PLUGIN_CMD_1025776;
      PLUGIN_CMD_1025773;
      PLUGIN_CMD_200000162;
      PLUGIN_CMD_200000163;
    }
    SUBMENU IDS_EDITOR_SOUND
    {
      PLUGIN_CMD_5139;
      SEPARATOR;
      PLUGIN_CMD_5138;
      PLUGIN_CMD_5151;
      IDM_MICRO2;
      IDM_DTS51;
      IDM_DDSEX61;
      IDM_SDDS71;
    }
  }
  SUBMENU IDS_EDITOR_SELECTION_TOOLS
  {
    SUBMENU IDS_SELECTIONFILTER
    {
      IDM_SELECTIONFILTER;
    }
    PLUGIN_CMD_200000083;
    PLUGIN_CMD_200000084;
    PLUGIN_CMD_200000085;
    PLUGIN_CMD_200000086;
    SEPARATOR;
    PLUGIN_CMD_1011192;
    PLUGIN_CMD_1011180;
    PLUGIN_CMD_1011179;
    PLUGIN_CMD_1011178;
    PLUGIN_CMD_1012129;
    PLUGIN_CMD_1019730;
    SEPARATOR;
    IDM_SEL_ALL;
    IDM_SEL_NONE;
    IDM_SEL_INVERT;
    SEPARATOR;
    IDM_SEL_CONNECTED;
    IDM_SEL_GROW;
    IDM_SEL_SHRINK;
    SEPARATOR;
    IDM_HIDESEL;
    IDM_HIDEUNSEL;
    IDM_UNHIDE;
    IDM_HIDEINVERT;
    SEPARATOR;
    PLUGIN_CMD_1011181;
    IDM_GENERATESELECTION;
    IDM_SETVERTEX_FROM_SELECTION;
  }
  SUBMENU IDS_EDITOR_TOOLS
  {
    PLUGIN_CMD_1027720;
    PLUGIN_CMD_1027822;
    SEPARATOR;
    PLUGIN_CMD_440000045;
    PLUGIN_CMD_1019952;
    PLUGIN_CMD_1011182;
    PLUGIN_CMD_1026593;
    SEPARATOR;
    SUBMENU IDS_MENU_WORKPLANE
    {
      PLUGIN_CMD_431000006;
      PLUGIN_CMD_431000007;
      PLUGIN_CMD_431000008;
      PLUGIN_CMD_431000009;
      SEPARATOR;
      PLUGIN_CMD_431000011;
    }
    SUBMENU IDS_MENU_ARRANGEOBJECTS
    {
      PLUGIN_CMD_200000068;
      PLUGIN_CMD_200000071;
      PLUGIN_CMD_200000067;
      PLUGIN_CMD_200000069;
      PLUGIN_CMD_200000070;
    }
    SUBMENU IDS_MENU_DOODLE
    {
      PLUGIN_CMD_1022257;
      PLUGIN_CMD_1022286;
      SEPARATOR;
      PLUGIN_CMD_1022215;
      PLUGIN_CMD_1022384;
      PLUGIN_CMD_1022281;
      PLUGIN_CMD_1022280;
      SEPARATOR;
      PLUGIN_CMD_1022285;
    }
    SUBMENU IDS_SUBMENU_WALKTHROUGH
    {
      PLUGIN_CMD_1018820;
      PLUGIN_CMD_1018880;
    }
    SUBMENU IDS_SUBMENU_SPACEMOUSE
    {
      PLUGIN_CMD_1016707;
      SEPARATOR;
      PLUGIN_CMD_1019601;
      PLUGIN_CMD_1016708;
      PLUGIN_CMD_1016709;
      PLUGIN_CMD_1016710;
    }
    SEPARATOR;
    SUBMENU IDS_MENU_COORDINATES
    {
      IDM_X;
      IDM_Y;
      IDM_Z;
      IDM_WELT;
      SEPARATOR;
      PLUGIN_CMD_1023335;
      PLUGIN_CMD_1023336;
    }
    SUBMENU IDS_MENU_MODES
    {
      IDM_ANSICHT;
      IDM_FLOBJEKTE;
      IDM_OBJEKTE;
      IDM_WORKPLANE;
      SEPARATOR;
      IDM_PUNKTE;
      IDM_EDGES;
      IDM_VIERECKE;
      SEPARATOR;
      PLUGIN_CMD_1027593;
      SEPARATOR;
      PLUGIN_CMD_1027594;
      PLUGIN_CMD_1027595;
      PLUGIN_CMD_431000012;
      SEPARATOR;
      PLUGIN_CMD_1027636;
      SEPARATOR;
      IDM_TEXTUR;
      SEPARATOR;
      IDM_ANIM;
      SEPARATOR;
      IDM_UVEDIT_POINTS;
      IDM_UVEDIT_POLYGONS;
      IDP_3DPAINT;
      SEPARATOR;
      IDM_ACHSEN;
    }
    SUBMENU IDS_MENU_EXECUTION
    {
      IDM_USE_ANIMATION;
      IDM_USE_EXPRESSIONS;
      IDM_USE_GENERATORS;
      IDM_USE_DEFORMERS;
      PLUGIN_CMD_465003037;
      SEPARATOR;
      PLUGIN_CMD_1019944;
      PLUGIN_CMD_1020190;
      PLUGIN_CMD_1019945;
      PLUGIN_CMD_1018421;
    }
    SEPARATOR;
    PLUGIN_CMD_200000088;
    PLUGIN_CMD_200000089;
    PLUGIN_CMD_200000090;
  }
  SUBMENU IDS_MENU_MESH
  {
    SUBMENU IDS_MENU_CONVERSION
    {
      IDM_MAKEFLAECHEN;
      IDM_TAKEANIM;
      SEPARATOR;
      IDM_VERBINDEN;
      IDM_CONNECTANDDELETE;
      SEPARATOR;
      IDM_MODELING_EXPLODESEGMENTS_POLY;
    }
    SUBMENU IDS_MENU_COMMANDS
    {
      PLUGIN_CMD_450000045;
      PLUGIN_CMD_450000042;
      IDM_MODELING_DISCONNECT;
      IDM_MODELING_SPLIT;
      SEPARATOR;
      PLUGIN_CMD_1015924;
      PLUGIN_CMD_440000042;
      PLUGIN_CMD_1010136;
      PLUGIN_CMD_440000043;
      SEPARATOR;
      IDM_MODELING_SUBDIVIDE;
      IDM_MODELING_TRIANGULATE;
      IDM_MODELING_UNTRIANGULATE;
      SEPARATOR;
      PLUGIN_CMD_200000065;
      PLUGIN_CMD_440000044;
      PLUGIN_CMD_1009671;
      IDM_CHANGEPOLYGON_ORDER;
      SEPARATOR;
      IDM_MODELING_OPTIMIZE;
      IDM_RESETAXIS;
    }
    SEPARATOR;
    SUBMENU IDS_MENU_CREATETOOLS
    {
      PLUGIN_CMD_450000007;
      PLUGIN_CMD_450000006;
      SEPARATOR;
      PLUGIN_CMD_1009661;
      PLUGIN_CMD_1016030;
      SEPARATOR;
      PLUGIN_CMD_431000015;
      PLUGIN_CMD_450000008;
      PLUGIN_CMD_450000009;
      SEPARATOR;
      PLUGIN_CMD_450000011;
      PLUGIN_CMD_450000010;
      SEPARATOR;
      PLUGIN_CMD_450000005;
      PLUGIN_CMD_1011183;
      PLUGIN_CMD_450000004;
      PLUGIN_CMD_1011126;
      PLUGIN_CMD_450000003;
    }
    SUBMENU IDS_MENU_TRANSFORMTOOLS
    {
      PLUGIN_CMD_1016202;
      PLUGIN_CMD_450000014;
      PLUGIN_CMD_1016185;
      SEPARATOR;
      IDM_MODELING_MIRROR;
      PLUGIN_CMD_450000012;
      SEPARATOR;
      PLUGIN_CMD_450000000;
      PLUGIN_CMD_450000001;
      PLUGIN_CMD_450000002;
      SEPARATOR;
      PLUGIN_CMD_1007573;
    }
    SEPARATOR;
    SUBMENU IDS_MENU_SPLINE
    {
      IDM_SPLINE_HARDINTER;
      IDM_SPLINE_SOFTINTER;
      SEPARATOR;
      IDM_SPLINE_EQUALLENGTH;
      IDM_SPLINE_EQUALDIRECTION;
      SEPARATOR;
      IDM_SPLINE_JOINSEGMENT;
      IDM_SPLINE_BREAKSEGMENT;
      IDM_MODELING_EXPLODESEGMENTS_SPLINE;
      SEPARATOR;
      IDM_SPLINE_REORDER;
      IDM_SPLINE_REVERSE;
      IDM_SPLINE_MOVEDOWN;
      IDM_SPLINE_MOVEUP;
      SEPARATOR;
      PLUGIN_CMD_450000043;
      IDM_SPLINE_CREATEOUTLINE;
      IDM_SPLINE_CROSSSECTION;
      IDM_SPLINE_LINEUP;
      PLUGIN_CMD_450000046;
      PLUGIN_CMD_450000039;
    }
    SUBMENU IDS_MENU_NGON
    {
      PLUGIN_CMD_1016160;
      PLUGIN_CMD_1016173;
      PLUGIN_CMD_1016174;
    }
    SUBMENU IDS_MENU_NORMALS
    {
      IDM_MODELING_ALIGNNORMALS;
      IDM_MODELING_REVERSENORMALS;
      SEPARATOR;
      IDM_BREAKPHONG;
      IDM_UNBREAKPHONG;
      IDM_PHONGTOSELECTION;
    }
    SUBMENU IDS_CENTERAXIS
    {
      PLUGIN_CMD_1010819;
      SEPARATOR;
      PLUGIN_CMD_1011982;
      PLUGIN_CMD_1011985;
      PLUGIN_CMD_1011984;
      PLUGIN_CMD_1011983;
      PLUGIN_CMD_1011981;
    }
  }
  SUBMENU IDS_EDITOR_SNAPPING
  {
    PLUGIN_CMD_440000121;
    PLUGIN_CMD_431000018;
    PLUGIN_CMD_431000016;
    PLUGIN_CMD_431000019;
    SEPARATOR;
    PLUGIN_CMD_431000005;
    SEPARATOR;
    PLUGIN_CMD_440000115;
    PLUGIN_CMD_440000123;
    PLUGIN_CMD_440000125;
    PLUGIN_CMD_440000116;
    PLUGIN_CMD_440000128;
    PLUGIN_CMD_440000114;
    PLUGIN_CMD_431000013;
    SEPARATOR;
    PLUGIN_CMD_440000127;
    PLUGIN_CMD_431000000;
    PLUGIN_CMD_431000001;
    SEPARATOR;
    PLUGIN_CMD_440000113;
    PLUGIN_CMD_440000117;
    PLUGIN_CMD_440000129;
  }
  SUBMENU IDS_TIMELINE_NAVIGATION
  {
    SUBMENU IDS_TIMELINE_RECORD
    {
      IDM_A_POS;
      IDM_A_SIZE;
      IDM_A_DIR;
      SEPARATOR;
      IDM_A_PLA;
      IDM_A_PARAMETER;
      SEPARATOR;
      IDM_KEYFRAMING_LINKGENERATION;
    }
    IDM_RECORD;
    SEPARATOR;
    IDM_AUTOKEYS;
    SUBMENU IDS_TIMELINE_KEYFRAME
    {
      IDM_KEYFRAME_SELECTION;
    }
    SEPARATOR;
    SUBMENU IDS_TIMELINE_PLAY_MODE
    {
      IDM_A_PREVIEW;
      SEPARATOR;
      IDM_SIMPLE;
      IDM_CYCLE;
      IDM_PINGPONG;
    }
    SUBMENU IDS_TIMELINE_FRAME_RATE
    {
      IDM_A_DROPLESS;
      IDM_FPS_DOC;
      SEPARATOR;
      IDM_FPS_1;
      IDM_FPS_5;
      IDM_FPS_10;
      IDM_FPS_15;
      IDM_FPS_18;
      IDM_FPS_24;
      IDM_FPS_25;
      IDM_FPS_30;
      IDM_FPS_50;
      IDM_FPS_60;
      IDM_FPS_100;
      IDM_FPS_250;
      IDM_FPS_500;
    }
    IDM_PLAY_FORWARDS;
    IDM_PLAY_BACKWARDS;
    IDM_U_STOP;
    SEPARATOR;
    IDM_SOUNDONOFF;
    SEPARATOR;
    IDM_GOTOMIN;
    IDM_GOTOMAX;
    IDM_GOTOFRAME;
    SEPARATOR;
    IDM_FRAME_NEXT;
    IDM_FRAME_LAST;
    IDM_KEY_NEXT;
    IDM_KEY_LAST;
    SEPARATOR;
    PLUGIN_CMD_465003048;
    PLUGIN_CMD_465003068;
    SEPARATOR;
    PLUGIN_CMD_465003044;
    PLUGIN_CMD_465003065;
    PLUGIN_CMD_100004839;
  }
  SUBMENU IDS_EDITOR_SIMULATION
  {
    SUBMENU IDS_EDITOR_SIMULATION_CLOTH
    {
      PLUGIN_CMD_100004007;
      PLUGIN_CMD_100004023;
    }
    SUBMENU IDS_EDITOR_SIMULATION_DYNAMICS
    {
      PLUGIN_CMD_180000011;
      PLUGIN_CMD_180000010;
      SEPARATOR;
      PLUGIN_CMD_180000103;
      PLUGIN_CMD_180000012;
    }
    SEPARATOR;
    SUBMENU IDS_EDITOR_PARTICLE
    {
      PLUGIN_CMD_5109;
      SEPARATOR;
      PLUGIN_CMD_5119;
      PLUGIN_CMD_5110;
      PLUGIN_CMD_5124;
      PLUGIN_CMD_5114;
      PLUGIN_CMD_5111;
      PLUGIN_CMD_5112;
      PLUGIN_CMD_5115;
      PLUGIN_CMD_5113;
      SEPARATOR;
      IDM_BAKEPARTI;
    }
    SUBMENU IDS_SUBMENU_TP
    {
      PLUGIN_CMD_1001414;
      PLUGIN_CMD_1001439;
      PLUGIN_CMD_1001446;
    }
    SEPARATOR;
    SUBMENU IDS_SUBMENU_HAIROBJECTS
    {
      PLUGIN_CMD_1018401;
      PLUGIN_CMD_1018396;
      PLUGIN_CMD_1018958;
    }
    SUBMENU IDS_SUBMENU_HAIRMODE
    {
      PLUGIN_CMD_1017460;
      PLUGIN_CMD_1017459;
      PLUGIN_CMD_1017457;
      PLUGIN_CMD_1017458;
      PLUGIN_CMD_1017487;
      SEPARATOR;
      PLUGIN_CMD_1018467;
      PLUGIN_CMD_1018468;
    }
    SUBMENU IDS_SUBMENU_HAIREDIT
    {
      PLUGIN_CMD_1018052;
      PLUGIN_CMD_1018051;
      PLUGIN_CMD_1018053;
      PLUGIN_CMD_1018465;
      PLUGIN_CMD_1018036;
      SEPARATOR;
      PLUGIN_CMD_1017540;
      PLUGIN_CMD_1017541;
      SEPARATOR;
      PLUGIN_CMD_1018462;
      PLUGIN_CMD_1018463;
      PLUGIN_CMD_1017637;
      PLUGIN_CMD_1018007;
      PLUGIN_CMD_1018466;
      PLUGIN_CMD_1017642;
    }
    SUBMENU IDS_SUBMENU_HAIRSELECTION
    {
      PLUGIN_CMD_1017448;
      PLUGIN_CMD_1018102;
      PLUGIN_CMD_1018101;
      PLUGIN_CMD_1018100;
      PLUGIN_CMD_1018464;
      PLUGIN_CMD_1018373;
      SEPARATOR;
      PLUGIN_CMD_1017530;
      SEPARATOR;
      PLUGIN_CMD_1017488;
      PLUGIN_CMD_1017489;
      PLUGIN_CMD_1017495;
      PLUGIN_CMD_1017510;
      SEPARATOR;
      PLUGIN_CMD_1017490;
      PLUGIN_CMD_1017533;
      PLUGIN_CMD_1017491;
      SEPARATOR;
      PLUGIN_CMD_1017531;
      PLUGIN_CMD_1017532;
      PLUGIN_CMD_1018470;
      SEPARATOR;
      PLUGIN_CMD_1017747;
    }
    SUBMENU IDS_SUBMENU_HAIRTOOLS
    {
      PLUGIN_CMD_1017454;
      PLUGIN_CMD_1017534;
      PLUGIN_CMD_1018169;
      SEPARATOR;
      PLUGIN_CMD_1017581;
      PLUGIN_CMD_1017617;
      PLUGIN_CMD_1017548;
      PLUGIN_CMD_1018166;
      PLUGIN_CMD_1017542;
      PLUGIN_CMD_1017568;
      PLUGIN_CMD_1017549;
      SEPARATOR;
      PLUGIN_CMD_1017640;
      PLUGIN_CMD_1018067;
      PLUGIN_CMD_1017638;
    }
    SUBMENU IDS_SUBMENU_HAIROPTIONS
    {
      PLUGIN_CMD_1018066;
      PLUGIN_CMD_1018124;
      SEPARATOR;
      PLUGIN_CMD_1018164;
      PLUGIN_CMD_1018123;
      PLUGIN_CMD_1018065;
    }
  }
  SUBMENU IDS_EDITOR_RENDER
  {
    IDM_RENDERALL;
    IDM_RENDERAUSSCHNITT;
    IDM_RENDERAKTU;
    SEPARATOR;
    IDM_RAYTRACING;
    PLUGIN_CMD_300002144;
    PLUGIN_CMD_1000974;
    SEPARATOR;
    PLUGIN_CMD_465003525;
    PLUGIN_CMD_465003500;
    SEPARATOR;
    PLUGIN_CMD_430000021;
    SEPARATOR;
    PLUGIN_CMD_12161;
    IDM_RENDERSETTINGS;
    SEPARATOR;
    PLUGIN_CMD_300002136;
    PLUGIN_CMD_300002167;
    SEPARATOR;
    SUBMENU IDS_MENU_CINEMAN
    {
      PLUGIN_CMD_1019501;
      SEPARATOR;
      PLUGIN_CMD_1019504;
      PLUGIN_CMD_1019502;
      PLUGIN_CMD_1020136;
    }
    IDM_FLUSHSOLUTIONS;
  }
  SUBMENU IDS_MENU_SCULPTING
  {
    PLUGIN_CMD_1024194;
    PLUGIN_CMD_1024196;
    PLUGIN_CMD_1024195;
    SEPARATOR;
    SUBMENU IDS_MENU_BRUSHES
    {
      PLUGIN_CMD_1024168;
      PLUGIN_CMD_1024197;
      PLUGIN_CMD_1024170;
      PLUGIN_CMD_1026518;
      PLUGIN_CMD_1026519;
      PLUGIN_CMD_1024171;
      PLUGIN_CMD_1024169;
      PLUGIN_CMD_1026708;
      PLUGIN_CMD_1029169;
      PLUGIN_CMD_1026710;
      PLUGIN_CMD_1027556;
      PLUGIN_CMD_1026715;
      SEPARATOR;
      PLUGIN_CMD_1024189;
    }
    SUBMENU IDS_MENU_MASK
    {
      PLUGIN_CMD_1024506;
      PLUGIN_CMD_1027039;
      PLUGIN_CMD_1027030;
      PLUGIN_CMD_1027041;
      PLUGIN_CMD_1027042;
    }
    SEPARATOR;
    PLUGIN_CMD_1027538;
    PLUGIN_CMD_1026225;
    PLUGIN_CMD_1029259;
  }
  SUBMENU IDS_MENU_MOGRAPH
  {
    SUBMENU IDS_MENU_EFFECTOR
    {
      PLUGIN_CMD_1019351;
      PLUGIN_CMD_1021337;
      SEPARATOR;
      PLUGIN_CMD_440000051;
      PLUGIN_CMD_1019234;
      PLUGIN_CMD_1018883;
      PLUGIN_CMD_1018775;
      PLUGIN_CMD_1025800;
      PLUGIN_CMD_1018643;
      PLUGIN_CMD_1018561;
      PLUGIN_CMD_1018882;
      PLUGIN_CMD_1018774;
      PLUGIN_CMD_1018881;
      PLUGIN_CMD_1018889;
      PLUGIN_CMD_1018935;
      PLUGIN_CMD_1021287;
    }
    SEPARATOR;
    PLUGIN_CMD_1021340;
    SEPARATOR;
    PLUGIN_CMD_1019342;
    PLUGIN_CMD_1019343;
    PLUGIN_CMD_1019344;
    SEPARATOR;
    PLUGIN_CMD_1018544;
    PLUGIN_CMD_1018545;
    PLUGIN_CMD_1018791;
    PLUGIN_CMD_1018957;
    PLUGIN_CMD_1019268;
    PLUGIN_CMD_1018655;
    PLUGIN_CMD_440000054;
    SEPARATOR;
    PLUGIN_CMD_1019358;
    PLUGIN_CMD_1019222;
  }
  SUBMENU IDS_EDITOR_CA
  {
    SUBMENU IDS_EDITOR_CA_MANAGER
    {
      PLUGIN_CMD_1025028;
      PLUGIN_CMD_1019773;
      PLUGIN_CMD_100001609;
      PLUGIN_CMD_100001200;
    }
    SUBMENU IDS_EDITOR_CA_COMMANDS
    {
      PLUGIN_CMD_1019884;
      PLUGIN_CMD_1019881;
      PLUGIN_CMD_1019883;
      SEPARATOR;
      PLUGIN_CMD_1019946;
      PLUGIN_CMD_1019948;
      PLUGIN_CMD_1019947;
      SEPARATOR;
      PLUGIN_CMD_1019940;
      PLUGIN_CMD_1019939;
      PLUGIN_CMD_1019938;
      PLUGIN_CMD_1019937;
      PLUGIN_CMD_1019954;
      SEPARATOR;
      PLUGIN_CMD_1021285;
      SEPARATOR;
      PLUGIN_CMD_1025623;
      PLUGIN_CMD_1025699;
      PLUGIN_CMD_1025539;
      PLUGIN_CMD_1025540;
    }
    SUBMENU IDS_MOCCACONVERSION
    {
      PLUGIN_CMD_1019950;
      PLUGIN_CMD_1019949;
      SEPARATOR;
      PLUGIN_CMD_1019941;
      PLUGIN_CMD_1019942;
      PLUGIN_CMD_1019943;
      PLUGIN_CMD_1022912;
    }
    SUBMENU IDS_CONSTRAINTS
    {
      PLUGIN_CMD_1022415;
      PLUGIN_CMD_1022426;
      PLUGIN_CMD_1022418;
      PLUGIN_CMD_1022420;
      PLUGIN_CMD_1022424;
      PLUGIN_CMD_1022416;
      PLUGIN_CMD_1022425;
      PLUGIN_CMD_1022428;
      PLUGIN_CMD_1022421;
      PLUGIN_CMD_1022414;
      PLUGIN_CMD_1022422;
      PLUGIN_CMD_1022423;
      PLUGIN_CMD_1022429;
      PLUGIN_CMD_1022419;
      PLUGIN_CMD_1022427;
      PLUGIN_CMD_1022417;
      PLUGIN_CMD_1023334;
    }
    SEPARATOR;
    PLUGIN_CMD_1021433;
    PLUGIN_CMD_1021824;
    SUBMENU IDS_CA_BUILDER
    {
      PLUGIN_CMD_1022250;
      PLUGIN_CMD_1022251;
      PLUGIN_CMD_1022252;
      PLUGIN_CMD_1022253;
      SEPARATOR;
      PLUGIN_CMD_1022302;
      PLUGIN_CMD_1022303;
      PLUGIN_CMD_1022304;
      PLUGIN_CMD_1022308;
      PLUGIN_CMD_1022307;
      PLUGIN_CMD_1022309;
      PLUGIN_CMD_1022305;
    }
    SEPARATOR;
    PLUGIN_CMD_1019600;
    PLUGIN_CMD_1021334;
    PLUGIN_CMD_1019953;
    PLUGIN_CMD_1021286;
    PLUGIN_CMD_1019499;
    SEPARATOR;
    PLUGIN_CMD_1019362;
    PLUGIN_CMD_1019363;
    SEPARATOR;
    PLUGIN_CMD_1026224;
    PLUGIN_CMD_1026352;
    SEPARATOR;
    PLUGIN_CMD_1021283;
    PLUGIN_CMD_1021318;
    PLUGIN_CMD_1025170;
    PLUGIN_CMD_1025169;
    PLUGIN_CMD_1019677;
  }
  SUBMENU IDS_EDITOR_PLUGINS
  {
    IDM_EXECUTE_LAST;
    SEPARATOR;
    IDM_PLUGINS;
    SEPARATOR;
    PLUGIN_CMD_12302;
    PLUGIN_CMD_1026375;
  }
  SUBMENU IDS_SCRIPTING_MAIN
  {
    SUBMENU IDS_SCRIPTS
    {
      PLUGIN_CMD_1022807;
      PLUGIN_CMD_1022735;
      SEPARATOR;
      PLUGIN_CMD_65000;
    }
    SEPARATOR;
    PLUGIN_CMD_12305;
    PLUGIN_CMD_300000116;
    PLUGIN_CMD_1001084;
    PLUGIN_CMD_1023699;
    SEPARATOR;
    PLUGIN_CMD_1023866;
    PLUGIN_CMD_1026374;
    PLUGIN_CMD_1024490;
  }
  SUBMENU IDS_EDITOR_WINDOW
  {
    SUBMENU IDS_LAYOUT
    {
      PLUGIN_CMD_300000186;
      SEPARATOR;
      SUBMENU IDS_MENU_MENUS
      {
        IDM_MAINMENU_C4D;
        IDM_MAINMENU_BP;
        IDM_MAINMENU_USER1;
        IDM_MAINMENU_USER2;
        IDM_MAINMENU_USER3;
        IDM_MAINMENU_USER4;
        IDM_MAINMENU_USER5;
      }
      M_COFFEEMANAGER_MENUMANAGER;
      SEPARATOR;
      SUBMENU IDS_MENU_LAYOUTS
      {
        IDM_DEFAULT_LAYOUTS;
      }
      IDM_LOADLAYOUT;
      IDM_SAVELAYOUT;
      IDM_SAVELAYOUTAS;
      IDM_LOCK_LAYOUT;
      SEPARATOR;
      IDM_CM_GROUPWINDOW;
      IDM_CM_NEWPALETTE;
      SEPARATOR;
      IDM_LOADPALETTE;
      IDM_CM_CUSTOMIZE;
    }
    SEPARATOR;
    IDM_FULLSCREEN;
    IDM_FULLSCREEN_GROUP;
    SEPARATOR;
    PLUGIN_CMD_1017163;
    PLUGIN_CMD_100004700;
    IDM_MATERIAL_MANAGER;
    PLUGIN_CMD_465001510;
    SEPARATOR;
    PLUGIN_CMD_1000468;
    IDM_INFO_MANAGER;
    PLUGIN_CMD_100004704;
    PLUGIN_CMD_1024015;
    IDM_SPREADSHEET;
    PLUGIN_CMD_1029486;
    SEPARATOR;
    PLUGIN_CMD_430000700;
    PLUGIN_CMD_200000045;
    IDM_NEWVIEW;
    SEPARATOR;
    SUBMENU IDS_PAINT_PAINTER
    {
      IDP_COLORSETTINGS;
      IDP_BRUSHPRESETS;
      IDP_COLORPRESETS;
      IDP_TEXTUREMANAGER;
      IDP_BITMAPINFO;
      IDP_NEWTEXTUREVIEW;
    }
    SUBMENU IDS_MOREMANAGER
    {
      PLUGIN_CMD_100004701;
      PLUGIN_CMD_100004702;
      PLUGIN_CMD_100004703;
      PLUGIN_CMD_465001511;
      PLUGIN_CMD_465001512;
      PLUGIN_CMD_465001513;
      PLUGIN_CMD_465001737;
    }
    SEPARATOR;
    PLUGIN_CMD_200000149;
    PLUGIN_CMD_1026761; // QC Plugins
    PLUGIN_CMD_1026791; // QC Plugins
    SEPARATOR;
    IDM_DOCUMENTS;
  }
  SUBMENU IDS_EDITOR_ABOUT
  {
    PLUGIN_CMD_1019760;
    PLUGIN_CMD_1025120;
    IDM_MAXONSUPPORT;
    SEPARATOR;
    PLUGIN_CMD_450000220;
    PLUGIN_CMD_450000229;
    SEPARATOR;
    PLUGIN_CMD_200000208; // Register Online
    IDM_PERSONALIZE;
		PLUGIN_CMD_200000280; // Change Demo 
		PLUGIN_CMD_200000203; // License Server Lease
    IDM_UEBER;
    SEPARATOR;
    PLUGIN_CMD_300001038;
  }
}
