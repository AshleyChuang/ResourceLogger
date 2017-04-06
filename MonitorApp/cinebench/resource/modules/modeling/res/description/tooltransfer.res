CONTAINER ToolTransfer
{
  NAME ToolTransfer;
	INCLUDE ToolBase;

  GROUP MDATA_MAINGROUP
  {
		GROUP
		{
			LINK MDATA_TRANSFER_OBJECT_LINK	{ ACCEPT { Obase;} }
		}

		GROUP
		{
			COLUMNS 4;
			BOOL MDATA_TRANSFER_USE_MOVE 			{ }
			BOOL MDATA_TRANSFER_USE_MOVE_X		{ }
			BOOL MDATA_TRANSFER_USE_MOVE_Y		{ }
			BOOL MDATA_TRANSFER_USE_MOVE_Z		{ }

			BOOL MDATA_TRANSFER_USE_SCALE			{ }
			STATICTEXT { JOINEND; }
			STATICTEXT { JOINEND; }
			STATICTEXT { JOINEND; }

			BOOL MDATA_TRANSFER_USE_ROTATION	{ }
			STATICTEXT { JOINEND; }
			STATICTEXT { JOINEND; }
			STATICTEXT { JOINEND; }
		}
  }
	GROUP MDATA_COMMANDGROUP
	{
		SHOW MDATA_APPLY;
	}
}
