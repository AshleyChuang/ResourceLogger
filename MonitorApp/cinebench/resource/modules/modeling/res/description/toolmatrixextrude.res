CONTAINER ToolMatrixExtrude
{
  NAME ToolMatrixExtrude;
	INCLUDE ToolBase;

  GROUP MDATA_MAINGROUP
  {
	  GROUP
	  {
			COLUMNS 2;

			LONG MDATA_MATRIXEXTRUDE_STEPS { MIN 0; }
			BOOL MDATA_MATRIXEXTRUDE_POLYGONCOORDS { }

			VECTOR MDATA_MATRIXEXTRUDE_MOVE { UNIT METER; }
			STATICTEXT { JOINEND; }

			VECTOR MDATA_MATRIXEXTRUDE_SCALE { UNIT PERCENT; }
			STATICTEXT { JOINEND; }

			VECTOR MDATA_MATRIXEXTRUDE_ROTATE { UNIT DEGREE; }
			STATICTEXT { JOINEND; }

			LONG MDATA_MATRIXEXTRUDE_VARIANCE { ALIGN_LEFT; CYCLE { MDATA_MATRIXEXTRUDE_VARIANCE_NONE; MDATA_MATRIXEXTRUDE_VARIANCE_INITIAL; MDATA_MATRIXEXTRUDE_VARIANCE_PERSTEP; } }
			STATICTEXT { JOINEND; }

			REAL MDATA_MATRIXEXTRUDE_MOVEFROM { UNIT PERCENT; }
			REAL MDATA_MATRIXEXTRUDE_MOVETO { UNIT PERCENT; }

			REAL MDATA_MATRIXEXTRUDE_SCALEFROM { UNIT PERCENT; }
			REAL MDATA_MATRIXEXTRUDE_SCALETO { UNIT PERCENT; }

			REAL MDATA_MATRIXEXTRUDE_ROTATEFROM { UNIT PERCENT; }
			REAL MDATA_MATRIXEXTRUDE_ROTATETO { UNIT PERCENT; }
		}
	}
}
