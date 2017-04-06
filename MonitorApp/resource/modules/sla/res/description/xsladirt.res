CONTAINER XSLADirt
{
  NAME XSLADirt;

  INCLUDE Mpreview;
  INCLUDE Xbase;

  GROUP ID_SHADERPROPERTIES
  {
    REAL SLA_DIRTY_RAY_BIAS { MIN 0; }
    REAL SLA_DIRTY_MAX_DISTANCE { MIN 0; }
    LONG SLA_DIRTY_NUM_RAYS { MIN 1; }
    REAL SLA_DIRTY_SPREAD { UNIT PERCENT; MIN 0; MAX 100; }
    REAL SLA_DIRTY_CONTRAST { UNIT PERCENT; MIN 0; MAX 100; }
  }
}