CONTAINER XSLALumas
{
  NAME XSLALumas;

  INCLUDE Mpreview;
  INCLUDE Xbase;

  GROUP ID_SHADERPROPERTIES
  {
    BOOL SLA_LUMAS_DIFFUSE_ACTIVE { }
    COLOR SLA_LUMAS_DIFFUSE_COLOR { }
    LONG SLA_LUMAS_DIFFUSE_ALGORITHM
    {
      CYCLE
      {
        SLA_LUMAS_DIFFUSE_ALGO_INTERNAL;
        SLA_LUMAS_DIFFUSE_ALGO_ORENNAYAR;
      }
    }
    REAL SLA_LUMAS_DIFFUSE_ROUGHNESS { MIN 0; MAX 200; UNIT PERCENT; }
    REAL SLA_LUMAS_DIFFUSE_ILLUMINATION { MIN 0; MAX 1000; UNIT PERCENT; }
    REAL SLA_LUMAS_DIFFUSE_CONTRAST { MIN -1000; MAX 1000; UNIT PERCENT; }
  }

  GROUP SLA_LUMAS_SPECULAR1_GROUP
  {
    BOOL SLA_LUMAS_SPECULAR1_ACTIVE { }
    COLOR SLA_LUMAS_SPECULAR1_COLOR { }
    REAL SLA_LUMAS_SPECULAR1_INTENSITY { MIN 0; MAX 1000; UNIT PERCENT; }
    REAL SLA_LUMAS_SPECULAR1_SIZE { MIN 0; MAX 200; UNIT PERCENT; }
    REAL SLA_LUMAS_SPECULAR1_CONTRAST { MIN 0; MAX 100; UNIT PERCENT; }
    REAL SLA_LUMAS_SPECULAR1_GLARE { MIN 0; MAX 1000; UNIT PERCENT; }
    REAL SLA_LUMAS_SPECULAR1_FALLOFF { MIN 0; UNIT PERCENT; }
  }

  GROUP SLA_LUMAS_SPECULAR2_GROUP
  {
    BOOL SLA_LUMAS_SPECULAR2_ACTIVE { }
    COLOR SLA_LUMAS_SPECULAR2_COLOR { }
    REAL SLA_LUMAS_SPECULAR2_INTENSITY { MIN 0; MAX 1000; UNIT PERCENT; }
    REAL SLA_LUMAS_SPECULAR2_SIZE { MIN 0; MAX 200; UNIT PERCENT; }
    REAL SLA_LUMAS_SPECULAR2_CONTRAST { MIN 0; MAX 100; UNIT PERCENT; }
    REAL SLA_LUMAS_SPECULAR2_GLARE { MIN 0; MAX 1000; UNIT PERCENT; }
    REAL SLA_LUMAS_SPECULAR2_FALLOFF { MIN 0; UNIT PERCENT; }
  }

  GROUP SLA_LUMAS_SPECULAR3_GROUP
  {
    BOOL SLA_LUMAS_SPECULAR3_ACTIVE { }
    COLOR SLA_LUMAS_SPECULAR3_COLOR { }
    REAL SLA_LUMAS_SPECULAR3_INTENSITY { MIN 0; MAX 1000; UNIT PERCENT; }
    REAL SLA_LUMAS_SPECULAR3_SIZE { MIN 0.01; MAX 200; UNIT PERCENT; }
    REAL SLA_LUMAS_SPECULAR3_CONTRAST { MIN 0; MAX 100; UNIT PERCENT; }
    REAL SLA_LUMAS_SPECULAR3_GLARE { MIN 0; MAX 1000; UNIT PERCENT; }
    REAL SLA_LUMAS_SPECULAR3_FALLOFF { MIN 0; UNIT PERCENT; }
  }

  GROUP SLA_LUMAS_ANISO_GROUP
  {
    BOOL SLA_LUMAS_ANISO_ACTIVE { }
    LONG SLA_LUMAS_ANISO_PROJECTION
    {
      CYCLE
      {
        SLA_LUMAS_ANISO_PROJECTION_PLANAR;
        SLA_LUMAS_ANISO_PROJECTION_AUTO_PLANAR;
        SLA_LUMAS_ANISO_PROJECTION_SHRINK_WRAP;
        SLA_LUMAS_ANISO_PROJECTION_RAD_AUTO_PLANAR;
        SLA_LUMAS_ANISO_PROJECTION_RAD_PAT_AUTO_PLANAR;
        SLA_LUMAS_ANISO_PROJECTION_RAD_PLANAR;
        SLA_LUMAS_ANISO_PROJECTION_RAD_PATTERN_PLANAR;
      }
    }
    REAL SLA_LUMAS_ANISO_PROJ_SCALE { MIN 0; MAX 1000; UNIT PERCENT; }
    SEPARATOR { LINE; }
    REAL SLA_LUMAS_ANISO_X_ROUGH { MIN 0; UNIT PERCENT; }
    REAL SLA_LUMAS_ANISO_Y_ROUGH { MIN 0; UNIT PERCENT; }
    BOOL SLA_LUMAS_ANISO_SPEC_CHANNEL_SPEC1 { }
    BOOL SLA_LUMAS_ANISO_SPEC_CHANNEL_SPEC2 { }
    BOOL SLA_LUMAS_ANISO_SPEC_CHANNEL_SPEC3 { }
    SEPARATOR { LINE; }
    REAL SLA_LUMAS_ANISO_AMPLITUDE { MIN 0; MAX 100; UNIT PERCENT; }
    REAL SLA_LUMAS_ANISO_SCALE { MIN 0; UNIT PERCENT; }
    REAL SLA_LUMAS_ANISO_LENGTH { MIN 0; UNIT PERCENT; }
    REAL SLA_LUMAS_ANISO_ATTENUATION { MIN 0; UNIT PERCENT; }
    BOOL SLA_LUMAS_ANISO_SCRATCH_CHANNEL_SPEC1 { }
    BOOL SLA_LUMAS_ANISO_SCRATCH_CHANNEL_SPEC2 { }
    BOOL SLA_LUMAS_ANISO_SCRATCH_CHANNEL_SPEC3 { }
  }
}