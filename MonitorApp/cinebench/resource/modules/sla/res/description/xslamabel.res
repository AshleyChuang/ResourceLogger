CONTAINER XSLAMabel
{
	NAME XSLAMabel;

	INCLUDE Mpreview;
	INCLUDE Mbase;

	GROUP Obaselist
	{
		LONG SLA_MABEL_SURFACE
		{
			MATEDNOTEXT;
			CYCLE
			{
				SLA_MABEL_SURFACE_1;
				SLA_MABEL_SURFACE_2;
				SLA_MABEL_SURFACE_BOTH;
			}
		}
		BOOL SLA_MABEL_VEINING { PARENTMSG ID_MABEL_VEINING; }

		GROUP
		{
			LAYOUTGROUP; COLUMNS 2; MATEDCOLUMNS 1;

			GROUP
			{
				BOOL SLA_MABEL_DIFFUSE_A { PARENTMSG ID_MABEL_DIFFUSE_A; }
				BOOL SLA_MABEL_SPECULAR1_A { PARENTMSG ID_MABEL_SPECULAR1_A; }
				BOOL SLA_MABEL_SPECULAR2_A { PARENTMSG ID_MABEL_SPECULAR2_A; }
				BOOL SLA_MABEL_SPECULAR3_A { PARENTMSG ID_MABEL_SPECULAR3_A; }
				BOOL SLA_MABEL_REFLECTION_A { PARENTMSG ID_MABEL_REFLECTION_A;  }
				BOOL SLA_MABEL_ENVIRONMENT_A { PARENTMSG ID_MABEL_ENVIRONMENT_A; }
				BOOL SLA_MABEL_AMBIENT_A { PARENTMSG ID_MABEL_AMBIENT_A; }
				BOOL SLA_MABEL_ROUGHNESS_A { PARENTMSG ID_MABEL_ROUGHNESS_A; }
				BOOL SLA_MABEL_ANISOTROPY_A { PARENTMSG ID_MABEL_ANISOTROPY_A; }
			}
			GROUP
			{
				BOOL SLA_MABEL_DIFFUSE_B  { PARENTMSG ID_MABEL_DIFFUSE_B; }
				BOOL SLA_MABEL_SPECULAR1_B  { PARENTMSG ID_MABEL_SPECULAR1_B; }
				BOOL SLA_MABEL_SPECULAR2_B  { PARENTMSG ID_MABEL_SPECULAR2_B; }
				BOOL SLA_MABEL_SPECULAR3_B  { PARENTMSG ID_MABEL_SPECULAR3_B; }
				BOOL SLA_MABEL_REFLECTION_B  { PARENTMSG ID_MABEL_REFLECTION_B; }
				BOOL SLA_MABEL_ENVIRONMENT_B  { PARENTMSG ID_MABEL_ENVIRONMENT_B; }
				BOOL SLA_MABEL_AMBIENT_B  { PARENTMSG ID_MABEL_AMBIENT_B; }
				BOOL SLA_MABEL_ROUGHNESS_B  { PARENTMSG ID_MABEL_ROUGHNESS_B; }
				BOOL SLA_MABEL_ANISOTROPY_B  { PARENTMSG ID_MABEL_ANISOTROPY_B; }
			}
		}
	}

	GROUP ID_MABEL_VEINING
	{
		LONG SLA_MABEL_SEED { }
		SEPARATOR { LINE; }
		LONG SLA_MABEL_VEINING_TURBULENCE
		{
			CYCLE
			{
			}
			CUSTOMGUI NOISE; NOISE_OFFSET 2100;
		}
		REAL SLA_MABEL_VEINING_STIRRING { UNIT PERCENT; MIN 0; }
		REAL SLA_MABEL_VEINING_SCALE { UNIT PERCENT; MIN 0; MAX 100; }
		REAL SLA_MABEL_VEINING_OCTAVES { MIN 0; MAX 20; STEP .1; }
		REAL SLA_MABEL_VEINING_SIZE { UNIT PERCENT; MIN 0; MAX 100; }
		REAL SLA_MABEL_VEINING_CONTRAST { UNIT PERCENT; MIN -100; MAX 100; }
		SEPARATOR { LINE; }
		LONG SLA_MABEL_VARIANCE_TURBULENCE
		{
			CYCLE
			{
			}
			CUSTOMGUI NOISE; NOISE_OFFSET 2100;
		}
		REAL SLA_MABEL_VARIANCE_AMPLITUDE { UNIT PERCENT; MIN 0; }
		REAL SLA_MABEL_VARIANCE_OCTAVES { MIN 0; MAX 20; STEP .1; }
		REAL SLA_MABEL_VARIANCE_SCALE { UNIT PERCENT; MIN 0; MAX 100; }
		REAL SLA_MABEL_VARIANCE_CONTRAST { UNIT PERCENT; MIN -100; MAX 100; }
	}

	GROUP ID_MABEL_DIFFUSE_A
	{
		COLOR SLA_MABEL_DIFFUSE_COLOR_A { }
		LONG SLA_MABEL_DIFFUSE_ALGORITHM_A
		{
			CYCLE
			{
				SLA_MABEL_DIFFUSE_ALGORITHM_INTERNAL;
				SLA_MABEL_DIFFUSE_ALGORITHM_OREN_NAYAR;
			}
		}
		REAL SLA_MABEL_DIFFUSE_ROUGHNESS_A { UNIT PERCENT; MIN 0; MAX 200; }
		REAL SLA_MABEL_DIFFUSE_ILLUMINATION_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_DIFFUSE_CONTRAST_A { UNIT PERCENT; MIN -1000; MAX 1000; }
	}
	GROUP ID_MABEL_SPECULAR1_A
	{
		COLOR SLA_MABEL_SPEC1_COLOR_A { };
		REAL SLA_MABEL_SPEC1_INTENSITY_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_SPEC1_SIZE_A { UNIT PERCENT; MIN 0; MAX 200; }
		REAL SLA_MABEL_SPEC1_CONTRAST_A { UNIT PERCENT; MIN 0; MAX 100; }
		REAL SLA_MABEL_SPEC1_GLARE_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_SPEC1_FALLOFF_A { UNIT PERCENT; MIN 0; }
	}
	GROUP ID_MABEL_SPECULAR2_A
	{
		COLOR SLA_MABEL_SPEC2_COLOR_A { };
		REAL SLA_MABEL_SPEC2_INTENSITY_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_SPEC2_SIZE_A { UNIT PERCENT; MIN 0; MAX 200; }
		REAL SLA_MABEL_SPEC2_CONTRAST_A { UNIT PERCENT; MIN 0; MAX 100; }
		REAL SLA_MABEL_SPEC2_GLARE_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_SPEC2_FALLOFF_A { UNIT PERCENT; MIN 0; }
	}
	GROUP ID_MABEL_SPECULAR3_A
	{
		COLOR SLA_MABEL_SPEC3_COLOR_A { };
		REAL SLA_MABEL_SPEC3_INTENSITY_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_SPEC3_SIZE_A { UNIT PERCENT; MIN 0; MAX 200; }
		REAL SLA_MABEL_SPEC3_CONTRAST_A { UNIT PERCENT; MIN 0; MAX 100; }
		REAL SLA_MABEL_SPEC3_GLARE_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_SPEC3_FALLOFF_A { UNIT PERCENT; MIN 0; }
	}
	GROUP ID_MABEL_REFLECTION_A
	{
		REAL SLA_MABEL_REFLECTION_INTENSITY_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_REFLECTION_EDGE_INTENSITY_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_REFLECTION_FALLOFF_A { UNIT PERCENT; MIN 0; }
		SEPARATOR { LINE; }
		COLOR SLA_MABEL_REFLECTION_REFLECTION_COLOR_A { }
		COLOR SLA_MABEL_REFLECTION_EDGE_COLOR_A { }
	}
	GROUP ID_MABEL_ENVIRONMENT_A
	{
		SHADERLINK SLA_MABEL_ENVIRONMENT_IMAGE { }
		REAL SLA_MABEL_ENVIRONMENT_INTENSITY_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_ENVIRONMENT_GLARE_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_ENVIRONMENT_FALLOFF_A { UNIT PERCENT; MIN 0; }
		SEPARATOR { LINE; }
		BOOL SLA_MABEL_ENVIRONMENT_UTILIZE_ANISO_SCRATCHES_A { }
		REAL SLA_MABEL_ENVIRONMENT_BLUR_A { UNIT PERCENT; MIN 0; MAX 100; }
		LONG SLA_MABEL_ENVIRONMENT_SAMPLES_A { MIN 2; }
		REAL SLA_MABEL_ENVIRONMENT_JITTER_A { UNIT PERCENT; MIN 0; MAX 1000; }
		SEPARATOR { LINE; }
		COLOR SLA_MABEL_ENVIRONMENT_ENVIRONMENT_COLOR_A { }
		COLOR SLA_MABEL_ENVIRONMENT_EDGE_COLOR_A { }
	}
	GROUP ID_MABEL_AMBIENT_A
	{
		COLOR SLA_MABEL_AMBIENT_COLOR_A { }
		REAL SLA_MABEL_AMBIENT_INTENSITY_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_AMBIENT_EDGE_INTENSITY_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_AMBIENT_FALLOFF_A { UNIT PERCENT; MIN 0; }
	}
	GROUP ID_MABEL_ROUGHNESS_A
	{
		LONG SLA_MABEL_ROUGHNESS_SEED_A { }
		LONG SLA_MABEL_ROUGHNESS_NOISE_A
		{
			CYCLE
			{
			}
			CUSTOMGUI NOISE; NOISE_OFFSET 2100;
		}
		REAL SLA_MABEL_ROUGHNESS_AMPLITUDE_A { UNIT PERCENT; MIN -1000; MAX 1000; }
		REAL SLA_MABEL_ROUGHNESS_OCTAVES_A { MIN 0; MAX 20; STEP .5; }
		REAL SLA_MABEL_ROUGHNESS_SCALE_A { UNIT PERCENT; MIN 0; }
		REAL SLA_MABEL_ROUGHNESS_ATTENUATION_A { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_ROUGHNESS_DELTA_A { UNIT PERCENT; MIN 0; }
		BOOL SLA_MABEL_ROUGHNESS_HARD_BUMP_A { }
		BOOL SLA_MABEL_ROUGHNESS_ABSOLUTE_A { }
		SEPARATOR { LINE; }
		REAL SLA_MABEL_ROUGHNESS_LOW_CLIP_A { UNIT PERCENT; MIN 0; MAX 100; MINSLIDER 0; MAXSLIDER 100; CUSTOMGUI REALSLIDER; }
		REAL SLA_MABEL_ROUGHNESS_HIGH_CLIP_A { UNIT PERCENT; MIN 0; MAX 100; MINSLIDER 0; MAXSLIDER 100; CUSTOMGUI REALSLIDER; }
		SEPARATOR { LINE; }
		COLOR SLA_MABEL_ROUGHNESS_GRIT_COLOR_A { }
		REAL SLA_MABEL_ROUGHNESS_GRIT_INTENSITY_A { UNIT PERCENT; MIN -200; MAX 200; MINSLIDER -200; MAXSLIDER 200; CUSTOMGUI REALSLIDER; }
		REAL SLA_MABEL_ROUGHNESS_GRIT_LOW_CLIP_A { UNIT PERCENT; MIN 0; MAX 100; MINSLIDER 0; MAXSLIDER 100; CUSTOMGUI REALSLIDER; }
		REAL SLA_MABEL_ROUGHNESS_GRIT_HIGH_CLIP_A { UNIT PERCENT; MIN 0; MAX 100; MINSLIDER 0; MAXSLIDER 100; CUSTOMGUI REALSLIDER; }
	}
	GROUP ID_MABEL_ANISOTROPY_A
	{
		LONG SLA_MABEL_ANISOTROPY_PROJECTION_A
		{
			CYCLE
			{
				SLA_MABEL_PROJECTION_PLANAR;
				SLA_MABEL_PROJECTION_AUTO_PLANAR;
				SLA_MABEL_PROJECTION_SHRINK_WRAP;
				SLA_MABEL_PROJECTION_RADIAL_AUTO_PLANAR;
				SLA_MABEL_PROJECTION_RAD_PATTERN_AUTO_PLANAR;
				SLA_MABEL_PROJECTION_RADIAL_PLANAR;
				SLA_MABEL_PROJECTION_RAD_PATTERN_PLANAR;
			}
		}
		REAL SLA_MABEL_ANISOTROPY_PROJ_SCALE_A { UNIT PERCENT; MIN 0; MAX 1000; }
		SEPARATOR { LINE; }
		REAL SLA_MABEL_ANISOTROPY_X_ROUGH_A { UNIT PERCENT; MIN 0; }
		REAL SLA_MABEL_ANISOTROPY_Y_ROUGH_A { UNIT PERCENT; MIN 0; }
		SEPARATOR { LINE; }
		REAL SLA_MABEL_ANISOTROPY_AMPL_A { UNIT PERCENT; MIN 0; MAX 100; }
		REAL SLA_MABEL_ANISOTROPY_SCALE_A { UNIT PERCENT; MIN 0; }
		REAL SLA_MABEL_ANISOTROPY_LENGTH_A { UNIT PERCENT; MIN 0; }
		REAL SLA_MABEL_ANISOTROPY_ATT_A { UNIT PERCENT; MIN 0; }
		BOOL SLA_MABEL_ANISOTROPY_CHANNEL1_A { }
		BOOL SLA_MABEL_ANISOTROPY_CHANNEL2_A { }
		BOOL SLA_MABEL_ANISOTROPY_CHANNEL3_A { }
	}



	GROUP ID_MABEL_DIFFUSE_B
	{
		COLOR SLA_MABEL_DIFFUSE_COLOR_B { }
		LONG SLA_MABEL_DIFFUSE_ALGORITHM_A
		{
			CYCLE
			{
				SLA_MABEL_DIFFUSE_ALGORITHM_INTERNAL;
				SLA_MABEL_DIFFUSE_ALGORITHM_OREN_NAYAR;
			}
		}
		REAL SLA_MABEL_DIFFUSE_ROUGHNESS_B { UNIT PERCENT; MIN 0; MAX 200; }
		REAL SLA_MABEL_DIFFUSE_ILLUMINATION_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_DIFFUSE_CONTRAST_B { UNIT PERCENT; MIN -1000; MAX 1000; }
	}
	GROUP ID_MABEL_SPECULAR1_B
	{
		COLOR SLA_MABEL_SPEC1_COLOR_B { };
		REAL SLA_MABEL_SPEC1_INTENSITY_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_SPEC1_SIZE_B { UNIT PERCENT; MIN 0; MAX 200; }
		REAL SLA_MABEL_SPEC1_CONTRAST_B { UNIT PERCENT; MIN 0; MAX 100; }
		REAL SLA_MABEL_SPEC1_GLARE_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_SPEC1_FALLOFF_B { UNIT PERCENT; MIN 0; }
	}
	GROUP ID_MABEL_SPECULAR2_B
	{
		COLOR SLA_MABEL_SPEC2_COLOR_B { };
		REAL SLA_MABEL_SPEC2_INTENSITY_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_SPEC2_SIZE_B { UNIT PERCENT; MIN 0; MAX 200; }
		REAL SLA_MABEL_SPEC2_CONTRAST_B { UNIT PERCENT; MIN 0; MAX 100; }
		REAL SLA_MABEL_SPEC2_GLARE_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_SPEC2_FALLOFF_B { UNIT PERCENT; MIN 0; }
	}
	GROUP ID_MABEL_SPECULAR3_B
	{
		COLOR SLA_MABEL_SPEC3_COLOR_B { };
		REAL SLA_MABEL_SPEC3_INTENSITY_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_SPEC3_SIZE_B { UNIT PERCENT; MIN 0; MAX 200; }
		REAL SLA_MABEL_SPEC3_CONTRAST_B { UNIT PERCENT; MIN 0; MAX 100; }
		REAL SLA_MABEL_SPEC3_GLARE_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_SPEC3_FALLOFF_B { UNIT PERCENT; MIN 0; }
	}
	GROUP ID_MABEL_REFLECTION_B
	{
		REAL SLA_MABEL_REFLECTION_INTENSITY_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_REFLECTION_EDGE_INTENSITY_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_REFLECTION_FALLOFF_B { UNIT PERCENT; MIN 0; }
		SEPARATOR { LINE; }
		COLOR SLA_MABEL_REFLECTION_REFLECTION_COLOR_B { }
		COLOR SLA_MABEL_REFLECTION_EDGE_COLOR_B { }
	}
	GROUP ID_MABEL_ENVIRONMENT_B
	{
		SHADERLINK SLA_MABEL_ENVIRONMENT_IMAGE { }
		REAL SLA_MABEL_ENVIRONMENT_INTENSITY_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_ENVIRONMENT_GLARE_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_ENVIRONMENT_FALLOFF_B { UNIT PERCENT; MIN 0; }
		SEPARATOR { LINE; }
		BOOL SLA_MABEL_ENVIRONMENT_UTILIZE_ANISO_SCRATCHES_B { }
		REAL SLA_MABEL_ENVIRONMENT_BLUR_B { UNIT PERCENT; MIN 0; MAX 100; }
		LONG SLA_MABEL_ENVIRONMENT_SAMPLES_B { MIN 2; }
		REAL SLA_MABEL_ENVIRONMENT_JITTER_B { UNIT PERCENT; MIN 0; MAX 1000; }
		SEPARATOR { LINE; }
		COLOR SLA_MABEL_ENVIRONMENT_ENVIRONMENT_COLOR_B { }
		COLOR SLA_MABEL_ENVIRONMENT_EDGE_COLOR_B { }
	}
	GROUP ID_MABEL_AMBIENT_B
	{
		COLOR SLA_MABEL_AMBIENT_COLOR_B { }
		REAL SLA_MABEL_AMBIENT_INTENSITY_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_AMBIENT_EDGE_INTENSITY_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_AMBIENT_FALLOFF_B { UNIT PERCENT; MIN 0; }
	}
	GROUP ID_MABEL_ROUGHNESS_B
	{
		LONG SLA_MABEL_ROUGHNESS_SEED_B { }
		LONG SLA_MABEL_ROUGHNESS_NOISE_B
		{
			CYCLE
			{
			}
			CUSTOMGUI NOISE; NOISE_OFFSET 2100;
		}
		REAL SLA_MABEL_ROUGHNESS_AMPLITUDE_B { UNIT PERCENT; MIN -1000; MAX 1000; }
		REAL SLA_MABEL_ROUGHNESS_OCTAVES_B { MIN 0; MAX 20; STEP .5; }
		REAL SLA_MABEL_ROUGHNESS_SCALE_B { UNIT PERCENT; MIN 0; }
		REAL SLA_MABEL_ROUGHNESS_ATTENUATION_B { UNIT PERCENT; MIN 0; MAX 1000; }
		REAL SLA_MABEL_ROUGHNESS_DELTA_B { UNIT PERCENT; MIN 0; }
		BOOL SLA_MABEL_ROUGHNESS_HARD_BUMP_B { }
		BOOL SLA_MABEL_ROUGHNESS_ABSOLUTE_B { }
		SEPARATOR { LINE; }
		REAL SLA_MABEL_ROUGHNESS_LOW_CLIP_B { UNIT PERCENT; MIN 0; MAX 100; MINSLIDER 0; MAXSLIDER 100; CUSTOMGUI REALSLIDER; }
		REAL SLA_MABEL_ROUGHNESS_HIGH_CLIP_B { UNIT PERCENT; MIN 0; MAX 100; MINSLIDER 0; MAXSLIDER 100; CUSTOMGUI REALSLIDER; }
		SEPARATOR { LINE; }
		COLOR SLA_MABEL_ROUGHNESS_GRIT_COLOR_B { }
		REAL SLA_MABEL_ROUGHNESS_GRIT_INTENSITY_B { UNIT PERCENT; MIN -200; MAX 200; MINSLIDER -200; MAXSLIDER 200; CUSTOMGUI REALSLIDER; }
		REAL SLA_MABEL_ROUGHNESS_GRIT_LOW_CLIP_B { UNIT PERCENT; MIN 0; MAX 100; MINSLIDER 0; MAXSLIDER 100; CUSTOMGUI REALSLIDER; }
		REAL SLA_MABEL_ROUGHNESS_GRIT_HIGH_CLIP_B { UNIT PERCENT; MIN 0; MAX 100; MINSLIDER 0; MAXSLIDER 100; CUSTOMGUI REALSLIDER; }
	}
	GROUP ID_MABEL_ANISOTROPY_B
	{
		LONG SLA_MABEL_ANISOTROPY_PROJECTION_B
		{
			CYCLE
			{
				SLA_MABEL_PROJECTION_PLANAR;
				SLA_MABEL_PROJECTION_AUTO_PLANAR;
				SLA_MABEL_PROJECTION_SHRINK_WRAP;
				SLA_MABEL_PROJECTION_RADIAL_AUTO_PLANAR;
				SLA_MABEL_PROJECTION_RAD_PATTERN_AUTO_PLANAR;
				SLA_MABEL_PROJECTION_RADIAL_PLANAR;
				SLA_MABEL_PROJECTION_RAD_PATTERN_PLANAR;
			}
		}
		REAL SLA_MABEL_ANISOTROPY_PROJ_SCALE_B { UNIT PERCENT; MIN 0; MAX 1000; }
		SEPARATOR { LINE; }
		REAL SLA_MABEL_ANISOTROPY_X_ROUGH_B { UNIT PERCENT; MIN 0; }
		REAL SLA_MABEL_ANISOTROPY_Y_ROUGH_B { UNIT PERCENT; MIN 0; }
		SEPARATOR { LINE; }
		REAL SLA_MABEL_ANISOTROPY_AMPL_B { UNIT PERCENT; MIN 0; MAX 100; }
		REAL SLA_MABEL_ANISOTROPY_SCALE_B { UNIT PERCENT; MIN 0; }
		REAL SLA_MABEL_ANISOTROPY_LENGTH_B { UNIT PERCENT; MIN 0; }
		REAL SLA_MABEL_ANISOTROPY_ATT_B { UNIT PERCENT; MIN 0; }
		BOOL SLA_MABEL_ANISOTROPY_CHANNEL1_B { }
		BOOL SLA_MABEL_ANISOTROPY_CHANNEL2_B { }
		BOOL SLA_MABEL_ANISOTROPY_CHANNEL3_B { }
	}

	INCLUDE Millum;
	INCLUDE Massign;
}