# Generated from /var/folders/34/52r9fr3x7kgcv2srt4rgpmcc0000gn/T//esql-gen-8.19.0.jyhQAI/adapted/EsqlBaseParser.g4 by ANTLR 4.13.1
# encoding: utf-8
from antlr4 import *
from io import StringIO
import sys
if sys.version_info[1] > 5:
	from typing import TextIO
else:
	from typing.io import TextIO


# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
# Adapted for esql-detection-rules-py from Elasticsearch antlr sources.

if "." in __name__:
    from .ParserConfig import ParserConfig
else:
    from ParserConfig import ParserConfig

def serializedATN():
    return [
        4,1,139,786,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,
        7,6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,2,13,7,
        13,2,14,7,14,2,15,7,15,2,16,7,16,2,17,7,17,2,18,7,18,2,19,7,19,2,
        20,7,20,2,21,7,21,2,22,7,22,2,23,7,23,2,24,7,24,2,25,7,25,2,26,7,
        26,2,27,7,27,2,28,7,28,2,29,7,29,2,30,7,30,2,31,7,31,2,32,7,32,2,
        33,7,33,2,34,7,34,2,35,7,35,2,36,7,36,2,37,7,37,2,38,7,38,2,39,7,
        39,2,40,7,40,2,41,7,41,2,42,7,42,2,43,7,43,2,44,7,44,2,45,7,45,2,
        46,7,46,2,47,7,47,2,48,7,48,2,49,7,49,2,50,7,50,2,51,7,51,2,52,7,
        52,2,53,7,53,2,54,7,54,2,55,7,55,2,56,7,56,2,57,7,57,2,58,7,58,2,
        59,7,59,2,60,7,60,2,61,7,61,2,62,7,62,2,63,7,63,2,64,7,64,2,65,7,
        65,2,66,7,66,2,67,7,67,2,68,7,68,2,69,7,69,2,70,7,70,2,71,7,71,2,
        72,7,72,2,73,7,73,2,74,7,74,2,75,7,75,2,76,7,76,2,77,7,77,2,78,7,
        78,2,79,7,79,2,80,7,80,1,0,1,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,5,1,172,
        8,1,10,1,12,1,175,9,1,1,2,1,2,1,2,1,2,1,2,1,2,3,2,183,8,2,1,3,1,
        3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,1,
        3,1,3,1,3,1,3,1,3,3,3,207,8,3,1,4,1,4,1,4,1,5,1,5,1,5,1,5,1,5,1,
        5,1,5,3,5,219,8,5,1,5,1,5,1,5,1,5,1,5,5,5,226,8,5,10,5,12,5,229,
        9,5,1,5,1,5,1,5,1,5,1,5,3,5,236,8,5,1,5,1,5,1,5,3,5,241,8,5,1,5,
        1,5,1,5,1,5,1,5,1,5,5,5,249,8,5,10,5,12,5,252,9,5,1,6,1,6,3,6,256,
        8,6,1,6,1,6,1,6,1,6,1,6,3,6,263,8,6,1,6,1,6,1,6,1,6,1,6,3,6,270,
        8,6,1,6,1,6,1,6,1,6,1,6,5,6,277,8,6,10,6,12,6,280,9,6,1,6,1,6,3,
        6,284,8,6,1,7,1,7,1,7,3,7,289,8,7,1,7,1,7,1,7,1,8,1,8,1,8,1,8,1,
        8,3,8,299,8,8,1,9,1,9,1,9,1,9,3,9,305,8,9,1,9,1,9,1,9,1,9,1,9,1,
        9,5,9,313,8,9,10,9,12,9,316,9,9,1,10,1,10,1,10,1,10,1,10,1,10,1,
        10,1,10,3,10,326,8,10,1,10,1,10,1,10,5,10,331,8,10,10,10,12,10,334,
        9,10,1,11,1,11,1,11,1,11,1,11,1,11,5,11,342,8,11,10,11,12,11,345,
        9,11,1,11,1,11,3,11,349,8,11,3,11,351,8,11,1,11,1,11,1,12,1,12,1,
        13,1,13,1,13,1,13,5,13,361,8,13,10,13,12,13,364,9,13,1,13,1,13,1,
        14,1,14,1,14,1,14,1,15,1,15,1,16,1,16,1,16,1,17,1,17,1,17,5,17,380,
        8,17,10,17,12,17,383,9,17,1,18,1,18,1,18,3,18,388,8,18,1,18,1,18,
        1,19,1,19,1,19,5,19,395,8,19,10,19,12,19,398,9,19,1,20,1,20,1,20,
        3,20,403,8,20,1,21,1,21,1,21,1,21,5,21,409,8,21,10,21,12,21,412,
        9,21,1,21,3,21,415,8,21,1,22,1,22,1,22,1,22,1,22,1,22,1,22,1,22,
        1,22,3,22,426,8,22,1,23,1,23,1,24,1,24,1,25,1,25,1,26,1,26,1,27,
        1,27,3,27,438,8,27,1,28,1,28,1,28,1,28,5,28,444,8,28,10,28,12,28,
        447,9,28,1,29,1,29,1,29,1,29,1,30,1,30,1,30,1,30,5,30,457,8,30,10,
        30,12,30,460,9,30,1,30,3,30,463,8,30,1,30,1,30,3,30,467,8,30,1,31,
        1,31,1,31,1,32,1,32,3,32,474,8,32,1,32,1,32,3,32,478,8,32,1,33,1,
        33,1,33,5,33,483,8,33,10,33,12,33,486,9,33,1,34,1,34,1,34,3,34,491,
        8,34,1,35,1,35,1,35,5,35,496,8,35,10,35,12,35,499,9,35,1,36,1,36,
        1,36,5,36,504,8,36,10,36,12,36,507,9,36,1,37,1,37,1,37,5,37,512,
        8,37,10,37,12,37,515,9,37,1,38,1,38,1,39,1,39,1,39,3,39,522,8,39,
        1,40,1,40,1,40,1,40,1,40,1,40,1,40,1,40,1,40,1,40,1,40,1,40,1,40,
        5,40,537,8,40,10,40,12,40,540,9,40,1,40,1,40,1,40,1,40,1,40,1,40,
        5,40,548,8,40,10,40,12,40,551,9,40,1,40,1,40,1,40,1,40,1,40,1,40,
        5,40,559,8,40,10,40,12,40,562,9,40,1,40,1,40,3,40,566,8,40,1,41,
        1,41,3,41,570,8,41,1,42,1,42,3,42,574,8,42,1,43,1,43,1,43,3,43,579,
        8,43,1,44,1,44,1,44,1,45,1,45,1,45,1,45,5,45,588,8,45,10,45,12,45,
        591,9,45,1,46,1,46,3,46,595,8,46,1,46,1,46,3,46,599,8,46,1,47,1,
        47,1,47,1,48,1,48,1,48,1,49,1,49,1,49,1,49,5,49,611,8,49,10,49,12,
        49,614,9,49,1,50,1,50,1,50,1,50,1,50,1,50,1,50,1,50,3,50,624,8,50,
        1,51,1,51,1,51,1,51,3,51,630,8,51,1,52,1,52,1,52,1,52,1,53,1,53,
        1,53,1,54,1,54,1,54,5,54,642,8,54,10,54,12,54,645,9,54,1,55,1,55,
        1,55,1,55,1,56,1,56,1,57,1,57,3,57,655,8,57,1,58,3,58,658,8,58,1,
        58,1,58,1,59,3,59,663,8,59,1,59,1,59,1,60,1,60,1,61,1,61,1,62,1,
        62,1,62,1,63,1,63,1,63,1,63,1,64,1,64,1,64,1,65,1,65,1,65,1,65,3,
        65,685,8,65,1,65,1,65,1,65,1,65,5,65,691,8,65,10,65,12,65,694,9,
        65,3,65,696,8,65,1,66,1,66,1,67,1,67,1,67,3,67,703,8,67,1,67,1,67,
        1,68,1,68,1,68,1,68,3,68,711,8,68,1,68,1,68,1,68,1,68,1,68,3,68,
        718,8,68,1,69,1,69,1,69,1,70,1,70,1,70,1,70,1,70,1,71,1,71,1,71,
        1,71,3,71,732,8,71,1,72,1,72,1,72,1,72,1,72,1,73,1,73,1,74,1,74,
        1,74,1,74,5,74,745,8,74,10,74,12,74,748,9,74,1,75,1,75,1,76,1,76,
        1,76,5,76,755,8,76,10,76,12,76,758,9,76,1,77,1,77,1,77,1,77,1,78,
        1,78,3,78,766,8,78,1,79,1,79,1,79,1,79,1,79,1,79,3,79,774,8,79,1,
        80,1,80,1,80,1,80,3,80,780,8,80,1,80,1,80,1,80,1,80,1,80,0,4,2,10,
        18,20,81,0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,
        40,42,44,46,48,50,52,54,56,58,60,62,64,66,68,70,72,74,76,78,80,82,
        84,86,88,90,92,94,96,98,100,102,104,106,108,110,112,114,116,118,
        120,122,124,126,128,130,132,134,136,138,140,142,144,146,148,150,
        152,154,156,158,160,0,10,1,0,69,70,1,0,71,73,2,0,33,33,90,90,1,0,
        81,82,2,0,37,37,43,43,2,0,46,46,49,49,2,0,45,45,60,60,2,0,62,62,
        64,68,2,0,33,33,102,102,2,0,19,19,26,27,817,0,162,1,0,0,0,2,165,
        1,0,0,0,4,182,1,0,0,0,6,206,1,0,0,0,8,208,1,0,0,0,10,240,1,0,0,0,
        12,283,1,0,0,0,14,285,1,0,0,0,16,298,1,0,0,0,18,304,1,0,0,0,20,325,
        1,0,0,0,22,335,1,0,0,0,24,354,1,0,0,0,26,356,1,0,0,0,28,367,1,0,
        0,0,30,371,1,0,0,0,32,373,1,0,0,0,34,376,1,0,0,0,36,387,1,0,0,0,
        38,391,1,0,0,0,40,399,1,0,0,0,42,404,1,0,0,0,44,425,1,0,0,0,46,427,
        1,0,0,0,48,429,1,0,0,0,50,431,1,0,0,0,52,433,1,0,0,0,54,437,1,0,
        0,0,56,439,1,0,0,0,58,448,1,0,0,0,60,452,1,0,0,0,62,468,1,0,0,0,
        64,471,1,0,0,0,66,479,1,0,0,0,68,487,1,0,0,0,70,492,1,0,0,0,72,500,
        1,0,0,0,74,508,1,0,0,0,76,516,1,0,0,0,78,521,1,0,0,0,80,565,1,0,
        0,0,82,569,1,0,0,0,84,573,1,0,0,0,86,578,1,0,0,0,88,580,1,0,0,0,
        90,583,1,0,0,0,92,592,1,0,0,0,94,600,1,0,0,0,96,603,1,0,0,0,98,606,
        1,0,0,0,100,623,1,0,0,0,102,625,1,0,0,0,104,631,1,0,0,0,106,635,
        1,0,0,0,108,638,1,0,0,0,110,646,1,0,0,0,112,650,1,0,0,0,114,654,
        1,0,0,0,116,657,1,0,0,0,118,662,1,0,0,0,120,666,1,0,0,0,122,668,
        1,0,0,0,124,670,1,0,0,0,126,673,1,0,0,0,128,677,1,0,0,0,130,680,
        1,0,0,0,132,697,1,0,0,0,134,702,1,0,0,0,136,706,1,0,0,0,138,719,
        1,0,0,0,140,722,1,0,0,0,142,727,1,0,0,0,144,733,1,0,0,0,146,738,
        1,0,0,0,148,740,1,0,0,0,150,749,1,0,0,0,152,751,1,0,0,0,154,759,
        1,0,0,0,156,765,1,0,0,0,158,767,1,0,0,0,160,775,1,0,0,0,162,163,
        3,2,1,0,163,164,5,0,0,1,164,1,1,0,0,0,165,166,6,1,-1,0,166,167,3,
        4,2,0,167,173,1,0,0,0,168,169,10,1,0,0,169,170,5,32,0,0,170,172,
        3,6,3,0,171,168,1,0,0,0,172,175,1,0,0,0,173,171,1,0,0,0,173,174,
        1,0,0,0,174,3,1,0,0,0,175,173,1,0,0,0,176,183,3,124,62,0,177,183,
        3,42,21,0,178,183,3,32,16,0,179,183,3,128,64,0,180,181,4,2,1,0,181,
        183,3,60,30,0,182,176,1,0,0,0,182,177,1,0,0,0,182,178,1,0,0,0,182,
        179,1,0,0,0,182,180,1,0,0,0,183,5,1,0,0,0,184,207,3,62,31,0,185,
        207,3,8,4,0,186,207,3,94,47,0,187,207,3,88,44,0,188,207,3,64,32,
        0,189,207,3,90,45,0,190,207,3,96,48,0,191,207,3,98,49,0,192,207,
        3,102,51,0,193,207,3,104,52,0,194,207,3,130,65,0,195,207,3,106,53,
        0,196,207,3,144,72,0,197,207,3,136,68,0,198,207,3,160,80,0,199,207,
        3,138,69,0,200,201,4,3,2,0,201,207,3,142,71,0,202,203,4,3,3,0,203,
        207,3,140,70,0,204,205,4,3,4,0,205,207,3,158,79,0,206,184,1,0,0,
        0,206,185,1,0,0,0,206,186,1,0,0,0,206,187,1,0,0,0,206,188,1,0,0,
        0,206,189,1,0,0,0,206,190,1,0,0,0,206,191,1,0,0,0,206,192,1,0,0,
        0,206,193,1,0,0,0,206,194,1,0,0,0,206,195,1,0,0,0,206,196,1,0,0,
        0,206,197,1,0,0,0,206,198,1,0,0,0,206,199,1,0,0,0,206,200,1,0,0,
        0,206,202,1,0,0,0,206,204,1,0,0,0,207,7,1,0,0,0,208,209,5,18,0,0,
        209,210,3,10,5,0,210,9,1,0,0,0,211,212,6,5,-1,0,212,213,5,52,0,0,
        213,241,3,10,5,8,214,241,3,16,8,0,215,241,3,12,6,0,216,218,3,16,
        8,0,217,219,5,52,0,0,218,217,1,0,0,0,218,219,1,0,0,0,219,220,1,0,
        0,0,220,221,5,47,0,0,221,222,5,51,0,0,222,227,3,16,8,0,223,224,5,
        42,0,0,224,226,3,16,8,0,225,223,1,0,0,0,226,229,1,0,0,0,227,225,
        1,0,0,0,227,228,1,0,0,0,228,230,1,0,0,0,229,227,1,0,0,0,230,231,
        5,59,0,0,231,241,1,0,0,0,232,233,3,16,8,0,233,235,5,48,0,0,234,236,
        5,52,0,0,235,234,1,0,0,0,235,236,1,0,0,0,236,237,1,0,0,0,237,238,
        5,53,0,0,238,241,1,0,0,0,239,241,3,14,7,0,240,211,1,0,0,0,240,214,
        1,0,0,0,240,215,1,0,0,0,240,216,1,0,0,0,240,232,1,0,0,0,240,239,
        1,0,0,0,241,250,1,0,0,0,242,243,10,5,0,0,243,244,5,36,0,0,244,249,
        3,10,5,6,245,246,10,4,0,0,246,247,5,56,0,0,247,249,3,10,5,5,248,
        242,1,0,0,0,248,245,1,0,0,0,249,252,1,0,0,0,250,248,1,0,0,0,250,
        251,1,0,0,0,251,11,1,0,0,0,252,250,1,0,0,0,253,255,3,16,8,0,254,
        256,5,52,0,0,255,254,1,0,0,0,255,256,1,0,0,0,256,257,1,0,0,0,257,
        258,5,50,0,0,258,259,3,120,60,0,259,284,1,0,0,0,260,262,3,16,8,0,
        261,263,5,52,0,0,262,261,1,0,0,0,262,263,1,0,0,0,263,264,1,0,0,0,
        264,265,5,58,0,0,265,266,3,120,60,0,266,284,1,0,0,0,267,269,3,16,
        8,0,268,270,5,52,0,0,269,268,1,0,0,0,269,270,1,0,0,0,270,271,1,0,
        0,0,271,272,5,50,0,0,272,273,5,51,0,0,273,278,3,120,60,0,274,275,
        5,42,0,0,275,277,3,120,60,0,276,274,1,0,0,0,277,280,1,0,0,0,278,
        276,1,0,0,0,278,279,1,0,0,0,279,281,1,0,0,0,280,278,1,0,0,0,281,
        282,5,59,0,0,282,284,1,0,0,0,283,253,1,0,0,0,283,260,1,0,0,0,283,
        267,1,0,0,0,284,13,1,0,0,0,285,288,3,70,35,0,286,287,5,40,0,0,287,
        289,3,30,15,0,288,286,1,0,0,0,288,289,1,0,0,0,289,290,1,0,0,0,290,
        291,5,41,0,0,291,292,3,80,40,0,292,15,1,0,0,0,293,299,3,18,9,0,294,
        295,3,18,9,0,295,296,3,122,61,0,296,297,3,18,9,0,297,299,1,0,0,0,
        298,293,1,0,0,0,298,294,1,0,0,0,299,17,1,0,0,0,300,301,6,9,-1,0,
        301,305,3,20,10,0,302,303,7,0,0,0,303,305,3,18,9,3,304,300,1,0,0,
        0,304,302,1,0,0,0,305,314,1,0,0,0,306,307,10,2,0,0,307,308,7,1,0,
        0,308,313,3,18,9,3,309,310,10,1,0,0,310,311,7,0,0,0,311,313,3,18,
        9,2,312,306,1,0,0,0,312,309,1,0,0,0,313,316,1,0,0,0,314,312,1,0,
        0,0,314,315,1,0,0,0,315,19,1,0,0,0,316,314,1,0,0,0,317,318,6,10,
        -1,0,318,326,3,80,40,0,319,326,3,70,35,0,320,326,3,22,11,0,321,322,
        5,51,0,0,322,323,3,10,5,0,323,324,5,59,0,0,324,326,1,0,0,0,325,317,
        1,0,0,0,325,319,1,0,0,0,325,320,1,0,0,0,325,321,1,0,0,0,326,332,
        1,0,0,0,327,328,10,1,0,0,328,329,5,40,0,0,329,331,3,30,15,0,330,
        327,1,0,0,0,331,334,1,0,0,0,332,330,1,0,0,0,332,333,1,0,0,0,333,
        21,1,0,0,0,334,332,1,0,0,0,335,336,3,24,12,0,336,350,5,51,0,0,337,
        351,5,71,0,0,338,343,3,10,5,0,339,340,5,42,0,0,340,342,3,10,5,0,
        341,339,1,0,0,0,342,345,1,0,0,0,343,341,1,0,0,0,343,344,1,0,0,0,
        344,348,1,0,0,0,345,343,1,0,0,0,346,347,5,42,0,0,347,349,3,26,13,
        0,348,346,1,0,0,0,348,349,1,0,0,0,349,351,1,0,0,0,350,337,1,0,0,
        0,350,338,1,0,0,0,350,351,1,0,0,0,351,352,1,0,0,0,352,353,5,59,0,
        0,353,23,1,0,0,0,354,355,3,86,43,0,355,25,1,0,0,0,356,357,5,74,0,
        0,357,362,3,28,14,0,358,359,5,42,0,0,359,361,3,28,14,0,360,358,1,
        0,0,0,361,364,1,0,0,0,362,360,1,0,0,0,362,363,1,0,0,0,363,365,1,
        0,0,0,364,362,1,0,0,0,365,366,5,75,0,0,366,27,1,0,0,0,367,368,3,
        120,60,0,368,369,5,41,0,0,369,370,3,80,40,0,370,29,1,0,0,0,371,372,
        3,76,38,0,372,31,1,0,0,0,373,374,5,13,0,0,374,375,3,34,17,0,375,
        33,1,0,0,0,376,381,3,36,18,0,377,378,5,42,0,0,378,380,3,36,18,0,
        379,377,1,0,0,0,380,383,1,0,0,0,381,379,1,0,0,0,381,382,1,0,0,0,
        382,35,1,0,0,0,383,381,1,0,0,0,384,385,3,70,35,0,385,386,5,38,0,
        0,386,388,1,0,0,0,387,384,1,0,0,0,387,388,1,0,0,0,388,389,1,0,0,
        0,389,390,3,10,5,0,390,37,1,0,0,0,391,396,3,40,20,0,392,393,5,42,
        0,0,393,395,3,40,20,0,394,392,1,0,0,0,395,398,1,0,0,0,396,394,1,
        0,0,0,396,397,1,0,0,0,397,39,1,0,0,0,398,396,1,0,0,0,399,402,3,70,
        35,0,400,401,5,38,0,0,401,403,3,10,5,0,402,400,1,0,0,0,402,403,1,
        0,0,0,403,41,1,0,0,0,404,405,5,7,0,0,405,410,3,44,22,0,406,407,5,
        42,0,0,407,409,3,44,22,0,408,406,1,0,0,0,409,412,1,0,0,0,410,408,
        1,0,0,0,410,411,1,0,0,0,411,414,1,0,0,0,412,410,1,0,0,0,413,415,
        3,54,27,0,414,413,1,0,0,0,414,415,1,0,0,0,415,43,1,0,0,0,416,417,
        3,46,23,0,417,418,5,41,0,0,418,419,3,50,25,0,419,426,1,0,0,0,420,
        421,3,50,25,0,421,422,5,40,0,0,422,423,3,48,24,0,423,426,1,0,0,0,
        424,426,3,52,26,0,425,416,1,0,0,0,425,420,1,0,0,0,425,424,1,0,0,
        0,426,45,1,0,0,0,427,428,5,90,0,0,428,47,1,0,0,0,429,430,5,90,0,
        0,430,49,1,0,0,0,431,432,5,90,0,0,432,51,1,0,0,0,433,434,7,2,0,0,
        434,53,1,0,0,0,435,438,3,56,28,0,436,438,3,58,29,0,437,435,1,0,0,
        0,437,436,1,0,0,0,438,55,1,0,0,0,439,440,5,89,0,0,440,445,5,90,0,
        0,441,442,5,42,0,0,442,444,5,90,0,0,443,441,1,0,0,0,444,447,1,0,
        0,0,445,443,1,0,0,0,445,446,1,0,0,0,446,57,1,0,0,0,447,445,1,0,0,
        0,448,449,5,79,0,0,449,450,3,56,28,0,450,451,5,80,0,0,451,59,1,0,
        0,0,452,453,5,23,0,0,453,458,3,44,22,0,454,455,5,42,0,0,455,457,
        3,44,22,0,456,454,1,0,0,0,457,460,1,0,0,0,458,456,1,0,0,0,458,459,
        1,0,0,0,459,462,1,0,0,0,460,458,1,0,0,0,461,463,3,66,33,0,462,461,
        1,0,0,0,462,463,1,0,0,0,463,466,1,0,0,0,464,465,5,39,0,0,465,467,
        3,34,17,0,466,464,1,0,0,0,466,467,1,0,0,0,467,61,1,0,0,0,468,469,
        5,5,0,0,469,470,3,34,17,0,470,63,1,0,0,0,471,473,5,17,0,0,472,474,
        3,66,33,0,473,472,1,0,0,0,473,474,1,0,0,0,474,477,1,0,0,0,475,476,
        5,39,0,0,476,478,3,34,17,0,477,475,1,0,0,0,477,478,1,0,0,0,478,65,
        1,0,0,0,479,484,3,68,34,0,480,481,5,42,0,0,481,483,3,68,34,0,482,
        480,1,0,0,0,483,486,1,0,0,0,484,482,1,0,0,0,484,485,1,0,0,0,485,
        67,1,0,0,0,486,484,1,0,0,0,487,490,3,36,18,0,488,489,5,18,0,0,489,
        491,3,10,5,0,490,488,1,0,0,0,490,491,1,0,0,0,491,69,1,0,0,0,492,
        497,3,86,43,0,493,494,5,44,0,0,494,496,3,86,43,0,495,493,1,0,0,0,
        496,499,1,0,0,0,497,495,1,0,0,0,497,498,1,0,0,0,498,71,1,0,0,0,499,
        497,1,0,0,0,500,505,3,78,39,0,501,502,5,44,0,0,502,504,3,78,39,0,
        503,501,1,0,0,0,504,507,1,0,0,0,505,503,1,0,0,0,505,506,1,0,0,0,
        506,73,1,0,0,0,507,505,1,0,0,0,508,513,3,72,36,0,509,510,5,42,0,
        0,510,512,3,72,36,0,511,509,1,0,0,0,512,515,1,0,0,0,513,511,1,0,
        0,0,513,514,1,0,0,0,514,75,1,0,0,0,515,513,1,0,0,0,516,517,7,3,0,
        0,517,77,1,0,0,0,518,522,5,94,0,0,519,522,3,82,41,0,520,522,3,84,
        42,0,521,518,1,0,0,0,521,519,1,0,0,0,521,520,1,0,0,0,522,79,1,0,
        0,0,523,566,5,53,0,0,524,525,3,118,59,0,525,526,5,81,0,0,526,566,
        1,0,0,0,527,566,3,116,58,0,528,566,3,118,59,0,529,566,3,112,56,0,
        530,566,3,82,41,0,531,566,3,120,60,0,532,533,5,79,0,0,533,538,3,
        114,57,0,534,535,5,42,0,0,535,537,3,114,57,0,536,534,1,0,0,0,537,
        540,1,0,0,0,538,536,1,0,0,0,538,539,1,0,0,0,539,541,1,0,0,0,540,
        538,1,0,0,0,541,542,5,80,0,0,542,566,1,0,0,0,543,544,5,79,0,0,544,
        549,3,112,56,0,545,546,5,42,0,0,546,548,3,112,56,0,547,545,1,0,0,
        0,548,551,1,0,0,0,549,547,1,0,0,0,549,550,1,0,0,0,550,552,1,0,0,
        0,551,549,1,0,0,0,552,553,5,80,0,0,553,566,1,0,0,0,554,555,5,79,
        0,0,555,560,3,120,60,0,556,557,5,42,0,0,557,559,3,120,60,0,558,556,
        1,0,0,0,559,562,1,0,0,0,560,558,1,0,0,0,560,561,1,0,0,0,561,563,
        1,0,0,0,562,560,1,0,0,0,563,564,5,80,0,0,564,566,1,0,0,0,565,523,
        1,0,0,0,565,524,1,0,0,0,565,527,1,0,0,0,565,528,1,0,0,0,565,529,
        1,0,0,0,565,530,1,0,0,0,565,531,1,0,0,0,565,532,1,0,0,0,565,543,
        1,0,0,0,565,554,1,0,0,0,566,81,1,0,0,0,567,570,5,57,0,0,568,570,
        5,77,0,0,569,567,1,0,0,0,569,568,1,0,0,0,570,83,1,0,0,0,571,574,
        5,76,0,0,572,574,5,78,0,0,573,571,1,0,0,0,573,572,1,0,0,0,574,85,
        1,0,0,0,575,579,3,76,38,0,576,579,3,82,41,0,577,579,3,84,42,0,578,
        575,1,0,0,0,578,576,1,0,0,0,578,577,1,0,0,0,579,87,1,0,0,0,580,581,
        5,10,0,0,581,582,3,80,40,0,582,89,1,0,0,0,583,584,5,16,0,0,584,589,
        3,92,46,0,585,586,5,42,0,0,586,588,3,92,46,0,587,585,1,0,0,0,588,
        591,1,0,0,0,589,587,1,0,0,0,589,590,1,0,0,0,590,91,1,0,0,0,591,589,
        1,0,0,0,592,594,3,10,5,0,593,595,7,4,0,0,594,593,1,0,0,0,594,595,
        1,0,0,0,595,598,1,0,0,0,596,597,5,54,0,0,597,599,7,5,0,0,598,596,
        1,0,0,0,598,599,1,0,0,0,599,93,1,0,0,0,600,601,5,9,0,0,601,602,3,
        74,37,0,602,95,1,0,0,0,603,604,5,3,0,0,604,605,3,74,37,0,605,97,
        1,0,0,0,606,607,5,12,0,0,607,612,3,100,50,0,608,609,5,42,0,0,609,
        611,3,100,50,0,610,608,1,0,0,0,611,614,1,0,0,0,612,610,1,0,0,0,612,
        613,1,0,0,0,613,99,1,0,0,0,614,612,1,0,0,0,615,616,3,72,36,0,616,
        617,5,98,0,0,617,618,3,72,36,0,618,624,1,0,0,0,619,620,3,72,36,0,
        620,621,5,38,0,0,621,622,3,72,36,0,622,624,1,0,0,0,623,615,1,0,0,
        0,623,619,1,0,0,0,624,101,1,0,0,0,625,626,5,2,0,0,626,627,3,20,10,
        0,627,629,3,120,60,0,628,630,3,108,54,0,629,628,1,0,0,0,629,630,
        1,0,0,0,630,103,1,0,0,0,631,632,5,8,0,0,632,633,3,20,10,0,633,634,
        3,120,60,0,634,105,1,0,0,0,635,636,5,11,0,0,636,637,3,70,35,0,637,
        107,1,0,0,0,638,643,3,110,55,0,639,640,5,42,0,0,640,642,3,110,55,
        0,641,639,1,0,0,0,642,645,1,0,0,0,643,641,1,0,0,0,643,644,1,0,0,
        0,644,109,1,0,0,0,645,643,1,0,0,0,646,647,3,76,38,0,647,648,5,38,
        0,0,648,649,3,80,40,0,649,111,1,0,0,0,650,651,7,6,0,0,651,113,1,
        0,0,0,652,655,3,116,58,0,653,655,3,118,59,0,654,652,1,0,0,0,654,
        653,1,0,0,0,655,115,1,0,0,0,656,658,7,0,0,0,657,656,1,0,0,0,657,
        658,1,0,0,0,658,659,1,0,0,0,659,660,5,35,0,0,660,117,1,0,0,0,661,
        663,7,0,0,0,662,661,1,0,0,0,662,663,1,0,0,0,663,664,1,0,0,0,664,
        665,5,34,0,0,665,119,1,0,0,0,666,667,5,33,0,0,667,121,1,0,0,0,668,
        669,7,7,0,0,669,123,1,0,0,0,670,671,5,6,0,0,671,672,3,126,63,0,672,
        125,1,0,0,0,673,674,5,79,0,0,674,675,3,2,1,0,675,676,5,80,0,0,676,
        127,1,0,0,0,677,678,5,15,0,0,678,679,5,112,0,0,679,129,1,0,0,0,680,
        681,5,4,0,0,681,684,3,132,66,0,682,683,5,55,0,0,683,685,3,72,36,
        0,684,682,1,0,0,0,684,685,1,0,0,0,685,695,1,0,0,0,686,687,5,61,0,
        0,687,692,3,134,67,0,688,689,5,42,0,0,689,691,3,134,67,0,690,688,
        1,0,0,0,691,694,1,0,0,0,692,690,1,0,0,0,692,693,1,0,0,0,693,696,
        1,0,0,0,694,692,1,0,0,0,695,686,1,0,0,0,695,696,1,0,0,0,696,131,
        1,0,0,0,697,698,7,8,0,0,698,133,1,0,0,0,699,700,3,72,36,0,700,701,
        5,38,0,0,701,703,1,0,0,0,702,699,1,0,0,0,702,703,1,0,0,0,703,704,
        1,0,0,0,704,705,3,72,36,0,705,135,1,0,0,0,706,707,5,20,0,0,707,710,
        3,70,35,0,708,709,5,55,0,0,709,711,3,70,35,0,710,708,1,0,0,0,710,
        711,1,0,0,0,711,717,1,0,0,0,712,713,5,98,0,0,713,714,3,70,35,0,714,
        715,5,42,0,0,715,716,3,70,35,0,716,718,1,0,0,0,717,712,1,0,0,0,717,
        718,1,0,0,0,718,137,1,0,0,0,719,720,5,14,0,0,720,721,3,80,40,0,721,
        139,1,0,0,0,722,723,5,22,0,0,723,724,3,44,22,0,724,725,5,55,0,0,
        725,726,3,74,37,0,726,141,1,0,0,0,727,728,5,21,0,0,728,731,3,66,
        33,0,729,730,5,39,0,0,730,732,3,34,17,0,731,729,1,0,0,0,731,732,
        1,0,0,0,732,143,1,0,0,0,733,734,7,9,0,0,734,735,5,126,0,0,735,736,
        3,146,73,0,736,737,3,148,74,0,737,145,1,0,0,0,738,739,3,44,22,0,
        739,147,1,0,0,0,740,741,5,55,0,0,741,746,3,150,75,0,742,743,5,42,
        0,0,743,745,3,150,75,0,744,742,1,0,0,0,745,748,1,0,0,0,746,744,1,
        0,0,0,746,747,1,0,0,0,747,149,1,0,0,0,748,746,1,0,0,0,749,750,3,
        16,8,0,750,151,1,0,0,0,751,756,3,154,77,0,752,753,5,42,0,0,753,755,
        3,154,77,0,754,752,1,0,0,0,755,758,1,0,0,0,756,754,1,0,0,0,756,757,
        1,0,0,0,757,153,1,0,0,0,758,756,1,0,0,0,759,760,3,76,38,0,760,761,
        5,38,0,0,761,762,3,156,78,0,762,155,1,0,0,0,763,766,3,80,40,0,764,
        766,3,76,38,0,765,763,1,0,0,0,765,764,1,0,0,0,766,157,1,0,0,0,767,
        768,5,24,0,0,768,769,3,80,40,0,769,770,5,55,0,0,770,773,3,38,19,
        0,771,772,5,61,0,0,772,774,3,152,76,0,773,771,1,0,0,0,773,774,1,
        0,0,0,774,159,1,0,0,0,775,779,5,1,0,0,776,777,3,70,35,0,777,778,
        5,38,0,0,778,780,1,0,0,0,779,776,1,0,0,0,779,780,1,0,0,0,780,781,
        1,0,0,0,781,782,3,20,10,0,782,783,5,61,0,0,783,784,3,86,43,0,784,
        161,1,0,0,0,74,173,182,206,218,227,235,240,248,250,255,262,269,278,
        283,288,298,304,312,314,325,332,343,348,350,362,381,387,396,402,
        410,414,425,437,445,458,462,466,473,477,484,490,497,505,513,521,
        538,549,560,565,569,573,578,589,594,598,612,623,629,643,654,657,
        662,684,692,695,702,710,717,731,746,756,765,773,779
    ]

class EsqlBaseParser ( ParserConfig ):

    grammarFileName = "EsqlBaseParser.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "'completion'", "'dissect'", "'drop'", 
                     "'enrich'", "'eval'", "'explain'", "'from'", "'grok'", 
                     "'keep'", "'limit'", "'mv_expand'", "'rename'", "'row'", 
                     "'sample'", "'show'", "'sort'", "'stats'", "'where'", 
                     "'lookup'", "'change_point'", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "'|'", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "'and'", "'asc'", "'='", "'by'", "'::'", "':'", "','", 
                     "'desc'", "'.'", "'false'", "'first'", "'in'", "'is'", 
                     "'last'", "'like'", "'('", "'not'", "'null'", "'nulls'", 
                     "'on'", "'or'", "'?'", "'rlike'", "')'", "'true'", 
                     "'with'", "'=='", "'=~'", "'!='", "'<'", "'<='", "'>'", 
                     "'>='", "'+'", "'-'", "'*'", "'/'", "'%'", "'{'", "'}'", 
                     "'??'", "<INVALID>", "<INVALID>", "<INVALID>", "']'", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "'metadata'", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "'as'", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "'info'", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "'join'", "'USING'" ]

    symbolicNames = [ "<INVALID>", "COMPLETION", "DISSECT", "DROP", "ENRICH", 
                      "EVAL", "EXPLAIN", "FROM", "GROK", "KEEP", "LIMIT", 
                      "MV_EXPAND", "RENAME", "ROW", "SAMPLE", "SHOW", "SORT", 
                      "STATS", "WHERE", "JOIN_LOOKUP", "CHANGE_POINT", "DEV_INLINESTATS", 
                      "DEV_LOOKUP", "DEV_METRICS", "DEV_RERANK", "DEV_JOIN_FULL", 
                      "DEV_JOIN_LEFT", "DEV_JOIN_RIGHT", "UNKNOWN_CMD", 
                      "LINE_COMMENT", "MULTILINE_COMMENT", "WS", "PIPE", 
                      "QUOTED_STRING", "INTEGER_LITERAL", "DECIMAL_LITERAL", 
                      "AND", "ASC", "ASSIGN", "BY", "CAST_OP", "COLON", 
                      "COMMA", "DESC", "DOT", "FALSE", "FIRST", "IN", "IS", 
                      "LAST", "LIKE", "LP", "NOT", "NULL", "NULLS", "ON", 
                      "OR", "PARAM", "RLIKE", "RP", "TRUE", "WITH", "EQ", 
                      "CIEQ", "NEQ", "LT", "LTE", "GT", "GTE", "PLUS", "MINUS", 
                      "ASTERISK", "SLASH", "PERCENT", "LEFT_BRACES", "RIGHT_BRACES", 
                      "DOUBLE_PARAMS", "NAMED_OR_POSITIONAL_PARAM", "NAMED_OR_POSITIONAL_DOUBLE_PARAMS", 
                      "OPENING_BRACKET", "CLOSING_BRACKET", "UNQUOTED_IDENTIFIER", 
                      "QUOTED_IDENTIFIER", "EXPR_LINE_COMMENT", "EXPR_MULTILINE_COMMENT", 
                      "EXPR_WS", "EXPLAIN_WS", "EXPLAIN_LINE_COMMENT", "EXPLAIN_MULTILINE_COMMENT", 
                      "METADATA", "UNQUOTED_SOURCE", "FROM_LINE_COMMENT", 
                      "FROM_MULTILINE_COMMENT", "FROM_WS", "ID_PATTERN", 
                      "PROJECT_LINE_COMMENT", "PROJECT_MULTILINE_COMMENT", 
                      "PROJECT_WS", "AS", "RENAME_LINE_COMMENT", "RENAME_MULTILINE_COMMENT", 
                      "RENAME_WS", "ENRICH_POLICY_NAME", "ENRICH_LINE_COMMENT", 
                      "ENRICH_MULTILINE_COMMENT", "ENRICH_WS", "ENRICH_FIELD_LINE_COMMENT", 
                      "ENRICH_FIELD_MULTILINE_COMMENT", "ENRICH_FIELD_WS", 
                      "MVEXPAND_LINE_COMMENT", "MVEXPAND_MULTILINE_COMMENT", 
                      "MVEXPAND_WS", "INFO", "SHOW_LINE_COMMENT", "SHOW_MULTILINE_COMMENT", 
                      "SHOW_WS", "SETTING", "SETTING_LINE_COMMENT", "SETTTING_MULTILINE_COMMENT", 
                      "SETTING_WS", "LOOKUP_LINE_COMMENT", "LOOKUP_MULTILINE_COMMENT", 
                      "LOOKUP_WS", "LOOKUP_FIELD_LINE_COMMENT", "LOOKUP_FIELD_MULTILINE_COMMENT", 
                      "LOOKUP_FIELD_WS", "JOIN", "USING", "JOIN_LINE_COMMENT", 
                      "JOIN_MULTILINE_COMMENT", "JOIN_WS", "METRICS_LINE_COMMENT", 
                      "METRICS_MULTILINE_COMMENT", "METRICS_WS", "CLOSING_METRICS_LINE_COMMENT", 
                      "CLOSING_METRICS_MULTILINE_COMMENT", "CLOSING_METRICS_WS", 
                      "CHANGE_POINT_LINE_COMMENT", "CHANGE_POINT_MULTILINE_COMMENT", 
                      "CHANGE_POINT_WS" ]

    RULE_singleStatement = 0
    RULE_query = 1
    RULE_sourceCommand = 2
    RULE_processingCommand = 3
    RULE_whereCommand = 4
    RULE_booleanExpression = 5
    RULE_regexBooleanExpression = 6
    RULE_matchBooleanExpression = 7
    RULE_valueExpression = 8
    RULE_operatorExpression = 9
    RULE_primaryExpression = 10
    RULE_functionExpression = 11
    RULE_functionName = 12
    RULE_mapExpression = 13
    RULE_entryExpression = 14
    RULE_dataType = 15
    RULE_rowCommand = 16
    RULE_fields = 17
    RULE_field = 18
    RULE_rerankFields = 19
    RULE_rerankField = 20
    RULE_fromCommand = 21
    RULE_indexPattern = 22
    RULE_clusterString = 23
    RULE_selectorString = 24
    RULE_unquotedIndexString = 25
    RULE_indexString = 26
    RULE_metadata = 27
    RULE_metadataOption = 28
    RULE_deprecated_metadata = 29
    RULE_metricsCommand = 30
    RULE_evalCommand = 31
    RULE_statsCommand = 32
    RULE_aggFields = 33
    RULE_aggField = 34
    RULE_qualifiedName = 35
    RULE_qualifiedNamePattern = 36
    RULE_qualifiedNamePatterns = 37
    RULE_identifier = 38
    RULE_identifierPattern = 39
    RULE_constant = 40
    RULE_parameter = 41
    RULE_doubleParameter = 42
    RULE_identifierOrParameter = 43
    RULE_limitCommand = 44
    RULE_sortCommand = 45
    RULE_orderExpression = 46
    RULE_keepCommand = 47
    RULE_dropCommand = 48
    RULE_renameCommand = 49
    RULE_renameClause = 50
    RULE_dissectCommand = 51
    RULE_grokCommand = 52
    RULE_mvExpandCommand = 53
    RULE_commandOptions = 54
    RULE_commandOption = 55
    RULE_booleanValue = 56
    RULE_numericValue = 57
    RULE_decimalValue = 58
    RULE_integerValue = 59
    RULE_string = 60
    RULE_comparisonOperator = 61
    RULE_explainCommand = 62
    RULE_subqueryExpression = 63
    RULE_showCommand = 64
    RULE_enrichCommand = 65
    RULE_enrichPolicyName = 66
    RULE_enrichWithClause = 67
    RULE_changePointCommand = 68
    RULE_sampleCommand = 69
    RULE_lookupCommand = 70
    RULE_inlinestatsCommand = 71
    RULE_joinCommand = 72
    RULE_joinTarget = 73
    RULE_joinCondition = 74
    RULE_joinPredicate = 75
    RULE_inferenceCommandOptions = 76
    RULE_inferenceCommandOption = 77
    RULE_inferenceCommandOptionValue = 78
    RULE_rerankCommand = 79
    RULE_completionCommand = 80

    ruleNames =  [ "singleStatement", "query", "sourceCommand", "processingCommand", 
                   "whereCommand", "booleanExpression", "regexBooleanExpression", 
                   "matchBooleanExpression", "valueExpression", "operatorExpression", 
                   "primaryExpression", "functionExpression", "functionName", 
                   "mapExpression", "entryExpression", "dataType", "rowCommand", 
                   "fields", "field", "rerankFields", "rerankField", "fromCommand", 
                   "indexPattern", "clusterString", "selectorString", "unquotedIndexString", 
                   "indexString", "metadata", "metadataOption", "deprecated_metadata", 
                   "metricsCommand", "evalCommand", "statsCommand", "aggFields", 
                   "aggField", "qualifiedName", "qualifiedNamePattern", 
                   "qualifiedNamePatterns", "identifier", "identifierPattern", 
                   "constant", "parameter", "doubleParameter", "identifierOrParameter", 
                   "limitCommand", "sortCommand", "orderExpression", "keepCommand", 
                   "dropCommand", "renameCommand", "renameClause", "dissectCommand", 
                   "grokCommand", "mvExpandCommand", "commandOptions", "commandOption", 
                   "booleanValue", "numericValue", "decimalValue", "integerValue", 
                   "string", "comparisonOperator", "explainCommand", "subqueryExpression", 
                   "showCommand", "enrichCommand", "enrichPolicyName", "enrichWithClause", 
                   "changePointCommand", "sampleCommand", "lookupCommand", 
                   "inlinestatsCommand", "joinCommand", "joinTarget", "joinCondition", 
                   "joinPredicate", "inferenceCommandOptions", "inferenceCommandOption", 
                   "inferenceCommandOptionValue", "rerankCommand", "completionCommand" ]

    EOF = Token.EOF
    COMPLETION=1
    DISSECT=2
    DROP=3
    ENRICH=4
    EVAL=5
    EXPLAIN=6
    FROM=7
    GROK=8
    KEEP=9
    LIMIT=10
    MV_EXPAND=11
    RENAME=12
    ROW=13
    SAMPLE=14
    SHOW=15
    SORT=16
    STATS=17
    WHERE=18
    JOIN_LOOKUP=19
    CHANGE_POINT=20
    DEV_INLINESTATS=21
    DEV_LOOKUP=22
    DEV_METRICS=23
    DEV_RERANK=24
    DEV_JOIN_FULL=25
    DEV_JOIN_LEFT=26
    DEV_JOIN_RIGHT=27
    UNKNOWN_CMD=28
    LINE_COMMENT=29
    MULTILINE_COMMENT=30
    WS=31
    PIPE=32
    QUOTED_STRING=33
    INTEGER_LITERAL=34
    DECIMAL_LITERAL=35
    AND=36
    ASC=37
    ASSIGN=38
    BY=39
    CAST_OP=40
    COLON=41
    COMMA=42
    DESC=43
    DOT=44
    FALSE=45
    FIRST=46
    IN=47
    IS=48
    LAST=49
    LIKE=50
    LP=51
    NOT=52
    NULL=53
    NULLS=54
    ON=55
    OR=56
    PARAM=57
    RLIKE=58
    RP=59
    TRUE=60
    WITH=61
    EQ=62
    CIEQ=63
    NEQ=64
    LT=65
    LTE=66
    GT=67
    GTE=68
    PLUS=69
    MINUS=70
    ASTERISK=71
    SLASH=72
    PERCENT=73
    LEFT_BRACES=74
    RIGHT_BRACES=75
    DOUBLE_PARAMS=76
    NAMED_OR_POSITIONAL_PARAM=77
    NAMED_OR_POSITIONAL_DOUBLE_PARAMS=78
    OPENING_BRACKET=79
    CLOSING_BRACKET=80
    UNQUOTED_IDENTIFIER=81
    QUOTED_IDENTIFIER=82
    EXPR_LINE_COMMENT=83
    EXPR_MULTILINE_COMMENT=84
    EXPR_WS=85
    EXPLAIN_WS=86
    EXPLAIN_LINE_COMMENT=87
    EXPLAIN_MULTILINE_COMMENT=88
    METADATA=89
    UNQUOTED_SOURCE=90
    FROM_LINE_COMMENT=91
    FROM_MULTILINE_COMMENT=92
    FROM_WS=93
    ID_PATTERN=94
    PROJECT_LINE_COMMENT=95
    PROJECT_MULTILINE_COMMENT=96
    PROJECT_WS=97
    AS=98
    RENAME_LINE_COMMENT=99
    RENAME_MULTILINE_COMMENT=100
    RENAME_WS=101
    ENRICH_POLICY_NAME=102
    ENRICH_LINE_COMMENT=103
    ENRICH_MULTILINE_COMMENT=104
    ENRICH_WS=105
    ENRICH_FIELD_LINE_COMMENT=106
    ENRICH_FIELD_MULTILINE_COMMENT=107
    ENRICH_FIELD_WS=108
    MVEXPAND_LINE_COMMENT=109
    MVEXPAND_MULTILINE_COMMENT=110
    MVEXPAND_WS=111
    INFO=112
    SHOW_LINE_COMMENT=113
    SHOW_MULTILINE_COMMENT=114
    SHOW_WS=115
    SETTING=116
    SETTING_LINE_COMMENT=117
    SETTTING_MULTILINE_COMMENT=118
    SETTING_WS=119
    LOOKUP_LINE_COMMENT=120
    LOOKUP_MULTILINE_COMMENT=121
    LOOKUP_WS=122
    LOOKUP_FIELD_LINE_COMMENT=123
    LOOKUP_FIELD_MULTILINE_COMMENT=124
    LOOKUP_FIELD_WS=125
    JOIN=126
    USING=127
    JOIN_LINE_COMMENT=128
    JOIN_MULTILINE_COMMENT=129
    JOIN_WS=130
    METRICS_LINE_COMMENT=131
    METRICS_MULTILINE_COMMENT=132
    METRICS_WS=133
    CLOSING_METRICS_LINE_COMMENT=134
    CLOSING_METRICS_MULTILINE_COMMENT=135
    CLOSING_METRICS_WS=136
    CHANGE_POINT_LINE_COMMENT=137
    CHANGE_POINT_MULTILINE_COMMENT=138
    CHANGE_POINT_WS=139

    def __init__(self, input:TokenStream, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.13.1")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None




    class SingleStatementContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def query(self):
            return self.getTypedRuleContext(EsqlBaseParser.QueryContext,0)


        def EOF(self):
            return self.getToken(EsqlBaseParser.EOF, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_singleStatement

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSingleStatement" ):
                listener.enterSingleStatement(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSingleStatement" ):
                listener.exitSingleStatement(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSingleStatement" ):
                return visitor.visitSingleStatement(self)
            else:
                return visitor.visitChildren(self)




    def singleStatement(self):

        localctx = EsqlBaseParser.SingleStatementContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_singleStatement)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 162
            self.query(0)
            self.state = 163
            self.match(EsqlBaseParser.EOF)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class QueryContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_query

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)


    class CompositeQueryContext(QueryContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.QueryContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def query(self):
            return self.getTypedRuleContext(EsqlBaseParser.QueryContext,0)

        def PIPE(self):
            return self.getToken(EsqlBaseParser.PIPE, 0)
        def processingCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.ProcessingCommandContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterCompositeQuery" ):
                listener.enterCompositeQuery(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitCompositeQuery" ):
                listener.exitCompositeQuery(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCompositeQuery" ):
                return visitor.visitCompositeQuery(self)
            else:
                return visitor.visitChildren(self)


    class SingleCommandQueryContext(QueryContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.QueryContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def sourceCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.SourceCommandContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSingleCommandQuery" ):
                listener.enterSingleCommandQuery(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSingleCommandQuery" ):
                listener.exitSingleCommandQuery(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSingleCommandQuery" ):
                return visitor.visitSingleCommandQuery(self)
            else:
                return visitor.visitChildren(self)



    def query(self, _p:int=0):
        _parentctx = self._ctx
        _parentState = self.state
        localctx = EsqlBaseParser.QueryContext(self, self._ctx, _parentState)
        _prevctx = localctx
        _startState = 2
        self.enterRecursionRule(localctx, 2, self.RULE_query, _p)
        try:
            self.enterOuterAlt(localctx, 1)
            localctx = EsqlBaseParser.SingleCommandQueryContext(self, localctx)
            self._ctx = localctx
            _prevctx = localctx

            self.state = 166
            self.sourceCommand()
            self._ctx.stop = self._input.LT(-1)
            self.state = 173
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,0,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    localctx = EsqlBaseParser.CompositeQueryContext(self, EsqlBaseParser.QueryContext(self, _parentctx, _parentState))
                    self.pushNewRecursionContext(localctx, _startState, self.RULE_query)
                    self.state = 168
                    if not self.precpred(self._ctx, 1):
                        from antlr4.error.Errors import FailedPredicateException
                        raise FailedPredicateException(self, "self.precpred(self._ctx, 1)")
                    self.state = 169
                    self.match(EsqlBaseParser.PIPE)
                    self.state = 170
                    self.processingCommand() 
                self.state = 175
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,0,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.unrollRecursionContexts(_parentctx)
        return localctx


    class SourceCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def explainCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.ExplainCommandContext,0)


        def fromCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.FromCommandContext,0)


        def rowCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.RowCommandContext,0)


        def showCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.ShowCommandContext,0)


        def metricsCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.MetricsCommandContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_sourceCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSourceCommand" ):
                listener.enterSourceCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSourceCommand" ):
                listener.exitSourceCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSourceCommand" ):
                return visitor.visitSourceCommand(self)
            else:
                return visitor.visitChildren(self)




    def sourceCommand(self):

        localctx = EsqlBaseParser.SourceCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 4, self.RULE_sourceCommand)
        try:
            self.state = 182
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,1,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 176
                self.explainCommand()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 177
                self.fromCommand()
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 178
                self.rowCommand()
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 179
                self.showCommand()
                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 180
                if not self.isDevVersion():
                    from antlr4.error.Errors import FailedPredicateException
                    raise FailedPredicateException(self, "self.isDevVersion()")
                self.state = 181
                self.metricsCommand()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ProcessingCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def evalCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.EvalCommandContext,0)


        def whereCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.WhereCommandContext,0)


        def keepCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.KeepCommandContext,0)


        def limitCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.LimitCommandContext,0)


        def statsCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.StatsCommandContext,0)


        def sortCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.SortCommandContext,0)


        def dropCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.DropCommandContext,0)


        def renameCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.RenameCommandContext,0)


        def dissectCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.DissectCommandContext,0)


        def grokCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.GrokCommandContext,0)


        def enrichCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.EnrichCommandContext,0)


        def mvExpandCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.MvExpandCommandContext,0)


        def joinCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.JoinCommandContext,0)


        def changePointCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.ChangePointCommandContext,0)


        def completionCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.CompletionCommandContext,0)


        def sampleCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.SampleCommandContext,0)


        def inlinestatsCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.InlinestatsCommandContext,0)


        def lookupCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.LookupCommandContext,0)


        def rerankCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.RerankCommandContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_processingCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterProcessingCommand" ):
                listener.enterProcessingCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitProcessingCommand" ):
                listener.exitProcessingCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitProcessingCommand" ):
                return visitor.visitProcessingCommand(self)
            else:
                return visitor.visitChildren(self)




    def processingCommand(self):

        localctx = EsqlBaseParser.ProcessingCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 6, self.RULE_processingCommand)
        try:
            self.state = 206
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,2,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 184
                self.evalCommand()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 185
                self.whereCommand()
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 186
                self.keepCommand()
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 187
                self.limitCommand()
                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 188
                self.statsCommand()
                pass

            elif la_ == 6:
                self.enterOuterAlt(localctx, 6)
                self.state = 189
                self.sortCommand()
                pass

            elif la_ == 7:
                self.enterOuterAlt(localctx, 7)
                self.state = 190
                self.dropCommand()
                pass

            elif la_ == 8:
                self.enterOuterAlt(localctx, 8)
                self.state = 191
                self.renameCommand()
                pass

            elif la_ == 9:
                self.enterOuterAlt(localctx, 9)
                self.state = 192
                self.dissectCommand()
                pass

            elif la_ == 10:
                self.enterOuterAlt(localctx, 10)
                self.state = 193
                self.grokCommand()
                pass

            elif la_ == 11:
                self.enterOuterAlt(localctx, 11)
                self.state = 194
                self.enrichCommand()
                pass

            elif la_ == 12:
                self.enterOuterAlt(localctx, 12)
                self.state = 195
                self.mvExpandCommand()
                pass

            elif la_ == 13:
                self.enterOuterAlt(localctx, 13)
                self.state = 196
                self.joinCommand()
                pass

            elif la_ == 14:
                self.enterOuterAlt(localctx, 14)
                self.state = 197
                self.changePointCommand()
                pass

            elif la_ == 15:
                self.enterOuterAlt(localctx, 15)
                self.state = 198
                self.completionCommand()
                pass

            elif la_ == 16:
                self.enterOuterAlt(localctx, 16)
                self.state = 199
                self.sampleCommand()
                pass

            elif la_ == 17:
                self.enterOuterAlt(localctx, 17)
                self.state = 200
                if not self.isDevVersion():
                    from antlr4.error.Errors import FailedPredicateException
                    raise FailedPredicateException(self, "self.isDevVersion()")
                self.state = 201
                self.inlinestatsCommand()
                pass

            elif la_ == 18:
                self.enterOuterAlt(localctx, 18)
                self.state = 202
                if not self.isDevVersion():
                    from antlr4.error.Errors import FailedPredicateException
                    raise FailedPredicateException(self, "self.isDevVersion()")
                self.state = 203
                self.lookupCommand()
                pass

            elif la_ == 19:
                self.enterOuterAlt(localctx, 19)
                self.state = 204
                if not self.isDevVersion():
                    from antlr4.error.Errors import FailedPredicateException
                    raise FailedPredicateException(self, "self.isDevVersion()")
                self.state = 205
                self.rerankCommand()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class WhereCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def WHERE(self):
            return self.getToken(EsqlBaseParser.WHERE, 0)

        def booleanExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.BooleanExpressionContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_whereCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterWhereCommand" ):
                listener.enterWhereCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitWhereCommand" ):
                listener.exitWhereCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitWhereCommand" ):
                return visitor.visitWhereCommand(self)
            else:
                return visitor.visitChildren(self)




    def whereCommand(self):

        localctx = EsqlBaseParser.WhereCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 8, self.RULE_whereCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 208
            self.match(EsqlBaseParser.WHERE)
            self.state = 209
            self.booleanExpression(0)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class BooleanExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_booleanExpression

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)


    class MatchExpressionContext(BooleanExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.BooleanExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def matchBooleanExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.MatchBooleanExpressionContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterMatchExpression" ):
                listener.enterMatchExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitMatchExpression" ):
                listener.exitMatchExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitMatchExpression" ):
                return visitor.visitMatchExpression(self)
            else:
                return visitor.visitChildren(self)


    class LogicalNotContext(BooleanExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.BooleanExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def NOT(self):
            return self.getToken(EsqlBaseParser.NOT, 0)
        def booleanExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.BooleanExpressionContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterLogicalNot" ):
                listener.enterLogicalNot(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitLogicalNot" ):
                listener.exitLogicalNot(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitLogicalNot" ):
                return visitor.visitLogicalNot(self)
            else:
                return visitor.visitChildren(self)


    class BooleanDefaultContext(BooleanExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.BooleanExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def valueExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.ValueExpressionContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterBooleanDefault" ):
                listener.enterBooleanDefault(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitBooleanDefault" ):
                listener.exitBooleanDefault(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitBooleanDefault" ):
                return visitor.visitBooleanDefault(self)
            else:
                return visitor.visitChildren(self)


    class IsNullContext(BooleanExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.BooleanExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def valueExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.ValueExpressionContext,0)

        def IS(self):
            return self.getToken(EsqlBaseParser.IS, 0)
        def NULL(self):
            return self.getToken(EsqlBaseParser.NULL, 0)
        def NOT(self):
            return self.getToken(EsqlBaseParser.NOT, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIsNull" ):
                listener.enterIsNull(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIsNull" ):
                listener.exitIsNull(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIsNull" ):
                return visitor.visitIsNull(self)
            else:
                return visitor.visitChildren(self)


    class RegexExpressionContext(BooleanExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.BooleanExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def regexBooleanExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.RegexBooleanExpressionContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRegexExpression" ):
                listener.enterRegexExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRegexExpression" ):
                listener.exitRegexExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitRegexExpression" ):
                return visitor.visitRegexExpression(self)
            else:
                return visitor.visitChildren(self)


    class LogicalInContext(BooleanExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.BooleanExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def valueExpression(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.ValueExpressionContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.ValueExpressionContext,i)

        def IN(self):
            return self.getToken(EsqlBaseParser.IN, 0)
        def LP(self):
            return self.getToken(EsqlBaseParser.LP, 0)
        def RP(self):
            return self.getToken(EsqlBaseParser.RP, 0)
        def NOT(self):
            return self.getToken(EsqlBaseParser.NOT, 0)
        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterLogicalIn" ):
                listener.enterLogicalIn(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitLogicalIn" ):
                listener.exitLogicalIn(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitLogicalIn" ):
                return visitor.visitLogicalIn(self)
            else:
                return visitor.visitChildren(self)


    class LogicalBinaryContext(BooleanExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.BooleanExpressionContext
            super().__init__(parser)
            self.left = None # BooleanExpressionContext
            self.operator = None # Token
            self.right = None # BooleanExpressionContext
            self.copyFrom(ctx)

        def booleanExpression(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.BooleanExpressionContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.BooleanExpressionContext,i)

        def AND(self):
            return self.getToken(EsqlBaseParser.AND, 0)
        def OR(self):
            return self.getToken(EsqlBaseParser.OR, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterLogicalBinary" ):
                listener.enterLogicalBinary(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitLogicalBinary" ):
                listener.exitLogicalBinary(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitLogicalBinary" ):
                return visitor.visitLogicalBinary(self)
            else:
                return visitor.visitChildren(self)



    def booleanExpression(self, _p:int=0):
        _parentctx = self._ctx
        _parentState = self.state
        localctx = EsqlBaseParser.BooleanExpressionContext(self, self._ctx, _parentState)
        _prevctx = localctx
        _startState = 10
        self.enterRecursionRule(localctx, 10, self.RULE_booleanExpression, _p)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 240
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,6,self._ctx)
            if la_ == 1:
                localctx = EsqlBaseParser.LogicalNotContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx

                self.state = 212
                self.match(EsqlBaseParser.NOT)
                self.state = 213
                self.booleanExpression(8)
                pass

            elif la_ == 2:
                localctx = EsqlBaseParser.BooleanDefaultContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 214
                self.valueExpression()
                pass

            elif la_ == 3:
                localctx = EsqlBaseParser.RegexExpressionContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 215
                self.regexBooleanExpression()
                pass

            elif la_ == 4:
                localctx = EsqlBaseParser.LogicalInContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 216
                self.valueExpression()
                self.state = 218
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==52:
                    self.state = 217
                    self.match(EsqlBaseParser.NOT)


                self.state = 220
                self.match(EsqlBaseParser.IN)
                self.state = 221
                self.match(EsqlBaseParser.LP)
                self.state = 222
                self.valueExpression()
                self.state = 227
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==42:
                    self.state = 223
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 224
                    self.valueExpression()
                    self.state = 229
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 230
                self.match(EsqlBaseParser.RP)
                pass

            elif la_ == 5:
                localctx = EsqlBaseParser.IsNullContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 232
                self.valueExpression()
                self.state = 233
                self.match(EsqlBaseParser.IS)
                self.state = 235
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==52:
                    self.state = 234
                    self.match(EsqlBaseParser.NOT)


                self.state = 237
                self.match(EsqlBaseParser.NULL)
                pass

            elif la_ == 6:
                localctx = EsqlBaseParser.MatchExpressionContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 239
                self.matchBooleanExpression()
                pass


            self._ctx.stop = self._input.LT(-1)
            self.state = 250
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,8,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    self.state = 248
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,7,self._ctx)
                    if la_ == 1:
                        localctx = EsqlBaseParser.LogicalBinaryContext(self, EsqlBaseParser.BooleanExpressionContext(self, _parentctx, _parentState))
                        localctx.left = _prevctx
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_booleanExpression)
                        self.state = 242
                        if not self.precpred(self._ctx, 5):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 5)")
                        self.state = 243
                        localctx.operator = self.match(EsqlBaseParser.AND)
                        self.state = 244
                        localctx.right = self.booleanExpression(6)
                        pass

                    elif la_ == 2:
                        localctx = EsqlBaseParser.LogicalBinaryContext(self, EsqlBaseParser.BooleanExpressionContext(self, _parentctx, _parentState))
                        localctx.left = _prevctx
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_booleanExpression)
                        self.state = 245
                        if not self.precpred(self._ctx, 4):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 4)")
                        self.state = 246
                        localctx.operator = self.match(EsqlBaseParser.OR)
                        self.state = 247
                        localctx.right = self.booleanExpression(5)
                        pass

             
                self.state = 252
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,8,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.unrollRecursionContexts(_parentctx)
        return localctx


    class RegexBooleanExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_regexBooleanExpression

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class LikeExpressionContext(RegexBooleanExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.RegexBooleanExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def valueExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.ValueExpressionContext,0)

        def LIKE(self):
            return self.getToken(EsqlBaseParser.LIKE, 0)
        def string(self):
            return self.getTypedRuleContext(EsqlBaseParser.StringContext,0)

        def NOT(self):
            return self.getToken(EsqlBaseParser.NOT, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterLikeExpression" ):
                listener.enterLikeExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitLikeExpression" ):
                listener.exitLikeExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitLikeExpression" ):
                return visitor.visitLikeExpression(self)
            else:
                return visitor.visitChildren(self)


    class LikeListExpressionContext(RegexBooleanExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.RegexBooleanExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def valueExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.ValueExpressionContext,0)

        def LIKE(self):
            return self.getToken(EsqlBaseParser.LIKE, 0)
        def LP(self):
            return self.getToken(EsqlBaseParser.LP, 0)
        def string(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.StringContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.StringContext,i)

        def RP(self):
            return self.getToken(EsqlBaseParser.RP, 0)
        def NOT(self):
            return self.getToken(EsqlBaseParser.NOT, 0)
        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterLikeListExpression" ):
                listener.enterLikeListExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitLikeListExpression" ):
                listener.exitLikeListExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitLikeListExpression" ):
                return visitor.visitLikeListExpression(self)
            else:
                return visitor.visitChildren(self)


    class RlikeExpressionContext(RegexBooleanExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.RegexBooleanExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def valueExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.ValueExpressionContext,0)

        def RLIKE(self):
            return self.getToken(EsqlBaseParser.RLIKE, 0)
        def string(self):
            return self.getTypedRuleContext(EsqlBaseParser.StringContext,0)

        def NOT(self):
            return self.getToken(EsqlBaseParser.NOT, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRlikeExpression" ):
                listener.enterRlikeExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRlikeExpression" ):
                listener.exitRlikeExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitRlikeExpression" ):
                return visitor.visitRlikeExpression(self)
            else:
                return visitor.visitChildren(self)



    def regexBooleanExpression(self):

        localctx = EsqlBaseParser.RegexBooleanExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 12, self.RULE_regexBooleanExpression)
        self._la = 0 # Token type
        try:
            self.state = 283
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,13,self._ctx)
            if la_ == 1:
                localctx = EsqlBaseParser.LikeExpressionContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 253
                self.valueExpression()
                self.state = 255
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==52:
                    self.state = 254
                    self.match(EsqlBaseParser.NOT)


                self.state = 257
                self.match(EsqlBaseParser.LIKE)
                self.state = 258
                self.string()
                pass

            elif la_ == 2:
                localctx = EsqlBaseParser.RlikeExpressionContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 260
                self.valueExpression()
                self.state = 262
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==52:
                    self.state = 261
                    self.match(EsqlBaseParser.NOT)


                self.state = 264
                self.match(EsqlBaseParser.RLIKE)
                self.state = 265
                self.string()
                pass

            elif la_ == 3:
                localctx = EsqlBaseParser.LikeListExpressionContext(self, localctx)
                self.enterOuterAlt(localctx, 3)
                self.state = 267
                self.valueExpression()
                self.state = 269
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==52:
                    self.state = 268
                    self.match(EsqlBaseParser.NOT)


                self.state = 271
                self.match(EsqlBaseParser.LIKE)
                self.state = 272
                self.match(EsqlBaseParser.LP)
                self.state = 273
                self.string()
                self.state = 278
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==42:
                    self.state = 274
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 275
                    self.string()
                    self.state = 280
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 281
                self.match(EsqlBaseParser.RP)
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class MatchBooleanExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.fieldExp = None # QualifiedNameContext
            self.fieldType = None # DataTypeContext
            self.matchQuery = None # ConstantContext

        def COLON(self):
            return self.getToken(EsqlBaseParser.COLON, 0)

        def qualifiedName(self):
            return self.getTypedRuleContext(EsqlBaseParser.QualifiedNameContext,0)


        def constant(self):
            return self.getTypedRuleContext(EsqlBaseParser.ConstantContext,0)


        def CAST_OP(self):
            return self.getToken(EsqlBaseParser.CAST_OP, 0)

        def dataType(self):
            return self.getTypedRuleContext(EsqlBaseParser.DataTypeContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_matchBooleanExpression

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterMatchBooleanExpression" ):
                listener.enterMatchBooleanExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitMatchBooleanExpression" ):
                listener.exitMatchBooleanExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitMatchBooleanExpression" ):
                return visitor.visitMatchBooleanExpression(self)
            else:
                return visitor.visitChildren(self)




    def matchBooleanExpression(self):

        localctx = EsqlBaseParser.MatchBooleanExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 14, self.RULE_matchBooleanExpression)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 285
            localctx.fieldExp = self.qualifiedName()
            self.state = 288
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==40:
                self.state = 286
                self.match(EsqlBaseParser.CAST_OP)
                self.state = 287
                localctx.fieldType = self.dataType()


            self.state = 290
            self.match(EsqlBaseParser.COLON)
            self.state = 291
            localctx.matchQuery = self.constant()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ValueExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_valueExpression

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class ValueExpressionDefaultContext(ValueExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ValueExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def operatorExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.OperatorExpressionContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterValueExpressionDefault" ):
                listener.enterValueExpressionDefault(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitValueExpressionDefault" ):
                listener.exitValueExpressionDefault(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitValueExpressionDefault" ):
                return visitor.visitValueExpressionDefault(self)
            else:
                return visitor.visitChildren(self)


    class ComparisonContext(ValueExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ValueExpressionContext
            super().__init__(parser)
            self.left = None # OperatorExpressionContext
            self.right = None # OperatorExpressionContext
            self.copyFrom(ctx)

        def comparisonOperator(self):
            return self.getTypedRuleContext(EsqlBaseParser.ComparisonOperatorContext,0)

        def operatorExpression(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.OperatorExpressionContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.OperatorExpressionContext,i)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterComparison" ):
                listener.enterComparison(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitComparison" ):
                listener.exitComparison(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitComparison" ):
                return visitor.visitComparison(self)
            else:
                return visitor.visitChildren(self)



    def valueExpression(self):

        localctx = EsqlBaseParser.ValueExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 16, self.RULE_valueExpression)
        try:
            self.state = 298
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,15,self._ctx)
            if la_ == 1:
                localctx = EsqlBaseParser.ValueExpressionDefaultContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 293
                self.operatorExpression(0)
                pass

            elif la_ == 2:
                localctx = EsqlBaseParser.ComparisonContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 294
                localctx.left = self.operatorExpression(0)
                self.state = 295
                self.comparisonOperator()
                self.state = 296
                localctx.right = self.operatorExpression(0)
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class OperatorExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_operatorExpression

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)


    class OperatorExpressionDefaultContext(OperatorExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.OperatorExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def primaryExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.PrimaryExpressionContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterOperatorExpressionDefault" ):
                listener.enterOperatorExpressionDefault(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitOperatorExpressionDefault" ):
                listener.exitOperatorExpressionDefault(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitOperatorExpressionDefault" ):
                return visitor.visitOperatorExpressionDefault(self)
            else:
                return visitor.visitChildren(self)


    class ArithmeticBinaryContext(OperatorExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.OperatorExpressionContext
            super().__init__(parser)
            self.left = None # OperatorExpressionContext
            self.operator = None # Token
            self.right = None # OperatorExpressionContext
            self.copyFrom(ctx)

        def operatorExpression(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.OperatorExpressionContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.OperatorExpressionContext,i)

        def ASTERISK(self):
            return self.getToken(EsqlBaseParser.ASTERISK, 0)
        def SLASH(self):
            return self.getToken(EsqlBaseParser.SLASH, 0)
        def PERCENT(self):
            return self.getToken(EsqlBaseParser.PERCENT, 0)
        def PLUS(self):
            return self.getToken(EsqlBaseParser.PLUS, 0)
        def MINUS(self):
            return self.getToken(EsqlBaseParser.MINUS, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterArithmeticBinary" ):
                listener.enterArithmeticBinary(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitArithmeticBinary" ):
                listener.exitArithmeticBinary(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitArithmeticBinary" ):
                return visitor.visitArithmeticBinary(self)
            else:
                return visitor.visitChildren(self)


    class ArithmeticUnaryContext(OperatorExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.OperatorExpressionContext
            super().__init__(parser)
            self.operator = None # Token
            self.copyFrom(ctx)

        def operatorExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.OperatorExpressionContext,0)

        def MINUS(self):
            return self.getToken(EsqlBaseParser.MINUS, 0)
        def PLUS(self):
            return self.getToken(EsqlBaseParser.PLUS, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterArithmeticUnary" ):
                listener.enterArithmeticUnary(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitArithmeticUnary" ):
                listener.exitArithmeticUnary(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitArithmeticUnary" ):
                return visitor.visitArithmeticUnary(self)
            else:
                return visitor.visitChildren(self)



    def operatorExpression(self, _p:int=0):
        _parentctx = self._ctx
        _parentState = self.state
        localctx = EsqlBaseParser.OperatorExpressionContext(self, self._ctx, _parentState)
        _prevctx = localctx
        _startState = 18
        self.enterRecursionRule(localctx, 18, self.RULE_operatorExpression, _p)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 304
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,16,self._ctx)
            if la_ == 1:
                localctx = EsqlBaseParser.OperatorExpressionDefaultContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx

                self.state = 301
                self.primaryExpression(0)
                pass

            elif la_ == 2:
                localctx = EsqlBaseParser.ArithmeticUnaryContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 302
                localctx.operator = self._input.LT(1)
                _la = self._input.LA(1)
                if not(_la==69 or _la==70):
                    localctx.operator = self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 303
                self.operatorExpression(3)
                pass


            self._ctx.stop = self._input.LT(-1)
            self.state = 314
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,18,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    self.state = 312
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,17,self._ctx)
                    if la_ == 1:
                        localctx = EsqlBaseParser.ArithmeticBinaryContext(self, EsqlBaseParser.OperatorExpressionContext(self, _parentctx, _parentState))
                        localctx.left = _prevctx
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_operatorExpression)
                        self.state = 306
                        if not self.precpred(self._ctx, 2):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 2)")
                        self.state = 307
                        localctx.operator = self._input.LT(1)
                        _la = self._input.LA(1)
                        if not(((((_la - 71)) & ~0x3f) == 0 and ((1 << (_la - 71)) & 7) != 0)):
                            localctx.operator = self._errHandler.recoverInline(self)
                        else:
                            self._errHandler.reportMatch(self)
                            self.consume()
                        self.state = 308
                        localctx.right = self.operatorExpression(3)
                        pass

                    elif la_ == 2:
                        localctx = EsqlBaseParser.ArithmeticBinaryContext(self, EsqlBaseParser.OperatorExpressionContext(self, _parentctx, _parentState))
                        localctx.left = _prevctx
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_operatorExpression)
                        self.state = 309
                        if not self.precpred(self._ctx, 1):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 1)")
                        self.state = 310
                        localctx.operator = self._input.LT(1)
                        _la = self._input.LA(1)
                        if not(_la==69 or _la==70):
                            localctx.operator = self._errHandler.recoverInline(self)
                        else:
                            self._errHandler.reportMatch(self)
                            self.consume()
                        self.state = 311
                        localctx.right = self.operatorExpression(2)
                        pass

             
                self.state = 316
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,18,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.unrollRecursionContexts(_parentctx)
        return localctx


    class PrimaryExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_primaryExpression

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)


    class DereferenceContext(PrimaryExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.PrimaryExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def qualifiedName(self):
            return self.getTypedRuleContext(EsqlBaseParser.QualifiedNameContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterDereference" ):
                listener.enterDereference(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitDereference" ):
                listener.exitDereference(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitDereference" ):
                return visitor.visitDereference(self)
            else:
                return visitor.visitChildren(self)


    class InlineCastContext(PrimaryExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.PrimaryExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def primaryExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.PrimaryExpressionContext,0)

        def CAST_OP(self):
            return self.getToken(EsqlBaseParser.CAST_OP, 0)
        def dataType(self):
            return self.getTypedRuleContext(EsqlBaseParser.DataTypeContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterInlineCast" ):
                listener.enterInlineCast(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitInlineCast" ):
                listener.exitInlineCast(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitInlineCast" ):
                return visitor.visitInlineCast(self)
            else:
                return visitor.visitChildren(self)


    class ConstantDefaultContext(PrimaryExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.PrimaryExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def constant(self):
            return self.getTypedRuleContext(EsqlBaseParser.ConstantContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterConstantDefault" ):
                listener.enterConstantDefault(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitConstantDefault" ):
                listener.exitConstantDefault(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitConstantDefault" ):
                return visitor.visitConstantDefault(self)
            else:
                return visitor.visitChildren(self)


    class ParenthesizedExpressionContext(PrimaryExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.PrimaryExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def LP(self):
            return self.getToken(EsqlBaseParser.LP, 0)
        def booleanExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.BooleanExpressionContext,0)

        def RP(self):
            return self.getToken(EsqlBaseParser.RP, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterParenthesizedExpression" ):
                listener.enterParenthesizedExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitParenthesizedExpression" ):
                listener.exitParenthesizedExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitParenthesizedExpression" ):
                return visitor.visitParenthesizedExpression(self)
            else:
                return visitor.visitChildren(self)


    class FunctionContext(PrimaryExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.PrimaryExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def functionExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.FunctionExpressionContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunction" ):
                listener.enterFunction(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunction" ):
                listener.exitFunction(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunction" ):
                return visitor.visitFunction(self)
            else:
                return visitor.visitChildren(self)



    def primaryExpression(self, _p:int=0):
        _parentctx = self._ctx
        _parentState = self.state
        localctx = EsqlBaseParser.PrimaryExpressionContext(self, self._ctx, _parentState)
        _prevctx = localctx
        _startState = 20
        self.enterRecursionRule(localctx, 20, self.RULE_primaryExpression, _p)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 325
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,19,self._ctx)
            if la_ == 1:
                localctx = EsqlBaseParser.ConstantDefaultContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx

                self.state = 318
                self.constant()
                pass

            elif la_ == 2:
                localctx = EsqlBaseParser.DereferenceContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 319
                self.qualifiedName()
                pass

            elif la_ == 3:
                localctx = EsqlBaseParser.FunctionContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 320
                self.functionExpression()
                pass

            elif la_ == 4:
                localctx = EsqlBaseParser.ParenthesizedExpressionContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 321
                self.match(EsqlBaseParser.LP)
                self.state = 322
                self.booleanExpression(0)
                self.state = 323
                self.match(EsqlBaseParser.RP)
                pass


            self._ctx.stop = self._input.LT(-1)
            self.state = 332
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,20,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    localctx = EsqlBaseParser.InlineCastContext(self, EsqlBaseParser.PrimaryExpressionContext(self, _parentctx, _parentState))
                    self.pushNewRecursionContext(localctx, _startState, self.RULE_primaryExpression)
                    self.state = 327
                    if not self.precpred(self._ctx, 1):
                        from antlr4.error.Errors import FailedPredicateException
                        raise FailedPredicateException(self, "self.precpred(self._ctx, 1)")
                    self.state = 328
                    self.match(EsqlBaseParser.CAST_OP)
                    self.state = 329
                    self.dataType() 
                self.state = 334
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,20,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.unrollRecursionContexts(_parentctx)
        return localctx


    class FunctionExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def functionName(self):
            return self.getTypedRuleContext(EsqlBaseParser.FunctionNameContext,0)


        def LP(self):
            return self.getToken(EsqlBaseParser.LP, 0)

        def RP(self):
            return self.getToken(EsqlBaseParser.RP, 0)

        def ASTERISK(self):
            return self.getToken(EsqlBaseParser.ASTERISK, 0)

        def booleanExpression(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.BooleanExpressionContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.BooleanExpressionContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def mapExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.MapExpressionContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_functionExpression

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunctionExpression" ):
                listener.enterFunctionExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunctionExpression" ):
                listener.exitFunctionExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunctionExpression" ):
                return visitor.visitFunctionExpression(self)
            else:
                return visitor.visitChildren(self)




    def functionExpression(self):

        localctx = EsqlBaseParser.FunctionExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 22, self.RULE_functionExpression)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 335
            self.functionName()
            self.state = 336
            self.match(EsqlBaseParser.LP)
            self.state = 350
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [71]:
                self.state = 337
                self.match(EsqlBaseParser.ASTERISK)
                pass
            elif token in [33, 34, 35, 45, 51, 52, 53, 57, 60, 69, 70, 76, 77, 78, 79, 81, 82]:
                self.state = 338
                self.booleanExpression(0)
                self.state = 343
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,21,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 339
                        self.match(EsqlBaseParser.COMMA)
                        self.state = 340
                        self.booleanExpression(0) 
                    self.state = 345
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,21,self._ctx)

                self.state = 348
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==42:
                    self.state = 346
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 347
                    self.mapExpression()


                pass
            elif token in [59]:
                pass
            else:
                pass
            self.state = 352
            self.match(EsqlBaseParser.RP)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class FunctionNameContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifierOrParameter(self):
            return self.getTypedRuleContext(EsqlBaseParser.IdentifierOrParameterContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_functionName

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunctionName" ):
                listener.enterFunctionName(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunctionName" ):
                listener.exitFunctionName(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunctionName" ):
                return visitor.visitFunctionName(self)
            else:
                return visitor.visitChildren(self)




    def functionName(self):

        localctx = EsqlBaseParser.FunctionNameContext(self, self._ctx, self.state)
        self.enterRule(localctx, 24, self.RULE_functionName)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 354
            self.identifierOrParameter()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class MapExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def LEFT_BRACES(self):
            return self.getToken(EsqlBaseParser.LEFT_BRACES, 0)

        def entryExpression(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.EntryExpressionContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.EntryExpressionContext,i)


        def RIGHT_BRACES(self):
            return self.getToken(EsqlBaseParser.RIGHT_BRACES, 0)

        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_mapExpression

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterMapExpression" ):
                listener.enterMapExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitMapExpression" ):
                listener.exitMapExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitMapExpression" ):
                return visitor.visitMapExpression(self)
            else:
                return visitor.visitChildren(self)




    def mapExpression(self):

        localctx = EsqlBaseParser.MapExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 26, self.RULE_mapExpression)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 356
            self.match(EsqlBaseParser.LEFT_BRACES)
            self.state = 357
            self.entryExpression()
            self.state = 362
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==42:
                self.state = 358
                self.match(EsqlBaseParser.COMMA)
                self.state = 359
                self.entryExpression()
                self.state = 364
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 365
            self.match(EsqlBaseParser.RIGHT_BRACES)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class EntryExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.key = None # StringContext
            self.value = None # ConstantContext

        def COLON(self):
            return self.getToken(EsqlBaseParser.COLON, 0)

        def string(self):
            return self.getTypedRuleContext(EsqlBaseParser.StringContext,0)


        def constant(self):
            return self.getTypedRuleContext(EsqlBaseParser.ConstantContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_entryExpression

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterEntryExpression" ):
                listener.enterEntryExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitEntryExpression" ):
                listener.exitEntryExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitEntryExpression" ):
                return visitor.visitEntryExpression(self)
            else:
                return visitor.visitChildren(self)




    def entryExpression(self):

        localctx = EsqlBaseParser.EntryExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 28, self.RULE_entryExpression)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 367
            localctx.key = self.string()
            self.state = 368
            self.match(EsqlBaseParser.COLON)
            self.state = 369
            localctx.value = self.constant()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class DataTypeContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_dataType

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class ToDataTypeContext(DataTypeContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.DataTypeContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def identifier(self):
            return self.getTypedRuleContext(EsqlBaseParser.IdentifierContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterToDataType" ):
                listener.enterToDataType(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitToDataType" ):
                listener.exitToDataType(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitToDataType" ):
                return visitor.visitToDataType(self)
            else:
                return visitor.visitChildren(self)



    def dataType(self):

        localctx = EsqlBaseParser.DataTypeContext(self, self._ctx, self.state)
        self.enterRule(localctx, 30, self.RULE_dataType)
        try:
            localctx = EsqlBaseParser.ToDataTypeContext(self, localctx)
            self.enterOuterAlt(localctx, 1)
            self.state = 371
            self.identifier()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class RowCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ROW(self):
            return self.getToken(EsqlBaseParser.ROW, 0)

        def fields(self):
            return self.getTypedRuleContext(EsqlBaseParser.FieldsContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_rowCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRowCommand" ):
                listener.enterRowCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRowCommand" ):
                listener.exitRowCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitRowCommand" ):
                return visitor.visitRowCommand(self)
            else:
                return visitor.visitChildren(self)




    def rowCommand(self):

        localctx = EsqlBaseParser.RowCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 32, self.RULE_rowCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 373
            self.match(EsqlBaseParser.ROW)
            self.state = 374
            self.fields()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class FieldsContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def field(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.FieldContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.FieldContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_fields

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFields" ):
                listener.enterFields(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFields" ):
                listener.exitFields(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFields" ):
                return visitor.visitFields(self)
            else:
                return visitor.visitChildren(self)




    def fields(self):

        localctx = EsqlBaseParser.FieldsContext(self, self._ctx, self.state)
        self.enterRule(localctx, 34, self.RULE_fields)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 376
            self.field()
            self.state = 381
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,25,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 377
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 378
                    self.field() 
                self.state = 383
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,25,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class FieldContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def booleanExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.BooleanExpressionContext,0)


        def qualifiedName(self):
            return self.getTypedRuleContext(EsqlBaseParser.QualifiedNameContext,0)


        def ASSIGN(self):
            return self.getToken(EsqlBaseParser.ASSIGN, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_field

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterField" ):
                listener.enterField(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitField" ):
                listener.exitField(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitField" ):
                return visitor.visitField(self)
            else:
                return visitor.visitChildren(self)




    def field(self):

        localctx = EsqlBaseParser.FieldContext(self, self._ctx, self.state)
        self.enterRule(localctx, 36, self.RULE_field)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 387
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,26,self._ctx)
            if la_ == 1:
                self.state = 384
                self.qualifiedName()
                self.state = 385
                self.match(EsqlBaseParser.ASSIGN)


            self.state = 389
            self.booleanExpression(0)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class RerankFieldsContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def rerankField(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.RerankFieldContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.RerankFieldContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_rerankFields

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRerankFields" ):
                listener.enterRerankFields(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRerankFields" ):
                listener.exitRerankFields(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitRerankFields" ):
                return visitor.visitRerankFields(self)
            else:
                return visitor.visitChildren(self)




    def rerankFields(self):

        localctx = EsqlBaseParser.RerankFieldsContext(self, self._ctx, self.state)
        self.enterRule(localctx, 38, self.RULE_rerankFields)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 391
            self.rerankField()
            self.state = 396
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,27,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 392
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 393
                    self.rerankField() 
                self.state = 398
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,27,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class RerankFieldContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def qualifiedName(self):
            return self.getTypedRuleContext(EsqlBaseParser.QualifiedNameContext,0)


        def ASSIGN(self):
            return self.getToken(EsqlBaseParser.ASSIGN, 0)

        def booleanExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.BooleanExpressionContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_rerankField

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRerankField" ):
                listener.enterRerankField(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRerankField" ):
                listener.exitRerankField(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitRerankField" ):
                return visitor.visitRerankField(self)
            else:
                return visitor.visitChildren(self)




    def rerankField(self):

        localctx = EsqlBaseParser.RerankFieldContext(self, self._ctx, self.state)
        self.enterRule(localctx, 40, self.RULE_rerankField)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 399
            self.qualifiedName()
            self.state = 402
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,28,self._ctx)
            if la_ == 1:
                self.state = 400
                self.match(EsqlBaseParser.ASSIGN)
                self.state = 401
                self.booleanExpression(0)


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class FromCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def FROM(self):
            return self.getToken(EsqlBaseParser.FROM, 0)

        def indexPattern(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.IndexPatternContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.IndexPatternContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def metadata(self):
            return self.getTypedRuleContext(EsqlBaseParser.MetadataContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_fromCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFromCommand" ):
                listener.enterFromCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFromCommand" ):
                listener.exitFromCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFromCommand" ):
                return visitor.visitFromCommand(self)
            else:
                return visitor.visitChildren(self)




    def fromCommand(self):

        localctx = EsqlBaseParser.FromCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 42, self.RULE_fromCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 404
            self.match(EsqlBaseParser.FROM)
            self.state = 405
            self.indexPattern()
            self.state = 410
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,29,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 406
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 407
                    self.indexPattern() 
                self.state = 412
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,29,self._ctx)

            self.state = 414
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,30,self._ctx)
            if la_ == 1:
                self.state = 413
                self.metadata()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IndexPatternContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def clusterString(self):
            return self.getTypedRuleContext(EsqlBaseParser.ClusterStringContext,0)


        def COLON(self):
            return self.getToken(EsqlBaseParser.COLON, 0)

        def unquotedIndexString(self):
            return self.getTypedRuleContext(EsqlBaseParser.UnquotedIndexStringContext,0)


        def CAST_OP(self):
            return self.getToken(EsqlBaseParser.CAST_OP, 0)

        def selectorString(self):
            return self.getTypedRuleContext(EsqlBaseParser.SelectorStringContext,0)


        def indexString(self):
            return self.getTypedRuleContext(EsqlBaseParser.IndexStringContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_indexPattern

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIndexPattern" ):
                listener.enterIndexPattern(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIndexPattern" ):
                listener.exitIndexPattern(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIndexPattern" ):
                return visitor.visitIndexPattern(self)
            else:
                return visitor.visitChildren(self)




    def indexPattern(self):

        localctx = EsqlBaseParser.IndexPatternContext(self, self._ctx, self.state)
        self.enterRule(localctx, 44, self.RULE_indexPattern)
        try:
            self.state = 425
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,31,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 416
                self.clusterString()
                self.state = 417
                self.match(EsqlBaseParser.COLON)
                self.state = 418
                self.unquotedIndexString()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 420
                self.unquotedIndexString()
                self.state = 421
                self.match(EsqlBaseParser.CAST_OP)
                self.state = 422
                self.selectorString()
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 424
                self.indexString()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ClusterStringContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def UNQUOTED_SOURCE(self):
            return self.getToken(EsqlBaseParser.UNQUOTED_SOURCE, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_clusterString

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterClusterString" ):
                listener.enterClusterString(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitClusterString" ):
                listener.exitClusterString(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitClusterString" ):
                return visitor.visitClusterString(self)
            else:
                return visitor.visitChildren(self)




    def clusterString(self):

        localctx = EsqlBaseParser.ClusterStringContext(self, self._ctx, self.state)
        self.enterRule(localctx, 46, self.RULE_clusterString)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 427
            self.match(EsqlBaseParser.UNQUOTED_SOURCE)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SelectorStringContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def UNQUOTED_SOURCE(self):
            return self.getToken(EsqlBaseParser.UNQUOTED_SOURCE, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_selectorString

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSelectorString" ):
                listener.enterSelectorString(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSelectorString" ):
                listener.exitSelectorString(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSelectorString" ):
                return visitor.visitSelectorString(self)
            else:
                return visitor.visitChildren(self)




    def selectorString(self):

        localctx = EsqlBaseParser.SelectorStringContext(self, self._ctx, self.state)
        self.enterRule(localctx, 48, self.RULE_selectorString)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 429
            self.match(EsqlBaseParser.UNQUOTED_SOURCE)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class UnquotedIndexStringContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def UNQUOTED_SOURCE(self):
            return self.getToken(EsqlBaseParser.UNQUOTED_SOURCE, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_unquotedIndexString

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterUnquotedIndexString" ):
                listener.enterUnquotedIndexString(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitUnquotedIndexString" ):
                listener.exitUnquotedIndexString(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitUnquotedIndexString" ):
                return visitor.visitUnquotedIndexString(self)
            else:
                return visitor.visitChildren(self)




    def unquotedIndexString(self):

        localctx = EsqlBaseParser.UnquotedIndexStringContext(self, self._ctx, self.state)
        self.enterRule(localctx, 50, self.RULE_unquotedIndexString)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 431
            self.match(EsqlBaseParser.UNQUOTED_SOURCE)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IndexStringContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def UNQUOTED_SOURCE(self):
            return self.getToken(EsqlBaseParser.UNQUOTED_SOURCE, 0)

        def QUOTED_STRING(self):
            return self.getToken(EsqlBaseParser.QUOTED_STRING, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_indexString

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIndexString" ):
                listener.enterIndexString(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIndexString" ):
                listener.exitIndexString(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIndexString" ):
                return visitor.visitIndexString(self)
            else:
                return visitor.visitChildren(self)




    def indexString(self):

        localctx = EsqlBaseParser.IndexStringContext(self, self._ctx, self.state)
        self.enterRule(localctx, 52, self.RULE_indexString)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 433
            _la = self._input.LA(1)
            if not(_la==33 or _la==90):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class MetadataContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def metadataOption(self):
            return self.getTypedRuleContext(EsqlBaseParser.MetadataOptionContext,0)


        def deprecated_metadata(self):
            return self.getTypedRuleContext(EsqlBaseParser.Deprecated_metadataContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_metadata

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterMetadata" ):
                listener.enterMetadata(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitMetadata" ):
                listener.exitMetadata(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitMetadata" ):
                return visitor.visitMetadata(self)
            else:
                return visitor.visitChildren(self)




    def metadata(self):

        localctx = EsqlBaseParser.MetadataContext(self, self._ctx, self.state)
        self.enterRule(localctx, 54, self.RULE_metadata)
        try:
            self.state = 437
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [89]:
                self.enterOuterAlt(localctx, 1)
                self.state = 435
                self.metadataOption()
                pass
            elif token in [79]:
                self.enterOuterAlt(localctx, 2)
                self.state = 436
                self.deprecated_metadata()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class MetadataOptionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def METADATA(self):
            return self.getToken(EsqlBaseParser.METADATA, 0)

        def UNQUOTED_SOURCE(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.UNQUOTED_SOURCE)
            else:
                return self.getToken(EsqlBaseParser.UNQUOTED_SOURCE, i)

        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_metadataOption

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterMetadataOption" ):
                listener.enterMetadataOption(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitMetadataOption" ):
                listener.exitMetadataOption(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitMetadataOption" ):
                return visitor.visitMetadataOption(self)
            else:
                return visitor.visitChildren(self)




    def metadataOption(self):

        localctx = EsqlBaseParser.MetadataOptionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 56, self.RULE_metadataOption)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 439
            self.match(EsqlBaseParser.METADATA)
            self.state = 440
            self.match(EsqlBaseParser.UNQUOTED_SOURCE)
            self.state = 445
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,33,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 441
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 442
                    self.match(EsqlBaseParser.UNQUOTED_SOURCE) 
                self.state = 447
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,33,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Deprecated_metadataContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def OPENING_BRACKET(self):
            return self.getToken(EsqlBaseParser.OPENING_BRACKET, 0)

        def metadataOption(self):
            return self.getTypedRuleContext(EsqlBaseParser.MetadataOptionContext,0)


        def CLOSING_BRACKET(self):
            return self.getToken(EsqlBaseParser.CLOSING_BRACKET, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_deprecated_metadata

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterDeprecated_metadata" ):
                listener.enterDeprecated_metadata(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitDeprecated_metadata" ):
                listener.exitDeprecated_metadata(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitDeprecated_metadata" ):
                return visitor.visitDeprecated_metadata(self)
            else:
                return visitor.visitChildren(self)




    def deprecated_metadata(self):

        localctx = EsqlBaseParser.Deprecated_metadataContext(self, self._ctx, self.state)
        self.enterRule(localctx, 58, self.RULE_deprecated_metadata)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 448
            self.match(EsqlBaseParser.OPENING_BRACKET)
            self.state = 449
            self.metadataOption()
            self.state = 450
            self.match(EsqlBaseParser.CLOSING_BRACKET)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class MetricsCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.aggregates = None # AggFieldsContext
            self.grouping = None # FieldsContext

        def DEV_METRICS(self):
            return self.getToken(EsqlBaseParser.DEV_METRICS, 0)

        def indexPattern(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.IndexPatternContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.IndexPatternContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def BY(self):
            return self.getToken(EsqlBaseParser.BY, 0)

        def aggFields(self):
            return self.getTypedRuleContext(EsqlBaseParser.AggFieldsContext,0)


        def fields(self):
            return self.getTypedRuleContext(EsqlBaseParser.FieldsContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_metricsCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterMetricsCommand" ):
                listener.enterMetricsCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitMetricsCommand" ):
                listener.exitMetricsCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitMetricsCommand" ):
                return visitor.visitMetricsCommand(self)
            else:
                return visitor.visitChildren(self)




    def metricsCommand(self):

        localctx = EsqlBaseParser.MetricsCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 60, self.RULE_metricsCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 452
            self.match(EsqlBaseParser.DEV_METRICS)
            self.state = 453
            self.indexPattern()
            self.state = 458
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,34,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 454
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 455
                    self.indexPattern() 
                self.state = 460
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,34,self._ctx)

            self.state = 462
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,35,self._ctx)
            if la_ == 1:
                self.state = 461
                localctx.aggregates = self.aggFields()


            self.state = 466
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,36,self._ctx)
            if la_ == 1:
                self.state = 464
                self.match(EsqlBaseParser.BY)
                self.state = 465
                localctx.grouping = self.fields()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class EvalCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def EVAL(self):
            return self.getToken(EsqlBaseParser.EVAL, 0)

        def fields(self):
            return self.getTypedRuleContext(EsqlBaseParser.FieldsContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_evalCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterEvalCommand" ):
                listener.enterEvalCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitEvalCommand" ):
                listener.exitEvalCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitEvalCommand" ):
                return visitor.visitEvalCommand(self)
            else:
                return visitor.visitChildren(self)




    def evalCommand(self):

        localctx = EsqlBaseParser.EvalCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 62, self.RULE_evalCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 468
            self.match(EsqlBaseParser.EVAL)
            self.state = 469
            self.fields()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class StatsCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.stats = None # AggFieldsContext
            self.grouping = None # FieldsContext

        def STATS(self):
            return self.getToken(EsqlBaseParser.STATS, 0)

        def BY(self):
            return self.getToken(EsqlBaseParser.BY, 0)

        def aggFields(self):
            return self.getTypedRuleContext(EsqlBaseParser.AggFieldsContext,0)


        def fields(self):
            return self.getTypedRuleContext(EsqlBaseParser.FieldsContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_statsCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterStatsCommand" ):
                listener.enterStatsCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitStatsCommand" ):
                listener.exitStatsCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitStatsCommand" ):
                return visitor.visitStatsCommand(self)
            else:
                return visitor.visitChildren(self)




    def statsCommand(self):

        localctx = EsqlBaseParser.StatsCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 64, self.RULE_statsCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 471
            self.match(EsqlBaseParser.STATS)
            self.state = 473
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,37,self._ctx)
            if la_ == 1:
                self.state = 472
                localctx.stats = self.aggFields()


            self.state = 477
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,38,self._ctx)
            if la_ == 1:
                self.state = 475
                self.match(EsqlBaseParser.BY)
                self.state = 476
                localctx.grouping = self.fields()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class AggFieldsContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def aggField(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.AggFieldContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.AggFieldContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_aggFields

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterAggFields" ):
                listener.enterAggFields(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitAggFields" ):
                listener.exitAggFields(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitAggFields" ):
                return visitor.visitAggFields(self)
            else:
                return visitor.visitChildren(self)




    def aggFields(self):

        localctx = EsqlBaseParser.AggFieldsContext(self, self._ctx, self.state)
        self.enterRule(localctx, 66, self.RULE_aggFields)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 479
            self.aggField()
            self.state = 484
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,39,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 480
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 481
                    self.aggField() 
                self.state = 486
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,39,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class AggFieldContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def field(self):
            return self.getTypedRuleContext(EsqlBaseParser.FieldContext,0)


        def WHERE(self):
            return self.getToken(EsqlBaseParser.WHERE, 0)

        def booleanExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.BooleanExpressionContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_aggField

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterAggField" ):
                listener.enterAggField(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitAggField" ):
                listener.exitAggField(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitAggField" ):
                return visitor.visitAggField(self)
            else:
                return visitor.visitChildren(self)




    def aggField(self):

        localctx = EsqlBaseParser.AggFieldContext(self, self._ctx, self.state)
        self.enterRule(localctx, 68, self.RULE_aggField)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 487
            self.field()
            self.state = 490
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,40,self._ctx)
            if la_ == 1:
                self.state = 488
                self.match(EsqlBaseParser.WHERE)
                self.state = 489
                self.booleanExpression(0)


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class QualifiedNameContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifierOrParameter(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.IdentifierOrParameterContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.IdentifierOrParameterContext,i)


        def DOT(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.DOT)
            else:
                return self.getToken(EsqlBaseParser.DOT, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_qualifiedName

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterQualifiedName" ):
                listener.enterQualifiedName(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitQualifiedName" ):
                listener.exitQualifiedName(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitQualifiedName" ):
                return visitor.visitQualifiedName(self)
            else:
                return visitor.visitChildren(self)




    def qualifiedName(self):

        localctx = EsqlBaseParser.QualifiedNameContext(self, self._ctx, self.state)
        self.enterRule(localctx, 70, self.RULE_qualifiedName)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 492
            self.identifierOrParameter()
            self.state = 497
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,41,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 493
                    self.match(EsqlBaseParser.DOT)
                    self.state = 494
                    self.identifierOrParameter() 
                self.state = 499
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,41,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class QualifiedNamePatternContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifierPattern(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.IdentifierPatternContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.IdentifierPatternContext,i)


        def DOT(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.DOT)
            else:
                return self.getToken(EsqlBaseParser.DOT, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_qualifiedNamePattern

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterQualifiedNamePattern" ):
                listener.enterQualifiedNamePattern(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitQualifiedNamePattern" ):
                listener.exitQualifiedNamePattern(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitQualifiedNamePattern" ):
                return visitor.visitQualifiedNamePattern(self)
            else:
                return visitor.visitChildren(self)




    def qualifiedNamePattern(self):

        localctx = EsqlBaseParser.QualifiedNamePatternContext(self, self._ctx, self.state)
        self.enterRule(localctx, 72, self.RULE_qualifiedNamePattern)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 500
            self.identifierPattern()
            self.state = 505
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,42,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 501
                    self.match(EsqlBaseParser.DOT)
                    self.state = 502
                    self.identifierPattern() 
                self.state = 507
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,42,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class QualifiedNamePatternsContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def qualifiedNamePattern(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.QualifiedNamePatternContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.QualifiedNamePatternContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_qualifiedNamePatterns

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterQualifiedNamePatterns" ):
                listener.enterQualifiedNamePatterns(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitQualifiedNamePatterns" ):
                listener.exitQualifiedNamePatterns(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitQualifiedNamePatterns" ):
                return visitor.visitQualifiedNamePatterns(self)
            else:
                return visitor.visitChildren(self)




    def qualifiedNamePatterns(self):

        localctx = EsqlBaseParser.QualifiedNamePatternsContext(self, self._ctx, self.state)
        self.enterRule(localctx, 74, self.RULE_qualifiedNamePatterns)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 508
            self.qualifiedNamePattern()
            self.state = 513
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,43,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 509
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 510
                    self.qualifiedNamePattern() 
                self.state = 515
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,43,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IdentifierContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def UNQUOTED_IDENTIFIER(self):
            return self.getToken(EsqlBaseParser.UNQUOTED_IDENTIFIER, 0)

        def QUOTED_IDENTIFIER(self):
            return self.getToken(EsqlBaseParser.QUOTED_IDENTIFIER, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_identifier

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIdentifier" ):
                listener.enterIdentifier(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIdentifier" ):
                listener.exitIdentifier(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIdentifier" ):
                return visitor.visitIdentifier(self)
            else:
                return visitor.visitChildren(self)




    def identifier(self):

        localctx = EsqlBaseParser.IdentifierContext(self, self._ctx, self.state)
        self.enterRule(localctx, 76, self.RULE_identifier)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 516
            _la = self._input.LA(1)
            if not(_la==81 or _la==82):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IdentifierPatternContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ID_PATTERN(self):
            return self.getToken(EsqlBaseParser.ID_PATTERN, 0)

        def parameter(self):
            return self.getTypedRuleContext(EsqlBaseParser.ParameterContext,0)


        def doubleParameter(self):
            return self.getTypedRuleContext(EsqlBaseParser.DoubleParameterContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_identifierPattern

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIdentifierPattern" ):
                listener.enterIdentifierPattern(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIdentifierPattern" ):
                listener.exitIdentifierPattern(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIdentifierPattern" ):
                return visitor.visitIdentifierPattern(self)
            else:
                return visitor.visitChildren(self)




    def identifierPattern(self):

        localctx = EsqlBaseParser.IdentifierPatternContext(self, self._ctx, self.state)
        self.enterRule(localctx, 78, self.RULE_identifierPattern)
        try:
            self.state = 521
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [94]:
                self.enterOuterAlt(localctx, 1)
                self.state = 518
                self.match(EsqlBaseParser.ID_PATTERN)
                pass
            elif token in [57, 77]:
                self.enterOuterAlt(localctx, 2)
                self.state = 519
                self.parameter()
                pass
            elif token in [76, 78]:
                self.enterOuterAlt(localctx, 3)
                self.state = 520
                self.doubleParameter()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ConstantContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_constant

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class BooleanArrayLiteralContext(ConstantContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ConstantContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def OPENING_BRACKET(self):
            return self.getToken(EsqlBaseParser.OPENING_BRACKET, 0)
        def booleanValue(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.BooleanValueContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.BooleanValueContext,i)

        def CLOSING_BRACKET(self):
            return self.getToken(EsqlBaseParser.CLOSING_BRACKET, 0)
        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterBooleanArrayLiteral" ):
                listener.enterBooleanArrayLiteral(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitBooleanArrayLiteral" ):
                listener.exitBooleanArrayLiteral(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitBooleanArrayLiteral" ):
                return visitor.visitBooleanArrayLiteral(self)
            else:
                return visitor.visitChildren(self)


    class DecimalLiteralContext(ConstantContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ConstantContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def decimalValue(self):
            return self.getTypedRuleContext(EsqlBaseParser.DecimalValueContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterDecimalLiteral" ):
                listener.enterDecimalLiteral(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitDecimalLiteral" ):
                listener.exitDecimalLiteral(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitDecimalLiteral" ):
                return visitor.visitDecimalLiteral(self)
            else:
                return visitor.visitChildren(self)


    class NullLiteralContext(ConstantContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ConstantContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def NULL(self):
            return self.getToken(EsqlBaseParser.NULL, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterNullLiteral" ):
                listener.enterNullLiteral(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitNullLiteral" ):
                listener.exitNullLiteral(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitNullLiteral" ):
                return visitor.visitNullLiteral(self)
            else:
                return visitor.visitChildren(self)


    class QualifiedIntegerLiteralContext(ConstantContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ConstantContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def integerValue(self):
            return self.getTypedRuleContext(EsqlBaseParser.IntegerValueContext,0)

        def UNQUOTED_IDENTIFIER(self):
            return self.getToken(EsqlBaseParser.UNQUOTED_IDENTIFIER, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterQualifiedIntegerLiteral" ):
                listener.enterQualifiedIntegerLiteral(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitQualifiedIntegerLiteral" ):
                listener.exitQualifiedIntegerLiteral(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitQualifiedIntegerLiteral" ):
                return visitor.visitQualifiedIntegerLiteral(self)
            else:
                return visitor.visitChildren(self)


    class StringArrayLiteralContext(ConstantContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ConstantContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def OPENING_BRACKET(self):
            return self.getToken(EsqlBaseParser.OPENING_BRACKET, 0)
        def string(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.StringContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.StringContext,i)

        def CLOSING_BRACKET(self):
            return self.getToken(EsqlBaseParser.CLOSING_BRACKET, 0)
        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterStringArrayLiteral" ):
                listener.enterStringArrayLiteral(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitStringArrayLiteral" ):
                listener.exitStringArrayLiteral(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitStringArrayLiteral" ):
                return visitor.visitStringArrayLiteral(self)
            else:
                return visitor.visitChildren(self)


    class InputParameterContext(ConstantContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ConstantContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def parameter(self):
            return self.getTypedRuleContext(EsqlBaseParser.ParameterContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterInputParameter" ):
                listener.enterInputParameter(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitInputParameter" ):
                listener.exitInputParameter(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitInputParameter" ):
                return visitor.visitInputParameter(self)
            else:
                return visitor.visitChildren(self)


    class StringLiteralContext(ConstantContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ConstantContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def string(self):
            return self.getTypedRuleContext(EsqlBaseParser.StringContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterStringLiteral" ):
                listener.enterStringLiteral(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitStringLiteral" ):
                listener.exitStringLiteral(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitStringLiteral" ):
                return visitor.visitStringLiteral(self)
            else:
                return visitor.visitChildren(self)


    class NumericArrayLiteralContext(ConstantContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ConstantContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def OPENING_BRACKET(self):
            return self.getToken(EsqlBaseParser.OPENING_BRACKET, 0)
        def numericValue(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.NumericValueContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.NumericValueContext,i)

        def CLOSING_BRACKET(self):
            return self.getToken(EsqlBaseParser.CLOSING_BRACKET, 0)
        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterNumericArrayLiteral" ):
                listener.enterNumericArrayLiteral(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitNumericArrayLiteral" ):
                listener.exitNumericArrayLiteral(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitNumericArrayLiteral" ):
                return visitor.visitNumericArrayLiteral(self)
            else:
                return visitor.visitChildren(self)


    class IntegerLiteralContext(ConstantContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ConstantContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def integerValue(self):
            return self.getTypedRuleContext(EsqlBaseParser.IntegerValueContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIntegerLiteral" ):
                listener.enterIntegerLiteral(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIntegerLiteral" ):
                listener.exitIntegerLiteral(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIntegerLiteral" ):
                return visitor.visitIntegerLiteral(self)
            else:
                return visitor.visitChildren(self)


    class BooleanLiteralContext(ConstantContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ConstantContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def booleanValue(self):
            return self.getTypedRuleContext(EsqlBaseParser.BooleanValueContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterBooleanLiteral" ):
                listener.enterBooleanLiteral(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitBooleanLiteral" ):
                listener.exitBooleanLiteral(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitBooleanLiteral" ):
                return visitor.visitBooleanLiteral(self)
            else:
                return visitor.visitChildren(self)



    def constant(self):

        localctx = EsqlBaseParser.ConstantContext(self, self._ctx, self.state)
        self.enterRule(localctx, 80, self.RULE_constant)
        self._la = 0 # Token type
        try:
            self.state = 565
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,48,self._ctx)
            if la_ == 1:
                localctx = EsqlBaseParser.NullLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 523
                self.match(EsqlBaseParser.NULL)
                pass

            elif la_ == 2:
                localctx = EsqlBaseParser.QualifiedIntegerLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 524
                self.integerValue()
                self.state = 525
                self.match(EsqlBaseParser.UNQUOTED_IDENTIFIER)
                pass

            elif la_ == 3:
                localctx = EsqlBaseParser.DecimalLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 3)
                self.state = 527
                self.decimalValue()
                pass

            elif la_ == 4:
                localctx = EsqlBaseParser.IntegerLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 4)
                self.state = 528
                self.integerValue()
                pass

            elif la_ == 5:
                localctx = EsqlBaseParser.BooleanLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 5)
                self.state = 529
                self.booleanValue()
                pass

            elif la_ == 6:
                localctx = EsqlBaseParser.InputParameterContext(self, localctx)
                self.enterOuterAlt(localctx, 6)
                self.state = 530
                self.parameter()
                pass

            elif la_ == 7:
                localctx = EsqlBaseParser.StringLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 7)
                self.state = 531
                self.string()
                pass

            elif la_ == 8:
                localctx = EsqlBaseParser.NumericArrayLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 8)
                self.state = 532
                self.match(EsqlBaseParser.OPENING_BRACKET)
                self.state = 533
                self.numericValue()
                self.state = 538
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==42:
                    self.state = 534
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 535
                    self.numericValue()
                    self.state = 540
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 541
                self.match(EsqlBaseParser.CLOSING_BRACKET)
                pass

            elif la_ == 9:
                localctx = EsqlBaseParser.BooleanArrayLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 9)
                self.state = 543
                self.match(EsqlBaseParser.OPENING_BRACKET)
                self.state = 544
                self.booleanValue()
                self.state = 549
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==42:
                    self.state = 545
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 546
                    self.booleanValue()
                    self.state = 551
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 552
                self.match(EsqlBaseParser.CLOSING_BRACKET)
                pass

            elif la_ == 10:
                localctx = EsqlBaseParser.StringArrayLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 10)
                self.state = 554
                self.match(EsqlBaseParser.OPENING_BRACKET)
                self.state = 555
                self.string()
                self.state = 560
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==42:
                    self.state = 556
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 557
                    self.string()
                    self.state = 562
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 563
                self.match(EsqlBaseParser.CLOSING_BRACKET)
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ParameterContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_parameter

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class InputNamedOrPositionalParamContext(ParameterContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ParameterContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def NAMED_OR_POSITIONAL_PARAM(self):
            return self.getToken(EsqlBaseParser.NAMED_OR_POSITIONAL_PARAM, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterInputNamedOrPositionalParam" ):
                listener.enterInputNamedOrPositionalParam(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitInputNamedOrPositionalParam" ):
                listener.exitInputNamedOrPositionalParam(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitInputNamedOrPositionalParam" ):
                return visitor.visitInputNamedOrPositionalParam(self)
            else:
                return visitor.visitChildren(self)


    class InputParamContext(ParameterContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ParameterContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def PARAM(self):
            return self.getToken(EsqlBaseParser.PARAM, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterInputParam" ):
                listener.enterInputParam(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitInputParam" ):
                listener.exitInputParam(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitInputParam" ):
                return visitor.visitInputParam(self)
            else:
                return visitor.visitChildren(self)



    def parameter(self):

        localctx = EsqlBaseParser.ParameterContext(self, self._ctx, self.state)
        self.enterRule(localctx, 82, self.RULE_parameter)
        try:
            self.state = 569
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [57]:
                localctx = EsqlBaseParser.InputParamContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 567
                self.match(EsqlBaseParser.PARAM)
                pass
            elif token in [77]:
                localctx = EsqlBaseParser.InputNamedOrPositionalParamContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 568
                self.match(EsqlBaseParser.NAMED_OR_POSITIONAL_PARAM)
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class DoubleParameterContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_doubleParameter

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class InputDoubleParamsContext(DoubleParameterContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.DoubleParameterContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def DOUBLE_PARAMS(self):
            return self.getToken(EsqlBaseParser.DOUBLE_PARAMS, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterInputDoubleParams" ):
                listener.enterInputDoubleParams(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitInputDoubleParams" ):
                listener.exitInputDoubleParams(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitInputDoubleParams" ):
                return visitor.visitInputDoubleParams(self)
            else:
                return visitor.visitChildren(self)


    class InputNamedOrPositionalDoubleParamsContext(DoubleParameterContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.DoubleParameterContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def NAMED_OR_POSITIONAL_DOUBLE_PARAMS(self):
            return self.getToken(EsqlBaseParser.NAMED_OR_POSITIONAL_DOUBLE_PARAMS, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterInputNamedOrPositionalDoubleParams" ):
                listener.enterInputNamedOrPositionalDoubleParams(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitInputNamedOrPositionalDoubleParams" ):
                listener.exitInputNamedOrPositionalDoubleParams(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitInputNamedOrPositionalDoubleParams" ):
                return visitor.visitInputNamedOrPositionalDoubleParams(self)
            else:
                return visitor.visitChildren(self)



    def doubleParameter(self):

        localctx = EsqlBaseParser.DoubleParameterContext(self, self._ctx, self.state)
        self.enterRule(localctx, 84, self.RULE_doubleParameter)
        try:
            self.state = 573
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [76]:
                localctx = EsqlBaseParser.InputDoubleParamsContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 571
                self.match(EsqlBaseParser.DOUBLE_PARAMS)
                pass
            elif token in [78]:
                localctx = EsqlBaseParser.InputNamedOrPositionalDoubleParamsContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 572
                self.match(EsqlBaseParser.NAMED_OR_POSITIONAL_DOUBLE_PARAMS)
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IdentifierOrParameterContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifier(self):
            return self.getTypedRuleContext(EsqlBaseParser.IdentifierContext,0)


        def parameter(self):
            return self.getTypedRuleContext(EsqlBaseParser.ParameterContext,0)


        def doubleParameter(self):
            return self.getTypedRuleContext(EsqlBaseParser.DoubleParameterContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_identifierOrParameter

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIdentifierOrParameter" ):
                listener.enterIdentifierOrParameter(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIdentifierOrParameter" ):
                listener.exitIdentifierOrParameter(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIdentifierOrParameter" ):
                return visitor.visitIdentifierOrParameter(self)
            else:
                return visitor.visitChildren(self)




    def identifierOrParameter(self):

        localctx = EsqlBaseParser.IdentifierOrParameterContext(self, self._ctx, self.state)
        self.enterRule(localctx, 86, self.RULE_identifierOrParameter)
        try:
            self.state = 578
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [81, 82]:
                self.enterOuterAlt(localctx, 1)
                self.state = 575
                self.identifier()
                pass
            elif token in [57, 77]:
                self.enterOuterAlt(localctx, 2)
                self.state = 576
                self.parameter()
                pass
            elif token in [76, 78]:
                self.enterOuterAlt(localctx, 3)
                self.state = 577
                self.doubleParameter()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class LimitCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def LIMIT(self):
            return self.getToken(EsqlBaseParser.LIMIT, 0)

        def constant(self):
            return self.getTypedRuleContext(EsqlBaseParser.ConstantContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_limitCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterLimitCommand" ):
                listener.enterLimitCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitLimitCommand" ):
                listener.exitLimitCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitLimitCommand" ):
                return visitor.visitLimitCommand(self)
            else:
                return visitor.visitChildren(self)




    def limitCommand(self):

        localctx = EsqlBaseParser.LimitCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 88, self.RULE_limitCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 580
            self.match(EsqlBaseParser.LIMIT)
            self.state = 581
            self.constant()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SortCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def SORT(self):
            return self.getToken(EsqlBaseParser.SORT, 0)

        def orderExpression(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.OrderExpressionContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.OrderExpressionContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_sortCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSortCommand" ):
                listener.enterSortCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSortCommand" ):
                listener.exitSortCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSortCommand" ):
                return visitor.visitSortCommand(self)
            else:
                return visitor.visitChildren(self)




    def sortCommand(self):

        localctx = EsqlBaseParser.SortCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 90, self.RULE_sortCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 583
            self.match(EsqlBaseParser.SORT)
            self.state = 584
            self.orderExpression()
            self.state = 589
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,52,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 585
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 586
                    self.orderExpression() 
                self.state = 591
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,52,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class OrderExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.ordering = None # Token
            self.nullOrdering = None # Token

        def booleanExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.BooleanExpressionContext,0)


        def NULLS(self):
            return self.getToken(EsqlBaseParser.NULLS, 0)

        def ASC(self):
            return self.getToken(EsqlBaseParser.ASC, 0)

        def DESC(self):
            return self.getToken(EsqlBaseParser.DESC, 0)

        def FIRST(self):
            return self.getToken(EsqlBaseParser.FIRST, 0)

        def LAST(self):
            return self.getToken(EsqlBaseParser.LAST, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_orderExpression

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterOrderExpression" ):
                listener.enterOrderExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitOrderExpression" ):
                listener.exitOrderExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitOrderExpression" ):
                return visitor.visitOrderExpression(self)
            else:
                return visitor.visitChildren(self)




    def orderExpression(self):

        localctx = EsqlBaseParser.OrderExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 92, self.RULE_orderExpression)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 592
            self.booleanExpression(0)
            self.state = 594
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,53,self._ctx)
            if la_ == 1:
                self.state = 593
                localctx.ordering = self._input.LT(1)
                _la = self._input.LA(1)
                if not(_la==37 or _la==43):
                    localctx.ordering = self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()


            self.state = 598
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,54,self._ctx)
            if la_ == 1:
                self.state = 596
                self.match(EsqlBaseParser.NULLS)
                self.state = 597
                localctx.nullOrdering = self._input.LT(1)
                _la = self._input.LA(1)
                if not(_la==46 or _la==49):
                    localctx.nullOrdering = self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class KeepCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def KEEP(self):
            return self.getToken(EsqlBaseParser.KEEP, 0)

        def qualifiedNamePatterns(self):
            return self.getTypedRuleContext(EsqlBaseParser.QualifiedNamePatternsContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_keepCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterKeepCommand" ):
                listener.enterKeepCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitKeepCommand" ):
                listener.exitKeepCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitKeepCommand" ):
                return visitor.visitKeepCommand(self)
            else:
                return visitor.visitChildren(self)




    def keepCommand(self):

        localctx = EsqlBaseParser.KeepCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 94, self.RULE_keepCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 600
            self.match(EsqlBaseParser.KEEP)
            self.state = 601
            self.qualifiedNamePatterns()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class DropCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DROP(self):
            return self.getToken(EsqlBaseParser.DROP, 0)

        def qualifiedNamePatterns(self):
            return self.getTypedRuleContext(EsqlBaseParser.QualifiedNamePatternsContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_dropCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterDropCommand" ):
                listener.enterDropCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitDropCommand" ):
                listener.exitDropCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitDropCommand" ):
                return visitor.visitDropCommand(self)
            else:
                return visitor.visitChildren(self)




    def dropCommand(self):

        localctx = EsqlBaseParser.DropCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 96, self.RULE_dropCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 603
            self.match(EsqlBaseParser.DROP)
            self.state = 604
            self.qualifiedNamePatterns()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class RenameCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def RENAME(self):
            return self.getToken(EsqlBaseParser.RENAME, 0)

        def renameClause(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.RenameClauseContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.RenameClauseContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_renameCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRenameCommand" ):
                listener.enterRenameCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRenameCommand" ):
                listener.exitRenameCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitRenameCommand" ):
                return visitor.visitRenameCommand(self)
            else:
                return visitor.visitChildren(self)




    def renameCommand(self):

        localctx = EsqlBaseParser.RenameCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 98, self.RULE_renameCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 606
            self.match(EsqlBaseParser.RENAME)
            self.state = 607
            self.renameClause()
            self.state = 612
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,55,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 608
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 609
                    self.renameClause() 
                self.state = 614
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,55,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class RenameClauseContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.oldName = None # QualifiedNamePatternContext
            self.newName = None # QualifiedNamePatternContext

        def AS(self):
            return self.getToken(EsqlBaseParser.AS, 0)

        def qualifiedNamePattern(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.QualifiedNamePatternContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.QualifiedNamePatternContext,i)


        def ASSIGN(self):
            return self.getToken(EsqlBaseParser.ASSIGN, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_renameClause

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRenameClause" ):
                listener.enterRenameClause(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRenameClause" ):
                listener.exitRenameClause(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitRenameClause" ):
                return visitor.visitRenameClause(self)
            else:
                return visitor.visitChildren(self)




    def renameClause(self):

        localctx = EsqlBaseParser.RenameClauseContext(self, self._ctx, self.state)
        self.enterRule(localctx, 100, self.RULE_renameClause)
        try:
            self.state = 623
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,56,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 615
                localctx.oldName = self.qualifiedNamePattern()
                self.state = 616
                self.match(EsqlBaseParser.AS)
                self.state = 617
                localctx.newName = self.qualifiedNamePattern()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 619
                localctx.newName = self.qualifiedNamePattern()
                self.state = 620
                self.match(EsqlBaseParser.ASSIGN)
                self.state = 621
                localctx.oldName = self.qualifiedNamePattern()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class DissectCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DISSECT(self):
            return self.getToken(EsqlBaseParser.DISSECT, 0)

        def primaryExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.PrimaryExpressionContext,0)


        def string(self):
            return self.getTypedRuleContext(EsqlBaseParser.StringContext,0)


        def commandOptions(self):
            return self.getTypedRuleContext(EsqlBaseParser.CommandOptionsContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_dissectCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterDissectCommand" ):
                listener.enterDissectCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitDissectCommand" ):
                listener.exitDissectCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitDissectCommand" ):
                return visitor.visitDissectCommand(self)
            else:
                return visitor.visitChildren(self)




    def dissectCommand(self):

        localctx = EsqlBaseParser.DissectCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 102, self.RULE_dissectCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 625
            self.match(EsqlBaseParser.DISSECT)
            self.state = 626
            self.primaryExpression(0)
            self.state = 627
            self.string()
            self.state = 629
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,57,self._ctx)
            if la_ == 1:
                self.state = 628
                self.commandOptions()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class GrokCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def GROK(self):
            return self.getToken(EsqlBaseParser.GROK, 0)

        def primaryExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.PrimaryExpressionContext,0)


        def string(self):
            return self.getTypedRuleContext(EsqlBaseParser.StringContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_grokCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterGrokCommand" ):
                listener.enterGrokCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitGrokCommand" ):
                listener.exitGrokCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitGrokCommand" ):
                return visitor.visitGrokCommand(self)
            else:
                return visitor.visitChildren(self)




    def grokCommand(self):

        localctx = EsqlBaseParser.GrokCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 104, self.RULE_grokCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 631
            self.match(EsqlBaseParser.GROK)
            self.state = 632
            self.primaryExpression(0)
            self.state = 633
            self.string()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class MvExpandCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def MV_EXPAND(self):
            return self.getToken(EsqlBaseParser.MV_EXPAND, 0)

        def qualifiedName(self):
            return self.getTypedRuleContext(EsqlBaseParser.QualifiedNameContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_mvExpandCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterMvExpandCommand" ):
                listener.enterMvExpandCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitMvExpandCommand" ):
                listener.exitMvExpandCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitMvExpandCommand" ):
                return visitor.visitMvExpandCommand(self)
            else:
                return visitor.visitChildren(self)




    def mvExpandCommand(self):

        localctx = EsqlBaseParser.MvExpandCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 106, self.RULE_mvExpandCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 635
            self.match(EsqlBaseParser.MV_EXPAND)
            self.state = 636
            self.qualifiedName()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class CommandOptionsContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def commandOption(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.CommandOptionContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.CommandOptionContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_commandOptions

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterCommandOptions" ):
                listener.enterCommandOptions(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitCommandOptions" ):
                listener.exitCommandOptions(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCommandOptions" ):
                return visitor.visitCommandOptions(self)
            else:
                return visitor.visitChildren(self)




    def commandOptions(self):

        localctx = EsqlBaseParser.CommandOptionsContext(self, self._ctx, self.state)
        self.enterRule(localctx, 108, self.RULE_commandOptions)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 638
            self.commandOption()
            self.state = 643
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,58,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 639
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 640
                    self.commandOption() 
                self.state = 645
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,58,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class CommandOptionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifier(self):
            return self.getTypedRuleContext(EsqlBaseParser.IdentifierContext,0)


        def ASSIGN(self):
            return self.getToken(EsqlBaseParser.ASSIGN, 0)

        def constant(self):
            return self.getTypedRuleContext(EsqlBaseParser.ConstantContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_commandOption

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterCommandOption" ):
                listener.enterCommandOption(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitCommandOption" ):
                listener.exitCommandOption(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCommandOption" ):
                return visitor.visitCommandOption(self)
            else:
                return visitor.visitChildren(self)




    def commandOption(self):

        localctx = EsqlBaseParser.CommandOptionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 110, self.RULE_commandOption)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 646
            self.identifier()
            self.state = 647
            self.match(EsqlBaseParser.ASSIGN)
            self.state = 648
            self.constant()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class BooleanValueContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def TRUE(self):
            return self.getToken(EsqlBaseParser.TRUE, 0)

        def FALSE(self):
            return self.getToken(EsqlBaseParser.FALSE, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_booleanValue

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterBooleanValue" ):
                listener.enterBooleanValue(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitBooleanValue" ):
                listener.exitBooleanValue(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitBooleanValue" ):
                return visitor.visitBooleanValue(self)
            else:
                return visitor.visitChildren(self)




    def booleanValue(self):

        localctx = EsqlBaseParser.BooleanValueContext(self, self._ctx, self.state)
        self.enterRule(localctx, 112, self.RULE_booleanValue)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 650
            _la = self._input.LA(1)
            if not(_la==45 or _la==60):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class NumericValueContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def decimalValue(self):
            return self.getTypedRuleContext(EsqlBaseParser.DecimalValueContext,0)


        def integerValue(self):
            return self.getTypedRuleContext(EsqlBaseParser.IntegerValueContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_numericValue

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterNumericValue" ):
                listener.enterNumericValue(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitNumericValue" ):
                listener.exitNumericValue(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitNumericValue" ):
                return visitor.visitNumericValue(self)
            else:
                return visitor.visitChildren(self)




    def numericValue(self):

        localctx = EsqlBaseParser.NumericValueContext(self, self._ctx, self.state)
        self.enterRule(localctx, 114, self.RULE_numericValue)
        try:
            self.state = 654
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,59,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 652
                self.decimalValue()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 653
                self.integerValue()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class DecimalValueContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DECIMAL_LITERAL(self):
            return self.getToken(EsqlBaseParser.DECIMAL_LITERAL, 0)

        def PLUS(self):
            return self.getToken(EsqlBaseParser.PLUS, 0)

        def MINUS(self):
            return self.getToken(EsqlBaseParser.MINUS, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_decimalValue

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterDecimalValue" ):
                listener.enterDecimalValue(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitDecimalValue" ):
                listener.exitDecimalValue(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitDecimalValue" ):
                return visitor.visitDecimalValue(self)
            else:
                return visitor.visitChildren(self)




    def decimalValue(self):

        localctx = EsqlBaseParser.DecimalValueContext(self, self._ctx, self.state)
        self.enterRule(localctx, 116, self.RULE_decimalValue)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 657
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==69 or _la==70:
                self.state = 656
                _la = self._input.LA(1)
                if not(_la==69 or _la==70):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()


            self.state = 659
            self.match(EsqlBaseParser.DECIMAL_LITERAL)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IntegerValueContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def INTEGER_LITERAL(self):
            return self.getToken(EsqlBaseParser.INTEGER_LITERAL, 0)

        def PLUS(self):
            return self.getToken(EsqlBaseParser.PLUS, 0)

        def MINUS(self):
            return self.getToken(EsqlBaseParser.MINUS, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_integerValue

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIntegerValue" ):
                listener.enterIntegerValue(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIntegerValue" ):
                listener.exitIntegerValue(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIntegerValue" ):
                return visitor.visitIntegerValue(self)
            else:
                return visitor.visitChildren(self)




    def integerValue(self):

        localctx = EsqlBaseParser.IntegerValueContext(self, self._ctx, self.state)
        self.enterRule(localctx, 118, self.RULE_integerValue)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 662
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==69 or _la==70:
                self.state = 661
                _la = self._input.LA(1)
                if not(_la==69 or _la==70):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()


            self.state = 664
            self.match(EsqlBaseParser.INTEGER_LITERAL)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class StringContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def QUOTED_STRING(self):
            return self.getToken(EsqlBaseParser.QUOTED_STRING, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_string

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterString" ):
                listener.enterString(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitString" ):
                listener.exitString(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitString" ):
                return visitor.visitString(self)
            else:
                return visitor.visitChildren(self)




    def string(self):

        localctx = EsqlBaseParser.StringContext(self, self._ctx, self.state)
        self.enterRule(localctx, 120, self.RULE_string)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 666
            self.match(EsqlBaseParser.QUOTED_STRING)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ComparisonOperatorContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def EQ(self):
            return self.getToken(EsqlBaseParser.EQ, 0)

        def NEQ(self):
            return self.getToken(EsqlBaseParser.NEQ, 0)

        def LT(self):
            return self.getToken(EsqlBaseParser.LT, 0)

        def LTE(self):
            return self.getToken(EsqlBaseParser.LTE, 0)

        def GT(self):
            return self.getToken(EsqlBaseParser.GT, 0)

        def GTE(self):
            return self.getToken(EsqlBaseParser.GTE, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_comparisonOperator

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterComparisonOperator" ):
                listener.enterComparisonOperator(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitComparisonOperator" ):
                listener.exitComparisonOperator(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitComparisonOperator" ):
                return visitor.visitComparisonOperator(self)
            else:
                return visitor.visitChildren(self)




    def comparisonOperator(self):

        localctx = EsqlBaseParser.ComparisonOperatorContext(self, self._ctx, self.state)
        self.enterRule(localctx, 122, self.RULE_comparisonOperator)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 668
            _la = self._input.LA(1)
            if not(((((_la - 62)) & ~0x3f) == 0 and ((1 << (_la - 62)) & 125) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ExplainCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def EXPLAIN(self):
            return self.getToken(EsqlBaseParser.EXPLAIN, 0)

        def subqueryExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.SubqueryExpressionContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_explainCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExplainCommand" ):
                listener.enterExplainCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExplainCommand" ):
                listener.exitExplainCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExplainCommand" ):
                return visitor.visitExplainCommand(self)
            else:
                return visitor.visitChildren(self)




    def explainCommand(self):

        localctx = EsqlBaseParser.ExplainCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 124, self.RULE_explainCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 670
            self.match(EsqlBaseParser.EXPLAIN)
            self.state = 671
            self.subqueryExpression()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SubqueryExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def OPENING_BRACKET(self):
            return self.getToken(EsqlBaseParser.OPENING_BRACKET, 0)

        def query(self):
            return self.getTypedRuleContext(EsqlBaseParser.QueryContext,0)


        def CLOSING_BRACKET(self):
            return self.getToken(EsqlBaseParser.CLOSING_BRACKET, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_subqueryExpression

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSubqueryExpression" ):
                listener.enterSubqueryExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSubqueryExpression" ):
                listener.exitSubqueryExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSubqueryExpression" ):
                return visitor.visitSubqueryExpression(self)
            else:
                return visitor.visitChildren(self)




    def subqueryExpression(self):

        localctx = EsqlBaseParser.SubqueryExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 126, self.RULE_subqueryExpression)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 673
            self.match(EsqlBaseParser.OPENING_BRACKET)
            self.state = 674
            self.query(0)
            self.state = 675
            self.match(EsqlBaseParser.CLOSING_BRACKET)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ShowCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_showCommand

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class ShowInfoContext(ShowCommandContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ShowCommandContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def SHOW(self):
            return self.getToken(EsqlBaseParser.SHOW, 0)
        def INFO(self):
            return self.getToken(EsqlBaseParser.INFO, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterShowInfo" ):
                listener.enterShowInfo(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitShowInfo" ):
                listener.exitShowInfo(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitShowInfo" ):
                return visitor.visitShowInfo(self)
            else:
                return visitor.visitChildren(self)



    def showCommand(self):

        localctx = EsqlBaseParser.ShowCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 128, self.RULE_showCommand)
        try:
            localctx = EsqlBaseParser.ShowInfoContext(self, localctx)
            self.enterOuterAlt(localctx, 1)
            self.state = 677
            self.match(EsqlBaseParser.SHOW)
            self.state = 678
            self.match(EsqlBaseParser.INFO)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class EnrichCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.policyName = None # EnrichPolicyNameContext
            self.matchField = None # QualifiedNamePatternContext

        def ENRICH(self):
            return self.getToken(EsqlBaseParser.ENRICH, 0)

        def enrichPolicyName(self):
            return self.getTypedRuleContext(EsqlBaseParser.EnrichPolicyNameContext,0)


        def ON(self):
            return self.getToken(EsqlBaseParser.ON, 0)

        def WITH(self):
            return self.getToken(EsqlBaseParser.WITH, 0)

        def enrichWithClause(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.EnrichWithClauseContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.EnrichWithClauseContext,i)


        def qualifiedNamePattern(self):
            return self.getTypedRuleContext(EsqlBaseParser.QualifiedNamePatternContext,0)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_enrichCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterEnrichCommand" ):
                listener.enterEnrichCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitEnrichCommand" ):
                listener.exitEnrichCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitEnrichCommand" ):
                return visitor.visitEnrichCommand(self)
            else:
                return visitor.visitChildren(self)




    def enrichCommand(self):

        localctx = EsqlBaseParser.EnrichCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 130, self.RULE_enrichCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 680
            self.match(EsqlBaseParser.ENRICH)
            self.state = 681
            localctx.policyName = self.enrichPolicyName()
            self.state = 684
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,62,self._ctx)
            if la_ == 1:
                self.state = 682
                self.match(EsqlBaseParser.ON)
                self.state = 683
                localctx.matchField = self.qualifiedNamePattern()


            self.state = 695
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,64,self._ctx)
            if la_ == 1:
                self.state = 686
                self.match(EsqlBaseParser.WITH)
                self.state = 687
                self.enrichWithClause()
                self.state = 692
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,63,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 688
                        self.match(EsqlBaseParser.COMMA)
                        self.state = 689
                        self.enrichWithClause() 
                    self.state = 694
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,63,self._ctx)



        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class EnrichPolicyNameContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ENRICH_POLICY_NAME(self):
            return self.getToken(EsqlBaseParser.ENRICH_POLICY_NAME, 0)

        def QUOTED_STRING(self):
            return self.getToken(EsqlBaseParser.QUOTED_STRING, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_enrichPolicyName

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterEnrichPolicyName" ):
                listener.enterEnrichPolicyName(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitEnrichPolicyName" ):
                listener.exitEnrichPolicyName(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitEnrichPolicyName" ):
                return visitor.visitEnrichPolicyName(self)
            else:
                return visitor.visitChildren(self)




    def enrichPolicyName(self):

        localctx = EsqlBaseParser.EnrichPolicyNameContext(self, self._ctx, self.state)
        self.enterRule(localctx, 132, self.RULE_enrichPolicyName)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 697
            _la = self._input.LA(1)
            if not(_la==33 or _la==102):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class EnrichWithClauseContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.newName = None # QualifiedNamePatternContext
            self.enrichField = None # QualifiedNamePatternContext

        def qualifiedNamePattern(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.QualifiedNamePatternContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.QualifiedNamePatternContext,i)


        def ASSIGN(self):
            return self.getToken(EsqlBaseParser.ASSIGN, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_enrichWithClause

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterEnrichWithClause" ):
                listener.enterEnrichWithClause(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitEnrichWithClause" ):
                listener.exitEnrichWithClause(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitEnrichWithClause" ):
                return visitor.visitEnrichWithClause(self)
            else:
                return visitor.visitChildren(self)




    def enrichWithClause(self):

        localctx = EsqlBaseParser.EnrichWithClauseContext(self, self._ctx, self.state)
        self.enterRule(localctx, 134, self.RULE_enrichWithClause)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 702
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,65,self._ctx)
            if la_ == 1:
                self.state = 699
                localctx.newName = self.qualifiedNamePattern()
                self.state = 700
                self.match(EsqlBaseParser.ASSIGN)


            self.state = 704
            localctx.enrichField = self.qualifiedNamePattern()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ChangePointCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.value = None # QualifiedNameContext
            self.key = None # QualifiedNameContext
            self.targetType = None # QualifiedNameContext
            self.targetPvalue = None # QualifiedNameContext

        def CHANGE_POINT(self):
            return self.getToken(EsqlBaseParser.CHANGE_POINT, 0)

        def qualifiedName(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.QualifiedNameContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.QualifiedNameContext,i)


        def ON(self):
            return self.getToken(EsqlBaseParser.ON, 0)

        def AS(self):
            return self.getToken(EsqlBaseParser.AS, 0)

        def COMMA(self):
            return self.getToken(EsqlBaseParser.COMMA, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_changePointCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterChangePointCommand" ):
                listener.enterChangePointCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitChangePointCommand" ):
                listener.exitChangePointCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitChangePointCommand" ):
                return visitor.visitChangePointCommand(self)
            else:
                return visitor.visitChildren(self)




    def changePointCommand(self):

        localctx = EsqlBaseParser.ChangePointCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 136, self.RULE_changePointCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 706
            self.match(EsqlBaseParser.CHANGE_POINT)
            self.state = 707
            localctx.value = self.qualifiedName()
            self.state = 710
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,66,self._ctx)
            if la_ == 1:
                self.state = 708
                self.match(EsqlBaseParser.ON)
                self.state = 709
                localctx.key = self.qualifiedName()


            self.state = 717
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,67,self._ctx)
            if la_ == 1:
                self.state = 712
                self.match(EsqlBaseParser.AS)
                self.state = 713
                localctx.targetType = self.qualifiedName()
                self.state = 714
                self.match(EsqlBaseParser.COMMA)
                self.state = 715
                localctx.targetPvalue = self.qualifiedName()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SampleCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.probability = None # ConstantContext

        def SAMPLE(self):
            return self.getToken(EsqlBaseParser.SAMPLE, 0)

        def constant(self):
            return self.getTypedRuleContext(EsqlBaseParser.ConstantContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_sampleCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSampleCommand" ):
                listener.enterSampleCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSampleCommand" ):
                listener.exitSampleCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSampleCommand" ):
                return visitor.visitSampleCommand(self)
            else:
                return visitor.visitChildren(self)




    def sampleCommand(self):

        localctx = EsqlBaseParser.SampleCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 138, self.RULE_sampleCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 719
            self.match(EsqlBaseParser.SAMPLE)
            self.state = 720
            localctx.probability = self.constant()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class LookupCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.tableName = None # IndexPatternContext
            self.matchFields = None # QualifiedNamePatternsContext

        def DEV_LOOKUP(self):
            return self.getToken(EsqlBaseParser.DEV_LOOKUP, 0)

        def ON(self):
            return self.getToken(EsqlBaseParser.ON, 0)

        def indexPattern(self):
            return self.getTypedRuleContext(EsqlBaseParser.IndexPatternContext,0)


        def qualifiedNamePatterns(self):
            return self.getTypedRuleContext(EsqlBaseParser.QualifiedNamePatternsContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_lookupCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterLookupCommand" ):
                listener.enterLookupCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitLookupCommand" ):
                listener.exitLookupCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitLookupCommand" ):
                return visitor.visitLookupCommand(self)
            else:
                return visitor.visitChildren(self)




    def lookupCommand(self):

        localctx = EsqlBaseParser.LookupCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 140, self.RULE_lookupCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 722
            self.match(EsqlBaseParser.DEV_LOOKUP)
            self.state = 723
            localctx.tableName = self.indexPattern()
            self.state = 724
            self.match(EsqlBaseParser.ON)
            self.state = 725
            localctx.matchFields = self.qualifiedNamePatterns()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class InlinestatsCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.stats = None # AggFieldsContext
            self.grouping = None # FieldsContext

        def DEV_INLINESTATS(self):
            return self.getToken(EsqlBaseParser.DEV_INLINESTATS, 0)

        def aggFields(self):
            return self.getTypedRuleContext(EsqlBaseParser.AggFieldsContext,0)


        def BY(self):
            return self.getToken(EsqlBaseParser.BY, 0)

        def fields(self):
            return self.getTypedRuleContext(EsqlBaseParser.FieldsContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_inlinestatsCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterInlinestatsCommand" ):
                listener.enterInlinestatsCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitInlinestatsCommand" ):
                listener.exitInlinestatsCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitInlinestatsCommand" ):
                return visitor.visitInlinestatsCommand(self)
            else:
                return visitor.visitChildren(self)




    def inlinestatsCommand(self):

        localctx = EsqlBaseParser.InlinestatsCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 142, self.RULE_inlinestatsCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 727
            self.match(EsqlBaseParser.DEV_INLINESTATS)
            self.state = 728
            localctx.stats = self.aggFields()
            self.state = 731
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,68,self._ctx)
            if la_ == 1:
                self.state = 729
                self.match(EsqlBaseParser.BY)
                self.state = 730
                localctx.grouping = self.fields()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class JoinCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.type_ = None # Token

        def JOIN(self):
            return self.getToken(EsqlBaseParser.JOIN, 0)

        def joinTarget(self):
            return self.getTypedRuleContext(EsqlBaseParser.JoinTargetContext,0)


        def joinCondition(self):
            return self.getTypedRuleContext(EsqlBaseParser.JoinConditionContext,0)


        def JOIN_LOOKUP(self):
            return self.getToken(EsqlBaseParser.JOIN_LOOKUP, 0)

        def DEV_JOIN_LEFT(self):
            return self.getToken(EsqlBaseParser.DEV_JOIN_LEFT, 0)

        def DEV_JOIN_RIGHT(self):
            return self.getToken(EsqlBaseParser.DEV_JOIN_RIGHT, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_joinCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJoinCommand" ):
                listener.enterJoinCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJoinCommand" ):
                listener.exitJoinCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJoinCommand" ):
                return visitor.visitJoinCommand(self)
            else:
                return visitor.visitChildren(self)




    def joinCommand(self):

        localctx = EsqlBaseParser.JoinCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 144, self.RULE_joinCommand)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 733
            localctx.type_ = self._input.LT(1)
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 201850880) != 0)):
                localctx.type_ = self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
            self.state = 734
            self.match(EsqlBaseParser.JOIN)
            self.state = 735
            self.joinTarget()
            self.state = 736
            self.joinCondition()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class JoinTargetContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.index = None # IndexPatternContext

        def indexPattern(self):
            return self.getTypedRuleContext(EsqlBaseParser.IndexPatternContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_joinTarget

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJoinTarget" ):
                listener.enterJoinTarget(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJoinTarget" ):
                listener.exitJoinTarget(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJoinTarget" ):
                return visitor.visitJoinTarget(self)
            else:
                return visitor.visitChildren(self)




    def joinTarget(self):

        localctx = EsqlBaseParser.JoinTargetContext(self, self._ctx, self.state)
        self.enterRule(localctx, 146, self.RULE_joinTarget)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 738
            localctx.index = self.indexPattern()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class JoinConditionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ON(self):
            return self.getToken(EsqlBaseParser.ON, 0)

        def joinPredicate(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.JoinPredicateContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.JoinPredicateContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_joinCondition

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJoinCondition" ):
                listener.enterJoinCondition(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJoinCondition" ):
                listener.exitJoinCondition(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJoinCondition" ):
                return visitor.visitJoinCondition(self)
            else:
                return visitor.visitChildren(self)




    def joinCondition(self):

        localctx = EsqlBaseParser.JoinConditionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 148, self.RULE_joinCondition)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 740
            self.match(EsqlBaseParser.ON)
            self.state = 741
            self.joinPredicate()
            self.state = 746
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,69,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 742
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 743
                    self.joinPredicate() 
                self.state = 748
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,69,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class JoinPredicateContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def valueExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.ValueExpressionContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_joinPredicate

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterJoinPredicate" ):
                listener.enterJoinPredicate(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitJoinPredicate" ):
                listener.exitJoinPredicate(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitJoinPredicate" ):
                return visitor.visitJoinPredicate(self)
            else:
                return visitor.visitChildren(self)




    def joinPredicate(self):

        localctx = EsqlBaseParser.JoinPredicateContext(self, self._ctx, self.state)
        self.enterRule(localctx, 150, self.RULE_joinPredicate)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 749
            self.valueExpression()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class InferenceCommandOptionsContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def inferenceCommandOption(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.InferenceCommandOptionContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.InferenceCommandOptionContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_inferenceCommandOptions

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterInferenceCommandOptions" ):
                listener.enterInferenceCommandOptions(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitInferenceCommandOptions" ):
                listener.exitInferenceCommandOptions(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitInferenceCommandOptions" ):
                return visitor.visitInferenceCommandOptions(self)
            else:
                return visitor.visitChildren(self)




    def inferenceCommandOptions(self):

        localctx = EsqlBaseParser.InferenceCommandOptionsContext(self, self._ctx, self.state)
        self.enterRule(localctx, 152, self.RULE_inferenceCommandOptions)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 751
            self.inferenceCommandOption()
            self.state = 756
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,70,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 752
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 753
                    self.inferenceCommandOption() 
                self.state = 758
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,70,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class InferenceCommandOptionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifier(self):
            return self.getTypedRuleContext(EsqlBaseParser.IdentifierContext,0)


        def ASSIGN(self):
            return self.getToken(EsqlBaseParser.ASSIGN, 0)

        def inferenceCommandOptionValue(self):
            return self.getTypedRuleContext(EsqlBaseParser.InferenceCommandOptionValueContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_inferenceCommandOption

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterInferenceCommandOption" ):
                listener.enterInferenceCommandOption(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitInferenceCommandOption" ):
                listener.exitInferenceCommandOption(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitInferenceCommandOption" ):
                return visitor.visitInferenceCommandOption(self)
            else:
                return visitor.visitChildren(self)




    def inferenceCommandOption(self):

        localctx = EsqlBaseParser.InferenceCommandOptionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 154, self.RULE_inferenceCommandOption)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 759
            self.identifier()
            self.state = 760
            self.match(EsqlBaseParser.ASSIGN)
            self.state = 761
            self.inferenceCommandOptionValue()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class InferenceCommandOptionValueContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def constant(self):
            return self.getTypedRuleContext(EsqlBaseParser.ConstantContext,0)


        def identifier(self):
            return self.getTypedRuleContext(EsqlBaseParser.IdentifierContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_inferenceCommandOptionValue

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterInferenceCommandOptionValue" ):
                listener.enterInferenceCommandOptionValue(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitInferenceCommandOptionValue" ):
                listener.exitInferenceCommandOptionValue(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitInferenceCommandOptionValue" ):
                return visitor.visitInferenceCommandOptionValue(self)
            else:
                return visitor.visitChildren(self)




    def inferenceCommandOptionValue(self):

        localctx = EsqlBaseParser.InferenceCommandOptionValueContext(self, self._ctx, self.state)
        self.enterRule(localctx, 156, self.RULE_inferenceCommandOptionValue)
        try:
            self.state = 765
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [33, 34, 35, 45, 53, 57, 60, 69, 70, 77, 79]:
                self.enterOuterAlt(localctx, 1)
                self.state = 763
                self.constant()
                pass
            elif token in [81, 82]:
                self.enterOuterAlt(localctx, 2)
                self.state = 764
                self.identifier()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class RerankCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.queryText = None # ConstantContext

        def DEV_RERANK(self):
            return self.getToken(EsqlBaseParser.DEV_RERANK, 0)

        def ON(self):
            return self.getToken(EsqlBaseParser.ON, 0)

        def rerankFields(self):
            return self.getTypedRuleContext(EsqlBaseParser.RerankFieldsContext,0)


        def constant(self):
            return self.getTypedRuleContext(EsqlBaseParser.ConstantContext,0)


        def WITH(self):
            return self.getToken(EsqlBaseParser.WITH, 0)

        def inferenceCommandOptions(self):
            return self.getTypedRuleContext(EsqlBaseParser.InferenceCommandOptionsContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_rerankCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRerankCommand" ):
                listener.enterRerankCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRerankCommand" ):
                listener.exitRerankCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitRerankCommand" ):
                return visitor.visitRerankCommand(self)
            else:
                return visitor.visitChildren(self)




    def rerankCommand(self):

        localctx = EsqlBaseParser.RerankCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 158, self.RULE_rerankCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 767
            self.match(EsqlBaseParser.DEV_RERANK)
            self.state = 768
            localctx.queryText = self.constant()
            self.state = 769
            self.match(EsqlBaseParser.ON)
            self.state = 770
            self.rerankFields()
            self.state = 773
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,72,self._ctx)
            if la_ == 1:
                self.state = 771
                self.match(EsqlBaseParser.WITH)
                self.state = 772
                self.inferenceCommandOptions()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class CompletionCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser
            self.targetField = None # QualifiedNameContext
            self.prompt = None # PrimaryExpressionContext
            self.inferenceId = None # IdentifierOrParameterContext

        def COMPLETION(self):
            return self.getToken(EsqlBaseParser.COMPLETION, 0)

        def WITH(self):
            return self.getToken(EsqlBaseParser.WITH, 0)

        def primaryExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.PrimaryExpressionContext,0)


        def identifierOrParameter(self):
            return self.getTypedRuleContext(EsqlBaseParser.IdentifierOrParameterContext,0)


        def ASSIGN(self):
            return self.getToken(EsqlBaseParser.ASSIGN, 0)

        def qualifiedName(self):
            return self.getTypedRuleContext(EsqlBaseParser.QualifiedNameContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_completionCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterCompletionCommand" ):
                listener.enterCompletionCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitCompletionCommand" ):
                listener.exitCompletionCommand(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCompletionCommand" ):
                return visitor.visitCompletionCommand(self)
            else:
                return visitor.visitChildren(self)




    def completionCommand(self):

        localctx = EsqlBaseParser.CompletionCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 160, self.RULE_completionCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 775
            self.match(EsqlBaseParser.COMPLETION)
            self.state = 779
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,73,self._ctx)
            if la_ == 1:
                self.state = 776
                localctx.targetField = self.qualifiedName()
                self.state = 777
                self.match(EsqlBaseParser.ASSIGN)


            self.state = 781
            localctx.prompt = self.primaryExpression(0)
            self.state = 782
            self.match(EsqlBaseParser.WITH)
            self.state = 783
            localctx.inferenceId = self.identifierOrParameter()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx



    def sempred(self, localctx:RuleContext, ruleIndex:int, predIndex:int):
        if self._predicates == None:
            self._predicates = dict()
        self._predicates[1] = self.query_sempred
        self._predicates[2] = self.sourceCommand_sempred
        self._predicates[3] = self.processingCommand_sempred
        self._predicates[5] = self.booleanExpression_sempred
        self._predicates[9] = self.operatorExpression_sempred
        self._predicates[10] = self.primaryExpression_sempred
        pred = self._predicates.get(ruleIndex, None)
        if pred is None:
            raise Exception("No predicate with index:" + str(ruleIndex))
        else:
            return pred(localctx, predIndex)

    def query_sempred(self, localctx:QueryContext, predIndex:int):
            if predIndex == 0:
                return self.precpred(self._ctx, 1)
         

    def sourceCommand_sempred(self, localctx:SourceCommandContext, predIndex:int):
            if predIndex == 1:
                return self.isDevVersion()
         

    def processingCommand_sempred(self, localctx:ProcessingCommandContext, predIndex:int):
            if predIndex == 2:
                return self.isDevVersion()
         

            if predIndex == 3:
                return self.isDevVersion()
         

            if predIndex == 4:
                return self.isDevVersion()
         

    def booleanExpression_sempred(self, localctx:BooleanExpressionContext, predIndex:int):
            if predIndex == 5:
                return self.precpred(self._ctx, 5)
         

            if predIndex == 6:
                return self.precpred(self._ctx, 4)
         

    def operatorExpression_sempred(self, localctx:OperatorExpressionContext, predIndex:int):
            if predIndex == 7:
                return self.precpred(self._ctx, 2)
         

            if predIndex == 8:
                return self.precpred(self._ctx, 1)
         

    def primaryExpression_sempred(self, localctx:PrimaryExpressionContext, predIndex:int):
            if predIndex == 9:
                return self.precpred(self._ctx, 1)
         




