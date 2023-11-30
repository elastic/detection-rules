# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# encoding: utf-8
from antlr4 import *
from io import StringIO
import sys
if sys.version_info[1] > 5:
	from typing import TextIO
else:
	from typing.io import TextIO

def serializedATN():
    return [
        4,1,80,488,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,
        6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,2,13,7,13,
        2,14,7,14,2,15,7,15,2,16,7,16,2,17,7,17,2,18,7,18,2,19,7,19,2,20,
        7,20,2,21,7,21,2,22,7,22,2,23,7,23,2,24,7,24,2,25,7,25,2,26,7,26,
        2,27,7,27,2,28,7,28,2,29,7,29,2,30,7,30,2,31,7,31,2,32,7,32,2,33,
        7,33,2,34,7,34,2,35,7,35,2,36,7,36,2,37,7,37,2,38,7,38,2,39,7,39,
        2,40,7,40,2,41,7,41,2,42,7,42,2,43,7,43,2,44,7,44,2,45,7,45,1,0,
        1,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,5,1,102,8,1,10,1,12,1,105,9,1,1,
        2,1,2,1,2,1,2,3,2,111,8,2,1,3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,1,
        3,1,3,1,3,1,3,3,3,126,8,3,1,4,1,4,1,4,1,5,1,5,1,5,1,5,1,5,1,5,1,
        5,3,5,138,8,5,1,5,1,5,1,5,1,5,1,5,5,5,145,8,5,10,5,12,5,148,9,5,
        1,5,1,5,3,5,152,8,5,1,5,1,5,1,5,1,5,1,5,1,5,5,5,160,8,5,10,5,12,
        5,163,9,5,1,6,1,6,3,6,167,8,6,1,6,1,6,1,6,1,6,1,6,3,6,174,8,6,1,
        6,1,6,1,6,3,6,179,8,6,1,7,1,7,1,7,1,7,1,7,3,7,186,8,7,1,8,1,8,1,
        8,1,8,3,8,192,8,8,1,8,1,8,1,8,1,8,1,8,1,8,5,8,200,8,8,10,8,12,8,
        203,9,8,1,9,1,9,1,9,1,9,1,9,1,9,1,9,1,9,1,9,1,9,1,9,5,9,216,8,9,
        10,9,12,9,219,9,9,3,9,221,8,9,1,9,1,9,3,9,225,8,9,1,10,1,10,1,10,
        1,11,1,11,1,11,5,11,233,8,11,10,11,12,11,236,9,11,1,12,1,12,1,12,
        1,12,1,12,3,12,243,8,12,1,13,1,13,1,13,1,13,5,13,249,8,13,10,13,
        12,13,252,9,13,1,13,3,13,255,8,13,1,14,1,14,1,14,1,14,1,14,5,14,
        262,8,14,10,14,12,14,265,9,14,1,14,1,14,1,15,1,15,1,15,1,16,1,16,
        3,16,274,8,16,1,16,1,16,3,16,278,8,16,1,17,1,17,1,17,1,17,3,17,284,
        8,17,1,18,1,18,1,18,5,18,289,8,18,10,18,12,18,292,9,18,1,19,1,19,
        1,20,1,20,1,20,5,20,299,8,20,10,20,12,20,302,9,20,1,21,1,21,1,22,
        1,22,1,22,1,22,1,22,1,22,1,22,1,22,1,22,1,22,1,22,1,22,1,22,5,22,
        319,8,22,10,22,12,22,322,9,22,1,22,1,22,1,22,1,22,1,22,1,22,5,22,
        330,8,22,10,22,12,22,333,9,22,1,22,1,22,1,22,1,22,1,22,1,22,5,22,
        341,8,22,10,22,12,22,344,9,22,1,22,1,22,3,22,348,8,22,1,23,1,23,
        1,23,1,24,1,24,1,24,1,24,5,24,357,8,24,10,24,12,24,360,9,24,1,25,
        1,25,3,25,364,8,25,1,25,1,25,3,25,368,8,25,1,26,1,26,1,26,1,26,5,
        26,374,8,26,10,26,12,26,377,9,26,1,26,1,26,1,26,1,26,5,26,383,8,
        26,10,26,12,26,386,9,26,3,26,388,8,26,1,27,1,27,1,27,1,27,5,27,394,
        8,27,10,27,12,27,397,9,27,1,28,1,28,1,28,1,28,5,28,403,8,28,10,28,
        12,28,406,9,28,1,29,1,29,1,29,1,29,1,30,1,30,1,30,1,30,3,30,416,
        8,30,1,31,1,31,1,31,1,31,1,32,1,32,1,32,1,33,1,33,1,33,5,33,428,
        8,33,10,33,12,33,431,9,33,1,34,1,34,1,34,1,34,1,35,1,35,1,36,1,36,
        3,36,441,8,36,1,37,1,37,1,38,1,38,1,39,1,39,1,40,1,40,1,41,1,41,
        1,41,1,42,1,42,1,42,1,42,1,43,1,43,1,43,1,43,3,43,462,8,43,1,44,
        1,44,1,44,1,44,3,44,468,8,44,1,44,1,44,1,44,1,44,5,44,474,8,44,10,
        44,12,44,477,9,44,3,44,479,8,44,1,45,1,45,1,45,3,45,484,8,45,1,45,
        1,45,1,45,0,3,2,10,16,46,0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,
        30,32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62,64,66,68,70,72,
        74,76,78,80,82,84,86,88,90,0,8,1,0,59,60,1,0,61,63,1,0,75,76,1,0,
        66,67,2,0,32,32,35,35,1,0,38,39,2,0,37,37,50,50,1,0,53,58,514,0,
        92,1,0,0,0,2,95,1,0,0,0,4,110,1,0,0,0,6,125,1,0,0,0,8,127,1,0,0,
        0,10,151,1,0,0,0,12,178,1,0,0,0,14,185,1,0,0,0,16,191,1,0,0,0,18,
        224,1,0,0,0,20,226,1,0,0,0,22,229,1,0,0,0,24,242,1,0,0,0,26,244,
        1,0,0,0,28,256,1,0,0,0,30,268,1,0,0,0,32,271,1,0,0,0,34,279,1,0,
        0,0,36,285,1,0,0,0,38,293,1,0,0,0,40,295,1,0,0,0,42,303,1,0,0,0,
        44,347,1,0,0,0,46,349,1,0,0,0,48,352,1,0,0,0,50,361,1,0,0,0,52,387,
        1,0,0,0,54,389,1,0,0,0,56,398,1,0,0,0,58,407,1,0,0,0,60,411,1,0,
        0,0,62,417,1,0,0,0,64,421,1,0,0,0,66,424,1,0,0,0,68,432,1,0,0,0,
        70,436,1,0,0,0,72,440,1,0,0,0,74,442,1,0,0,0,76,444,1,0,0,0,78,446,
        1,0,0,0,80,448,1,0,0,0,82,450,1,0,0,0,84,453,1,0,0,0,86,461,1,0,
        0,0,88,463,1,0,0,0,90,483,1,0,0,0,92,93,3,2,1,0,93,94,5,0,0,1,94,
        1,1,0,0,0,95,96,6,1,-1,0,96,97,3,4,2,0,97,103,1,0,0,0,98,99,10,1,
        0,0,99,100,5,26,0,0,100,102,3,6,3,0,101,98,1,0,0,0,102,105,1,0,0,
        0,103,101,1,0,0,0,103,104,1,0,0,0,104,3,1,0,0,0,105,103,1,0,0,0,
        106,111,3,82,41,0,107,111,3,26,13,0,108,111,3,20,10,0,109,111,3,
        86,43,0,110,106,1,0,0,0,110,107,1,0,0,0,110,108,1,0,0,0,110,109,
        1,0,0,0,111,5,1,0,0,0,112,126,3,30,15,0,113,126,3,34,17,0,114,126,
        3,46,23,0,115,126,3,52,26,0,116,126,3,48,24,0,117,126,3,32,16,0,
        118,126,3,8,4,0,119,126,3,54,27,0,120,126,3,56,28,0,121,126,3,60,
        30,0,122,126,3,62,31,0,123,126,3,88,44,0,124,126,3,64,32,0,125,112,
        1,0,0,0,125,113,1,0,0,0,125,114,1,0,0,0,125,115,1,0,0,0,125,116,
        1,0,0,0,125,117,1,0,0,0,125,118,1,0,0,0,125,119,1,0,0,0,125,120,
        1,0,0,0,125,121,1,0,0,0,125,122,1,0,0,0,125,123,1,0,0,0,125,124,
        1,0,0,0,126,7,1,0,0,0,127,128,5,18,0,0,128,129,3,10,5,0,129,9,1,
        0,0,0,130,131,6,5,-1,0,131,132,5,43,0,0,132,152,3,10,5,6,133,152,
        3,14,7,0,134,152,3,12,6,0,135,137,3,14,7,0,136,138,5,43,0,0,137,
        136,1,0,0,0,137,138,1,0,0,0,138,139,1,0,0,0,139,140,5,41,0,0,140,
        141,5,40,0,0,141,146,3,14,7,0,142,143,5,34,0,0,143,145,3,14,7,0,
        144,142,1,0,0,0,145,148,1,0,0,0,146,144,1,0,0,0,146,147,1,0,0,0,
        147,149,1,0,0,0,148,146,1,0,0,0,149,150,5,49,0,0,150,152,1,0,0,0,
        151,130,1,0,0,0,151,133,1,0,0,0,151,134,1,0,0,0,151,135,1,0,0,0,
        152,161,1,0,0,0,153,154,10,3,0,0,154,155,5,31,0,0,155,160,3,10,5,
        4,156,157,10,2,0,0,157,158,5,46,0,0,158,160,3,10,5,3,159,153,1,0,
        0,0,159,156,1,0,0,0,160,163,1,0,0,0,161,159,1,0,0,0,161,162,1,0,
        0,0,162,11,1,0,0,0,163,161,1,0,0,0,164,166,3,14,7,0,165,167,5,43,
        0,0,166,165,1,0,0,0,166,167,1,0,0,0,167,168,1,0,0,0,168,169,5,42,
        0,0,169,170,3,78,39,0,170,179,1,0,0,0,171,173,3,14,7,0,172,174,5,
        43,0,0,173,172,1,0,0,0,173,174,1,0,0,0,174,175,1,0,0,0,175,176,5,
        48,0,0,176,177,3,78,39,0,177,179,1,0,0,0,178,164,1,0,0,0,178,171,
        1,0,0,0,179,13,1,0,0,0,180,186,3,16,8,0,181,182,3,16,8,0,182,183,
        3,80,40,0,183,184,3,16,8,0,184,186,1,0,0,0,185,180,1,0,0,0,185,181,
        1,0,0,0,186,15,1,0,0,0,187,188,6,8,-1,0,188,192,3,18,9,0,189,190,
        7,0,0,0,190,192,3,16,8,3,191,187,1,0,0,0,191,189,1,0,0,0,192,201,
        1,0,0,0,193,194,10,2,0,0,194,195,7,1,0,0,195,200,3,16,8,3,196,197,
        10,1,0,0,197,198,7,0,0,0,198,200,3,16,8,2,199,193,1,0,0,0,199,196,
        1,0,0,0,200,203,1,0,0,0,201,199,1,0,0,0,201,202,1,0,0,0,202,17,1,
        0,0,0,203,201,1,0,0,0,204,225,3,44,22,0,205,225,3,40,20,0,206,207,
        5,40,0,0,207,208,3,10,5,0,208,209,5,49,0,0,209,225,1,0,0,0,210,211,
        3,42,21,0,211,220,5,40,0,0,212,217,3,10,5,0,213,214,5,34,0,0,214,
        216,3,10,5,0,215,213,1,0,0,0,216,219,1,0,0,0,217,215,1,0,0,0,217,
        218,1,0,0,0,218,221,1,0,0,0,219,217,1,0,0,0,220,212,1,0,0,0,220,
        221,1,0,0,0,221,222,1,0,0,0,222,223,5,49,0,0,223,225,1,0,0,0,224,
        204,1,0,0,0,224,205,1,0,0,0,224,206,1,0,0,0,224,210,1,0,0,0,225,
        19,1,0,0,0,226,227,5,14,0,0,227,228,3,22,11,0,228,21,1,0,0,0,229,
        234,3,24,12,0,230,231,5,34,0,0,231,233,3,24,12,0,232,230,1,0,0,0,
        233,236,1,0,0,0,234,232,1,0,0,0,234,235,1,0,0,0,235,23,1,0,0,0,236,
        234,1,0,0,0,237,243,3,10,5,0,238,239,3,40,20,0,239,240,5,33,0,0,
        240,241,3,10,5,0,241,243,1,0,0,0,242,237,1,0,0,0,242,238,1,0,0,0,
        243,25,1,0,0,0,244,245,5,6,0,0,245,250,3,38,19,0,246,247,5,34,0,
        0,247,249,3,38,19,0,248,246,1,0,0,0,249,252,1,0,0,0,250,248,1,0,
        0,0,250,251,1,0,0,0,251,254,1,0,0,0,252,250,1,0,0,0,253,255,3,28,
        14,0,254,253,1,0,0,0,254,255,1,0,0,0,255,27,1,0,0,0,256,257,5,64,
        0,0,257,258,5,72,0,0,258,263,3,38,19,0,259,260,5,34,0,0,260,262,
        3,38,19,0,261,259,1,0,0,0,262,265,1,0,0,0,263,261,1,0,0,0,263,264,
        1,0,0,0,264,266,1,0,0,0,265,263,1,0,0,0,266,267,5,65,0,0,267,29,
        1,0,0,0,268,269,5,4,0,0,269,270,3,22,11,0,270,31,1,0,0,0,271,273,
        5,17,0,0,272,274,3,22,11,0,273,272,1,0,0,0,273,274,1,0,0,0,274,277,
        1,0,0,0,275,276,5,30,0,0,276,278,3,36,18,0,277,275,1,0,0,0,277,278,
        1,0,0,0,278,33,1,0,0,0,279,280,5,8,0,0,280,283,3,22,11,0,281,282,
        5,30,0,0,282,284,3,36,18,0,283,281,1,0,0,0,283,284,1,0,0,0,284,35,
        1,0,0,0,285,290,3,40,20,0,286,287,5,34,0,0,287,289,3,40,20,0,288,
        286,1,0,0,0,289,292,1,0,0,0,290,288,1,0,0,0,290,291,1,0,0,0,291,
        37,1,0,0,0,292,290,1,0,0,0,293,294,7,2,0,0,294,39,1,0,0,0,295,300,
        3,42,21,0,296,297,5,36,0,0,297,299,3,42,21,0,298,296,1,0,0,0,299,
        302,1,0,0,0,300,298,1,0,0,0,300,301,1,0,0,0,301,41,1,0,0,0,302,300,
        1,0,0,0,303,304,7,3,0,0,304,43,1,0,0,0,305,348,5,44,0,0,306,307,
        3,76,38,0,307,308,5,66,0,0,308,348,1,0,0,0,309,348,3,74,37,0,310,
        348,3,76,38,0,311,348,3,70,35,0,312,348,5,47,0,0,313,348,3,78,39,
        0,314,315,5,64,0,0,315,320,3,72,36,0,316,317,5,34,0,0,317,319,3,
        72,36,0,318,316,1,0,0,0,319,322,1,0,0,0,320,318,1,0,0,0,320,321,
        1,0,0,0,321,323,1,0,0,0,322,320,1,0,0,0,323,324,5,65,0,0,324,348,
        1,0,0,0,325,326,5,64,0,0,326,331,3,70,35,0,327,328,5,34,0,0,328,
        330,3,70,35,0,329,327,1,0,0,0,330,333,1,0,0,0,331,329,1,0,0,0,331,
        332,1,0,0,0,332,334,1,0,0,0,333,331,1,0,0,0,334,335,5,65,0,0,335,
        348,1,0,0,0,336,337,5,64,0,0,337,342,3,78,39,0,338,339,5,34,0,0,
        339,341,3,78,39,0,340,338,1,0,0,0,341,344,1,0,0,0,342,340,1,0,0,
        0,342,343,1,0,0,0,343,345,1,0,0,0,344,342,1,0,0,0,345,346,5,65,0,
        0,346,348,1,0,0,0,347,305,1,0,0,0,347,306,1,0,0,0,347,309,1,0,0,
        0,347,310,1,0,0,0,347,311,1,0,0,0,347,312,1,0,0,0,347,313,1,0,0,
        0,347,314,1,0,0,0,347,325,1,0,0,0,347,336,1,0,0,0,348,45,1,0,0,0,
        349,350,5,10,0,0,350,351,5,28,0,0,351,47,1,0,0,0,352,353,5,16,0,
        0,353,358,3,50,25,0,354,355,5,34,0,0,355,357,3,50,25,0,356,354,1,
        0,0,0,357,360,1,0,0,0,358,356,1,0,0,0,358,359,1,0,0,0,359,49,1,0,
        0,0,360,358,1,0,0,0,361,363,3,10,5,0,362,364,7,4,0,0,363,362,1,0,
        0,0,363,364,1,0,0,0,364,367,1,0,0,0,365,366,5,45,0,0,366,368,7,5,
        0,0,367,365,1,0,0,0,367,368,1,0,0,0,368,51,1,0,0,0,369,370,5,9,0,
        0,370,375,3,38,19,0,371,372,5,34,0,0,372,374,3,38,19,0,373,371,1,
        0,0,0,374,377,1,0,0,0,375,373,1,0,0,0,375,376,1,0,0,0,376,388,1,
        0,0,0,377,375,1,0,0,0,378,379,5,12,0,0,379,384,3,38,19,0,380,381,
        5,34,0,0,381,383,3,38,19,0,382,380,1,0,0,0,383,386,1,0,0,0,384,382,
        1,0,0,0,384,385,1,0,0,0,385,388,1,0,0,0,386,384,1,0,0,0,387,369,
        1,0,0,0,387,378,1,0,0,0,388,53,1,0,0,0,389,390,5,2,0,0,390,395,3,
        38,19,0,391,392,5,34,0,0,392,394,3,38,19,0,393,391,1,0,0,0,394,397,
        1,0,0,0,395,393,1,0,0,0,395,396,1,0,0,0,396,55,1,0,0,0,397,395,1,
        0,0,0,398,399,5,13,0,0,399,404,3,58,29,0,400,401,5,34,0,0,401,403,
        3,58,29,0,402,400,1,0,0,0,403,406,1,0,0,0,404,402,1,0,0,0,404,405,
        1,0,0,0,405,57,1,0,0,0,406,404,1,0,0,0,407,408,3,38,19,0,408,409,
        5,71,0,0,409,410,3,38,19,0,410,59,1,0,0,0,411,412,5,1,0,0,412,413,
        3,18,9,0,413,415,3,78,39,0,414,416,3,66,33,0,415,414,1,0,0,0,415,
        416,1,0,0,0,416,61,1,0,0,0,417,418,5,7,0,0,418,419,3,18,9,0,419,
        420,3,78,39,0,420,63,1,0,0,0,421,422,5,11,0,0,422,423,3,38,19,0,
        423,65,1,0,0,0,424,429,3,68,34,0,425,426,5,34,0,0,426,428,3,68,34,
        0,427,425,1,0,0,0,428,431,1,0,0,0,429,427,1,0,0,0,429,430,1,0,0,
        0,430,67,1,0,0,0,431,429,1,0,0,0,432,433,3,42,21,0,433,434,5,33,
        0,0,434,435,3,44,22,0,435,69,1,0,0,0,436,437,7,6,0,0,437,71,1,0,
        0,0,438,441,3,74,37,0,439,441,3,76,38,0,440,438,1,0,0,0,440,439,
        1,0,0,0,441,73,1,0,0,0,442,443,5,29,0,0,443,75,1,0,0,0,444,445,5,
        28,0,0,445,77,1,0,0,0,446,447,5,27,0,0,447,79,1,0,0,0,448,449,7,
        7,0,0,449,81,1,0,0,0,450,451,5,5,0,0,451,452,3,84,42,0,452,83,1,
        0,0,0,453,454,5,64,0,0,454,455,3,2,1,0,455,456,5,65,0,0,456,85,1,
        0,0,0,457,458,5,15,0,0,458,462,5,51,0,0,459,460,5,15,0,0,460,462,
        5,52,0,0,461,457,1,0,0,0,461,459,1,0,0,0,462,87,1,0,0,0,463,464,
        5,3,0,0,464,467,3,38,19,0,465,466,5,73,0,0,466,468,3,38,19,0,467,
        465,1,0,0,0,467,468,1,0,0,0,468,478,1,0,0,0,469,470,5,74,0,0,470,
        475,3,90,45,0,471,472,5,34,0,0,472,474,3,90,45,0,473,471,1,0,0,0,
        474,477,1,0,0,0,475,473,1,0,0,0,475,476,1,0,0,0,476,479,1,0,0,0,
        477,475,1,0,0,0,478,469,1,0,0,0,478,479,1,0,0,0,479,89,1,0,0,0,480,
        481,3,38,19,0,481,482,5,33,0,0,482,484,1,0,0,0,483,480,1,0,0,0,483,
        484,1,0,0,0,484,485,1,0,0,0,485,486,3,38,19,0,486,91,1,0,0,0,48,
        103,110,125,137,146,151,159,161,166,173,178,185,191,199,201,217,
        220,224,234,242,250,254,263,273,277,283,290,300,320,331,342,347,
        358,363,367,375,384,387,395,404,415,429,440,461,467,475,478,483
    ]

class EsqlBaseParser ( Parser ):

    grammarFileName = "EsqlBaseParser.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "'dissect'", "'drop'", "'enrich'", "'eval'",
                     "'explain'", "'from'", "'grok'", "'inlinestats'", "'keep'",
                     "'limit'", "'mv_expand'", "'project'", "'rename'",
                     "'row'", "'show'", "'sort'", "'stats'", "'where'",
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>",
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>",
                     "<INVALID>", "<INVALID>", "<INVALID>", "'by'", "'and'",
                     "'asc'", "<INVALID>", "<INVALID>", "'desc'", "'.'",
                     "'false'", "'first'", "'last'", "'('", "'in'", "'like'",
                     "'not'", "'null'", "'nulls'", "'or'", "'?'", "'rlike'",
                     "')'", "'true'", "'info'", "'functions'", "'=='", "'!='",
                     "'<'", "'<='", "'>'", "'>='", "'+'", "'-'", "'*'",
                     "'/'", "'%'", "<INVALID>", "']'", "<INVALID>", "<INVALID>",
                     "<INVALID>", "<INVALID>", "<INVALID>", "'as'", "'metadata'",
                     "'on'", "'with'" ]

    symbolicNames = [ "<INVALID>", "DISSECT", "DROP", "ENRICH", "EVAL",
                      "EXPLAIN", "FROM", "GROK", "INLINESTATS", "KEEP",
                      "LIMIT", "MV_EXPAND", "PROJECT", "RENAME", "ROW",
                      "SHOW", "SORT", "STATS", "WHERE", "UNKNOWN_CMD", "LINE_COMMENT",
                      "MULTILINE_COMMENT", "WS", "EXPLAIN_WS", "EXPLAIN_LINE_COMMENT",
                      "EXPLAIN_MULTILINE_COMMENT", "PIPE", "STRING", "INTEGER_LITERAL",
                      "DECIMAL_LITERAL", "BY", "AND", "ASC", "ASSIGN", "COMMA",
                      "DESC", "DOT", "FALSE", "FIRST", "LAST", "LP", "IN",
                      "LIKE", "NOT", "NULL", "NULLS", "OR", "PARAM", "RLIKE",
                      "RP", "TRUE", "INFO", "FUNCTIONS", "EQ", "NEQ", "LT",
                      "LTE", "GT", "GTE", "PLUS", "MINUS", "ASTERISK", "SLASH",
                      "PERCENT", "OPENING_BRACKET", "CLOSING_BRACKET", "UNQUOTED_IDENTIFIER",
                      "QUOTED_IDENTIFIER", "EXPR_LINE_COMMENT", "EXPR_MULTILINE_COMMENT",
                      "EXPR_WS", "AS", "METADATA", "ON", "WITH", "SRC_UNQUOTED_IDENTIFIER",
                      "SRC_QUOTED_IDENTIFIER", "SRC_LINE_COMMENT", "SRC_MULTILINE_COMMENT",
                      "SRC_WS", "EXPLAIN_PIPE" ]

    RULE_singleStatement = 0
    RULE_query = 1
    RULE_sourceCommand = 2
    RULE_processingCommand = 3
    RULE_whereCommand = 4
    RULE_booleanExpression = 5
    RULE_regexBooleanExpression = 6
    RULE_valueExpression = 7
    RULE_operatorExpression = 8
    RULE_primaryExpression = 9
    RULE_rowCommand = 10
    RULE_fields = 11
    RULE_field = 12
    RULE_fromCommand = 13
    RULE_metadata = 14
    RULE_evalCommand = 15
    RULE_statsCommand = 16
    RULE_inlinestatsCommand = 17
    RULE_grouping = 18
    RULE_sourceIdentifier = 19
    RULE_qualifiedName = 20
    RULE_identifier = 21
    RULE_constant = 22
    RULE_limitCommand = 23
    RULE_sortCommand = 24
    RULE_orderExpression = 25
    RULE_keepCommand = 26
    RULE_dropCommand = 27
    RULE_renameCommand = 28
    RULE_renameClause = 29
    RULE_dissectCommand = 30
    RULE_grokCommand = 31
    RULE_mvExpandCommand = 32
    RULE_commandOptions = 33
    RULE_commandOption = 34
    RULE_booleanValue = 35
    RULE_numericValue = 36
    RULE_decimalValue = 37
    RULE_integerValue = 38
    RULE_string = 39
    RULE_comparisonOperator = 40
    RULE_explainCommand = 41
    RULE_subqueryExpression = 42
    RULE_showCommand = 43
    RULE_enrichCommand = 44
    RULE_enrichWithClause = 45

    ruleNames =  [ "singleStatement", "query", "sourceCommand", "processingCommand",
                   "whereCommand", "booleanExpression", "regexBooleanExpression",
                   "valueExpression", "operatorExpression", "primaryExpression",
                   "rowCommand", "fields", "field", "fromCommand", "metadata",
                   "evalCommand", "statsCommand", "inlinestatsCommand",
                   "grouping", "sourceIdentifier", "qualifiedName", "identifier",
                   "constant", "limitCommand", "sortCommand", "orderExpression",
                   "keepCommand", "dropCommand", "renameCommand", "renameClause",
                   "dissectCommand", "grokCommand", "mvExpandCommand", "commandOptions",
                   "commandOption", "booleanValue", "numericValue", "decimalValue",
                   "integerValue", "string", "comparisonOperator", "explainCommand",
                   "subqueryExpression", "showCommand", "enrichCommand",
                   "enrichWithClause" ]

    EOF = Token.EOF
    DISSECT=1
    DROP=2
    ENRICH=3
    EVAL=4
    EXPLAIN=5
    FROM=6
    GROK=7
    INLINESTATS=8
    KEEP=9
    LIMIT=10
    MV_EXPAND=11
    PROJECT=12
    RENAME=13
    ROW=14
    SHOW=15
    SORT=16
    STATS=17
    WHERE=18
    UNKNOWN_CMD=19
    LINE_COMMENT=20
    MULTILINE_COMMENT=21
    WS=22
    EXPLAIN_WS=23
    EXPLAIN_LINE_COMMENT=24
    EXPLAIN_MULTILINE_COMMENT=25
    PIPE=26
    STRING=27
    INTEGER_LITERAL=28
    DECIMAL_LITERAL=29
    BY=30
    AND=31
    ASC=32
    ASSIGN=33
    COMMA=34
    DESC=35
    DOT=36
    FALSE=37
    FIRST=38
    LAST=39
    LP=40
    IN=41
    LIKE=42
    NOT=43
    NULL=44
    NULLS=45
    OR=46
    PARAM=47
    RLIKE=48
    RP=49
    TRUE=50
    INFO=51
    FUNCTIONS=52
    EQ=53
    NEQ=54
    LT=55
    LTE=56
    GT=57
    GTE=58
    PLUS=59
    MINUS=60
    ASTERISK=61
    SLASH=62
    PERCENT=63
    OPENING_BRACKET=64
    CLOSING_BRACKET=65
    UNQUOTED_IDENTIFIER=66
    QUOTED_IDENTIFIER=67
    EXPR_LINE_COMMENT=68
    EXPR_MULTILINE_COMMENT=69
    EXPR_WS=70
    AS=71
    METADATA=72
    ON=73
    WITH=74
    SRC_UNQUOTED_IDENTIFIER=75
    SRC_QUOTED_IDENTIFIER=76
    SRC_LINE_COMMENT=77
    SRC_MULTILINE_COMMENT=78
    SRC_WS=79
    EXPLAIN_PIPE=80

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




    def singleStatement(self):

        localctx = EsqlBaseParser.SingleStatementContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_singleStatement)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 92
            self.query(0)
            self.state = 93
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

            self.state = 96
            self.sourceCommand()
            self._ctx.stop = self._input.LT(-1)
            self.state = 103
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,0,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    localctx = EsqlBaseParser.CompositeQueryContext(self, EsqlBaseParser.QueryContext(self, _parentctx, _parentState))
                    self.pushNewRecursionContext(localctx, _startState, self.RULE_query)
                    self.state = 98
                    if not self.precpred(self._ctx, 1):
                        from antlr4.error.Errors import FailedPredicateException
                        raise FailedPredicateException(self, "self.precpred(self._ctx, 1)")
                    self.state = 99
                    self.match(EsqlBaseParser.PIPE)
                    self.state = 100
                    self.processingCommand()
                self.state = 105
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


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_sourceCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSourceCommand" ):
                listener.enterSourceCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSourceCommand" ):
                listener.exitSourceCommand(self)




    def sourceCommand(self):

        localctx = EsqlBaseParser.SourceCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 4, self.RULE_sourceCommand)
        try:
            self.state = 110
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [5]:
                self.enterOuterAlt(localctx, 1)
                self.state = 106
                self.explainCommand()
                pass
            elif token in [6]:
                self.enterOuterAlt(localctx, 2)
                self.state = 107
                self.fromCommand()
                pass
            elif token in [14]:
                self.enterOuterAlt(localctx, 3)
                self.state = 108
                self.rowCommand()
                pass
            elif token in [15]:
                self.enterOuterAlt(localctx, 4)
                self.state = 109
                self.showCommand()
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


    class ProcessingCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def evalCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.EvalCommandContext,0)


        def inlinestatsCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.InlinestatsCommandContext,0)


        def limitCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.LimitCommandContext,0)


        def keepCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.KeepCommandContext,0)


        def sortCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.SortCommandContext,0)


        def statsCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.StatsCommandContext,0)


        def whereCommand(self):
            return self.getTypedRuleContext(EsqlBaseParser.WhereCommandContext,0)


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


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_processingCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterProcessingCommand" ):
                listener.enterProcessingCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitProcessingCommand" ):
                listener.exitProcessingCommand(self)




    def processingCommand(self):

        localctx = EsqlBaseParser.ProcessingCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 6, self.RULE_processingCommand)
        try:
            self.state = 125
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [4]:
                self.enterOuterAlt(localctx, 1)
                self.state = 112
                self.evalCommand()
                pass
            elif token in [8]:
                self.enterOuterAlt(localctx, 2)
                self.state = 113
                self.inlinestatsCommand()
                pass
            elif token in [10]:
                self.enterOuterAlt(localctx, 3)
                self.state = 114
                self.limitCommand()
                pass
            elif token in [9, 12]:
                self.enterOuterAlt(localctx, 4)
                self.state = 115
                self.keepCommand()
                pass
            elif token in [16]:
                self.enterOuterAlt(localctx, 5)
                self.state = 116
                self.sortCommand()
                pass
            elif token in [17]:
                self.enterOuterAlt(localctx, 6)
                self.state = 117
                self.statsCommand()
                pass
            elif token in [18]:
                self.enterOuterAlt(localctx, 7)
                self.state = 118
                self.whereCommand()
                pass
            elif token in [2]:
                self.enterOuterAlt(localctx, 8)
                self.state = 119
                self.dropCommand()
                pass
            elif token in [13]:
                self.enterOuterAlt(localctx, 9)
                self.state = 120
                self.renameCommand()
                pass
            elif token in [1]:
                self.enterOuterAlt(localctx, 10)
                self.state = 121
                self.dissectCommand()
                pass
            elif token in [7]:
                self.enterOuterAlt(localctx, 11)
                self.state = 122
                self.grokCommand()
                pass
            elif token in [3]:
                self.enterOuterAlt(localctx, 12)
                self.state = 123
                self.enrichCommand()
                pass
            elif token in [11]:
                self.enterOuterAlt(localctx, 13)
                self.state = 124
                self.mvExpandCommand()
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




    def whereCommand(self):

        localctx = EsqlBaseParser.WhereCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 8, self.RULE_whereCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 127
            self.match(EsqlBaseParser.WHERE)
            self.state = 128
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
            self.state = 151
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,5,self._ctx)
            if la_ == 1:
                localctx = EsqlBaseParser.LogicalNotContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx

                self.state = 131
                self.match(EsqlBaseParser.NOT)
                self.state = 132
                self.booleanExpression(6)
                pass

            elif la_ == 2:
                localctx = EsqlBaseParser.BooleanDefaultContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 133
                self.valueExpression()
                pass

            elif la_ == 3:
                localctx = EsqlBaseParser.RegexExpressionContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 134
                self.regexBooleanExpression()
                pass

            elif la_ == 4:
                localctx = EsqlBaseParser.LogicalInContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 135
                self.valueExpression()
                self.state = 137
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==43:
                    self.state = 136
                    self.match(EsqlBaseParser.NOT)


                self.state = 139
                self.match(EsqlBaseParser.IN)
                self.state = 140
                self.match(EsqlBaseParser.LP)
                self.state = 141
                self.valueExpression()
                self.state = 146
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==34:
                    self.state = 142
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 143
                    self.valueExpression()
                    self.state = 148
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 149
                self.match(EsqlBaseParser.RP)
                pass


            self._ctx.stop = self._input.LT(-1)
            self.state = 161
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,7,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    self.state = 159
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,6,self._ctx)
                    if la_ == 1:
                        localctx = EsqlBaseParser.LogicalBinaryContext(self, EsqlBaseParser.BooleanExpressionContext(self, _parentctx, _parentState))
                        localctx.left = _prevctx
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_booleanExpression)
                        self.state = 153
                        if not self.precpred(self._ctx, 3):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 3)")
                        self.state = 154
                        localctx.operator = self.match(EsqlBaseParser.AND)
                        self.state = 155
                        localctx.right = self.booleanExpression(4)
                        pass

                    elif la_ == 2:
                        localctx = EsqlBaseParser.LogicalBinaryContext(self, EsqlBaseParser.BooleanExpressionContext(self, _parentctx, _parentState))
                        localctx.left = _prevctx
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_booleanExpression)
                        self.state = 156
                        if not self.precpred(self._ctx, 2):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 2)")
                        self.state = 157
                        localctx.operator = self.match(EsqlBaseParser.OR)
                        self.state = 158
                        localctx.right = self.booleanExpression(3)
                        pass


                self.state = 163
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,7,self._ctx)

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
            self.kind = None # Token
            self.pattern = None # StringContext

        def valueExpression(self):
            return self.getTypedRuleContext(EsqlBaseParser.ValueExpressionContext,0)


        def LIKE(self):
            return self.getToken(EsqlBaseParser.LIKE, 0)

        def string(self):
            return self.getTypedRuleContext(EsqlBaseParser.StringContext,0)


        def NOT(self):
            return self.getToken(EsqlBaseParser.NOT, 0)

        def RLIKE(self):
            return self.getToken(EsqlBaseParser.RLIKE, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_regexBooleanExpression

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRegexBooleanExpression" ):
                listener.enterRegexBooleanExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRegexBooleanExpression" ):
                listener.exitRegexBooleanExpression(self)




    def regexBooleanExpression(self):

        localctx = EsqlBaseParser.RegexBooleanExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 12, self.RULE_regexBooleanExpression)
        self._la = 0 # Token type
        try:
            self.state = 178
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,10,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 164
                self.valueExpression()
                self.state = 166
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==43:
                    self.state = 165
                    self.match(EsqlBaseParser.NOT)


                self.state = 168
                localctx.kind = self.match(EsqlBaseParser.LIKE)
                self.state = 169
                localctx.pattern = self.string()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 171
                self.valueExpression()
                self.state = 173
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==43:
                    self.state = 172
                    self.match(EsqlBaseParser.NOT)


                self.state = 175
                localctx.kind = self.match(EsqlBaseParser.RLIKE)
                self.state = 176
                localctx.pattern = self.string()
                pass


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



    def valueExpression(self):

        localctx = EsqlBaseParser.ValueExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 14, self.RULE_valueExpression)
        try:
            self.state = 185
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,11,self._ctx)
            if la_ == 1:
                localctx = EsqlBaseParser.ValueExpressionDefaultContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 180
                self.operatorExpression(0)
                pass

            elif la_ == 2:
                localctx = EsqlBaseParser.ComparisonContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 181
                localctx.left = self.operatorExpression(0)
                self.state = 182
                self.comparisonOperator()
                self.state = 183
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



    def operatorExpression(self, _p:int=0):
        _parentctx = self._ctx
        _parentState = self.state
        localctx = EsqlBaseParser.OperatorExpressionContext(self, self._ctx, _parentState)
        _prevctx = localctx
        _startState = 16
        self.enterRecursionRule(localctx, 16, self.RULE_operatorExpression, _p)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 191
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [27, 28, 29, 37, 40, 44, 47, 50, 64, 66, 67]:
                localctx = EsqlBaseParser.OperatorExpressionDefaultContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx

                self.state = 188
                self.primaryExpression()
                pass
            elif token in [59, 60]:
                localctx = EsqlBaseParser.ArithmeticUnaryContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 189
                localctx.operator = self._input.LT(1)
                _la = self._input.LA(1)
                if not(_la==59 or _la==60):
                    localctx.operator = self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 190
                self.operatorExpression(3)
                pass
            else:
                raise NoViableAltException(self)

            self._ctx.stop = self._input.LT(-1)
            self.state = 201
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,14,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    self.state = 199
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,13,self._ctx)
                    if la_ == 1:
                        localctx = EsqlBaseParser.ArithmeticBinaryContext(self, EsqlBaseParser.OperatorExpressionContext(self, _parentctx, _parentState))
                        localctx.left = _prevctx
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_operatorExpression)
                        self.state = 193
                        if not self.precpred(self._ctx, 2):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 2)")
                        self.state = 194
                        localctx.operator = self._input.LT(1)
                        _la = self._input.LA(1)
                        if not((((_la) & ~0x3f) == 0 and ((1 << _la) & -2305843009213693952) != 0)):
                            localctx.operator = self._errHandler.recoverInline(self)
                        else:
                            self._errHandler.reportMatch(self)
                            self.consume()
                        self.state = 195
                        localctx.right = self.operatorExpression(3)
                        pass

                    elif la_ == 2:
                        localctx = EsqlBaseParser.ArithmeticBinaryContext(self, EsqlBaseParser.OperatorExpressionContext(self, _parentctx, _parentState))
                        localctx.left = _prevctx
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_operatorExpression)
                        self.state = 196
                        if not self.precpred(self._ctx, 1):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 1)")
                        self.state = 197
                        localctx.operator = self._input.LT(1)
                        _la = self._input.LA(1)
                        if not(_la==59 or _la==60):
                            localctx.operator = self._errHandler.recoverInline(self)
                        else:
                            self._errHandler.reportMatch(self)
                            self.consume()
                        self.state = 198
                        localctx.right = self.operatorExpression(2)
                        pass


                self.state = 203
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,14,self._ctx)

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


    class FunctionExpressionContext(PrimaryExpressionContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.PrimaryExpressionContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def identifier(self):
            return self.getTypedRuleContext(EsqlBaseParser.IdentifierContext,0)

        def LP(self):
            return self.getToken(EsqlBaseParser.LP, 0)
        def RP(self):
            return self.getToken(EsqlBaseParser.RP, 0)
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

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunctionExpression" ):
                listener.enterFunctionExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunctionExpression" ):
                listener.exitFunctionExpression(self)



    def primaryExpression(self):

        localctx = EsqlBaseParser.PrimaryExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 18, self.RULE_primaryExpression)
        self._la = 0 # Token type
        try:
            self.state = 224
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,17,self._ctx)
            if la_ == 1:
                localctx = EsqlBaseParser.ConstantDefaultContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 204
                self.constant()
                pass

            elif la_ == 2:
                localctx = EsqlBaseParser.DereferenceContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 205
                self.qualifiedName()
                pass

            elif la_ == 3:
                localctx = EsqlBaseParser.ParenthesizedExpressionContext(self, localctx)
                self.enterOuterAlt(localctx, 3)
                self.state = 206
                self.match(EsqlBaseParser.LP)
                self.state = 207
                self.booleanExpression(0)
                self.state = 208
                self.match(EsqlBaseParser.RP)
                pass

            elif la_ == 4:
                localctx = EsqlBaseParser.FunctionExpressionContext(self, localctx)
                self.enterOuterAlt(localctx, 4)
                self.state = 210
                self.identifier()
                self.state = 211
                self.match(EsqlBaseParser.LP)
                self.state = 220
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if ((((_la - 27)) & ~0x3f) == 0 and ((1 << (_la - 27)) & 1799600940039) != 0):
                    self.state = 212
                    self.booleanExpression(0)
                    self.state = 217
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    while _la==34:
                        self.state = 213
                        self.match(EsqlBaseParser.COMMA)
                        self.state = 214
                        self.booleanExpression(0)
                        self.state = 219
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)



                self.state = 222
                self.match(EsqlBaseParser.RP)
                pass


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




    def rowCommand(self):

        localctx = EsqlBaseParser.RowCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 20, self.RULE_rowCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 226
            self.match(EsqlBaseParser.ROW)
            self.state = 227
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




    def fields(self):

        localctx = EsqlBaseParser.FieldsContext(self, self._ctx, self.state)
        self.enterRule(localctx, 22, self.RULE_fields)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 229
            self.field()
            self.state = 234
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,18,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 230
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 231
                    self.field()
                self.state = 236
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,18,self._ctx)

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




    def field(self):

        localctx = EsqlBaseParser.FieldContext(self, self._ctx, self.state)
        self.enterRule(localctx, 24, self.RULE_field)
        try:
            self.state = 242
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,19,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 237
                self.booleanExpression(0)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 238
                self.qualifiedName()
                self.state = 239
                self.match(EsqlBaseParser.ASSIGN)
                self.state = 240
                self.booleanExpression(0)
                pass


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

        def sourceIdentifier(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.SourceIdentifierContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.SourceIdentifierContext,i)


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




    def fromCommand(self):

        localctx = EsqlBaseParser.FromCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 26, self.RULE_fromCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 244
            self.match(EsqlBaseParser.FROM)
            self.state = 245
            self.sourceIdentifier()
            self.state = 250
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,20,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 246
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 247
                    self.sourceIdentifier()
                self.state = 252
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,20,self._ctx)

            self.state = 254
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,21,self._ctx)
            if la_ == 1:
                self.state = 253
                self.metadata()


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

        def OPENING_BRACKET(self):
            return self.getToken(EsqlBaseParser.OPENING_BRACKET, 0)

        def METADATA(self):
            return self.getToken(EsqlBaseParser.METADATA, 0)

        def sourceIdentifier(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.SourceIdentifierContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.SourceIdentifierContext,i)


        def CLOSING_BRACKET(self):
            return self.getToken(EsqlBaseParser.CLOSING_BRACKET, 0)

        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_metadata

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterMetadata" ):
                listener.enterMetadata(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitMetadata" ):
                listener.exitMetadata(self)




    def metadata(self):

        localctx = EsqlBaseParser.MetadataContext(self, self._ctx, self.state)
        self.enterRule(localctx, 28, self.RULE_metadata)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 256
            self.match(EsqlBaseParser.OPENING_BRACKET)
            self.state = 257
            self.match(EsqlBaseParser.METADATA)
            self.state = 258
            self.sourceIdentifier()
            self.state = 263
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==34:
                self.state = 259
                self.match(EsqlBaseParser.COMMA)
                self.state = 260
                self.sourceIdentifier()
                self.state = 265
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 266
            self.match(EsqlBaseParser.CLOSING_BRACKET)
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




    def evalCommand(self):

        localctx = EsqlBaseParser.EvalCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 30, self.RULE_evalCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 268
            self.match(EsqlBaseParser.EVAL)
            self.state = 269
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

        def STATS(self):
            return self.getToken(EsqlBaseParser.STATS, 0)

        def fields(self):
            return self.getTypedRuleContext(EsqlBaseParser.FieldsContext,0)


        def BY(self):
            return self.getToken(EsqlBaseParser.BY, 0)

        def grouping(self):
            return self.getTypedRuleContext(EsqlBaseParser.GroupingContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_statsCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterStatsCommand" ):
                listener.enterStatsCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitStatsCommand" ):
                listener.exitStatsCommand(self)




    def statsCommand(self):

        localctx = EsqlBaseParser.StatsCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 32, self.RULE_statsCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 271
            self.match(EsqlBaseParser.STATS)
            self.state = 273
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,23,self._ctx)
            if la_ == 1:
                self.state = 272
                self.fields()


            self.state = 277
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,24,self._ctx)
            if la_ == 1:
                self.state = 275
                self.match(EsqlBaseParser.BY)
                self.state = 276
                self.grouping()


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

        def INLINESTATS(self):
            return self.getToken(EsqlBaseParser.INLINESTATS, 0)

        def fields(self):
            return self.getTypedRuleContext(EsqlBaseParser.FieldsContext,0)


        def BY(self):
            return self.getToken(EsqlBaseParser.BY, 0)

        def grouping(self):
            return self.getTypedRuleContext(EsqlBaseParser.GroupingContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_inlinestatsCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterInlinestatsCommand" ):
                listener.enterInlinestatsCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitInlinestatsCommand" ):
                listener.exitInlinestatsCommand(self)




    def inlinestatsCommand(self):

        localctx = EsqlBaseParser.InlinestatsCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 34, self.RULE_inlinestatsCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 279
            self.match(EsqlBaseParser.INLINESTATS)
            self.state = 280
            self.fields()
            self.state = 283
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,25,self._ctx)
            if la_ == 1:
                self.state = 281
                self.match(EsqlBaseParser.BY)
                self.state = 282
                self.grouping()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class GroupingContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def qualifiedName(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.QualifiedNameContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.QualifiedNameContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_grouping

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterGrouping" ):
                listener.enterGrouping(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitGrouping" ):
                listener.exitGrouping(self)




    def grouping(self):

        localctx = EsqlBaseParser.GroupingContext(self, self._ctx, self.state)
        self.enterRule(localctx, 36, self.RULE_grouping)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 285
            self.qualifiedName()
            self.state = 290
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,26,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 286
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 287
                    self.qualifiedName()
                self.state = 292
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,26,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SourceIdentifierContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def SRC_UNQUOTED_IDENTIFIER(self):
            return self.getToken(EsqlBaseParser.SRC_UNQUOTED_IDENTIFIER, 0)

        def SRC_QUOTED_IDENTIFIER(self):
            return self.getToken(EsqlBaseParser.SRC_QUOTED_IDENTIFIER, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_sourceIdentifier

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSourceIdentifier" ):
                listener.enterSourceIdentifier(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSourceIdentifier" ):
                listener.exitSourceIdentifier(self)




    def sourceIdentifier(self):

        localctx = EsqlBaseParser.SourceIdentifierContext(self, self._ctx, self.state)
        self.enterRule(localctx, 38, self.RULE_sourceIdentifier)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 293
            _la = self._input.LA(1)
            if not(_la==75 or _la==76):
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


    class QualifiedNameContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifier(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.IdentifierContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.IdentifierContext,i)


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




    def qualifiedName(self):

        localctx = EsqlBaseParser.QualifiedNameContext(self, self._ctx, self.state)
        self.enterRule(localctx, 40, self.RULE_qualifiedName)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 295
            self.identifier()
            self.state = 300
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,27,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 296
                    self.match(EsqlBaseParser.DOT)
                    self.state = 297
                    self.identifier()
                self.state = 302
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,27,self._ctx)

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




    def identifier(self):

        localctx = EsqlBaseParser.IdentifierContext(self, self._ctx, self.state)
        self.enterRule(localctx, 42, self.RULE_identifier)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 303
            _la = self._input.LA(1)
            if not(_la==66 or _la==67):
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


    class InputParamContext(ConstantContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ConstantContext
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



    def constant(self):

        localctx = EsqlBaseParser.ConstantContext(self, self._ctx, self.state)
        self.enterRule(localctx, 44, self.RULE_constant)
        self._la = 0 # Token type
        try:
            self.state = 347
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,31,self._ctx)
            if la_ == 1:
                localctx = EsqlBaseParser.NullLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 305
                self.match(EsqlBaseParser.NULL)
                pass

            elif la_ == 2:
                localctx = EsqlBaseParser.QualifiedIntegerLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 306
                self.integerValue()
                self.state = 307
                self.match(EsqlBaseParser.UNQUOTED_IDENTIFIER)
                pass

            elif la_ == 3:
                localctx = EsqlBaseParser.DecimalLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 3)
                self.state = 309
                self.decimalValue()
                pass

            elif la_ == 4:
                localctx = EsqlBaseParser.IntegerLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 4)
                self.state = 310
                self.integerValue()
                pass

            elif la_ == 5:
                localctx = EsqlBaseParser.BooleanLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 5)
                self.state = 311
                self.booleanValue()
                pass

            elif la_ == 6:
                localctx = EsqlBaseParser.InputParamContext(self, localctx)
                self.enterOuterAlt(localctx, 6)
                self.state = 312
                self.match(EsqlBaseParser.PARAM)
                pass

            elif la_ == 7:
                localctx = EsqlBaseParser.StringLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 7)
                self.state = 313
                self.string()
                pass

            elif la_ == 8:
                localctx = EsqlBaseParser.NumericArrayLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 8)
                self.state = 314
                self.match(EsqlBaseParser.OPENING_BRACKET)
                self.state = 315
                self.numericValue()
                self.state = 320
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==34:
                    self.state = 316
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 317
                    self.numericValue()
                    self.state = 322
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 323
                self.match(EsqlBaseParser.CLOSING_BRACKET)
                pass

            elif la_ == 9:
                localctx = EsqlBaseParser.BooleanArrayLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 9)
                self.state = 325
                self.match(EsqlBaseParser.OPENING_BRACKET)
                self.state = 326
                self.booleanValue()
                self.state = 331
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==34:
                    self.state = 327
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 328
                    self.booleanValue()
                    self.state = 333
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 334
                self.match(EsqlBaseParser.CLOSING_BRACKET)
                pass

            elif la_ == 10:
                localctx = EsqlBaseParser.StringArrayLiteralContext(self, localctx)
                self.enterOuterAlt(localctx, 10)
                self.state = 336
                self.match(EsqlBaseParser.OPENING_BRACKET)
                self.state = 337
                self.string()
                self.state = 342
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==34:
                    self.state = 338
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 339
                    self.string()
                    self.state = 344
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 345
                self.match(EsqlBaseParser.CLOSING_BRACKET)
                pass


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

        def INTEGER_LITERAL(self):
            return self.getToken(EsqlBaseParser.INTEGER_LITERAL, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_limitCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterLimitCommand" ):
                listener.enterLimitCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitLimitCommand" ):
                listener.exitLimitCommand(self)




    def limitCommand(self):

        localctx = EsqlBaseParser.LimitCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 46, self.RULE_limitCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 349
            self.match(EsqlBaseParser.LIMIT)
            self.state = 350
            self.match(EsqlBaseParser.INTEGER_LITERAL)
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




    def sortCommand(self):

        localctx = EsqlBaseParser.SortCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 48, self.RULE_sortCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 352
            self.match(EsqlBaseParser.SORT)
            self.state = 353
            self.orderExpression()
            self.state = 358
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,32,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 354
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 355
                    self.orderExpression()
                self.state = 360
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,32,self._ctx)

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




    def orderExpression(self):

        localctx = EsqlBaseParser.OrderExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 50, self.RULE_orderExpression)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 361
            self.booleanExpression(0)
            self.state = 363
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,33,self._ctx)
            if la_ == 1:
                self.state = 362
                localctx.ordering = self._input.LT(1)
                _la = self._input.LA(1)
                if not(_la==32 or _la==35):
                    localctx.ordering = self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()


            self.state = 367
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,34,self._ctx)
            if la_ == 1:
                self.state = 365
                self.match(EsqlBaseParser.NULLS)
                self.state = 366
                localctx.nullOrdering = self._input.LT(1)
                _la = self._input.LA(1)
                if not(_la==38 or _la==39):
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

        def sourceIdentifier(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.SourceIdentifierContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.SourceIdentifierContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def PROJECT(self):
            return self.getToken(EsqlBaseParser.PROJECT, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_keepCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterKeepCommand" ):
                listener.enterKeepCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitKeepCommand" ):
                listener.exitKeepCommand(self)




    def keepCommand(self):

        localctx = EsqlBaseParser.KeepCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 52, self.RULE_keepCommand)
        try:
            self.state = 387
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [9]:
                self.enterOuterAlt(localctx, 1)
                self.state = 369
                self.match(EsqlBaseParser.KEEP)
                self.state = 370
                self.sourceIdentifier()
                self.state = 375
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,35,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 371
                        self.match(EsqlBaseParser.COMMA)
                        self.state = 372
                        self.sourceIdentifier()
                    self.state = 377
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,35,self._ctx)

                pass
            elif token in [12]:
                self.enterOuterAlt(localctx, 2)
                self.state = 378
                self.match(EsqlBaseParser.PROJECT)
                self.state = 379
                self.sourceIdentifier()
                self.state = 384
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,36,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 380
                        self.match(EsqlBaseParser.COMMA)
                        self.state = 381
                        self.sourceIdentifier()
                    self.state = 386
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,36,self._ctx)

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


    class DropCommandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DROP(self):
            return self.getToken(EsqlBaseParser.DROP, 0)

        def sourceIdentifier(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.SourceIdentifierContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.SourceIdentifierContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(EsqlBaseParser.COMMA)
            else:
                return self.getToken(EsqlBaseParser.COMMA, i)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_dropCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterDropCommand" ):
                listener.enterDropCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitDropCommand" ):
                listener.exitDropCommand(self)




    def dropCommand(self):

        localctx = EsqlBaseParser.DropCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 54, self.RULE_dropCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 389
            self.match(EsqlBaseParser.DROP)
            self.state = 390
            self.sourceIdentifier()
            self.state = 395
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,38,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 391
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 392
                    self.sourceIdentifier()
                self.state = 397
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,38,self._ctx)

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




    def renameCommand(self):

        localctx = EsqlBaseParser.RenameCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 56, self.RULE_renameCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 398
            self.match(EsqlBaseParser.RENAME)
            self.state = 399
            self.renameClause()
            self.state = 404
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,39,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 400
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 401
                    self.renameClause()
                self.state = 406
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,39,self._ctx)

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
            self.oldName = None # SourceIdentifierContext
            self.newName = None # SourceIdentifierContext

        def AS(self):
            return self.getToken(EsqlBaseParser.AS, 0)

        def sourceIdentifier(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.SourceIdentifierContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.SourceIdentifierContext,i)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_renameClause

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRenameClause" ):
                listener.enterRenameClause(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRenameClause" ):
                listener.exitRenameClause(self)




    def renameClause(self):

        localctx = EsqlBaseParser.RenameClauseContext(self, self._ctx, self.state)
        self.enterRule(localctx, 58, self.RULE_renameClause)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 407
            localctx.oldName = self.sourceIdentifier()
            self.state = 408
            self.match(EsqlBaseParser.AS)
            self.state = 409
            localctx.newName = self.sourceIdentifier()
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




    def dissectCommand(self):

        localctx = EsqlBaseParser.DissectCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 60, self.RULE_dissectCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 411
            self.match(EsqlBaseParser.DISSECT)
            self.state = 412
            self.primaryExpression()
            self.state = 413
            self.string()
            self.state = 415
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,40,self._ctx)
            if la_ == 1:
                self.state = 414
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




    def grokCommand(self):

        localctx = EsqlBaseParser.GrokCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 62, self.RULE_grokCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 417
            self.match(EsqlBaseParser.GROK)
            self.state = 418
            self.primaryExpression()
            self.state = 419
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

        def sourceIdentifier(self):
            return self.getTypedRuleContext(EsqlBaseParser.SourceIdentifierContext,0)


        def getRuleIndex(self):
            return EsqlBaseParser.RULE_mvExpandCommand

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterMvExpandCommand" ):
                listener.enterMvExpandCommand(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitMvExpandCommand" ):
                listener.exitMvExpandCommand(self)




    def mvExpandCommand(self):

        localctx = EsqlBaseParser.MvExpandCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 64, self.RULE_mvExpandCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 421
            self.match(EsqlBaseParser.MV_EXPAND)
            self.state = 422
            self.sourceIdentifier()
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




    def commandOptions(self):

        localctx = EsqlBaseParser.CommandOptionsContext(self, self._ctx, self.state)
        self.enterRule(localctx, 66, self.RULE_commandOptions)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 424
            self.commandOption()
            self.state = 429
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,41,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 425
                    self.match(EsqlBaseParser.COMMA)
                    self.state = 426
                    self.commandOption()
                self.state = 431
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,41,self._ctx)

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




    def commandOption(self):

        localctx = EsqlBaseParser.CommandOptionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 68, self.RULE_commandOption)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 432
            self.identifier()
            self.state = 433
            self.match(EsqlBaseParser.ASSIGN)
            self.state = 434
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




    def booleanValue(self):

        localctx = EsqlBaseParser.BooleanValueContext(self, self._ctx, self.state)
        self.enterRule(localctx, 70, self.RULE_booleanValue)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 436
            _la = self._input.LA(1)
            if not(_la==37 or _la==50):
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




    def numericValue(self):

        localctx = EsqlBaseParser.NumericValueContext(self, self._ctx, self.state)
        self.enterRule(localctx, 72, self.RULE_numericValue)
        try:
            self.state = 440
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [29]:
                self.enterOuterAlt(localctx, 1)
                self.state = 438
                self.decimalValue()
                pass
            elif token in [28]:
                self.enterOuterAlt(localctx, 2)
                self.state = 439
                self.integerValue()
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


    class DecimalValueContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DECIMAL_LITERAL(self):
            return self.getToken(EsqlBaseParser.DECIMAL_LITERAL, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_decimalValue

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterDecimalValue" ):
                listener.enterDecimalValue(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitDecimalValue" ):
                listener.exitDecimalValue(self)




    def decimalValue(self):

        localctx = EsqlBaseParser.DecimalValueContext(self, self._ctx, self.state)
        self.enterRule(localctx, 74, self.RULE_decimalValue)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 442
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

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_integerValue

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIntegerValue" ):
                listener.enterIntegerValue(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIntegerValue" ):
                listener.exitIntegerValue(self)




    def integerValue(self):

        localctx = EsqlBaseParser.IntegerValueContext(self, self._ctx, self.state)
        self.enterRule(localctx, 76, self.RULE_integerValue)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 444
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

        def STRING(self):
            return self.getToken(EsqlBaseParser.STRING, 0)

        def getRuleIndex(self):
            return EsqlBaseParser.RULE_string

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterString" ):
                listener.enterString(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitString" ):
                listener.exitString(self)




    def string(self):

        localctx = EsqlBaseParser.StringContext(self, self._ctx, self.state)
        self.enterRule(localctx, 78, self.RULE_string)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 446
            self.match(EsqlBaseParser.STRING)
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




    def comparisonOperator(self):

        localctx = EsqlBaseParser.ComparisonOperatorContext(self, self._ctx, self.state)
        self.enterRule(localctx, 80, self.RULE_comparisonOperator)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 448
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 567453553048682496) != 0)):
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




    def explainCommand(self):

        localctx = EsqlBaseParser.ExplainCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 82, self.RULE_explainCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 450
            self.match(EsqlBaseParser.EXPLAIN)
            self.state = 451
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




    def subqueryExpression(self):

        localctx = EsqlBaseParser.SubqueryExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 84, self.RULE_subqueryExpression)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 453
            self.match(EsqlBaseParser.OPENING_BRACKET)
            self.state = 454
            self.query(0)
            self.state = 455
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


    class ShowFunctionsContext(ShowCommandContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a EsqlBaseParser.ShowCommandContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def SHOW(self):
            return self.getToken(EsqlBaseParser.SHOW, 0)
        def FUNCTIONS(self):
            return self.getToken(EsqlBaseParser.FUNCTIONS, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterShowFunctions" ):
                listener.enterShowFunctions(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitShowFunctions" ):
                listener.exitShowFunctions(self)



    def showCommand(self):

        localctx = EsqlBaseParser.ShowCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 86, self.RULE_showCommand)
        try:
            self.state = 461
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,43,self._ctx)
            if la_ == 1:
                localctx = EsqlBaseParser.ShowInfoContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 457
                self.match(EsqlBaseParser.SHOW)
                self.state = 458
                self.match(EsqlBaseParser.INFO)
                pass

            elif la_ == 2:
                localctx = EsqlBaseParser.ShowFunctionsContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 459
                self.match(EsqlBaseParser.SHOW)
                self.state = 460
                self.match(EsqlBaseParser.FUNCTIONS)
                pass


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
            self.policyName = None # SourceIdentifierContext
            self.matchField = None # SourceIdentifierContext

        def ENRICH(self):
            return self.getToken(EsqlBaseParser.ENRICH, 0)

        def sourceIdentifier(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.SourceIdentifierContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.SourceIdentifierContext,i)


        def ON(self):
            return self.getToken(EsqlBaseParser.ON, 0)

        def WITH(self):
            return self.getToken(EsqlBaseParser.WITH, 0)

        def enrichWithClause(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.EnrichWithClauseContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.EnrichWithClauseContext,i)


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




    def enrichCommand(self):

        localctx = EsqlBaseParser.EnrichCommandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 88, self.RULE_enrichCommand)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 463
            self.match(EsqlBaseParser.ENRICH)
            self.state = 464
            localctx.policyName = self.sourceIdentifier()
            self.state = 467
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,44,self._ctx)
            if la_ == 1:
                self.state = 465
                self.match(EsqlBaseParser.ON)
                self.state = 466
                localctx.matchField = self.sourceIdentifier()


            self.state = 478
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,46,self._ctx)
            if la_ == 1:
                self.state = 469
                self.match(EsqlBaseParser.WITH)
                self.state = 470
                self.enrichWithClause()
                self.state = 475
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,45,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 471
                        self.match(EsqlBaseParser.COMMA)
                        self.state = 472
                        self.enrichWithClause()
                    self.state = 477
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,45,self._ctx)



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
            self.newName = None # SourceIdentifierContext
            self.enrichField = None # SourceIdentifierContext

        def sourceIdentifier(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(EsqlBaseParser.SourceIdentifierContext)
            else:
                return self.getTypedRuleContext(EsqlBaseParser.SourceIdentifierContext,i)


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




    def enrichWithClause(self):

        localctx = EsqlBaseParser.EnrichWithClauseContext(self, self._ctx, self.state)
        self.enterRule(localctx, 90, self.RULE_enrichWithClause)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 483
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,47,self._ctx)
            if la_ == 1:
                self.state = 480
                localctx.newName = self.sourceIdentifier()
                self.state = 481
                self.match(EsqlBaseParser.ASSIGN)


            self.state = 485
            localctx.enrichField = self.sourceIdentifier()
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
        self._predicates[5] = self.booleanExpression_sempred
        self._predicates[8] = self.operatorExpression_sempred
        pred = self._predicates.get(ruleIndex, None)
        if pred is None:
            raise Exception("No predicate with index:" + str(ruleIndex))
        else:
            return pred(localctx, predIndex)

    def query_sempred(self, localctx:QueryContext, predIndex:int):
            if predIndex == 0:
                return self.precpred(self._ctx, 1)


    def booleanExpression_sempred(self, localctx:BooleanExpressionContext, predIndex:int):
            if predIndex == 1:
                return self.precpred(self._ctx, 3)


            if predIndex == 2:
                return self.precpred(self._ctx, 2)


    def operatorExpression_sempred(self, localctx:OperatorExpressionContext, predIndex:int):
            if predIndex == 3:
                return self.precpred(self._ctx, 2)


            if predIndex == 4:
                return self.precpred(self._ctx, 1)





