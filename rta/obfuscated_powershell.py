# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Obfuscated PowerShell Commands
# RTA: obfuscated_powershell.py
# ATT&CK: T1027,T1140,T1192,T1193
# Description:   Runs commands through PowerShell that are obfuscated using multiple techniques.
import time

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a52a72cb-6fc7-48b2-b365-8479a6cdb2e6",
    platforms=["windows"],
    endpoint=[],
    siem=[],
    techniques=[]
)


@common.requires_os(*metadata.platforms)
def main():
    # All encoded versions of the following:
    # `iex("Write-Host 'This is my test command' -ForegroundColor Green; start c:\windows\system32\calc")`
    commands = r"""
        .($env:public[13]+$env:public[5]+'x')("Write-Host 'This is my test command' -ForegroundColor Green; start c:\windows\system32\calc.exe")
        iex((('W'+'rite-Hos'+'t no'+'HThi'+'s'+' is'+' my test comma'+'n'+'dnoH'+' '+'-F'+'oregroundCol'+'or G'+'r'+'e'+'en'+'; start'+' c:z'+'R'+'d'+'window'+'szRdsystem'+'3'+'2zRdca'+'lc').rEPlacE(([chaR]122+[chaR]82+[chaR]100),'\').rEPlacE('noH',[StrINg][chaR]39)))
        iex("W''rite-H''ost 'This is my test command' -Fore''grou''ndC''olor Gr''een; start c:\windows\system32\ca''lc.ex''e")
        iex("Write-Host 'This is my test command' -ForegroundColor Green; start c:\windows\system32\" + $env:public[-1] + "alc.exe")
        iex(((("{23}{7}{8}{16}{25}{9}{21}{18}{2}{5}{15}{11}{20}{24}{6}{12}{22}{17}{1}{13}{3}{10}{14}{19}{0}{4}" -f 'alc.ex','ndowsSDUsyst','dm4','2','e','H','r','r','ite-Ho','This i','S','oregroundC',' Gr','em3','DU',' -F','s','rt c:SDUwi','t comman','c','ol','s my tes','een; sta','W','o','t m4H')).rePlAce(([Char]109+[Char]52+[Char]72),[StrIng][Char]39).rePlAce(([Char]83+[Char]68+[Char]85),'\')))
        i`ex("Write-Host 'This is my t`est co`mmand' -ForegroundColor Gr`een; start c`:\wind`ows\syste`m32\calc.e`xe")
        &( ([StrIng]$vERbosEpreFereNCE)[1,3]+'x'-JoiN'') ([char[]]( 105 , 101 ,120 ,40 ,34 , 87,114 ,105,116,101 ,45,72 , 111,115,116, 32 , 39,84, 104,105 ,115 ,32, 105 , 115, 32 , 109 ,121 ,32 , 116 ,101,115 ,116 , 32 , 99, 111,109 ,109, 97 , 110,100 , 39 ,32,45,70,111 ,114 ,101, 103 ,114 ,111 ,117 ,110, 100, 67 ,111 ,108 , 111,114,32, 71 ,114, 101, 101, 110, 59, 32, 115 ,116,97, 114,116, 32, 99,58 ,92 , 119,105 ,110 , 100 , 111 , 119 , 115,92 ,115 , 121 ,115, 116, 101,109, 51 , 50 , 92,99, 97, 108 , 99,46 , 101, 120,101 , 34,41) -jOIN'' )
        " $( SET-vARiAble 'ofs'  '' )"+[StRInG]('69>65n78g28g22R57R72>69R74u65g2dR48M6fn73R74V20%27V54n68M69>73n20%69u73V20>6dV79>20V74M65%73g74>20M63M6fM6dn6dV61g6eR64>27M20M2d%46n6fM72M65M67>72>6fn75u6eV64>43g6fV6cM6fn72M20u47n72M65>65>6e%3bR20R73%74V61R72V74u20R63M3an5c%77%69g6e>64%6fg77n73u5cV73V79n73V74>65M6dn33%32V5cV63g61V6cg63%2eg65%78n65%22>29'.spLiT('Mu>RV%gn')| % { ( [chAr]([coNVErT]::tOINT16( ([sTRING]$_ ) ,16 ))) }) +" $(SET-Item 'vARiable:OFS' ' ' ) " |& ( $verbOsePREFeRENce.tOstrING()[1,3]+'X'-JOIn'')
        ${  }=  +$();  ${       }  =${  };  ${            }=  ++  ${  };${        }=  ++${  };  ${         }=++  ${  };${    }  =  ++  ${  };${ }=  ++  ${  };  ${           }  =  ++  ${  };${   }=++  ${  };  ${      }=  ++  ${  };${     }  =++  ${  };  ${          }  ="["  +  "$(@{}  )  "[  ${   }]  +  "$(@{})"[  "${            }${     }"  ]+"$(  @{}  )  "["${        }${       }"  ]  +  "$?  "[${            }]+  "]";${  }=  "".("$(  @{  }  )  "[  "${            }"+"${    }"  ]  +  "$(@{})"["${            }"  +"${           }"]+"$(  @{  }  )"[${       }]+  "$(@{  })  "[  ${    }  ]  +"$?"[${            }]  +  "$(@{  })  "[${         }]  );${  }  ="$(@{})"["${            }${    }"  ]+  "$(@{})"[  ${    }]  +"${  }"["${        }${   }"];  "${  }(${          }${            }${       }${ }  +  ${          }${            }${       }${            }+  ${          }${            }${        }${       }  +  ${          }${    }${       }+  ${          }${         }${    }  +  ${          }${      }${   }  +  ${          }${            }${            }${    }+  ${          }${            }${       }${ }+  ${          }${            }${            }${           }  +  ${          }${            }${       }${            }  +  ${          }${    }${ }+  ${          }${   }${        }+${          }${            }${            }${            }  +  ${          }${            }${            }${ }  +  ${          }${            }${            }${           }  +${          }${         }${        }+  ${          }${         }${     }+  ${          }${      }${    }+${          }${            }${       }${    }+${          }${            }${       }${ }+${          }${            }${            }${ }  +${          }${         }${        }  +  ${          }${            }${       }${ }  +  ${          }${            }${            }${ }  +  ${          }${         }${        }+${          }${            }${       }${     }  +${          }${            }${        }${            }+  ${          }${         }${        }  +${          }${            }${            }${           }+${          }${            }${       }${            }+${          }${            }${            }${ }+  ${          }${            }${            }${           }+  ${          }${         }${        }+  ${          }${     }${     }+${          }${            }${            }${            }  +${          }${            }${       }${     }  +${          }${            }${       }${     }  +  ${          }${     }${   }  +${          }${            }${            }${       }  +${          }${            }${       }${       }+  ${          }${         }${     }  +${          }${         }${        }  +${          }${    }${ }+${          }${   }${       }+${          }${            }${            }${            }  +  ${          }${            }${            }${    }  +  ${          }${            }${       }${            }+${          }${            }${       }${         }  +${          }${            }${            }${    }  +  ${          }${            }${            }${            }  +${          }${            }${            }${   }  +${          }${            }${            }${       }+${          }${            }${       }${       }+  ${          }${           }${   }  +  ${          }${            }${            }${            }  +${          }${            }${       }${      }+  ${          }${            }${            }${            }  +  ${          }${            }${            }${    }  +  ${          }${         }${        }  +  ${          }${   }${            }+  ${          }${            }${            }${    }  +${          }${            }${       }${            }+${          }${            }${       }${            }  +  ${          }${            }${            }${       }+${          }${ }${     }+${          }${         }${        }+  ${          }${            }${            }${ }+${          }${            }${            }${           }+  ${          }${     }${   }+${          }${            }${            }${    }+${          }${            }${            }${           }  +  ${          }${         }${        }+  ${          }${     }${     }  +  ${          }${ }${      }+${          }${     }${        }  +${          }${            }${            }${     }+${          }${            }${       }${ }  +  ${          }${            }${            }${       }+${          }${            }${       }${       }+  ${          }${            }${            }${            }+${          }${            }${            }${     }+${          }${            }${            }${ }+  ${          }${     }${        }  +${          }${            }${            }${ }  +${          }${            }${        }${            }  +  ${          }${            }${            }${ }+${          }${            }${            }${           }+  ${          }${            }${       }${            }+${          }${            }${       }${     }+${          }${ }${            }  +  ${          }${ }${       }  +  ${          }${     }${        }+${          }${     }${     }  +  ${          }${     }${   }  +${          }${            }${       }${      }+  ${          }${     }${     }  +  ${          }${    }${           }  +  ${          }${            }${       }${            }+  ${          }${            }${        }${       }  +${          }${            }${       }${            }+${          }${         }${    }  +  ${          }${    }${            }  )"|  &${  }
    """  # noqa: E501
    commands = [c.strip() for c in commands.splitlines()]

    for command in commands:
        common.execute(["powershell", "-c", command], shell=True)
        time.sleep(1)

    common.execute(["taskkill", "/F", "/im", "calc.exe"])
    common.execute(["taskkill", "/F", "/im", "calculator.exe"])


if __name__ == "__main__":
    main()
