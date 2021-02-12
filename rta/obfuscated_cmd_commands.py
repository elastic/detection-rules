# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Emulate Obfuscated cmd Commands
# RTA: obfuscated_cmd_commands.py
# ATT&CK: T1036
# Description: Runs commands through cmd that are obfuscated using multiple techniques.
import time

from . import common


@common.requires_os(common.WINDOWS)
def main():
    # All encoded versions of the following: `start calc && ping -n 2 127.0.0.1>nul && taskkill /im calc.exe`
    commands = """
        %comspec% /c "cm%OS:~-7,1% /c start%CommonProgramFiles(x86):~29,1%%PUBLIC:~-1%alc && ping -%APPDATA:~-2,-1% 2 127.0.0.1>nul &&%CommonProgramFiles(x86):~-6,1%taskkil%CommonProgramFiles:~-3,-2% /im %TMP:~-8,1%alc.exe
        cmd /c "%pUBLIc:~     14%%PRogRamFIleS:~   9,   -6%%Os:~      3,   -6% /%pubLIc:~      14,     1% s%TeMp:~     -13,      -12%%aPPdATA:~   -11,      1%%prograMfILeS(x86):~     -18,     1%%tMP:~    -13,    -12%%prOGRAMw6432:~     -6,     -5%%PubliC:~     14,    1%%Temp:~   -12,      -11%%tMP:~      -6,      1%%pubLic:~   14%%COmmONPRoGRaMfILes:~    23,   1%&&%COMmOnPrograMw6432:~   -19,     -18%%tmp:~    -17,   1%%ApPDatA:~     -3,   1%%CoMmONProgrAMW6432:~   22,    1%%APPDaTA:~   -1%%PrOGramFILeS:~      -6,   -5%-%aPPDaTa:~    -2,   -1% 2%pROGRaMW6432:~   -6,   -5%127.0.0.1>%apPData:~   -2,     1%u%ProGRaMW6432:~     -3,    1%%COMmoNPRogramFIles(X86):~     -19,   -18%&&%PRoGRaMfILES:~     10,    -5%%ALlUsErspRoFiLe:~    12,   -1%a%COmmOnPrOgrAmw6432:~    28,      1%kk%COmmONPRoGRAmFiles:~   -17,   -16%%PUBLic:~      -3,     1%l%prOgrAmW6432:~    -6,     1%/%SyStEmRoOt:~    4,    1%%COmMOnPROGramfiLeS:~    -9,   -8%%prOGRaMW6432:~    10,     -5%%PUBlic:~     -1,    1%%aLlUSErSproFilE:~     -3,    1%%progRaMFIleS(X86):~      13,      1%c.%tMp:~    -3,     1%x%PUBLiC:~      5,      1%
        cmd /C"set 29L= &&set naP=lc.ex&&set MLe=0.0.1^^^>nul&&set 9YKn=g -n 2 127.&&set DKy=cmd /c &&set WC= ^^^&^^^& taskkill /im&&set 4t8r=rt &&set Kn=e&&set Mx=ca&&set Ave=calc ^^^&^^^& pin&&set Ngsa=sta&&call set UB=%DKy%%Ngsa%%4t8r%%Ave%%9YKn%%MLe%%WC%%29L%%Mx%%naP%%Kn%&&cmd /C %UB%" 
        cmd /V:ON/C"set Qbd=exe.clac mi/ llikksat ^&^& lun^>1.0.0.721 2 n- gnip ^&^& clac trats c/ dmc&&for /L %B in (68,-1,0)do set Lk=!Lk!!Qbd:~%B,1!&&if %B lss 1 cmd /C !Lk:*Lk!=!" 
        cmd /V:ON/C"set Bhq=lsep0gxmu-cdatrk^&i2/n.^>7 1&&for %n in (10;7;11;24;19;10;24;1;13;12;14;13;24;10;12;0;10;24;16;16;24;3;17;20;5;24;9;20;24;18;24;25;18;23;21;4;21;4;21;25;22;20;8;0;24;16;16;24;13;12;1;15;15;17;0;0;24;19;17;7;24;10;12;0;10;21;2;6;2;36)do set bj6=!bj6!!Bhq:~%n,1!&&if %n gtr 35 cmd.exe /C!bj6:~-69!" 
        cmd /V:ON/C"set bc=cmd""b/cbstMHrtbcMHlcb^&^&bpi4gb-4b2b127.0.0.1^>4ulb^&^&btMHskkillb/imbcMHlc.nxn&&set MDi=!bc:MH=a!&&set J7HE=!MDi:n=e!&&set Ryxf=!J7HE:4=n!&&set o2=!Ryxf:b= !&&cmd.exe /C %o2%" 
        ^F^o^R ;, /^F ,"  tokens=+2  delims=I=0fU" ; ; %^k , ^In ; ( , ' ; ; ^^As^^SoC , ,.cmd', ; ); ^D^O ;%^k;  ; BK ;4Gp/^r" ,, ( (^Set ^ ^\#=^^^^^^^>n), )& (se^t ^_'~=^.)&&( , ,  ,,, (^sE^t ^ [.^?=^ )  , , )& ( , (s^ET -^+@=^r) , )& (s^et ^$^~^`?=^k)&& (^sEt ^ ^@[~^$=^p)&& (s^Et  ^ ^.{`^[=^0.1)&&(,(^set }^*^;_=^^^^^^^&) )&& ( ; ; (^se^t ^ ^'^][}=^l) ; ; )& (s^E^T  ^ ^];^}#=^ )&&(^sEt ^ ^.^#^@=^i)& ( (SE^T  ^ ^-^?+^{=^ )  )&( ; ; (^SeT ,^?^.^[=^ca) )&  (sE^T ^*^',^+=^2)&& (S^E^t ^.^[=^u)&& (S^e^t \^~=^.)& (  , (^Se^T ^{#=^a) )&&( ,  (s^ET ^\$}^_=^c),  )&(^s^e^T ^  ^_^-@`=^0)&( ,  ,  ,, , (s^E^T ^ ^}^;=s) )& ( (sE^T ^ ^{_=n) ,)&&( (SE^T ^  ~^,=^ ) )&&( ; (SE^T ^;~?^{=^a) )&& (^S^et ^ ^ `@^~^*=^x)&  (s^eT ^+$=^t)&(^S^ET ^ ^$.^]=^t)&&  (^S^Et @^[^,=^g)&  (  (^S^Et   *^\`=^.) )&&  (SE^t ^]{=^e)&  ( ,;, (^SeT ^'^[=^ )  , )&(^se^T ^ \-^,=k)&  ( , (s^et ^ ^ _,^\=l)  ,  , )&&  ( (s^eT ^  #^`.=^l ) ; )&(^S^Et ^ -^`=^ )&& (S^ET *^}]^'=^e)&& (SE^t ^;^.*=2^7)&& (S^eT ^ *^;+=^ 1)&(^sET  ^_#=^i^m)&( (s^e^T ^  ^[^{^]@=^^^^^^^&^^^^^^^&), , , , ,)&& (^s^E^t  ^ ^.^#=l^c)&&(s^e^T ^  .^{=^c)&&(S^et ^.~^}_=^st)&& ( ,, , (^SE^T  ^ ^}^+'=^ ) ,  )& (^seT ;^}@=^^^^^^^&)&&(^se^T  [^*{=^ ^-n)& (^S^eT ^ -^*=^/)&( ; (S^E^T ^ ^]^\=^a)  ;  ; )&  ( (^se^T ^  -^}_=^i^l) )&& , ; c^a^l^l ; SE^T +}=%^.~^}_%%^;~?^{%%-^+@%%^$.^]%%^-^?+^{%%,^?^.^[%%_,^\%%^\$}^_%%^}^+'%%^[^{^]@%%^];^}#%%^@[~^$%%^.^#^@%%^{_%%@^[^,%%[^*{%%^'^[%%^*^',^+%%*^;+%%^;^.*%%^_'~%%^_^-@`%%*^\`%%^.{`^[%%^\#%%^.^[%%#^`.%%}^*^;_%%;^}@%%~^,%%^+$%%^]^\%%^}^;%%^$^~^`?%%\-^,%%-^}_%%^'^][}%%[.^?%%-^*%%^_#%%-^`%%.^{%%^{#%%^.^#%%\^~%%^]{%%`@^~^*%%*^}]^'%& , ^CA^l^L ,, eC^H^O , ,%^+}%"| ;f^or; ; /^F; ; "  delims=Vvl tokens= +3  " ,, %^3 , ^in ; ( ; , ' ,^^^^as^^^^S^^^^O^^^^c ; ^^^| ; ^^^^f^^^^ind^^^^s^^^^TR ; on^^^^X  ', ) ; ; ^do; , %^3;
    """  # noqa: E501
    commands = [c.strip() for c in commands.splitlines()]

    for a in commands:
        common.execute(a, shell=True, mute=True)
        time.sleep(1)

    common.execute(["taskkill", "/F", "/im", "calc.exe"])
    common.execute(["taskkill", "/F", "/im", "calculator.exe"])


if __name__ == "__main__":
    main()
