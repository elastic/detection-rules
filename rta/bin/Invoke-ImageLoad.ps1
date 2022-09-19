function Invoke-ImageLoad {

    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$True)]
        [String]
        $DllPath
    )
    
    $type=@"
    using System;
    using System.Runtime.InteropServices;
    public class ImportIt
    {
        public const string DLLPath = @"$DLLPath";
        [DllImport(DLLPath, EntryPoint = "GetClassNameW", CharSet = CharSet.Unicode)]
        public static extern int MessageBox(IntPtr hWnd, String text, String caption, uint type);
        
        public static void Main()
        {
            MessageBox(new IntPtr(0), "Hello RTA!", "Hello Dialog", 0);
        }
    }
"@
    Add-Type -TypeDefinition $type;
    [ImportIt]::Main();
}