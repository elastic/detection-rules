dim shellobj
dim fs
dim logFile

set fs = CreateObject("Scripting.FileSystemObject")
set shellObj = WScript.CreateObject("wscript.shell")

name = "rta-vbs-persistence"
logPath = shellObj.ExpandEnvironmentStrings("%USERPROFILE%") & "\" & name & ".log"

set logFile = fs.OpenTextFile(logPath, 8, True)

startupDir    = shellObj.SpecialFolders("Startup")
shortcutLink  = startupDir & "\" & name & "-startup.lnk"

startupTarget = startupDir & "\" & name & "-startup.vbs"
shortcutTarget = shellObj.ExpandEnvironmentStrings("%USERPROFILE%") & "\" & name & "-startup-shortcut.vbs"
taskTarget     = shellObj.ExpandEnvironmentStrings("%USERPROFILE%") & "\" & name & "-task.vbs"
runTarget      = shellObj.ExpandEnvironmentStrings("%USERPROFILE%") & "\" & name & "-run-key.vbs"

runKey = "HKEY_CURRENT_USER\software\microsoft\windows\currentversion\run\" & name


function log(logType, message)
    line = "[" & logType & "] " & wscript.ScriptName & " - " & message
    ' WScript.Echo line
    logFile.WriteLine line
end function

function logLine
    logFile.WriteLine ""
end function


'Add self logging functions
function copyScript(target)
    log "+", "Copying " & wscript.ScriptFullName & " to " & target
    fs.CopyFile wscript.ScriptFullName, target, true
end function

function deleteFile(path)
    log "-", "Deleting " & path
    fs.DeleteFile(path)
end function

function run(command)
    log ">", command
    errorCode = shellObj.Run(command, 0, True)
    if errorCode <> 0 then
        log ">", "exit code = " & errorCode
    end if
end function

function deleteScript()
    deleteFile wscript.ScriptFullName
end function


log "=", "Started"

'Establish persistence or remove persistence after the first execution
if wscript.ScriptFullName = shortcutTarget then
    'Check if this is running and came from a shortcut
    log "+", "Running from a shortcut target"
    deleteScript
    deleteFile shortcutLink

elseif wscript.ScriptFullName = startupTarget then
    'Delete the file
    log "+", "Running from the startup folder directly"
    deleteScript

elseif wscript.ScriptFullName = taskTarget then
    'Remove the task and the file
    log "+", "Running as a scheduled task"
    deleteScript
    run "schtasks.exe /delete /f /tn " & name

elseif wscript.ScriptFullName = runTarget then
    'Remove the registry key and the file
    log "+", "Running as a run item"
    deleteScript
    log "-", "Removing registry key " & runKey
    shellObj.RegDelete runKey

else
    'Copy the file to a few locations
    dim shortcut
    log "+", "Establish Persistence" & crlf


    'Copy to the StartUp directory
    log "+", "Startup File"
    copyScript startupTarget
    logLine

    'Create a shortcut in the StartUp directory
    log "+", "Startup Shortcut"
    copyScript shortcutTarget
    set shortcut = shellObj.CreateShortcut(shortcutLink)
    shortcut.TargetPath = "wscript.exe"
    shortcut.Arguments = "//B " & chrw(34) & shortcutTarget & chrw(34)
    shortcut.save()
    logLine

    'Create a scheduled task
    log "-", "Scheduled Task" & crlf
    copyScript taskTarget
    run "schtasks.exe /create /f /sc onlogon /tn " & name & " /tr " & chrw(34) & "wscript.exe //B " & ("\" & chrw(34)) & runTarget & ("\" & chrw(34)) & chrw(34)
    logLine

    'Create the run key
    log "+", "Run Key via Registry"
    copyScript runTarget
    shellObj.RegWrite runKey, "wscript.exe //B " & chrw(34) & runTarget & chrw(34), "REG_SZ"
    logLine

end if

log "-", "Exiting"
logFile.WriteLine ""
logFile.WriteLine ""
logFile.Close()