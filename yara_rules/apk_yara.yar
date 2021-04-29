/**
This rule is use to match apk virus
**/

rule best_for_her_virus
{
    meta:
        author = "loopher"
        decription = "check best_for_her.apk "
        info = "shellcode method: com.nirenr.screencapture.ScreenShot.java -> a(Lcom/nirenr/screencapture/ScreenShot;,Lcom/nirenr/screencapture/ScreenShot;)Lcom/nirenr/screencapture/ScreenCaptureListener; "
    strings:
        $str = "https://hmma.baidu.com/app.gif" nocase
        $shellcode = {5b  01  61  11  11  01}
    condition:
        (#str == 30) or ($shellcode)

}