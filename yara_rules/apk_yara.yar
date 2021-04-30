/**
This rule is use to match apk virus
**/

rule best_for_her_virus
{
    meta:
        author = "loopher"
        decription = "check best_for_her.apk "
        info = "shellcode method: com.androlua.uaUtil.java -> captureScreen(Landroid/app/Activity;)Landroid/graphics/Bitmap;"
    strings:
        $str = "https://hmma.baidu.com/app.gif" nocase
        $shellcode = {22  00  bd  00  70  10  96  02  00  00  1a  01  6f  21  6e  20  13  00  19  00  0c  09  1f  09  e6  00  72  10  72  03  09  00  0c  09  6e  20  a6  02  09  00  52  01  82  00  52  00  83  00  6e  10  a7  02  09  00  0a  09  22  02  6e  00  70  10  cc  01  02  00  71  20  cd  01  29  00  52  29  65  00  92  02  01  00  92  09  09  02  23  99  a7  05  12  03  12  34  71  00  6f  28  00  00  0c  05  23  46  ea  05  1a  07  05  02  4d  07  06  03  1a  07  c6  01  12  18  4d  07  06  08  1a  07  a4  13  12  28  4d  07  06  08  6e  20  6e  28  65  00  28  05  0d  05  71  10  9b  0e  05  00  22  05  d8  04  22  06  d7  04  1a  07  f8  01  70  20  62  27  76  00  70  20  7b  27  65  00  22  06  d5  04  70  20  59  27  56  00  6e  20  5b  27  96  00  28  05  0d  05  71  10  9b  0e  05  00  23  22  aa  05  21  25  35  53  27  00  da  05  03  04  48  06  09  05  d5  66  ff  00  d8  07  05  01  48  07  09  07  d5  77  ff  00  d8  08  05  02  48  08  09  08  d5  88  ff  00  b0  45  48  05  09  05  d5  55  ff  00  e0  05  05  18  e0  06  06  10  b0  65  e0  06  07  08  b0  65  b0  85  4b  05  02  03  d8  03  03  01  28  d9  62  09  58  00  71  40  7e  01  02  91  0c  09  11  09}
    condition:
        $str  and ($shellcode)

}