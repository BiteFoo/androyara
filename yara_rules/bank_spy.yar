rule  BYL_bank_trojan: Android {
    meta:
        author = "loopher"
    strings:
        // $str = "http://ksjajsxccb.com" wide ascii
        $str = "http://ksjajsxccb.com/api/index/information"
        $shellcode ={22  00  ee  08  70  20  84  4a  40  00  12  41  23  11  54  0c  12  02  1a  03  bd  53  4d  03  01  02  12  12  4d  05  01  02  12  25  1a  02  5b  53  4d  02  01  05  12  35  4d  06  01  05  1a  05  83  40  71  30  59  4b  05  01  0e 
 00 }
    condition:
        $str and $shellcode
}
