rule  BYL_bank_trojan: Android {
    meta:
        author = "loopher"
    strings:
        // $str = "http://ksjajsxccb.com" wide ascii
        $str = "http://ksjajsxccb.com/api/index/information"
        $shellcode = {55  40  38  00  38  00  03  00  0e  00  55  40  3a  00  39  00  fd  ff  52  40  37  00  54  41  35  00  6e  10  e7  02  01  00  0a  01  35  10  f3  ff  52  40  3d  00  d8  00  00  01  59  40  3d  00  52  41  31  00  34  10  e9  ff  1a  01  9a  00  22  02  8f  00  1a  00  04  03  70  20  a5  02  02  00  54  40  35  00  52  43  37  00  6e  20  e5  02  30  00  0c  00  1f  00  49  00  6e  10  4e  01  00  00  0c  00  6e  20  aa  02  02  00  0c  00  1a  02  8b  04  6e  20  aa  02  20  00  0c  02  54  40  35  00  52  43  37  00  6e  20  e5  02  30  00  0c  00  1f  00  49  00  6e  10  4d  01  00  00  0c  00  6e  20  aa  02  02  00  0c  00  6e  10  ac  02  00  00  0c  00  71  20  c2  01  01  00  12  10  5c  40  3a  00  12  00  59  40  3d  00  54  41  36  00  54  40  35  00  52  42  37  00  6e  20  e5  02  20  00  0c  00  1f  00  49  00  6e  10  4e  01  00  00  0c  02  54  40  35  00  52  43  37  00  6e  20  e5  02  30  00  0c  00  1f  00  49  00  6e  10  4d  01  00  00  0c  00  6e  30  56  01  21  00  52  40  37  00  d8  00  00  01  59  40  37  00  28  80}
    condition:
        any of  them 
}