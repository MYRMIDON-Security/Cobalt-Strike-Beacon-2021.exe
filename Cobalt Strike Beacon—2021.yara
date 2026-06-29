rule Cobalt Strike Beacon—2021.exe {
    
    meta:
        description = "Cobalt Strike Beacon—2021.exe"
        author = "Will Schmidt"
        date = "6-26-26"
        hash = "942a315f52b49601cb8a2080fa318268f7a670194f9c5be108d936db32affd52"
        reference = "service-jfm40pz6-1305872363.gz.apigw.tencentcs.com"

    strings:
        // MZ check
        $PE_magic_byte = "MZ"

        // C2 domain found in sample
        $c2domain = "service-jfm40pz6-1305872363.gz.apigw.tencentcs.com" ascii fullword
        
        // Potential Tencent domain variations
        $variant1 = "apigw.tencentcs.com" ascii
        $variant2 = ".gz.apigw.tencentcs.com" ascii
        
        // Size of the encrypted blob (0x551E5)
        $size1 = { 55 1E 05 }     
        $size2 = { 00 05 51 E5 }  

        // Reflective loading signatures
        $reflect1 = "VirtualAlloc" ascii
        $reflect2 = "memcpy" ascii
        
        // User Agent and Booststrap Pattern
        $useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0" ascii
        $path = "/bootstrap-2.min.js" ascii

    condition:
        $PE_magic_byte at 0 and
        (
            $c2 or
            (1 of ($variant*)) or
            (1 of ($size*)) or
            (all of ($reflect*)) or
            ($ua and $path)
        )
}