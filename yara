rule redis_miner {
    meta:
        description = "Detects Redis Miner malware"
        author = "Your Name"
    strings:
        $str1 = "REDIS_MINER" nocase
        $str2 = "lua"
    condition:
        $str1 and $str2
}
