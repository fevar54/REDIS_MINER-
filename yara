rule redis_miner {
    meta:
        description = "Detects Redis Miner malware"
        author = "FEVAR54"
    strings:
        $str1 = "REDIS_MINER" nocase
        $str2 = "lua"
    condition:
        $str1 and $str2
}
