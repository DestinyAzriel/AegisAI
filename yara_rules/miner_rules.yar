rule CryptocurrencyMiner
{
    meta:
        description = "Detects cryptocurrency mining malware"
        author = "AegisAI"
        date = "2025-10-20"
        threat_level = 3
        version = "1.0"
    
    strings:
        $mz = "MZ"
        $pool1 = "pool" ascii nocase
        $pool2 = "mining" ascii nocase
        $pool3 = "stratum" ascii nocase
        $pool4 = "xmr" ascii nocase
        $pool5 = "monero" ascii nocase
        $pool6 = "bitcoin" ascii nocase
        $pool7 = "litecoin" ascii nocase
        $pool8 = "dogecoin" ascii nocase
        $pool9 = "ether" ascii nocase
        $pool10 = "dash" ascii nocase
        $algo1 = "sha256" ascii nocase
        $algo2 = "scrypt" ascii nocase
        $algo3 = "x11" ascii nocase
        $algo4 = "cryptonight" ascii nocase
        $algo5 = "equihash" ascii nocase
        $algo6 = "ethash" ascii nocase
        $wallet1 = "wallet" ascii nocase
        $wallet2 = "address" ascii nocase
        $wallet3 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" ascii nocase
        $wallet4 = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy" ascii nocase
        $cpu1 = "cpu" ascii nocase
        $cpu2 = "threads" ascii nocase
        $cpu3 = "cores" ascii nocase
        $gpu1 = "gpu" ascii nocase
        $gpu2 = "cuda" ascii nocase
        $gpu3 = "opencl" ascii nocase
        $gpu4 = "nvidia" ascii nocase
        $gpu5 = "amd" ascii nocase
        $hashrate1 = "hashrate" ascii nocase
        $hashrate2 = "mh/s" ascii nocase
        $hashrate3 = "kh/s" ascii nocase
        $hashrate4 = "gh/s" ascii nocase
        
    condition:
        $mz at 0 and
        4 of ($pool*, $algo*, $wallet*, $cpu*, $gpu*, $hashrate*) and
        filesize < 10000KB
}

rule MinerConfig
{
    meta:
        description = "Detects cryptocurrency miner configuration files"
        author = "AegisAI"
        date = "2025-10-20"
        threat_level = 3
        version = "1.0"
    
    strings:
        $config1 = "pools" ascii nocase
        $config2 = "user" ascii nocase
        $config3 = "pass" ascii nocase
        $config4 = "algo" ascii nocase
        $config5 = "url" ascii nocase
        $config6 = "stratum" ascii nocase
        $config7 = "wallet" ascii nocase
        $config8 = "address" ascii nocase
        $config9 = "threads" ascii nocase
        $config10 = "cpu" ascii nocase
        $config11 = "gpu" ascii nocase
        $config12 = "intensity" ascii nocase
        $config13 = "worksize" ascii nocase
        $config14 = "rawintensity" ascii nocase
        $config15 = "thread_concurrency" ascii nocase
        
    condition:
        3 of ($config*) and
        filesize < 100KB
}