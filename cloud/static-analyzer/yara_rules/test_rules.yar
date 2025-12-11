/*
AegisAI YARA Rules
==================

Basic YARA rules for testing the static analyzer.
In a production environment, these would be more comprehensive.
*/

rule EICAR_Test_Signature
{
    meta:
        description = "EICAR test signature for antivirus testing"
        reference = "http://www.eicar.org/86-0-Intended-use.html"
        
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        
    condition:
        $eicar
}

rule Simple_Test_Rule
{
    meta:
        description = "Simple test rule for demonstration"
        author = "AegisAI Team"
        
    strings:
        $test_string = "This is a test file for static analysis"
        
    condition:
        $test_string
}

rule PE_File_Detection
{
    meta:
        description = "Detects PE files by MZ header"
        author = "AegisAI Team"
        
    strings:
        $mz_header = { 4D 5A }
        
    condition:
        $mz_header at 0
}