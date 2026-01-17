rule test
{
	strings:
		$h00 = { 51 E8 01 FF FF FF 83 C4 08 8B C8 FF 15 04 72 40 00 8B E5 }
		$s00 = "B::f()" ascii wide nocase
		$s01 = "A::f()" ascii wide nocase
		$s02 = "C::f()" ascii wide nocase
	condition:
		any of them
}

rule hex_text
{
	strings:
		$h00 = /[A-Fa-f0-9]+/
	condition:
		any of them
}

rule printable_text
{
	strings:
		$h00 = /[[:print:]]+/
	condition:
		any of them
}
