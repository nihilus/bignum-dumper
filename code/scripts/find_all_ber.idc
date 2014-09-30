#include <idc.idc>
static main(void)
{
	auto start = GetLongPrm(INF_MIN_EA);
	auto ea = start;
	Message("%08X\n", ea);
	ea  = FindBinary(ea, 3, "02");
	while(ea!=BADADDR)
	{
		Message("%08X\n", ea);
		dump( BER_int_offset(ea), BER_int_length(ea), 1, 0, 1, 1 );
		ea  = FindBinary(ea, 3, "02");    
	}
}
