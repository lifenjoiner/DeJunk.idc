/*  DeJunk.idc
    $: Remove junk codes in IDA by IDC
    @: lifenjoiner
    L: GPL
    
    H:
    v0.1.0 20190614
*/

#include <idc.idc>

extern total_junks;

//static de_junk(long start, long end, string junk_sig, long len_sig, long len_operand);
static de_junk(start, end, junk_sig, len_sig, len_operand)
{
    auto ea, ea_x;
    auto n, i;
    //strlen
    //Message("start, end, junk_sig: %x, %x, %s\n", start, end, junk_sig);
    ea = start - 1;
    while (ea = FindBinary(ea, SEARCH_DOWN|SEARCH_NEXT, junk_sig), ea != BADADDR && ea < end) {
        // don't break parsed code
        if (ea != FindCode(ea - 1, SEARCH_DOWN|SEARCH_NEXT)) continue;
        //
        //Message("Sig-ea: %x\n", ea);
        // GetOperandValue(ea, 0): -1
        ea_x = ea + len_sig;
        if (len_operand == 1) {
            n = Byte(ea_x);
            if (n > 0x7F) n = n | 0xFFFFFF00;
        } else if (len_operand == 4) {
            n = Dword(ea_x);
        }
        //Message("jmp-len: %d\n", n);
        if (n <= 0) continue;
        // n < 0 ? haven't seen this type.
        // are all data?
        if ( FindCode(ea_x, SEARCH_DOWN|SEARCH_NEXT) < ea + n ) continue;
        n = len_sig + len_operand + n;
        Message("junk code ea: %x len: %d\n", ea, n);
        total_junks++;
        for (i = 0; i < n; i++) PatchByte(ea + i, 0x90);
    }
}

/*
// https://en.wikipedia.org/wiki/X86_instruction_listings
// http://ref.x86asm.net/coder32.html

?   Opcode  Mnemonic    operand
    70      J??         rel8
    ...     J??         rel8
    7F      J??         rel8
    
    9A      CALLF       ptr16:16/32
    E3      J(E)CXZ     rel8
Y   E8      CALL        rel16/32
    FF/2    CALL
    FF/3    CALLF
?   E9      JMP         rel16/32
    EA      JMPF        ptr16:16/32
Y   EB      JMP         rel8
    FF/4    JMP
    FF/4    JMPF
    
    0F80    J??         rel16/32
    ...     J??         rel16/32
    0F8F    J??         rel16/32

leading 0xF2/0xF3

*/

//static de_junks(long start, long end);
// MUST be junk code and no data!
static de_junks(start, end)
{
    de_junk(start, end, "F2 EB",    2, 1);
    de_junk(start, end, "F3 EB",    2, 1);
    de_junk(start, end, "EB",       1, 1);
    //
    de_junk(start, end, "F2 E8",    2, 4);
    de_junk(start, end, "F3 E8",    2, 4);
    de_junk(start, end, "E8",       1, 4);
}


/*
    What is juck code?
    Pattern: "[db +] (short) Jmp/call + db + dest" in the same block
    The same block?
    IDA is a heuristic analyzer. It can tell from the previous analysis.
    
    IDA v 6.8:
    
    The function enumerates all chunks of all functions in the database:
    long NextFchunk(long ea);
    long PrevFchunk(long ea);
    
    MinEA();
    MaxEA();
    
    long FindCode(long ea, long flag);
    long AnalyzeArea(long sEA, long eEA);
    
    AskAddr
*/

static main(void)
{
    auto ea, ea_start;
    //
    // Message("MinEA(), MaxEA(): %x, %x\n", MinEA(), MaxEA());
    total_junks = 0;
    for (ea = MaxEA() - 1; ea > MinEA(); ) {
        ea_start = PrevFchunk(ea);
        if (ea_start == BADADDR || ea < MinEA()) break;
        //
        de_junks(ea_start, ea);
        //
        ea = ea_start;
    }
    //
    AnalyzeArea(MinEA(), MaxEA());
    //
    Message("total junks removed: %d\n", total_junks);
    Message("Finished!\n");
}
