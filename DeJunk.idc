/*  DeJunk.idc
    $: Remove junk codes in IDA by IDC
    @: lifenjoiner
    L: GPL
    
    H:
    v0.1.0 20190614
*/

#include <idc.idc>

#ifdef __EA64__

#endif

// won't be that long
#define JUNK_DATA_LEN 0x7F

extern total_junks;

extern junks_start_ea;
extern junks_end_ea;

/*  skip useless code to reduce the code size
    For every junk code, we fix it's caller's operand.
    So, we get the codes slimmed.
*/
static skip_junk(start, len_skip) {
    auto cur, t, op, cur_x, opnd;
    for (cur = RfirstB(start); cur != BADADDR; cur = RnextB(start, cur)) {
        t = XrefType();
        //GetOpType(cur, 0); // 7, short or near?
        op = Byte(cur);
        //Message("xref, type: %x, %d\n", cur, t);
        cur_x = cur;
        if (op == 0xF2 || op == 0xF3) {
            cur_x++;
            op = Byte(cur_x);
        }
        if (op == 0x0F) {
            op = Word(cur_x);
            cur_x = cur_x + 2;
        }
         //Message("op: %x\n", op);
        if (t == fl_CN) {
            if (op == 0xE8) {
                opnd = Dword(cur_x);
                // overflow?
                opnd = opnd + len_skip;
                if (opnd > 0x7FFFFFFF || opnd < -0x7FFFFFFF) break;
                PatchDword(cur_x, opnd);
            }
            // FF/2
        } else if (t == fl_JN) {
            // short: 70 ~ 7F, E3, EB
            // near: E9, FF/4, 0F80 ~ 0F8F
            if ((0x70 <= op && op <= 0x7F) || op == 0xE3 || op == 0xEB) {
                opnd = Byte(cur_x);
                if (opnd > 0x7F) opnd = opnd | 0xFFFFFF00;
                opnd = opnd + len_skip;
                // overflow?
                if (opnd > 0x7F || opnd < -0x7F) break;
                PatchByte(cur_x, opnd);
            } else if ((0x0F80 <= op && op <= 0x0F8F) || op == 0xE9 || op == 0xFF) {
                opnd = Dword(cur_x);
                // overflow?
                opnd = opnd + len_skip;
                if (opnd > 0x7FFFFFFF || opnd < -0x7FFFFFFF) break;
                PatchDword(cur_x, opnd);
            }
        } else if (t == fl_JF || t == fl_CF) {
            //
        }
    }
}

static skip_mid_nop(start, end) {
    auto ea;
    while (ea = FindCode(ea, SEARCH_DOWN|SEARCH_NEXT), ea != BADADDR && ea < end) {
    }
}

// topological merging?


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
        // are ALL data? dynamic (x + y * i) jump?
        // data and code not in a function chunk
        // some junk data would be left as code
        //
        auto found_real_code = 0;
        i = len_sig + len_operand + n;
        while (ea_x = FindCode(ea_x, SEARCH_DOWN|SEARCH_NEXT), ea_x < ea + i) {
            if (GetFchunkAttr(ea_x, FUNCATTR_START) != BADADDR) {
                found_real_code = 1;
                break;
            }
        }
        if (found_real_code == 1) continue;
        // too long may include real data
        if (ea + i >= end && n > JUNK_DATA_LEN) continue;
        //
        n = i;
        Message("junk code ea: %x len: %d\n", ea, n);
        total_junks++;
        for (i = 0; i < n; i++) PatchByte(ea + i, 0x90);
        //
        skip_junk(ea, n);
        //
        RemoveFchunk(ea, ea);
    }
}

/*  1 jump
// https://en.wikipedia.org/wiki/X86_instruction_listings
// https://www.felixcloutier.com/x86/
// http://ref.x86asm.net/coder32.html
// http://ref.x86asm.net/#column_op
// https://en.wikibooks.org/wiki/X86_Assembly/16,_32,_and_64_Bits

?   Opcode  Mnemonic    operand         comments
    70      Jcc         rel8            8 bits relative offset
    ...     Jcc         rel8
    7F      Jcc         rel8
    
    9A      CALLF       ptr16:16/32     32-bit or 48-bit pointer direct address
    E3      J(E)CXZ     rel8
Y   E8      CALL        rel16/32
    FF/2    CALL        r/m16/32
    FF/3    CALLF       m16:16/32
?   E9      JMP         rel16/32
    EA      JMPF        ptr16:16/32
Y   EB      JMP         rel8
    FF/4    JMP         r/m16/32
    FF/5    JMPF        m16:16/32
    
    0F80    Jcc         rel16/32
    ...     Jcc         rel16/32
    0F8F    Jcc         rel16/32

leading 0xF2/0xF3: REPxx

*/

/*  special conditional jump
    CLC
    JNB     Dst
    db Junks
Dst:
*/

/*  2 jumps: true or false with the same dst:
    J?      Dst
    Jn?     Dst
    db Junks
Dst:
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
    auto n;
    //
    // Message("MinEA(), MaxEA(): %x, %x\n", MinEA(), MaxEA());
    total_junks = 0;
    junks_start_ea = MaxEA();
    junks_end_ea = MinEA();
    for (ea = MaxEA() - 1; ea > MinEA(); ) {
        ea_start = PrevFchunk(ea);
        if (ea_start == BADADDR || ea < MinEA()) break;
        //
        n = total_junks;
        de_junks(ea_start, ea);
        if (n < total_junks) {
            if (junks_end_ea < ea) junks_end_ea = ea;
            if (junks_start_ea > ea_start) junks_start_ea = ea_start;
        }
        //
        ea = ea_start;
    }
    //
    n = junks_end_ea - junks_start_ea;
    if (n > 0) {
        AnalyzeArea(junks_start_ea, junks_end_ea);
    }
    //
    Message("total junks removed [%x, %x]: %d\n", junks_start_ea, junks_end_ea, total_junks);
    Message("Finished!\n");
}
