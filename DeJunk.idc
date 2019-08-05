/*  DeJunk.idc
    $: Remove junk codes in IDA by IDC
    @: lifenjoiner
    L: GPL
    
    H:
    v0.2.0 20190616
    v0.1.0 20190614
*/

#include <idc.idc>
#include "opr.idc"

#ifdef __EA64__

#endif

// won't be that long
#define JUNK_DATA_LEN 0x7F

extern total_junks;

extern junks_start_ea;
extern junks_end_ea;


static patch_byte_operand(ea, op_len, opnd_change, flowtype) {
    auto cur_x, opnd_old, opnd;

    cur_x = ea + op_len;
    opnd_old = read_byte_opnd(cur_x);
    opnd = opnd_old + opnd_change;
    // overflow?
    if (opnd > 0x7F || opnd < -0x7F) return 0;
    if (opnd_change != 0) {
        PatchByte(cur_x, opnd);
        DelCodeXref(ea, cur_x + 1 + opnd_old, 0);
        AddCodeXref(ea, cur_x + 1 + opnd, XREF_USER | flowtype);
        //Message("Patch: ea = %#x, old = %#x, new = %#x\n", ea, cur_x + 1 + opnd_old, cur_x + 1 + opnd);
    }
    return opnd;
}

static patch_dword_operand(ea, op_len, opnd_change, flowtype) {
    auto cur_x, opnd_old, opnd;

    cur_x = ea + op_len;
    opnd_old = Dword(cur_x);
    opnd = opnd_old + opnd_change;
    // overflow?
    if (opnd > 0x7FFFFFFF || opnd < -0x7FFFFFFF) return 0;
    if (opnd_change != 0) {
        PatchDword(cur_x, opnd);
        DelCodeXref(ea, cur_x + 4 + opnd_old, 0);
        AddCodeXref(ea, cur_x + 4 + opnd, XREF_USER | flowtype);
        //Message("Patch: ea = %#x, old = %#x, new = %#x\n", ea, cur_x + 4 + opnd_old, cur_x + 4 + opnd);
    }
    return opnd;
}

static nop_bytes(ea, len) {
    auto i, end;
    end = ea + len;
    for (i = ea; i < end; i++) {
        DelCodeXref(i, Rfirst0(i), 0);
        MakeUnkn(i, DOUNK_DELNAMES);
        PatchByte(i, 0x90);
        MakeCode(i);
    }
}

static is_not_xref_block(ea) {
    auto cur;
    cur = ea;
    // all previous codes have NO xref to
    while ( (cur = RfirstB(cur)) != BADADDR) {
        if (FindData(cur, SEARCH_DOWN) > FindCode(cur, SEARCH_DOWN)) {
            if (RfirstB0(cur) != BADADDR) return 0;
        }
        else {
            return 0;
        }
    }
    return 1;
}

/*  skip useless code to reduce the code size
    For every junk code, we fix it's caller's operand.
    So, we get the codes slimmed.
    Far jmp/call shouldn't be in this case, leave it.
*/
static fix_opnd_rva(start, opnd_change, recur) {
    auto cur, t, op, cur_x, n, opnd_old, opnd;
    auto retn, counter, changed;
    retn = 0;
    counter = 0;
    changed = 0;
    n = 0;
    for (cur = RfirstB0(start); cur != BADADDR; cur = RnextB0(start, cur)) {
        t = XrefType();
        //Message("xref, type: %#x, %d\n", cur, t);
        //GetOpType(cur, 0); // 7, short or near?
        op = Byte(cur);
        cur_x = cur;
        if (op == 0xF2 || op == 0xF3) {
            cur_x++;
        }
        //
        counter++;
        n = 0;
        //
        if (t == fl_CN) {
            if ( n = is_near_call(cur_x) ) {
                n = n + cur_x - cur;
                opnd = patch_dword_operand(cur, n, opnd_change, t);
                if ( !opnd ) continue;
                //Message("dest: %#x, %#x\n", cur, cur_x + 4 + opnd);
                n = n + 4;
            }
        } else if (t == fl_JN) {
            if ( n = is_short_jmp(cur_x) ) {
                n = n + cur_x - cur;
                opnd = patch_byte_operand(cur, n, opnd_change, t);
                if ( !opnd ) continue;
                //Message("dest: %#x, %#x\n", cur, cur_x + 1 + opnd);
                // merge jumps
                n = n + 1;
                if (recur && n != -opnd) {
                    retn = retn + fix_opnd_rva(cur, n + opnd, recur);
                }
            } else if ( n = is_short_jxc(cur_x) ) {
                n = n + cur_x - cur;
                opnd = patch_byte_operand(cur, n, opnd_change, t);
                if ( !opnd ) continue;
                //Message("dest: %#x, %#x\n", cur, cur_x + 1 + opnd);
                n = n + 1;
            } else if ( n = is_near_jmp(cur_x) ) {
                n = n + cur_x - cur;
                opnd = patch_dword_operand(cur, n, opnd_change, t);
                if ( !opnd ) continue;
                //Message("dest: %#x, %#x\n", cur, cur_x + 4 + opnd);
                // merge jumps
                n = n + 4;
                if (recur && n != -opnd) {
                    retn = retn + fix_opnd_rva(cur, n + opnd, recur);
                }
            } else if ( n = is_near_jxc(cur_x) ) {
                n = n + cur_x - cur;
                opnd = patch_dword_operand(cur, n, opnd_change, t);
                if ( !opnd ) continue;
                //Message("dest: %#x, %#x\n", cur, cur_x + 4 + opnd);
                n = n + 4;
            }
        } else if (t == fl_JF || t == fl_CF) {
            // shouldn't happen
        }
        //
        if (opnd_change != 0 && n != 0) changed++;
        // patch stage: nopped xref-from without xref-to
        else if (!recur && op == 0x90 && RfirstB0(cur) == BADADDR) DelCodeXref(cur, start, 0);
    }
    // merge jumps state
    // the ones in middle: all jump to this are updated?
    if (recur && opnd_change && counter && counter == changed) {
        //
        n = 0;
        opnd = 0;
        // nop
        if (Byte(start) == 0x90) {
            // accelerate
        }
        else if (is_not_xref_block(start)) {
            op = Byte(start);
            cur_x = start;
            if (op == 0xF2 || op == 0xF3) {
                cur_x++;
            }
            if (n = is_short_jmp(cur_x)) {
                opnd = read_byte_opnd(cur_x + n);
                n = cur_x - start + n + 1;
            }
            else if (n = is_near_jmp(cur_x)) {
                opnd = Dword(cur_x + n);
                n = cur_x - start + n + 4;
            }
        }
        //
        if (n > 0) nop_bytes(start, n);
        if (n + opnd != 0) DelCodeXref(start, start + n + opnd, 0);
        MakeName(start, "");
    }
    //
    return retn + changed;
}

static merge_jumps(start, end) {
    auto ea, cur, n, total;
    total = 0;
    for (ea = start; ea < end && ea != BADADDR; ea = FindCode(ea, SEARCH_DOWN|SEARCH_NEXT)) {
        cur = ea;
        while (ea < end && Byte(ea) == 0x90) {ea++;}
        n = fix_opnd_rva(cur, ea - cur, 1);
        //
        if (ea > cur) ea--;
        total = total + n;
        if (n > 0) {
            // better ideas?
            if (ea > cur) Jump(ea);
            //
            Message("merge_jumps ea: %#x\n", ea);
            if (junks_end_ea < ea) junks_end_ea = ea;
            if (junks_start_ea > cur) junks_start_ea = cur;
        }
    }
    return total;
}

static skip_mid_nop(start, end) {
    auto ea, cur;
    auto nop_start, jump_start;
    auto n, op, opnd_old, opnd, len_code_old, len_opnd_old, len_opnd;
    auto counter;
    //
    counter = 0;
    ea = start - 1;
    while (ea = FindCode(ea, SEARCH_DOWN|SEARCH_NEXT), ea != BADADDR && ea < end) {
        if (Byte(ea) != 0x90) continue;
        nop_start = ea;
        while (ea++, ea < end && Byte(ea) == 0x90 && RfirstB0(ea) == BADADDR) {}
        if (RfirstB0(ea) != BADADDR) {
            ea--;
            continue;
        }
        //
        cur = ea;
        op = Byte(ea);
        if (op == 0xF2 || op == 0xF3) {
            ea++;
        }
        opnd_old = 0;
        if (n = is_short_jmp(ea)) {
            ea = ea + n;
            opnd_old = read_byte_opnd(ea);
            ea = ea + 1;
        }
        else if (n = is_near_jmp(ea)) {
            ea = ea + n;
            opnd_old = Dword(ea);
            ea = ea + 4;
        }
        //
        if (opnd_old == 0) continue;
        //
        len_code_old = ea - cur;
        len_opnd_old = ea - cur - n;
        opnd = opnd_old;
        jump_start = cur;
        // merge dest nops
        cur = ea + opnd_old;
        while (cur < end && Byte(cur) == 0x90) {cur++;}
        n = cur - ea - opnd_old;
        if (n > 0) {
            Message("nop blocks ea (to): %#x, len: %#d\n", ea + opnd_old, n);
            opnd = opnd_old + n;
        }
        //
        n = jump_start - nop_start;
        Message("nop blocks ea: %#x, len: %#d\n", nop_start, n);
        opnd = opnd + n;
        //
        if (0x7FFFFFFF < opnd || opnd < -0x7FFFFFFF) continue;
        // get more space
        while (ea++, ea < end && Byte(ea) == 0x90 && FindCode(ea, SEARCH_DOWN) == ea && RfirstB0(ea) == BADADDR) {}
        if (RfirstB0(ea) != BADADDR) {
            ea--;
        }
        //
        if (nop_start + 5 <= ea) {
            cur = nop_start + 5;
            if (cur > ea) continue;
            PatchByte(nop_start, 0xE9);
            if (len_opnd_old == 1) {
                opnd = opnd - 3;
            }
            PatchDword(nop_start + 1, opnd);
            len_opnd = 4;
        }
        else if (-0x80 < opnd && opnd < 0x80) {
            cur = nop_start + 2;
            PatchByte(nop_start, 0xEB);
            PatchByte(nop_start + 1, opnd);
            len_opnd = 1;
        }
        else {
            // overflow short opnd
            continue;
        }
        //
        if (jump_start >= cur) PatchByte(jump_start, 0x90);
        if (jump_start + 1 > cur) cur = jump_start + 1;
        nop_bytes(cur, ea - cur);
        counter++;
        //
        DelCodeXref(jump_start, jump_start + len_code_old + opnd_old, 0);
        AddCodeXref(nop_start, nop_start + 1 + len_opnd + opnd, XREF_USER | fl_JN);
        //Message("Patch: %#x, %#x -> %#x, %#x\n", jump_start, jump_start + len_code_old + opnd_old, nop_start, nop_start + 1 + len_opnd + opnd);
    }
    return counter;
}

// topological merging?


static ReAnalyzeArea(start, end)
{
    auto ea, ea_start;
    for (ea = end; ea > start; ) {
        ea_start = PrevFchunk(ea);
        if (ea_start == BADADDR || ea < start) break;
        RemoveFchunk(ea_start, ea_start);
        DelFunction(ea_start);
        ea = ea_start;
    }
    AnalyzeArea(MinEA(), MaxEA());
}

static de_junk(start, end, junk_sig, len_sig, len_operand, tail, len_tail)
{
    auto ea, ea_x;
    auto n, i;
    //strlen
    //Message("start, end, junk_sig: %#x, %#x, %s\n", start, end, junk_sig);
    ea = start - 1;
    while (ea = FindBinary(ea, SEARCH_DOWN|SEARCH_NEXT, junk_sig), ea != BADADDR && ea < end) {
        // don't break parsed code
        if (ea != FindCode(ea - 1, SEARCH_DOWN|SEARCH_NEXT)) continue;
        //
        //Message("Sig-ea: %#x\n", ea);
        // GetOperandValue(ea, 0): -1
        ea_x = ea + len_sig;
        n = 0;
        if (len_operand == 1) {
            n = read_byte_opnd(ea_x);
        } else if (len_operand == 4) {
            n = Dword(ea_x);
        }
        //Message("jmp-len: %d\n", n);
        if (n < 0) continue;
        // n < 0 ? haven't seen this type.
        //
        if (len_tail > 0 && ea + len_sig + len_operand + n != FindBinary(ea + len_sig + len_operand, SEARCH_DOWN, tail)) continue;
        // are ALL data? dynamic (x + y * i) jump?
        // data and code not in a function chunk
        // some junk data would be left as code
        //
        auto flags = 0, found_real_code = 0;
        i = len_sig + len_operand + len_tail + n;
        ea_x = ea_x + len_operand + len_tail - 1;
        if (is_call(ea)) flags = 0x00008000;
        while (ea_x = FindCode(ea_x, SEARCH_DOWN|SEARCH_NEXT), ea_x < ea + i) {
            // further determination on the junk data that can be treated as code
            if (RfirstB0(ea_x) != BADADDR) {
                flags = flags + 0x01000000;
            }
            else if (is_retn(ea_x)) {
                if (flags & 0x00008000 == 0x00008000) {
                    flags = flags + 0x00100000;
                }
                else {
                    flags = flags + 0x00010000;
                }
            }
            else if (is_call(ea_x) || is_jump(ea_x)) {
                flags = flags + 0x00010000;
            }
            else if ( Byte(ea_x) == 0x90 ) {
                // ignore nop
            }
            else if (GetFchunkAttr(ea_x, FUNCATTR_START) != BADADDR) {
                flags = flags + 1;
            }
            // Not only 1 fake command?
            if (flags > 0x1 && flags != 0x10000 && flags != 0x8000 && flags != 0x8001 && flags != 0x18000) {
                found_real_code = 1;
                break;
            }
        }
        if (found_real_code > 0) continue;
        // too long may include real data
        if (ea + i >= end && n > JUNK_DATA_LEN) continue;
        //
        n = i;
        Message("junk code ea: %#x len: %d\n", ea, n);
        total_junks++;
        //
        nop_bytes(ea, n);
        //
        fix_opnd_rva(ea, n, 0);
        //
        if (junks_end_ea < ea) junks_end_ea = ea;
        if (junks_start_ea > ea) junks_start_ea = ea;
    }
}

/*  1 jump
// https://en.wikipedia.org/wiki/X86_instruction_listings
// https://www.felixcloutier.com/x86/
// http://ref.x86asm.net/coder32.html
// http://ref.x86asm.net/#column_op

// https://stackoverflow.com/questions/15209993/what-does-opcode-ff350e204000-do?rq=1
// https://wiki.osdev.org/X86-64_Instruction_Encoding#ModR.2FM

// https://en.wikibooks.org/wiki/X86_Assembly/16,_32,_and_64_Bits

// Far jump:
   A jump to an instruction located in a different segment than the current code segment
   but at the same privilege level, sometimes referred to as an intersegment jump.
// Far Call:
   A call to a procedure located in a different segment than the current code segment,
   sometimes referred to as an inter-segment call.

?   Opcode  Mnemonic    operand         comments
    70      Jcc         rel8            8 bits relative offset
    ...     Jcc         rel8
    7F      Jcc         rel8
    
n   9A      CALLF       ptr16:16/32     32-bit or 48-bit pointer direct address
    E3      J(E)CXZ     rel8
Y   E8      CALL        rel16/32
?   FF/2    CALL        r/m16/32
n   FF/3    CALLF       m16:16/32
    E9      JMP         rel16/32
n   EA      JMPF        ptr16:16/32
Y   EB      JMP         rel8
n   FF/4    JMP         r/m16/32
n   FF/5    JMPF        m16:16/32
    
    0F80    Jcc         rel16/32
    ...     Jcc         rel16/32
    0F8F    Jcc         rel16/32

leading 0xF2/0xF3: REPxx

*/

/*  special conditional jump
//////
F873

    CLC
    JNB     Dst
    db      Junks
Dst:

//////
F972

    STC
    JB      Dst
    db      Junks
Dst:

//////
31 C9 E3

;		push	ecx
;		xor		ecx,ecx
;		jcxz	label
;		db		_junkcode
;label:	pop		ecx

*/

/*  2 jumps: true or false with the same dst:
//////
7C 03 EB 03 ?? 74 FB

seg000:00401D3C 7C 03                             jl      short loc_401D41
seg000:00401D3E EB 1E                             jmp     short loc_401D5E
seg000:00401D40                   ; ---------------------------------------------------------------------------
seg000:00401D40 A5                                movsd
seg000:00401D41
seg000:00401D41                   loc_401D41:                             ; CODE XREF: seg000:loc_401D3C j
seg000:00401D41 74 1B                             jz      short loc_401D5E

//////
    J?      Dst
    Jn?     Dst
    db Junks
Dst:
*/

//static de_junks(long start, long end);
// MUST be junk code and not data!
static de_junks(start, end)
{
    //
    // block type first, isn't changed by the simple types
    de_junk(start, end, "7C 03 EB 03 ?? 74 FB", 7, 0, "", 0);
    //
    // call xxx, 'lea esp, [esp+4]'
    de_junk(start, end, "F2 E8",    2, 4, "8D 64 24 04", 4);
    de_junk(start, end, "F3 E8",    2, 4, "8D 64 24 04", 4);
    de_junk(start, end, "E8",       1, 4, "8D 64 24 04", 4);
    //
    de_junk(start, end, "F2 EB",    2, 1, "", 0);
    de_junk(start, end, "F3 EB",    2, 1, "", 0);
    de_junk(start, end, "EB",       1, 1, "", 0);
    //
    de_junk(start, end, "F8 73",    2, 1, "", 0);
    de_junk(start, end, "F9 72",    2, 1, "", 0);
    de_junk(start, end, "31 C9 E3", 3, 1, "", 0);
    //
    // sal eax, 0
    de_junk(start, end, "C1 F0 00", 3, 0, "", 0);
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

static DeJunks(start, end)
{
    auto ea, ea_start;
    auto total_merges;
    auto total_nop_blocks;
    //
    // Message("start, end: %#x, %#x\n", start, end);
    total_junks = 0;
    if (junks_start_ea == 0) junks_start_ea = end;
    if (junks_end_ea == 0) junks_end_ea = start;
    //
    de_junks(start, end);
    // analyse in global scope
    total_merges = merge_jumps(start, end);
    //
    total_nop_blocks = skip_mid_nop(start, end);
    //
    if (total_junks || total_merges) {
        ReAnalyzeArea(junks_start_ea, junks_end_ea);
    }
    //
    Message("junks range [%#x, %#x]\n", junks_start_ea, junks_end_ea);
    Message("total junks removed [%#x, %#x]: %d\n", start, end, total_junks);
    Message("total jumps merged [%#x, %#x]: %d\n", start, end, total_merges);
    Message("total nop blocks skipped [%#x, %#x]: %d\n", start, end, total_nop_blocks);
    Message("Command available: DeJunks(MinEA(), MaxEA());\n");
    Message("Command available: ReAnalyzeArea(junks_start_ea, junks_end_ea);\n");
    Message("Finished!\n");
}

static main(void)
{
    junks_start_ea = MaxEA();
    junks_end_ea = MinEA();
    DeJunks(MinEA(), MaxEA());
}
