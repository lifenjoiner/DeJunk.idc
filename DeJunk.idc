/*  DeJunk.idc
    $: Remove junk codes in IDA by IDC
    @: lifenjoiner
    L: GPL
    
    H:
    v0.2.0 20190616
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

// return op length

static is_FF_r(ea, ro) {
    auto op = Byte(ea);
    if ( op == 0xFF && Byte(ea + 1) >> 3 & 7 == ro ) {
        return 2;
    } else {
        return 0;
    }
}

static is_short_jump(ea) {
    auto op = Byte(ea);
    if ( op == 0xEB ) {
        return 1;
    } else {
        return 0;
    }
}

static is_short_jxc(ea) {
    auto op = Byte(ea);
    if ( (0x70 <= op && op <= 0x7F) || op == 0xE3 ) {
        return 1;
    } else {
        return 0;
    }
}

static is_near_jump(ea) {
    auto op = Byte(ea);
    auto n = 1;
    if ( op == 0xE9 ) {
        return n;
    } else {
        return 0;
    }
}

static is_near_jxc(ea) {
    auto op = Byte(ea);
    auto n = 1;
    if (op == 0x0F) {
        op = op * 256 + Byte(ea + 1);
        n = 2;
    }
    if ( 0x0F80 <= op && op <= 0x0F8F ) {
        return n;
    } else {
        return 0;
    }
}

static is_near_jump_r(ea) {
    return is_FF_r(ea, 4);
}

static is_far_jump(ea) {
    auto op = Byte(ea);
    if (op == 0xEA) {
        return 1;
    } else {
        return 0;
    }
}

static is_far_jump_r(ea) {
    return is_FF_r(ea, 5);
}

static is_jump(ea) {
    return is_short_jump(ea) || is_short_jxc(ea) || is_near_jump(ea) || is_near_jxc(ea) || is_near_jump_r(ea) || is_far_jump(ea) || is_far_jump_r(ea);
}

static is_near_call(ea) {
    auto op = Byte(ea);
    if (op == 0xE8) {
        return 1;
    } else {
        return 0;
    }
}

static is_near_call_r(ea) {
    return is_FF_r(ea, 2);
}

static is_far_call(ea) {
    auto op = Byte(ea);
    if (op == 0x9A) {
        return 1;
    } else {
        return 0;
    }
}

static is_far_call_r(ea) {
    return is_FF_r(ea, 3);
}

static is_call(ea) {
    return is_near_call(ea) || is_near_call_r(ea) || is_far_call(ea) || is_far_call_r(ea);
}

static is_retn(ea) {
    auto op = Byte(ea);
    if (op == 0xC3 || op == 0xCB || op == 0xC2 || op == 0xCA || op == 0xCF) {
        return 1;
    } else {
        return 0;
    }
}

static patch_byte_operand(ea, op_len, opnd_change, flowtype) {
    auto cur_x, opnd_old, opnd;

    cur_x = ea + op_len;
    opnd_old = Byte(cur_x);
    if (opnd_old > 0x7F) opnd_old = opnd_old | 0xFFFFFF00;
    opnd = opnd_old + opnd_change;
    // overflow?
    if (opnd > 0x7F || opnd < -0x7F) return 0;
    if (opnd_change != 0) {
        PatchByte(cur_x, opnd);
        DelCodeXref(ea, cur_x + 1 + opnd_old, 0);
        AddCodeXref(ea, cur_x + 1 + opnd, XREF_USER | flowtype);
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
    }
    return opnd;
}

static nop_bytes(ea, len) {
    auto i;
    for (i = 0; i < len; i++) PatchByte(ea + i, 0x90);
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
    auto retn, counter;
    retn = 0;
    counter = 0;
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
            if ( n = is_short_jump(cur_x) ) {
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
            } else if ( n = is_near_jump(cur_x) ) {
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
        counter++;
        if (opnd_change != 0 && n != 0) retn++;
    }
    // the ones in middle: all jump to this are updated?
    if (recur && opnd_change && counter && counter == retn) {
        //
        n = 0;
        opnd = 0;
        //
        if (is_not_xref_block(start)) {
            op = Byte(cur);
            cur_x = start;
            if (op == 0xF2 || op == 0xF3) {
                cur_x++;
            }
            if (n = is_short_jump(cur_x)) {
                opnd = Byte(cur_x + n);
                if (opnd > 0x7F) opnd = opnd | 0xFFFFFF00;
                n = cur_x - start + n + 1;
            }
            else if (n = is_near_jump(cur_x)) {
                opnd = Dword(cur_x + n);
                n = cur_x - start + n + 4;
            }
        }
        // nop
        //
        if (n > 0) nop_bytes(start, n);
        DelCodeXref(start, start + n + opnd, 0);
        MakeName(start, "");
    }
    //
    return retn;
}

static merge_jumps(start, end) {
    auto ea, n, total;
    total = 0;
    for (ea = start; ea < end && ea != BADADDR; ea = FindCode(ea, SEARCH_DOWN|SEARCH_NEXT)) {
        n = fix_opnd_rva(ea, Byte(ea) == 0x90 ? 1: 0, 1);
        total = total + n;
        if (n > 0) {
            Message("merge_jumps ea: %#x\n", ea);
            if (junks_end_ea < ea) junks_end_ea = ea;
            if (junks_start_ea > ea) junks_start_ea = ea;
        }
    }
    return total;
}

static skip_mid_nop(start, end) {
    auto ea, cur;
    auto nop_start, jump_start;
    auto n, op, opnd;
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
        opnd = 0;
        if (n = is_short_jump(ea)) {
            ea = ea + n;
            opnd = Byte(ea);
            if (opnd > 0x7F) opnd = opnd | 0xFFFFFF00;
            ea = ea + 1;
        }
        else if (n = is_near_jump(ea)) {
            ea = ea + n;
            opnd = Dword(ea);
            ea = ea + 4;
        }
        //
        if (opnd == 0) continue;
        //
        jump_start = cur;
        n = jump_start - nop_start;
        Message("nop blocks ea: %#x, len: %#d\n", nop_start, n);
        opnd = opnd + n;
        //
        if (0x7FFFFFFF < opnd || opnd < -0x7FFFFFFF) continue;
        //
        if (-0x80 < opnd && opnd < 0x80) {
            cur = nop_start + 2;
            PatchByte(nop_start, 0xEB);
            PatchByte(nop_start + 1, opnd);
        }
        else {
            cur = nop_start + 5;
            if (cur > ea) continue;
            PatchByte(nop_start, 0xE9);
            PatchDword(nop_start + 1, opnd);
        }
        //
        if (jump_start >= cur) PatchByte(jump_start, 0x90);
        if (jump_start + 1 > cur) cur = jump_start + 1;
        nop_bytes(cur, ea - cur);
        counter++;
        //
        fix_opnd_rva(jump_start, -n, 0);
        //
        DelCodeXref(jump_start, ea - n + opnd, 0);
        AddCodeXref(nop_start, ea - n + opnd, XREF_USER | fl_JN);
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
        if (len_operand == 1) {
            n = Byte(ea_x);
            if (n > 0x7F) n = n | 0xFFFFFF00;
        } else if (len_operand == 4) {
            n = Dword(ea_x);
        }
        //Message("jmp-len: %d\n", n);
        if (n <= 0) continue;
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
        DelCodeXref(ea, ea + n, 0);
        MakeName(ea + n, "");
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
    CLC
    JNB     Dst
    db      Junks
Dst:
F873

    STC
    JB      Dst
    db      Junks
Dst:
F972

;		push	ecx
;		xor		ecx,ecx
;		jcxz	label
;		db		_junkcode
;label:	pop		ecx
31 C9 E3

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
    de_junk(start, end, "F2 EB",    2, 1, "", 0);
    de_junk(start, end, "F3 EB",    2, 1, "", 0);
    de_junk(start, end, "EB",       1, 1, "", 0);
    // call xxx, 'lea     esp, [esp+4]'
    de_junk(start, end, "F2 E8",    2, 4, "8D 64 24 04", 4);
    de_junk(start, end, "F3 E8",    2, 4, "8D 64 24 04", 4);
    de_junk(start, end, "E8",       1, 4, "8D 64 24 04", 4);
    //
    de_junk(start, end, "F8 73",    2, 1, "", 0);
    de_junk(start, end, "F9 72",    2, 1, "", 0);
    de_junk(start, end, "31 C9 E3", 3, 1, "", 0);
    //
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
    Message("Finished!\n");
}

static main(void)
{
    junks_start_ea = MaxEA();
    junks_end_ea = MinEA();
    DeJunks(MinEA(), MaxEA());
    Message("Command available: DeJunks(MinEA(), MaxEA());\n");
    Message("Command available: ReAnalyzeArea(junks_start_ea, junks_end_ea);\n");
}
