/* opr: a lib for op operand code
    @lifenjoiner
    #201907
    $: MIT
*/

#include <idc.idc>

#ifndef _OP_RELATIVE
#define _OP_RELATIVE

/* op code */

// return op length
// "FAR" specifies both a segment and offset, which are both absolute

static is_FF_r(ea, ro) {
    auto op = Byte(ea);
    if (op == 0xFF && Byte(ea + 1) >> 3 & 7 == ro) return 2;
    return 0;
}

static is_short_jmp(ea) {
    auto op = Byte(ea);
    if ( op == 0xEB ) return 1;
    return 0;
}

static is_short_jxc(ea) { // Jcc or JECXZ
    auto op = Byte(ea);
    if ((0x70 <= op && op <= 0x7F) || op == 0xE3) return 1;
    return 0;
}

static is_near_jmp(ea) {
    auto op = Byte(ea);
    if (op == 0xE9) return 1;
    return 0;
}

static is_near_jxc(ea) {
    auto op = Byte(ea);
    if (op == 0x0F) {
        op = Byte(ea + 1);
        if (0x80 <= op && op <= 0x8F) return 2;
    }
    return 0;
}

static is_near_jmp_r(ea) {
    return is_FF_r(ea, 4);
}

static is_far_jmp(ea) {
    auto op = Byte(ea);
    if (op == 0xEA) return 1;
    return 0;
}

static is_far_jmp_r(ea) {
    return is_FF_r(ea, 5);
}

static is_jump(ea) {
    return is_short_jmp(ea) || is_short_jxc(ea) || is_near_jmp(ea) || is_near_jxc(ea) || is_near_jmp_r(ea) || is_far_jmp(ea) || is_far_jmp_r(ea);
}

static is_near_call(ea) {
    auto op = Byte(ea);
    if (op == 0xE8) return 1;
    return 0;
}

// specifies both a segment and offset, which are both absolute
static is_near_call_r(ea) {
    return is_FF_r(ea, 2);
}

static is_far_call(ea) {
    auto op = Byte(ea);
    if (op == 0x9A) return 1;
    return 0;
}

static is_far_call_r(ea) {
    return is_FF_r(ea, 3);
}

static is_call(ea) {
    return is_near_call(ea) || is_near_call_r(ea) || is_far_call(ea) || is_far_call_r(ea);
}

static is_retn(ea) {
    auto op = Byte(ea);
    if (op == 0xC3 || op == 0xCB || op == 0xC2 || op == 0xCA || op == 0xCF) return 1;
    return 0;
}

/* *** */

static read_byte_opnd(ea) {
    auto opnd = Byte(ea);
    if (opnd > 0x7F) opnd = opnd | 0xFFFFFF00;
    return opnd;
}

static has_prev_nbr_code(ea) {
    return RfirstB(ea) == FindCode(ea, SEARCH_UP|SEARCH_NEXT) && RfirstB(ea) != RfirstB0(ea);
}

static has_next_nbr_code(ea) {
    return Rfirst(ea) == FindCode(ea, SEARCH_DOWN|SEARCH_NEXT) && Rfirst(ea) != Rfirst0(ea);
}

#endif
