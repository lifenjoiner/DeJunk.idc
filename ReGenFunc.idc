/* ReGenFunc.idc: an IDA script for regenerating a function from dejunked code pieces
    @lifenjoiner
    #201907
    $: MIT
*/

/* initiate

GetManyBytes

GetSegmentAttr

SegName
RenameSeg

AddSegEx
DelSeg
*/

#include <idc.idc>
#include "opr.idc"

#define BACKUP_SEG_NAME "backup_y"
#define HELPER_SEG_NAME "backup_x"

//

static copy_bytes(dst, src, size) {
    while (--size >= 0) {
        PatchByte(dst, Byte(src));
        dst++;
        src++;
    }
}

//

static cleanup_prev_analyze(ea) {
    auto cur;
    for (cur = RfirstB0(ea); cur != BADADDR; cur = RnextB0(ea, cur)) {
        DelCodeXref(cur, ea, 0);
    }
}

static cleanup_area(start, end) {
    auto ea;
    for (ea = start; ea < end; ea++) {
        cleanup_prev_analyze(ea);
        MakeUnkn(ea, DOUNK_DELNAMES);
        PatchByte(ea, 0);
        RecalcSpd(ea);
    }
}

static cleanup_area_comment(start, end) {
    auto ea, i = 0;
    for (ea = start; ea != BADADDR && ea < end; ea = FindCode(ea, SEARCH_DOWN|SEARCH_NEXT)) {
        MakeComm(ea, "");
        i++;
    }
    return i;
}

static seg_start_by_name(seg_name) {
    auto ea;
    for (ea = MinEA(); ea < MaxEA() && ea != BADADDR; ea = SegEnd(ea)) {
        if (SegName(ea) == seg_name) return ea;
    }
    return -1;
}

static del_seg_by_name(seg_name) {
    auto ea = seg_start_by_name(seg_name);
    if (ea != -1) {
        DelSeg(ea, SEGMOD_KILL | SEGMOD_SILENT);
        return 1;
    }
    return 0;
}

static add_seg_cus(size, seg_name, for_ea) {
    auto new_seg_start;
    //
    new_seg_start = MaxEA();
    if (!AddSegEx(new_seg_start, new_seg_start + size,
            GetSegmentAttr(for_ea, SEGATTR_SEL),
            GetSegmentAttr(for_ea, SEGATTR_BITNESS),
            GetSegmentAttr(for_ea, SEGATTR_ALIGN) | ADDSEG_FILLGAP,
            GetSegmentAttr(for_ea, SEGATTR_COMB),
            ADDSEG_QUIET)
    ) {
        return -1;
    }
    if (!RenameSeg(new_seg_start, seg_name)) {
        DelSeg(new_seg_start, SEGMOD_KILL | SEGMOD_SILENT);
        return -1;
    }
    //
    return seg_start_by_name(seg_name); // truncate start or fill gap
}

static backup_all() {
    auto start, end, backup_seg_start, seg_delta;
    //
    start = MinEA();
    end = MaxEA();
    backup_seg_start = add_seg_cus(end - start, BACKUP_SEG_NAME, start); // all in one named seg
    if (backup_seg_start == -1) return -1;
    //
    seg_delta = backup_seg_start - start;
    copy_bytes(start + seg_delta, start, end - start);
    AnalyzeArea(start + seg_delta, end + seg_delta);
    //
    return backup_seg_start;
}

static backup_func_attr(start, end, entry, seg_delta) {
    auto backup_entry;
    auto back_name;
    //
    backup_entry = entry + seg_delta;
    back_name = BACKUP_SEG_NAME + ltoa(entry, 16);
    if (GetFunctionCmt(backup_entry, 0) == back_name) return;
    //
    MakeCode(backup_entry);
    AnalyzeArea(start + seg_delta, end + seg_delta);
    MakeFunction(backup_entry, GetFunctionAttr(entry, FUNCATTR_END) + seg_delta);
    SetFunctionCmt(backup_entry, back_name, 0);
    //
    return;
}

static restore_func(start, end) {
    auto ea = seg_start_by_name(BACKUP_SEG_NAME);
    if (ea != -1) {
        copy_bytes(start, ea - MinEA() + start, end - start);
        AnalyzeArea(start, end);
        return 1;
    }
    return 0;
}

//

static read_comment_ea(ea, min, max) {
    ea = xtol(CommentEx(ea, 0));
    // comment: a1, a2 ...
    if (ea < MinEA()) ea = 0;
    if (MaxEA() <= ea) ea = 0;
    if (MinEA() < min && ea < min) ea = 0;
    if (min < max && max <= ea) ea = 0;
    return ea;
}

static write_comment_ea(ea, v) {
    MakeComm(ea, "0x"+ ltoa(v, 16));
}

static get_space_for_comment_ea(start, end) {
    auto ea;
    for (ea = start; ea < end && ea != BADADDR; ea = FindCode(ea, SEARCH_DOWN|SEARCH_NEXT)) {
        if (Byte(ea) == 0x90 && read_comment_ea(ea, 0, 0) == 0) return ea;
    }
    return -1;
}

//

#define HELPER_DATA_SIZE 15

// op_type
#define NORMAL      0
#define SHORT_JMP   2
#define SHORT_JXC   3
#define NEAR_JMP    5
#define NEAR_JXC    6
#define NEAR_CALL   9
#define LOOP_X      10

// easier to change data size

static code_param_write_byte(ea, v) {
    PatchByte(ea, v);
    MakeByte(ea);
    return ea + 1;
}

static code_param_write_Dword(ea, v) {
    PatchDword(ea, v);
    MakeDword(ea);
    return ea + 4;
}

static code_param_write_ea(ea, v) {
    return code_param_write_Dword(ea, v);
}

static code_param_write_old_size(ea, v) {
    return code_param_write_byte(ea + 4, v);
}

static code_param_write_operand(ea, v) {
    return code_param_write_Dword(ea + 5, v);
}

static code_param_write_type(ea, v) {
    return code_param_write_byte(ea + 9, v);
}

static code_param_write_size(ea, v) {
    return code_param_write_byte(ea + 10, v);
}

static code_param_write_new_operand(ea, v) {
    return code_param_write_Dword(ea + 11, v);
}

static code_param_read_ea(ea) {
    return Dword(ea);
}

static code_param_read_old_size(ea) {
    return Byte(ea + 4);
}

static code_param_read_operand(ea) {
    return Dword(ea + 5);
}

static code_param_read_type(ea) {
    return Byte(ea + 9);
}

static code_param_read_size(ea) {
    return Byte(ea + 10);
}

static code_param_read_new_operand(ea) {
    return Dword(ea + 11);
}

static write_code_param(ea, ea_code, old_size, operand, op_type, size, operand_new) {
    write_comment_ea(ea_code, ea);
    //
    code_param_write_ea(ea, ea_code);
    code_param_write_old_size(ea, old_size);
    code_param_write_type(ea, op_type);
    code_param_write_operand(ea, operand);
    code_param_write_size(ea, size);
    code_param_write_new_operand(ea, operand_new);
    //
    return ea + HELPER_DATA_SIZE;
}

/* idea to regenerate a function
    1. compact jmp and nop to get the trunk
    2. follow into jcc and repeat step 1 to get a branch,
       append it to the end of the trunk. fallback to the next round.
       jcc-to must be an end piece or jmp to an existing end piece. if not, error.
       call-to must be out of the specified range of this function.
    3. solve the length and operand of jump for target code sequence (far jump or call lenght is solid)
    4. regenerate the function by relative RVA rebased and jcc type determined
*/

/* data structure
    code_param: {
        DWORD ea;
        Byte old_size;  // store to avoid reparse
        DWORD jxx_opnd;
        Byte op_type;
        Byte size;
        DWORD new_jxx_opnd;
    }
    parse: current + next + next_of_jmp
    If current is not an existing end, for the last, overwrite jmp code_param or update jcc operand.
*/

static concat_next_code(cur, code_start, code_end, p_code_param, data_start, data_end, p_code_param_jump, greedy_end) {
    auto op, cur_x, n, new_len, opnd, opnd_s, opnd_i;
    auto p_code_param_x, p_code_param_o, p_code_param_n;
    auto op_type, op_type_o;
    auto p_code_param_jump_n;
    //
    //Message("concat_next_code: code ea %#x ~> p_code_param %#x\n", cur, p_code_param);
    //
    if (p_code_param < data_start || p_code_param > data_end - HELPER_DATA_SIZE) {
        Message("concat_next_code: data ea out of boundaries [%#x, %#x) <-x- %#x <= %#x, size[%d]\n",
                data_start, data_end, p_code_param, cur, HELPER_DATA_SIZE);
        return -1;
    }
    if (greedy_end > 0) {
        if (cur == greedy_end) return p_code_param; // force end for merging enclave code pieces
    }
    else if (cur < code_start || cur >= code_end) {
        Message("concat_next_code: code ea out of boundaries [%#x, %#x) <-x- %#x\n", code_start, code_end, cur);
        // special end: call ExitProcess, jmp OEP?
        return p_code_param;
    }
    //
    if (MakeCode(cur) == 0) { // some codes can't be recognized correctly, especally following a call
        Message("concat_next_code: MakeCode failed %#x\n", cur);
        return -1;
    }
    //
    if (Byte(cur) == 0x90) { // in case
        if (p_code_param_jump) { // update jxc operand
            code_param_write_operand(p_code_param_jump, code_param_read_operand(p_code_param_jump) + 1);
        }
        return concat_next_code(cur + 1, code_start, code_end, p_code_param, data_start, data_end, p_code_param_jump, greedy_end);
    }
    //
    cur_x = cur;
    op = Byte(cur_x);
    // in case
    if (op == 0xF2 || op == 0xF3) cur_x++;
    //
    // get op type
    //
    opnd = 0;
    opnd_s = 0;
    // is jmp?
    if (n = is_short_jmp(cur_x)) {
        cur_x = cur_x + n;
        opnd = read_byte_opnd(cur_x);
        cur_x = cur_x + 1;
        new_len = 0; // to be calculated, drop the REPxx 0xF2, 0xF3
        n = cur_x - cur; // store to avoid reparse
        opnd_s = cur_x + opnd;
        op_type = SHORT_JMP;
    }
    else if (n = is_near_jmp(cur_x)) {
        cur_x = cur_x + n;
        opnd = Dword(cur_x);
        cur_x = cur_x + 4;
        n = cur_x - cur;
        new_len = 0; // to be calculated
        opnd_s = cur_x + opnd;
        op_type = NEAR_JMP;
    }
    // non-jmp as normal code to keep
    else if (n = is_near_call(cur_x)) {
        cur_x = cur_x + n;
        opnd = Dword(cur_x);
        cur_x = cur_x + 4;
        new_len = n + 4;
        n = cur_x - cur;
        opnd_s = cur_x + opnd;
        op_type = NEAR_CALL;
        //
        if (code_start < opnd_s && opnd_s < code_end) { // jump is tested while following in
            Message("concat_next_code: call into boundaries [%#x, %#x): <- %#x <= %#x\n", code_start, code_end, opnd_s, cur);
            return -1;
        }
        //
        opnd_s = cur_x; // don't follow in
    }
    else if (n = is_short_jxc(cur_x)) {
        cur_x = cur_x + n;
        opnd = read_byte_opnd(cur_x);
        cur_x = cur_x + 1;
        new_len = 0; // to be calculated
        n = cur_x - cur;
        opnd_s = cur_x; // only follow jmp
        op_type = SHORT_JXC;
    }
    else if (n = is_loopx(cur_x)) { // only back to exist
        cur_x = cur_x + n;
        opnd = read_byte_opnd(cur_x);
        cur_x = cur_x + 1;
        new_len = 0; // operand need to be calculated
        n = cur_x - cur;
        opnd_s = cur_x; // only follow jmp
        op_type = LOOP_X;
    }
    else if (n = is_near_jxc(cur_x)) {
        cur_x = cur_x + n;
        opnd = Dword(cur_x);
        cur_x = cur_x + 4;
        new_len = 0; // to be calculated
        n = cur_x - cur;
        opnd_s = cur_x; // only follow jmp
        op_type = NEAR_JXC;
    }
    else { // other codes of the block
        n = NextNotTail(cur) - cur;
        new_len = n;
        cur_x = cur + n;
        opnd_s = cur_x;
        op_type = NORMAL;
    }
    //
    // already in main trunk?
    //
    p_code_param_x = read_comment_ea(cur, data_start, data_end);
    //
    // decide
    // If current is not an existing end, for the last, overwrite jmp code_param or update jcc operand.
    // All others, run next round recursively ...
    //
    if (data_start <= p_code_param_x && p_code_param_x < p_code_param) { //exist in the trunk
        if (p_code_param_jump) { // from jcc
            return p_code_param;
        }
        else { // from normal code following jcc, need extra jmp
            opnd = get_space_for_comment_ea(code_start, code_end); // need to store comment_ea
            if (opnd == -1) {
                Message("concat_next_code: can't add jmp for %#x -> %#x\n", p_code_param, p_code_param_x);
                return -1;
            }
            //
            op_type = NEAR_JMP;
            n = 0;
            opnd_s = cur;
            cur = opnd;
            opnd = opnd_s - cur;
            new_len = 0;
            //
            return write_code_param(p_code_param, cur, n, opnd, op_type, new_len, 0);
        }
    }
    //
    // new, not exist in the trunk
    //
    // store param first
    //
    // overwrite current jmp before writing
    //
    if (p_code_param_jump && (op_type == SHORT_JMP || op_type == NEAR_JMP)) {
        opnd = n + opnd; // ori_code_len + operand, overwriten next
        if (code_param_read_ea(p_code_param) > data_start) opnd = opnd + code_param_read_operand(p_code_param); // get cumulated operand of middle jmps for Jcc
    }
    //
    //Message("concat_next_code: p_code_param <- ea_code, old_size, opnd, op_type, new_size: %#x <- %#x, %#x, %#x, %#x\n", p_code_param, cur, n, opnd, op_type, new_len);
    //
    p_code_param_n = write_code_param(p_code_param, cur, n, opnd, op_type, new_len, 0); // new, moved forward
    //
    // good end
    //
    if (is_retn(cur)) return p_code_param_n;
    //
    p_code_param_jump_n = 0;
    p_code_param_x = read_comment_ea(opnd_s, 0, p_code_param); // could be jmpout to regenerated ea
    if (op_type == SHORT_JMP || op_type == NEAR_JMP) {
        if (p_code_param_x == 0) { // jmp to new, since the first to the last
            p_code_param_n = p_code_param; // move backward, overwrite
        } // jmp to exist need fall to fix jcc caller
        // trunk or regenerated
        else if (p_code_param_jump) { // delivery through current jmp, middle jmp params are overwritten
            p_code_param_jump_n = p_code_param_jump;
        }
        else { // necessary jmp, initial
            p_code_param_jump_n = p_code_param;
        }
    }
    //
    // recur
    //
    // jmps from initial jcc are overwriten by the last jmp to trunk, with operand comulated,
    // and then the last jmp is jumpped over when fallback updated the jcc operand.
    // jmp to trunk from normal code is kept when fallbak.
    // jmp to new code from normal code is skipped when fallbak.
    //
    p_code_param_x = concat_next_code(opnd_s, code_start, code_end, p_code_param_n, data_start, data_end, p_code_param_jump_n, greedy_end);
    //
    // fallback
    //
    if (p_code_param_x == -1) return -1;
    if (p_code_param_n < p_code_param_x - HELPER_DATA_SIZE) return p_code_param_x; // appended more than 1 codes
    //
    // jumpout to new, but outof function range, 0 code appended, keep the jmp
    //
    if (p_code_param == p_code_param_x) return p_code_param_x + HELPER_DATA_SIZE;
    //
    // only 1 code appended, jumping to exist code appends a jmp
    //
    if (p_code_param_n < p_code_param_x) p_code_param_n = p_code_param_x;
    //
    if (!p_code_param_jump) return p_code_param_n; // not from jump
    //
    // update jcc operand after falling back
    // special:
    //  only appended 1 jmp: jcc + jmp to the trunk, drop jmp, new operand determins updating jcc (or not)
    //   jcc + jmp to new code, jmp is overwriten by the next, finally can be jmp to the trunk
    //  cross-over/loop jumps
    //
    p_code_param_o = p_code_param_jump; // p_code_param_jump is given through jmps by the initial jcc
    op_type_o = code_param_read_type(p_code_param_o);
    opnd = code_param_read_operand(p_code_param); // get cumulated operand, 0 is not jump
    if ((op_type == SHORT_JMP || op_type == NEAR_JMP) && opnd &&
        (op_type_o == SHORT_JXC || op_type_o == NEAR_JXC)
    ) { // also include must-keep jmp
        opnd = opnd + code_param_read_operand(p_code_param_o); // cumulate only last is jump
        // update operand, keep comment_ea, move backward
        code_param_write_operand(p_code_param_o, opnd);
        p_code_param_n = p_code_param; // drop the jmp after jcc
        write_code_param(p_code_param, 0, 0, 0, 0, 0, 0); // in case of it's the last one
    }
    //
    return p_code_param_n;
}

// based on concat_next_code p_code_param
static concat_next_jxcto(p_cur, code_start, code_end, p_code_param, data_start, data_end, greedy_end) {
    auto cur, cur_x, op_type, n;
    auto p_code_param_x, p_code_param_n;
    //
    if (p_cur == p_code_param) return p_code_param; // good end
    //
    cur = code_param_read_ea(p_cur);
    //
    //Message("concat_next_jxcto: p_cur %#x -> code ea %#x ~> p_dst %#x\n", p_cur, cur, p_code_param);
    //
    if (p_code_param < data_start || p_code_param > data_end - HELPER_DATA_SIZE) {
        Message("concat_next_jxcto: data ea out of boundaries [%#x, %#x) <-x- %#x <= %#x, size[%d]\n",
                data_start, data_end, p_code_param, cur, HELPER_DATA_SIZE);
        return -1;
    }
    if (greedy_end > 0) {
        if (cur == greedy_end) return p_code_param; // force end for merging enclave code pieces
    }
    else if (cur < code_start || cur >= code_end) {
        Message("concat_next_jxcto: code ea out of boundaries [%#x, %#x) <-x- %#x\n", code_start, code_end, cur);
        return -1;
    }
    //
    // get op type
    op_type = code_param_read_type(p_cur);
    //
    // is jcc?
    if (op_type != SHORT_JXC && op_type != NEAR_JXC) { // skip others which already have been processed
        return concat_next_jxcto(p_cur + HELPER_DATA_SIZE, code_start, code_end, p_code_param, data_start, data_end, greedy_end);
    }
    //
    n = code_param_read_old_size(p_cur);
    cur_x = cur + n;
    //
    // Only jcc (processed)
    // already in main trunk?
    //
    p_code_param_x = read_comment_ea(cur, data_start, data_end);
    //
    if (p_code_param_x != p_cur) { // new, not exist in the trunk
        Message("concat_next_jxcto: p_cur %#x -> code ea %#x ~> p_dst %#x\n", p_cur, cur, p_code_param_x);
        return -1;
    }
    //
    // need concat
    //
    // handle it to concat_next_code
    //
    cur_x = cur_x + code_param_read_operand(p_cur);
    p_code_param_n = concat_next_code(cur_x, code_start, code_end, p_code_param, data_start, data_end, p_cur, greedy_end);
    //
    if (p_code_param_n == -1) return -1;
    if (p_code_param < p_code_param_n) p_code_param = p_code_param_n;
    //
    // next main flow code in trunk
    //
    return concat_next_jxcto(p_cur + HELPER_DATA_SIZE, code_start, code_end, p_code_param, data_start, data_end, greedy_end);
}

static solve_required_jump_i(cur, code_start, code_end, p_cur, data_start, data_end, greedy_end) {
    auto cur_x, n, opnd, opnd_s, opnd_e, jump_forward;
    auto p_cur_x, ea, size, unsolved, guess_min, guess_max, code_len;
    auto op_type, op_type_x;
    auto sum_code_param_size_p_start, sum_code_param_size_p_end;
    //
    if (p_cur == data_end) return data_end; // good end
    //
    //Message("solve_required_jump: p_cur => ea : %#x => %#x\n", p_cur, cur);
    //
    if (p_cur < data_start || p_cur > data_end - HELPER_DATA_SIZE) {
        Message("solve_required_jump: data ea out of boundaries [%#x, %#x) <-x- %#x <= %#x, size[%d]\n",
                data_start, data_end, p_cur, cur, HELPER_DATA_SIZE);
        return -1;
    }
    if (greedy_end > 0) {
        if (cur == greedy_end) return p_cur; // force end for merging enclave code pieces
    }
    else if (cur < code_start || cur >= code_end) {
        Message("solve_required_jump: code ea out of boundaries [%#x, %#x) <-x- %#x\n", code_start, code_end, cur);
        return -1;
    }
    //
    // skip solved
    //
    unsolved = 0;
    //
    if (code_param_read_size(p_cur) > 0 && code_param_read_new_operand(p_cur)) return unsolved;
    //
    // get op type
    op_type = code_param_read_type(p_cur);
    //
    // is jcc or neccessary jmp? ("||" expressions are all executed!)
    if (op_type != SHORT_JXC && op_type != SHORT_JMP && op_type != NEAR_JMP && op_type != NEAR_JXC && op_type != LOOP_X) return unsolved;
    n = code_param_read_old_size(p_cur);
    cur_x = cur + n;
    //
    p_cur_x = read_comment_ea(cur, data_start, data_end);
    if (p_cur_x != p_cur) {
        Message("solve_required_jump: p_cur_x <=> code_ea <=x=> data_ea : %#x <=> %#x <=x=> %#x\n", p_cur_x, cur, p_cur);
        return -1;
    }
    //
    // get jump operand for oringinal code
    //
    opnd = code_param_read_operand(p_cur);
    if (opnd == 0) {
        Message("solve_required_jump: not solved operand of param %#x => %#x\n", p_cur, cur);
        return -1;
    }
    //
    opnd_e = 0;
    opnd_s = cur_x + opnd;
    p_cur_x = read_comment_ea(opnd_s, 0, 0);
    //
    if (opnd_s < code_start || opnd_s >= code_end) {
        Message("solve_required_jump: jump out of boundaries %#x => %#x => %#x\n", p_cur, cur, opnd_s);
        //
        // not regenerated yet
        //
        if (p_cur_x == 0 || data_start <= p_cur_x) return -1;
        //
        // the ugly mess function jump out, p_cur_x is the new code ea
        //
        // in case of a bad start code, we stored the entry as repeatable comment of data_start
        opnd_e = xtol(CommentEx(data_start, 1)) - p_cur_x; // +: before this block, -: after this block
        p_cur_x = data_start;
    }
    else if (p_cur_x < data_start || p_cur_x > data_end - HELPER_DATA_SIZE) {
        Message("solve_required_jump: operand ea out of boundaries [%#x, %#x) <-x- %#x <= %#x <= %#x, size[%d]\n",
                data_start, data_end, p_cur_x, opnd_s, cur_x, HELPER_DATA_SIZE);
        return -1;
    }
    //
    // need solve
    //
    // sum code length without unknown items for decision making
    //
    //Message("solve_required_jump: from -> to (ea) : %#x => %#x (%#x)\n", p_cur, p_cur_x, opnd_s);
    //
    n = 0;
    guess_min = 0;
    guess_max = 0;
    //
    if (p_cur <= p_cur_x) { // jump forward, exclude start code, exclude dest code
        sum_code_param_size_p_start = p_cur + HELPER_DATA_SIZE;
        sum_code_param_size_p_end = p_cur_x;
    }
    else { // jump backward, include dest code, include start code (examine separately)
        sum_code_param_size_p_start = p_cur_x;
        sum_code_param_size_p_end = p_cur; // + HELPER_DATA_SIZE;
        if (opnd_e < 0) sum_code_param_size_p_end = p_cur + HELPER_DATA_SIZE; // jump out forward indeed
    }
    // sum_code_param_size
    for (ea = sum_code_param_size_p_start; ea < sum_code_param_size_p_end; ea = ea + HELPER_DATA_SIZE) {
        size = code_param_read_size(ea);
        if (size > 0) {
            n = n + size;
            guess_min = guess_min + size;
            guess_max = guess_max + size;
        }
        else {
            unsolved++;
            op_type_x = code_param_read_type(ea);
            if (op_type_x == SHORT_JMP || op_type_x == NEAR_JMP) {
                guess_min = guess_min + 1;
                guess_max = guess_max + 1;
            }
            else if (op_type_x == SHORT_JXC || op_type_x == NEAR_JXC) {
                guess_min = guess_min + 1;
                guess_max = guess_max + 2;
            }
        }
        //Message("solve_required_jump: size total p_code_param %#x %#x %#x\n", size, n, ea);
    }
    //
    // decide new operand and code length for jump
    //
    // guess size
    //
    code_len = 1; // SHORT_JMP, NEAR_JMP, SHORT_JXC, drop REPNZ/REP 0xF2/0xF3
    if (opnd_e > 0) { // the ugly mess function jump out, before this block
        n = n + opnd_e;
        guess_min = guess_min + opnd_e;
        guess_max = guess_max + opnd_e;
        //
        jump_forward = -1;
    }
    else if (opnd_e < 0) { // after this block
        n = -opnd_e - n;
        jump_forward = guess_min;
        guess_min = -opnd_e - guess_max; // <- left, logic changes
        guess_max = -opnd_e - jump_forward;
        //
        jump_forward = 1;
    }
    // opnd_e == 0
    else if (p_cur > p_cur_x) {
        jump_forward = -1;
    }
    else {
        jump_forward = 1;
    }
    //
    if (code_param_read_size(p_cur) <= 0) { // all solved or unsolved jmp
        if (jump_forward < 0) { // backward, consider the start jump itself
            if (guess_max + unsolved * 4 < 0x7E) { // 0x80 - 0x02
                code_len = 2;
                code_param_write_size(p_cur, code_len);
            }
            else if (guess_min + unsolved >= 0x7E) {
                if (op_type == SHORT_JXC || op_type == NEAR_JXC) code_len = 2;
                code_len = code_len + 4;
                code_param_write_size(p_cur, code_len);
            }
            if (unsolved == 0) n = n + code_len; // n == guess_min == guess_max
        }
        else { // forward
            if (guess_max + unsolved * 4 < 0x80) {
                code_len = 2;
                code_param_write_size(p_cur, code_len);
            }
            else if (guess_min + unsolved >= 0x80) {
                if (op_type == SHORT_JXC || op_type == NEAR_JXC) code_len = 2;
                code_param_write_size(p_cur, code_len + 4);
            }
        }
    }
    //
    // save solved new operand
    //
    //Message("solve_required_jump: p_cur min, solid, max, unsolved, forward: %#x %#x %#x %#x %d %d\n", p_cur, guess_min, n, guess_max, unsolved, jump_forward);
    if (unsolved == 0) { // all solved, n is the operand for target ordered code
        if (op_type == LOOP_X && n > 0x7F) {
            Message("solve_required_jump: wrong opnd for loopx %#x\n", n);
            return -1;
        }
        //Message("solve_required_jump: new opnd %#x\n", n * jump_forward);
        code_param_write_new_operand(p_cur, n * jump_forward);
    }
    //
    return unsolved;
}

static solve_required_jump_m(code_start, code_end, p_cur, data_start, data_end, greedy_end) {
    auto cur, p_cur_n;
    auto n, unsolved;
    //
    Message("solve_required_jump: new round\n");
    //
    p_cur_n = p_cur;
    unsolved = 0;
    while (p_cur = p_cur_n, data_start <= p_cur && p_cur < data_end) {
        p_cur_n = p_cur + HELPER_DATA_SIZE;
        cur = code_param_read_ea(p_cur);
        n = solve_required_jump_i(cur, code_start, code_end, p_cur, data_start, data_end, greedy_end);
        if (n < 0) return -1;
        unsolved = unsolved + n;
    }
    //
    return unsolved;
}

static solve_required_jump(code_start, code_end, p_cur, data_start, data_end, greedy_end) {
    auto unsolved, unsolved_o;
    //
    unsolved_o = 0x7FFFFFFF;
    while ((unsolved = solve_required_jump_m(code_start, code_end, p_cur, data_start, data_end, greedy_end)) > 0 && unsolved < unsolved_o) {
        //Message("solve_required_jump: left %d\n", unsolved);
        unsolved_o = unsolved;
    }
    return unsolved;
}

static show_unsolved_jump(data_start, data_end) {
    auto p_data, op_type;
    for (p_data = data_start; p_data < data_end; p_data = p_data + HELPER_DATA_SIZE) {
        op_type = code_param_read_type(p_data);
        if (op_type != SHORT_JXC && op_type != SHORT_JMP && op_type != NEAR_JMP && op_type != NEAR_JXC) continue;
        if (code_param_read_size(p_data) == 0 || code_param_read_new_operand(p_data) == 0) {
            Message("unsolved jump: %#x\n", p_data);
        }
    }
}

static gen_code(dst, code_start, code_end, p_cur, data_start, data_end, seg_delta, greedy_end) {
    auto cur, size, op_type, opnd;
    //
    cur = code_param_read_ea(p_cur);
    //
    if (p_cur > data_end - HELPER_DATA_SIZE) return dst; // finished
    //
    if (greedy_end > 0) {
        if (cur == greedy_end) return p_cur; // force end for merging enclave code pieces
    }
    else if (cur < code_start || cur >= code_end) {
        Message("gen_code: code ea out of boundaries [%#x, %#x) <-x- %#x\n", code_start, code_end, cur);
        return -1;
    }
    //
    //Message("gen_code: p_code_param => ea_old -> ea_new size : %#x => %#x -> %#x %#x\n", p_cur, cur, dst, code_param_read_size(p_cur));
    //
    // assume all good prepared
    //
    size = code_param_read_size(p_cur);
    op_type = code_param_read_type(p_cur);
    opnd = code_param_read_new_operand(p_cur);
    //
    if (dst + size > code_end - seg_delta) {
        Message("gen_code: no enough space %#x <~ %#x <- %#x\n", dst, cur, p_cur);
        return -1;
    }
    //
    write_comment_ea(cur, dst); // for jump from the ugly mess functions
    //
    if (op_type == NORMAL) {
        copy_bytes(dst, cur, size); // drop REP for jmp
        dst = dst + size;
    }
    else if (op_type == NEAR_CALL) {
        PatchByte(dst, 0xE8);
        opnd = code_param_read_operand(p_cur); // original, calculate now
        opnd = opnd + cur - seg_delta - dst;
        PatchDword(dst + 1, opnd); // shouldn't overflow
        //Message("gen_code: near call opnd <- ea_new <= seg_delta <= ea_old : %#x <- %#x <= %#x <= %#x\n", opnd, dst, seg_delta, cur);
        dst = dst + 5;
    }
    else if (op_type == SHORT_JXC) {
        if (-0x80 < opnd && opnd < 0x80) {
            PatchByte(dst, Byte(cur));
            dst++;
            PatchByte(dst, opnd);
            dst++;
        }
        else {
            PatchByte(dst, 0x0F);
            dst = dst + 1;
            PatchByte(dst, Byte(cur) + 0x10);
            dst = dst + 1;
            PatchDword(dst, opnd);
            dst = dst + 4;
        }
    }
    else if (op_type == NEAR_JXC) {
        if (-0x80 < opnd && opnd < 0x80) {
            PatchByte(dst, Byte(cur + 1) - 0x10);
            dst++;
            PatchByte(dst, opnd);
            dst++;
        }
        else {
            PatchDword(dst, Dword(cur));
            dst = dst + 2;
            PatchDword(dst, opnd);
            dst = dst + 4;
        }
    }
    else if (op_type == SHORT_JMP || op_type == NEAR_JMP) {
        if (-0x80 < opnd && opnd < 0x80) {
            PatchByte(dst, 0xEB);
            dst++;
            PatchByte(dst, opnd);
            dst++;
        }
        else {
            PatchByte(dst, 0xE9);
            dst = dst + 1;
            PatchDword(dst, opnd);
            dst = dst + 4;
        }
    }
    else if (op_type == LOOP_X) {
        PatchByte(dst, Byte(cur));
        dst++;
        PatchByte(dst, opnd);
        dst++;
    }
    //
    MakeCode(dst - size);
    //
    return gen_code(dst, code_start, code_end, p_cur + HELPER_DATA_SIZE, data_start, data_end, seg_delta, greedy_end);
}

static ReGenFunc(start, end, entry) {
    return ReGenFuncEx(start, end, entry, 0);
}

// greedy_end: explicit end of function while having enclave code piece, separated by other functions, jumpout/jumpback
static ReGenFuncEx(start, end, entry, greedy_end) {
    auto bak_start, bak_end, bak_entry, seg_delta;
    auto helper_seg_start, helper_seg_end, helper_cur;
    auto n, func_name, func_tinfo;
    //
    Message("backup ...\n");
    bak_start = seg_start_by_name(BACKUP_SEG_NAME);
    if (bak_start == -1) bak_start = backup_all();
    if (bak_start == -1) return 0;
    //
    seg_delta = bak_start - MinEA();
    //
    if (entry == -1) entry = start;
    else if (entry < start || end <= entry) {
        Message("wrong entry: [%#x, %#x) <-x- %#x\n", start, end, entry);
        return 0;
    }
    //
    func_name = "";
    if (entry == GetFunctionAttr(entry, FUNCATTR_START)) { // is function, not Fchunk
        func_name = GetFunctionName(entry);
        func_tinfo = GetTinfo(entry);
        backup_func_attr(start, end, entry, seg_delta);
    }
    //
    bak_start = start + seg_delta;
    bak_end = end + seg_delta;
    bak_entry = entry + seg_delta;
    //
    if (greedy_end == -1) greedy_end = bak_end;
    else if (greedy_end > 0) greedy_end = greedy_end + seg_delta;
    //
    Message("cleanup_area_comment ...\n");
    n = cleanup_area_comment(bak_start, bak_end);
    Message("cleanup_area_comment total codes %d ...\n", n);
    //
    Message("add_seg_cus ...\n");
    del_seg_by_name(HELPER_SEG_NAME);
    helper_seg_start = add_seg_cus(n * HELPER_DATA_SIZE, HELPER_SEG_NAME, start);
    if (helper_seg_start <= 0) return 0;
    helper_seg_end = SegEnd(helper_seg_start);
    //
    MakeRptCmt(helper_seg_start, "0x"+ ltoa(entry, 16)); // store entry
    //
    cleanup_area(helper_seg_start, helper_seg_end); // in case last remains
    //
    Message("concat_next_code ...\n");
    helper_cur = concat_next_code(bak_entry, bak_start, bak_end, helper_seg_start, helper_seg_start, helper_seg_end, 0, greedy_end);
    if (helper_cur <= 0) return 0;
    //
    Message("concat_next_jxcto: ...\n");
    helper_cur = concat_next_jxcto(helper_seg_start, bak_start, bak_end, helper_cur, helper_seg_start, helper_seg_end, greedy_end);
    if (helper_cur <= 0) return 0;
    //
    // helper_cur is the code_param end bound
    //
    Message("solve_required_jump ...\n");
    n = solve_required_jump(bak_entry, bak_end, helper_seg_start, helper_seg_start, helper_cur, greedy_end);
    if (n) {
        Message("solve_required_jump: unsolved jcc count: %d\n", n);
        show_unsolved_jump(helper_seg_start, helper_cur);
        return 0;
    }
    //
    Message("cleanup_area(%#x, %#x) ...\n", start, end);
    cleanup_area(start, end);
    //
    Message("gen_code ...\n");
    n = gen_code(entry, bak_start, bak_end, helper_seg_start, helper_seg_start, helper_cur, seg_delta, greedy_end);
    if (n == -1) return 0;
    //
    Message("cleanup ...\n");
    del_seg_by_name(HELPER_SEG_NAME); // kept to allow jmp out
    //
    MakeCode(entry);
    //
    AnalyzeArea(MinEA(), MaxEA());
    //
    if (func_name != "") {
        MakeFunction(entry, BADADDR); // could fail
        SetFunctionEnd(entry, n);
        if (substr(func_name, 0, 4) != "sub_") {
            MakeName(entry, func_name);
            ApplyType(entry, func_tinfo, TINFO_DEFINITE);
        }
    }
    //
    return n - start;
}

static main(void)
{
    Message("ReGenFunc(start, end, entry) // entry: -1, use start\n");
    Message("RestoreFunc(start, end) // backup is better\n");
    Message("del_seg_by_name(SEG_NAME)\n");
    Message("ReGenFuncEx(start, end, entry, greedy_end) // greedy_end: force end for merging enclave codes; -1 , use end\n");
}
