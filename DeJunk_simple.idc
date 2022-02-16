/*  DeJunk.idc for the simple type junks
    $: Remove junk codes in IDA by IDC
    @: lifenjoiner
    L: MIT
*/

#include "DeJunk.idc"

static main(void)
{
    DeJunks(MinEA(), MaxEA(), de_junks);
}
