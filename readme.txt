DeJunk 和 ReGenFunc 是在做 https://github.com/lifenjoiner/unfsg2 项目时写的，用于处理i386汇编加花的 IDA 脚本。

用法

DeJunk：去除花指令。
运行 DeJunk.idc，按提示输入命令；或者直接运行 DeJunk_simple.idc。

ReGenFunc：重组去花之后的指令，使 IDA 可反编译。
运行 ReGenFunc.idc，按提示输入命令。
FallbackToJxx 分支，是另一种排布条件 jump 分支代码的方法，使重组的汇编读起来更相关。

MSLRH 分支中，DeJunk_MSLRH.idc 是一个调用 DeJunk.idc 尝试去花 MSLRHv0.31a 的例子。

https://github.com/lifenjoiner/DeJunk.idc
