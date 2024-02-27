# Environment variables

  This document discusses the environment variables used by AFL++ to expose
  various exotic functions that may be (rarely) useful for power users or for
  some types of custom fuzzing setups. For general information about AFL++, see
  [README.md](../README.md).
  本文档讨论了AFL++ 所使用的环境变量，以公开各种奇特的函数，这些函数可能对高级用户或某些类型的自定义模糊设置有用。 [README.md](../README.md).  

  Note: Most tools will warn on any unknown AFL++ environment variables; for
  example, because of typos. If you want to disable this check, then set the
  `AFL_IGNORE_UNKNOWN_ENVS` environment variable.
  注意：afl++ 大多数工具会对任何未知的 AFL++ 环境变量发出警告；例如，由于拼写错误。如果你想禁用这个检查，那么设置 `AFL_IGNORE_UNKNOWN_ENVS` 环境变量。

## 1) Settings for all compilers
为所有编译器进行设置

Starting with AFL++ 3.0, there is only one compiler: afl-cc.

To select the different instrumentation modes, use one of the following options:

  - Pass the --afl-MODE command-line option to the compiler. Only this option
    accepts further AFL-specific command-line options.
  - Use a symlink to afl-cc: afl-clang, afl-clang++, afl-clang-fast,
    afl-clang-fast++, afl-clang-lto, afl-clang-lto++, afl-g++, afl-g++-fast,
    afl-gcc, afl-gcc-fast. This option does not accept AFL-specific command-line
    options. Instead, use environment variables.
  - Use the `AFL_CC_COMPILER` environment variable with `MODE`. To select
    `MODE`, use one of the following values:

    - `GCC` (afl-gcc/afl-g++)
    - `GCC_PLUGIN` (afl-g*-fast)
    - `LLVM` (afl-clang-fast*)
    - `LTO` (afl-clang-lto*).

从AFL++ 3.0开始，只有一个编译器：afl-cc。

要选择不同的插桩模式，可以使用以下选项之一：

  - 将--afl-MODE命令行选项传递给编译器。只有这个选项接受更多的AFL特定命令行选项。
  - 使用到afl-cc的符号链接：afl-clang，afl-clang++，afl-clang-fast，afl-clang-fast++，afl-clang-lto，afl-clang-lto++，afl-g++，afl-g++-fast，afl-gcc，afl-gcc-fast。此选项不接受AFL特定的命令行选项。相反，使用环境变量。
  - 使用`AFL_CC_COMPILER`环境变量与`MODE`。要选择`MODE`，使用以下值之一：

    - `GCC` (afl-gcc/afl-g++)
    - `GCC_PLUGIN` (afl-g*-fast)
    - `LLVM` (afl-clang-fast*)
    - `LTO` (afl-clang-lto*)。

The compile-time tools do not accept AFL-specific command-line options. The
--afl-MODE command line option is the only exception. The other options make
fairly broad use of environment variables instead:

  - Some build/configure scripts break with AFL++ compilers. To be able to pass
    them, do:

    ```
          export CC=afl-cc
          export CXX=afl-c++
          export AFL_NOOPT=1
          ./configure --disable-shared --disabler-werror
          unset AFL_NOOPT
          make
    ```

  - Setting `AFL_AS`, `AFL_CC`, and `AFL_CXX` lets you use alternate downstream
    compilation tools, rather than the default 'as', 'clang', or 'gcc' binaries
    in your `$PATH`.

  - If you are a weird person that wants to compile and instrument asm text
    files, then use the `AFL_AS_FORCE_INSTRUMENT` variable:
    `AFL_AS_FORCE_INSTRUMENT=1 afl-gcc foo.s -o foo`

  - Most AFL tools do not print any output if stdout/stderr are redirected. If
    you want to get the output into a file, then set the `AFL_DEBUG` environment
    variable. This is sadly necessary for various build processes which fail
    otherwise.

  - By default, the wrapper appends `-O3` to optimize builds. Very rarely, this
    will cause problems in programs built with -Werror, because `-O3` enables
    more thorough code analysis and can spew out additional warnings. To disable
    optimizations, set `AFL_DONT_OPTIMIZE`. However, if `-O...` and/or
    `-fno-unroll-loops` are set, these are not overridden.

  - Setting `AFL_HARDEN` automatically adds code hardening options when invoking
    the downstream compiler. This currently includes `-D_FORTIFY_SOURCE=2` and
    `-fstack-protector-all`. The setting is useful for catching non-crashing
    memory bugs at the expense of a very slight (sub-5%) performance loss.

  - Setting `AFL_INST_RATIO` to a percentage between 0 and 100 controls the
    probability of instrumenting every branch. This is (very rarely) useful when
    dealing with exceptionally complex programs that saturate the output bitmap.
    Examples include ffmpeg, perl, and v8.

    (If this ever happens, afl-fuzz will warn you ahead of the time by
    displaying the "bitmap density" field in fiery red.)

    Setting `AFL_INST_RATIO` to 0 is a valid choice. This will instrument only
    the transitions between function entry points, but not individual branches.

    Note that this is an outdated variable. A few instances (e.g., afl-gcc)
    still support these, but state-of-the-art (e.g., LLVM LTO and LLVM PCGUARD)
    do not need this.

  - `AFL_NO_BUILTIN` causes the compiler to generate code suitable for use with
    libtokencap.so (but perhaps running a bit slower than without the flag).

  - `AFL_PATH` can be used to point afl-gcc to an alternate location of afl-as.
    One possible use of this is utils/clang_asm_normalize/, which lets you
    instrument hand-written assembly when compiling clang code by plugging a
    normalizer into the chain. (There is no equivalent feature for GCC.)

  - Setting `AFL_QUIET` will prevent afl-as and afl-cc banners from being
    displayed during compilation, in case you find them distracting.

  - Setting `AFL_USE_...` automatically enables supported sanitizers - provided
    that your compiler supports it. Available are:
    - `AFL_USE_ASAN=1` - activates the address sanitizer (memory corruption
      detection)
    - `AFL_USE_CFISAN=1` - activates the Control Flow Integrity sanitizer (e.g.
      type confusion vulnerabilities)
    - `AFL_USE_LSAN` - activates the leak sanitizer. To perform a leak check
      within your program at a certain point (such as at the end of an
      `__AFL_LOOP()`), you can run the macro  `__AFL_LEAK_CHECK();` which will
      cause an abort if any memory is leaked (you can combine this with the
      `__AFL_LSAN_OFF();` and `__AFL_LSAN_ON();` macros to avoid checking for
      memory leaks from memory allocated between these two calls.
    - `AFL_USE_MSAN=1` - activates the memory sanitizer (uninitialized memory)
    - `AFL_USE_TSAN=1` - activates the thread sanitizer to find thread race
      conditions
    - `AFL_USE_UBSAN=1` - activates the undefined behavior sanitizer

  - `TMPDIR` is used by afl-as for temporary files; if this variable is not set,
    the tool defaults to /tmp.

编译时工具不接受AFL特定的命令行选项。--afl-MODE命令行选项是唯一的例外。其他选项则广泛地使用环境变量：

  - 一些构建/配置脚本在AFL++编译器中会出错。为了能够通过它们，可以这样做：

    ```c
          export CC=afl-cc
          export CXX=afl-c++
          export AFL_NOOPT=1
          ./configure --disable-shared --disabler-werror
          unset AFL_NOOPT
          make
    ```

  - 设置`AFL_AS`，`AFL_CC`和`AFL_CXX`可以让你使用替代的下游编译工具，而不是你的`$PATH`中的默认'as'，'clang'或'gcc'二进制文件。

  - 如果你是一个想要编译和插桩asm文本文件的奇怪的人，那么使用`AFL_AS_FORCE_INSTRUMENT`变量：
    `AFL_AS_FORCE_INSTRUMENT=1 afl-gcc foo.s -o foo`

  - 如果stdout/stderr被重定向，大多数AFL工具不会打印任何输出。如果你想将输出获取到一个文件中，那么设置`AFL_DEBUG`环境变量。遗憾的是，这对于各种可能失败的构建过程是必要的。

  - 默认情况下，包装器会添加`-O3`来优化构建。非常少见的情况下，这会在使用-Werror构建的程序中引起问题，因为`-O3`启用了更彻底的代码分析，并可能产生额外的警告。要禁用优化，设置`AFL_DONT_OPTIMIZE`。然而，如果设置了`-O...`和/或`-fno-unroll-loops`，这些将不会被覆盖。

  - 设置`AFL_HARDEN`会在调用下游编译器时自动添加代码硬化选项。这目前包括`-D_FORTIFY_SOURCE=2`和`-fstack-protector-all`。这个设置对于捕获非崩溃的内存错误很有用，但代价是非常轻微的（低于5%）性能损失。

  - 将`AFL_INST_RATIO`设置为0到100之间的百分比，可以控制插桩每个分支的概率。这在处理异常复杂的程序时（很少见）有用，这些程序会饱和输出位图。例如包括ffmpeg，perl和v8。

    （如果这种情况发生，afl-fuzz会提前警告你，通过以火红色显示"位图密度"字段。）

    将`AFL_INST_RATIO`设置为0是一个有效的选择。这将只插桩函数入口点之间的转换，而不插桩单个分支。

    注意，这是一个过时的变量。一些实例（例如，afl-gcc）仍然支持这些，但最先进的（例如，LLVM LTO和LLVM PCGUARD）不需要这个。

  - `AFL_NO_BUILTIN`会导致编译器生成适合与libtokencap.so一起使用的代码（但可能比没有该标志运行得稍慢）。

  - `AFL_PATH`可以用来将afl-gcc指向afl-as的另一个位置。这的一个可能的用途是utils/clang_asm_normalize/，它让你在编译clang代码时插桩手写的汇编，通过将一个规范器插入到链中。（GCC没有等效的特性。）

  - 设置`AFL_QUIET`将防止在编译过程中显示afl-as和afl-cc的横幅，以防你觉得它们分散注意力。

  - 设置`AFL_USE_...`会自动启用支持的清理器 - 前提是你的编译器支持它。可用的有：
      - `AFL_USE_ASAN=1` - 激活地址清理器（内存破坏检测）
      - `AFL_USE_CFISAN=1` - 激活控制流完整性清理器（例如类型混淆漏洞）
      - `AFL_USE_LSAN` - 激活泄漏清理器。要在你的程序的某个点（例如在`__AFL_LOOP()`的结束处）执行泄漏检查，你可以运行宏`__AFL_LEAK_CHECK();`，如果有任何内存泄漏，这将导致中止（你可以将这个与`__AFL_LSAN_OFF();`和`__AFL_LSAN_ON();`宏结合使用，以避免检查在这两次调用之间分配的内存的泄漏。
      - `AFL_USE_MSAN=1` - 激活内存清理器（未初始化的内存）
      - `AFL_USE_TSAN=1` - 激活线程清理器以查找线程竞态条件
      - `AFL_USE_UBSAN=1` - 激活未定义行为清理器

  - `TMPDIR`被afl-as用于临时文件；如果这个变量没有设置，工具默认为/tmp。
## 2) Settings for LLVM and LTO: afl-clang-fast / afl-clang-fast++ / afl-clang-lto / afl-clang-lto++

The native instrumentation helpers (instrumentation and gcc_plugin) accept a
subset of the settings discussed in section 1, with the exception of:

  - `AFL_AS`, since this toolchain does not directly invoke GNU `as`.

  - `AFL_INST_RATIO`, as we use collision free instrumentation by default. Not
    all passes support this option though as it is an outdated feature.

  - LLVM modes support `AFL_LLVM_DICT2FILE=/absolute/path/file.txt` which will
    write all constant string comparisons to this file to be used later with
    afl-fuzz' `-x` option.

  - An option to `AFL_LLVM_DICT2FILE` is `AFL_LLVM_DICT2FILE_NO_MAIN=1` which
    skill not parse `main()`.

  - `TMPDIR` and `AFL_KEEP_ASSEMBLY`, since no temporary assembly files are
    created.

  - LLVM modes compiling C++ will normally set rpath in the binary if LLVM is
    not in a usual location (/usr or /lib). Setting `AFL_LLVM_NO_RPATH=1`
    disables this behaviour in case it isn't desired. For example, the compiling
    toolchain might be in a custom location, but the target machine has LLVM
    runtime libs in the search path.

Then there are a few specific features that are only available in
instrumentation mode:

### Select the instrumentation mode

`AFL_LLVM_INSTRUMENT` - this configures the instrumentation mode.

Available options:

  - CLANG - outdated clang instrumentation
  - CLASSIC - classic AFL (map[cur_loc ^ prev_loc >> 1]++) (default)

    You can also specify CTX and/or NGRAM, separate the options with a comma ","
    then, e.g.: `AFL_LLVM_INSTRUMENT=CLASSIC,CTX,NGRAM-4`

    Note: It is actually not a good idea to use both CTX and NGRAM. :)
  - CTX - context sensitive instrumentation
  - GCC - outdated gcc instrumentation
  - LTO - LTO instrumentation
  - NATIVE - clang's original pcguard based instrumentation
  - NGRAM-x - deeper previous location coverage (from NGRAM-2 up to NGRAM-16)
  - PCGUARD - our own pcguard based instrumentation (default)

#### CMPLOG

Setting `AFL_LLVM_CMPLOG=1` during compilation will tell afl-clang-fast to
produce a CmpLog binary.

For afl-gcc-fast, set `AFL_GCC_CMPLOG=1` instead.

For more information, see
[instrumentation/README.cmplog.md](../instrumentation/README.cmplog.md).

#### CTX

Setting `AFL_LLVM_CTX` or `AFL_LLVM_INSTRUMENT=CTX` activates context sensitive
branch coverage - meaning that each edge is additionally combined with its
caller. It is highly recommended to increase the `MAP_SIZE_POW2` definition in
config.h to at least 18 and maybe up to 20 for this as otherwise too many map
collisions occur.

For more information, see
[instrumentation/README.llvm.md#6) AFL++ Context Sensitive Branch Coverage](../instrumentation/README.llvm.md#6-afl-context-sensitive-branch-coverage).

#### INSTRUMENT LIST (selectively instrument files and functions)

This feature allows selective instrumentation of the source.

Setting `AFL_LLVM_ALLOWLIST` or `AFL_LLVM_DENYLIST` with a file name and/or
function will only instrument (or skip) those files that match the names listed
in the specified file.

For more information, see
[instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md).

#### INJECTIONS

This feature is able to find simple injection vulnerabilities in insecure
calls to mysql/mariadb/nosql/postgresql/ldap and XSS in libxml2.

  - Setting `AFL_LLVM_INJECTIONS_ALL` will enable all injection hooking

  - Setting `AFL_LLVM_INJECTIONS_SQL` will enable SQL injection hooking

  - Setting `AFL_LLVM_INJECTIONS_LDAP` will enable LDAP injection hooking

  - Setting `AFL_LLVM_INJECTIONS_XSS` will enable XSS injection hooking

#### LAF-INTEL

This great feature will split compares into series of single byte comparisons to
allow afl-fuzz to find otherwise rather impossible paths. It is not restricted
to Intel CPUs. ;-)

  - Setting `AFL_LLVM_LAF_TRANSFORM_COMPARES` will split string compare
    functions.

  - Setting `AFL_LLVM_LAF_SPLIT_COMPARES` will split all floating point and 64,
    32 and 16 bit integer CMP instructions.

  - Setting `AFL_LLVM_LAF_SPLIT_FLOATS` will split floating points, needs
    `AFL_LLVM_LAF_SPLIT_COMPARES` to be set.

  - Setting `AFL_LLVM_LAF_SPLIT_SWITCHES` will split all `switch` constructs.

  - Setting `AFL_LLVM_LAF_ALL` sets all of the above.

For more information, see
[instrumentation/README.laf-intel.md](../instrumentation/README.laf-intel.md).

#### LTO

This is a different way of instrumentation: first it compiles all code in LTO
(link time optimization) and then performs an edge inserting instrumentation
which is 100% collision free (collisions are a big issue in AFL and AFL-like
instrumentations). This is performed by using afl-clang-lto/afl-clang-lto++
instead of afl-clang-fast, but is only built if LLVM 11 or newer is used.

`AFL_LLVM_INSTRUMENT=CFG` will use Control Flow Graph instrumentation. (Not
recommended for afl-clang-fast, default for afl-clang-lto as there it is a
different and better kind of instrumentation.)

None of the following options are necessary to be used and are rather for manual
use (which only ever the author of this LTO implementation will use). These are
used if several separated instrumentations are performed which are then later
combined.

  - `AFL_LLVM_DOCUMENT_IDS=file` will document to a file which edge ID was given
    to which function. This helps to identify functions with variable bytes or
    which functions were touched by an input.
  - `AFL_LLVM_LTO_DONTWRITEID` prevents that the highest location ID written
    into the instrumentation is set in a global variable.
  - `AFL_LLVM_LTO_STARTID` sets the starting location ID for the
    instrumentation. This defaults to 1.
  - `AFL_LLVM_MAP_ADDR` sets the fixed map address to a different address than
    the default `0x10000`. A value of 0 or empty sets the map address to be
    dynamic (the original AFL way, which is slower).
  - `AFL_LLVM_MAP_DYNAMIC` sets the shared memory address to be dynamic.
  - `AFL_LLVM_LTO_SKIPINIT` skips adding initialization code. Some global vars
    (e.g. the highest location ID) are not injected. Needed to instrument with
    [WAFL](https://github.com/fgsect/WAFL.git).
  For more information, see
  [instrumentation/README.lto.md](../instrumentation/README.lto.md).

#### NGRAM

Setting `AFL_LLVM_INSTRUMENT=NGRAM-{value}` or `AFL_LLVM_NGRAM_SIZE` activates
ngram prev_loc coverage. Good values are 2, 4, or 8 (any value between 2 and 16
is valid). It is highly recommended to increase the `MAP_SIZE_POW2` definition
in config.h to at least 18 and maybe up to 20 for this as otherwise too many map
collisions occur.

For more information, see
[instrumentation/README.llvm.md#7) AFL++ N-Gram Branch Coverage](../instrumentation/README.llvm.md#7-afl-n-gram-branch-coverage).

#### NOT_ZERO

  - Setting `AFL_LLVM_NOT_ZERO=1` during compilation will use counters that skip
    zero on overflow. This is the default for llvm >= 9, however, for llvm
    versions below that this will increase an unnecessary slowdown due a
    performance issue that is only fixed in llvm 9+. This feature increases path
    discovery by a little bit.

  - Setting `AFL_LLVM_SKIP_NEVERZERO=1` will not implement the skip zero test.
    If the target performs only a few loops, then this will give a small
    performance boost.

#### Thread safe instrumentation counters (in all modes)

Setting `AFL_LLVM_THREADSAFE_INST` will inject code that implements thread safe
counters. The overhead is a little bit higher compared to the older non-thread
safe case. Note that this disables neverzero (see NOT_ZERO).

## 3) Settings for GCC / GCC_PLUGIN modes

There are a few specific features that are only available in GCC and GCC_PLUGIN
mode.

  - GCC mode only: Setting `AFL_KEEP_ASSEMBLY` prevents afl-as from deleting
    instrumented assembly files. Useful for troubleshooting problems or
    understanding how the tool works.

    To get them in a predictable place, try something like:

    ```
    mkdir assembly_here
    TMPDIR=$PWD/assembly_here AFL_KEEP_ASSEMBLY=1 make clean all
    ```

  - GCC_PLUGIN mode only: Setting `AFL_GCC_INSTRUMENT_FILE` or
    `AFL_GCC_ALLOWLIST` with a filename will only instrument those files that
    match the names listed in this file (one filename per line).

    Setting `AFL_GCC_DENYLIST` or `AFL_GCC_BLOCKLIST` with a file name and/or
    function will only skip those files that match the names listed in the
    specified file. See
    [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md)
    for more information.

    Setting `AFL_GCC_OUT_OF_LINE=1` will instruct afl-gcc-fast to instrument the
    code with calls to an injected subroutine instead of the much more efficient
    inline instrumentation.

    Setting `AFL_GCC_SKIP_NEVERZERO=1` will not implement the skip zero test. If
    the target performs only a few loops, then this will give a small
    performance boost.

## 3) GCC / GCC_PLUGIN模式的设置

只有在GCC和GCC_PLUGIN模式中才有一些特定的特性。

  - 仅GCC模式：设置`AFL_KEEP_ASSEMBLY`可以防止afl-as删除插桩的汇编文件。这对于排查问题或理解工具的工作方式很有用。

    要将它们放在一个可预测的位置，可以尝试这样做：

    ```c
    mkdir assembly_here
    TMPDIR=$PWD/assembly_here AFL_KEEP_ASSEMBLY=1 make clean all
    ```

  - 仅GCC_PLUGIN模式：使用文件名设置`AFL_GCC_INSTRUMENT_FILE`或`AFL_GCC_ALLOWLIST`将只对那些与此文件中列出的名称匹配的文件进行插桩（每行一个文件名）。

    使用文件名和/或函数设置`AFL_GCC_DENYLIST`或`AFL_GCC_BLOCKLIST`将只跳过那些与指定文件中列出的名称匹配的文件。有关更多信息，请参见[instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md)。

    设置`AFL_GCC_OUT_OF_LINE=1`将指示afl-gcc-fast用调用注入的子程序来插桩代码，而不是更高效的内联插桩。

    设置`AFL_GCC_SKIP_NEVERZERO=1`将不实现跳过零测试。如果目标只执行少数几个循环，那么这将给出小的性能提升。
## 4) Settings for afl-fuzz

The main fuzzer binary accepts several options that disable a couple of sanity
checks or alter some of the more exotic semantics of the tool:

  - Setting `AFL_AUTORESUME` will resume a fuzz run (same as providing `-i -`)
    for an existing out folder, even if a different `-i` was provided. Without
    this setting, afl-fuzz will refuse execution for a long-fuzzed out dir.

  - Benchmarking only: `AFL_BENCH_JUST_ONE` causes the fuzzer to exit after
    processing the first queue entry; and `AFL_BENCH_UNTIL_CRASH` causes it to
    exit soon after the first crash is found.

  - `AFL_CMPLOG_ONLY_NEW` will only perform the expensive cmplog feature for
    newly found test cases and not for test cases that are loaded on startup
    (`-i in`). This is an important feature to set when resuming a fuzzing
    session.

  - `AFL_IGNORE_SEED_PROBLEMS` will skip over crashes and timeouts in the seeds
    instead of exiting.

  - Setting `AFL_CRASH_EXITCODE` sets the exit code AFL++ treats as crash. For
    example, if `AFL_CRASH_EXITCODE='-1'` is set, each input resulting in a `-1`
    return code (i.e. `exit(-1)` got called), will be treated as if a crash had
    occurred. This may be beneficial if you look for higher-level faulty
    conditions in which your target still exits gracefully.

  - Setting `AFL_CUSTOM_MUTATOR_LIBRARY` to a shared library with
    afl_custom_fuzz() creates additional mutations through this library. If
    afl-fuzz is compiled with Python (which is autodetected during building
    afl-fuzz), setting `AFL_PYTHON_MODULE` to a Python module can also provide
    additional mutations. If `AFL_CUSTOM_MUTATOR_ONLY` is also set, all
    mutations will solely be performed with the custom mutator. This feature
    allows to configure custom mutators which can be very helpful, e.g., fuzzing
    XML or other highly flexible structured input. For details, see
    [custom_mutators.md](custom_mutators.md).

  - Setting `AFL_CYCLE_SCHEDULES` will switch to a different schedule every time
    a cycle is finished.

  - Setting `AFL_DEBUG_CHILD` will not suppress the child output. This lets you
    see all output of the child, making setup issues obvious. For example, in an
    unicornafl harness, you might see python stacktraces. You may also see other
    logs that way, indicating why the forkserver won't start. Not pretty but
    good for debugging purposes. Note that `AFL_DEBUG_CHILD_OUTPUT` is
    deprecated.

  - Setting `AFL_DISABLE_TRIM` tells afl-fuzz not to trim test cases. This is
    usually a bad idea!

  - Setting `AFL_KEEP_TIMEOUTS` will keep longer running inputs if they reach
    new coverage

  - On the contrary, if you are not interested in any timeouts, you can set
    `AFL_IGNORE_TIMEOUTS` to get a bit of speed instead.

  - `AFL_EXIT_ON_SEED_ISSUES` will restore the vanilla afl-fuzz behavior which
    does not allow crashes or timeout seeds in the initial -i corpus.

  - `AFL_CRASHING_SEEDS_AS_NEW_CRASH` will treat crashing seeds as new crash. these 
    crashes will be written to crashes folder as op:dry_run, and orig:<seed_file_name>.

  - `AFL_EXIT_ON_TIME` causes afl-fuzz to terminate if no new paths were found
    within a specified period of time (in seconds). May be convenient for some
    types of automated jobs.

  - `AFL_EXIT_WHEN_DONE` causes afl-fuzz to terminate when all existing paths
    have been fuzzed and there were no new finds for a while. This would be
    normally indicated by the cycle counter in the UI turning green. May be
    convenient for some types of automated jobs.

  - Setting `AFL_EXPAND_HAVOC_NOW` will start in the extended havoc mode that
    includes costly mutations. afl-fuzz automatically enables this mode when
    deemed useful otherwise.

  - `AFL_FAST_CAL` keeps the calibration stage about 2.5x faster (albeit less
    precise), which can help when starting a session against a slow target.
    `AFL_CAL_FAST` works too.

  - Setting `AFL_FORCE_UI` will force painting the UI on the screen even if no
    valid terminal was detected (for virtual consoles).

  - Setting `AFL_FORKSRV_INIT_TMOUT` allows you to specify a different timeout
    to wait for the forkserver to spin up. The specified value is the new timeout, in milliseconds.
    The default is the `-t` value times `FORK_WAIT_MULT` from `config.h` (usually 10), so for a `-t 100`, the default would wait for `1000` milliseconds.
    The `AFL_FORKSRV_INIT_TMOUT` value does not get multiplied. It overwrites the initial timeout afl-fuzz waits for the target to come up with a constant time.
    Setting a different time here is useful if the target has a very slow startup time, for example, when doing
    full-system fuzzing or emulation, but you don't want the actual runs to wait
    too long for timeouts.

  - Setting `AFL_HANG_TMOUT` allows you to specify a different timeout for
    deciding if a particular test case is a "hang". The default is 1 second or
    the value of the `-t` parameter, whichever is larger. Dialing the value down
    can be useful if you are very concerned about slow inputs, or if you don't
    want AFL++ to spend too much time classifying that stuff and just rapidly
    put all timeouts in that bin.

  - If you are Jakub, you may need `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`.
    Others need not apply, unless they also want to disable the
    `/proc/sys/kernel/core_pattern` check.

  - If afl-fuzz encounters an incorrect fuzzing setup during a fuzzing session
    (not at startup), it will terminate. If you do not want this, then you can
    set `AFL_IGNORE_PROBLEMS`. If you additionally want to also ignore coverage
    from late loaded libraries, you can set `AFL_IGNORE_PROBLEMS_COVERAGE`.

  - When running with multiple afl-fuzz or with `-F`,  setting `AFL_IMPORT_FIRST`
    causes the fuzzer to import test cases from other instances before doing
    anything else. This makes the "own finds" counter in the UI more accurate.

  - When running with multiple afl-fuzz or with `-F`,  setting `AFL_FINAL_SYNC`
    will cause the fuzzer to perform a final import of test cases when
    terminating. This is beneficial for `-M` main fuzzers to ensure it has all
    unique test cases and hence you only need to `afl-cmin` this single
    queue.

  - Setting `AFL_INPUT_LEN_MIN` and `AFL_INPUT_LEN_MAX` are an alternative to
    the afl-fuzz -g/-G command line option to control the minimum/maximum
    of fuzzing input generated.

  - `AFL_KILL_SIGNAL`: Set the signal ID to be delivered to child processes
    on timeout. Unless you implement your own targets or instrumentation, you
    likely don't have to set it. By default, on timeout and on exit, `SIGKILL`
    (`AFL_KILL_SIGNAL=9`) will be delivered to the child.

  - `AFL_FORK_SERVER_KILL_SIGNAL`: Set the signal ID to be delivered to the
    fork server when AFL++ is terminated. Unless you implement your
    fork server, you likely do not have to set it. By default, `SIGTERM`
    (`AFL_FORK_SERVER_KILL_SIGNAL=15`) will be delivered to the fork server.
    If only `AFL_KILL_SIGNAL` is provided, `AFL_FORK_SERVER_KILL_SIGNAL` will
    be set to same value as `AFL_KILL_SIGNAL` to provide backward compatibility.
    If `AFL_FORK_SERVER_KILL_SIGNAL` is also set, it takes precedence.

    NOTE: Uncatchable signals, such as `SIGKILL`, cause child processes of
    the fork server to be orphaned and leaves them in a zombie state.

  - `AFL_MAP_SIZE` sets the size of the shared map that afl-analyze, afl-fuzz,
    afl-showmap, and afl-tmin create to gather instrumentation data from the
    target. This must be equal or larger than the size the target was compiled
    with.

  - Setting `AFL_MAX_DET_EXTRAS` will change the threshold at what number of
    elements in the `-x` dictionary and LTO autodict (combined) the
    probabilistic mode will kick off. In probabilistic mode, not all dictionary
    entries will be used all of the time for fuzzing mutations to not slow down
    fuzzing. The default count is `200` elements. So for the 200 + 1st element,
    there is a 1 in 201 chance, that one of the dictionary entries will not be
    used directly.

  - Setting `AFL_NO_AFFINITY` disables attempts to bind to a specific CPU core
    on Linux systems. This slows things down, but lets you run more instances of
    afl-fuzz than would be prudent (if you really want to).

  - `AFL_NO_ARITH` causes AFL++ to skip most of the deterministic arithmetics.
    This can be useful to speed up the fuzzing of text-based file formats.

  - Setting `AFL_NO_AUTODICT` will not load an LTO generated auto dictionary
    that is compiled into the target.

  - Setting `AFL_NO_COLOR` or `AFL_NO_COLOUR` will omit control sequences for
    coloring console output when configured with USE_COLOR and not
    ALWAYS_COLORED.

  - The CPU widget shown at the bottom of the screen is fairly simplistic and
    may complain of high load prematurely, especially on systems with low core
    counts. To avoid the alarming red color for very high CPU usages, you can
    set `AFL_NO_CPU_RED`.

  - Setting `AFL_NO_FORKSRV` disables the forkserver optimization, reverting to
    fork + execve() call for every tested input. This is useful mostly when
    working with unruly libraries that create threads or do other crazy things
    when initializing (before the instrumentation has a chance to run).

    Note that this setting inhibits some of the user-friendly diagnostics
    normally done when starting up the forkserver and causes a pretty
    significant performance drop.

  - `AFL_NO_SNAPSHOT` will advise afl-fuzz not to use the snapshot feature if
    the snapshot lkm is loaded.

  - Setting `AFL_NO_UI` inhibits the UI altogether and just periodically prints
    some basic stats. This behavior is also automatically triggered when the
    output from afl-fuzz is redirected to a file or to a pipe.

  - Setting `AFL_NO_STARTUP_CALIBRATION` will skip the initial calibration
    of all starting seeds, and start fuzzing at once. Use with care, this
    degrades the fuzzing performance!

  - Setting `AFL_NO_WARN_INSTABILITY` will suppress instability warnings.

  - In QEMU mode (-Q) and FRIDA mode (-O), `AFL_PATH` will be searched for
    afl-qemu-trace and afl-frida-trace.so.

  - If you are using persistent mode (you should, see
    [instrumentation/README.persistent_mode.md](../instrumentation/README.persistent_mode.md)),
    some targets keep inherent state due which a detected crash test case does
    not crash the target again when the test case is given. To be able to still
    re-trigger these crashes, you can use the `AFL_PERSISTENT_RECORD` variable
    with a value of how many previous fuzz cases to keep prior a crash. If set to
    e.g., 10, then the 9 previous inputs are written to out/default/crashes as
    RECORD:000000,cnt:000000 to RECORD:000000,cnt:000008 and
    RECORD:000000,cnt:000009 being the crash case. NOTE: This option needs to be
    enabled in config.h first!

  - Note that `AFL_POST_LIBRARY` is deprecated, use `AFL_CUSTOM_MUTATOR_LIBRARY`
    instead.

  - Setting `AFL_PRELOAD` causes AFL++ to set `LD_PRELOAD` for the target binary
    without disrupting the afl-fuzz process itself. This is useful, among other
    things, for bootstrapping libdislocator.so.

  - In QEMU mode (-Q), setting `AFL_QEMU_CUSTOM_BIN` will cause afl-fuzz to skip
    prepending `afl-qemu-trace` to your command line. Use this if you wish to
    use a custom afl-qemu-trace or if you need to modify the afl-qemu-trace
    arguments.

  - `AFL_SHUFFLE_QUEUE` randomly reorders the input queue on startup. Requested
    by some users for unorthodox parallelized fuzzing setups, but not advisable
    otherwise.

  - When developing custom instrumentation on top of afl-fuzz, you can use
    `AFL_SKIP_BIN_CHECK` to inhibit the checks for non-instrumented binaries and
    shell scripts; and `AFL_DUMB_FORKSRV` in conjunction with the `-n` setting
    to instruct afl-fuzz to still follow the fork server protocol without
    expecting any instrumentation data in return. Note that this also turns off
    auto map size detection.

  - Setting `AFL_SKIP_CPUFREQ` skips the check for CPU scaling policy. This is
    useful if you can't change the defaults (e.g., no root access to the system)
    and are OK with some performance loss.

  - Setting `AFL_STATSD` enables StatsD metrics collection. By default, AFL++
    will send these metrics over UDP to 127.0.0.1:8125. The host and port are
    configurable with `AFL_STATSD_HOST` and `AFL_STATSD_PORT` respectively. To
    enable tags (banner and afl_version), you should provide
    `AFL_STATSD_TAGS_FLAVOR` that matches your StatsD server (see
    `AFL_STATSD_TAGS_FLAVOR`).

  - Setting `AFL_STATSD_TAGS_FLAVOR` to one of `dogstatsd`, `influxdb`,
    `librato`, or `signalfx` allows you to add tags to your fuzzing instances.
    This is especially useful when running multiple instances (`-M/-S` for
    example). Applied tags are `banner` and `afl_version`. `banner` corresponds
    to the name of the fuzzer provided through `-M/-S`. `afl_version`
    corresponds to the currently running AFL++ version (e.g., `++3.0c`). Default
    (empty/non present) will add no tags to the metrics. For more information,
    see [rpc_statsd.md](rpc_statsd.md).

  - `AFL_SYNC_TIME` allows you to specify a different minimal time (in minutes)
    between fuzzing instances synchronization. Default sync time is 30 minutes,
    note that time is halved for -M main nodes.

  - Setting `AFL_TARGET_ENV` causes AFL++ to set extra environment variables for
    the target binary. Example: `AFL_TARGET_ENV="VAR1=1 VAR2='a b c'" afl-fuzz
    ... `. This exists mostly for things like `LD_LIBRARY_PATH` but it would
    theoretically allow fuzzing of AFL++ itself (with 'target' AFL++ using some
    AFL_ vars that would disrupt work of 'fuzzer' AFL++). Note that when using
    QEMU mode, the `AFL_TARGET_ENV` environment variables will apply to QEMU, as
    well as the target binary. Therefore, in this case, you might want to use
    QEMU's `QEMU_SET_ENV` environment variable (see QEMU's documentation because
    the format is different from `AFL_TARGET_ENV`) to apply the environment
    variables to the target and not QEMU.

  - `AFL_TESTCACHE_SIZE` allows you to override the size of `#define
    TESTCASE_CACHE` in config.h. Recommended values are 50-250MB - or more if
    your fuzzing finds a huge amount of paths for large inputs.

  - `AFL_TMPDIR` is used to write the `.cur_input` file to if it exists, and in
    the normal output directory otherwise. You would use this to point to a
    ramdisk/tmpfs. This increases the speed by a small value but also reduces
    the stress on SSDs.

  - Setting `AFL_TRY_AFFINITY` tries to attempt binding to a specific CPU core
    on Linux systems, but will not terminate if that fails.

  - The following environment variables are only needed if you implemented
    your own forkserver or persistent mode, or if __AFL_LOOP or __AFL_INIT
    are in a shared library and not the main binary:
    - `AFL_DEFER_FORKSRV` enforces a deferred forkserver even if none was
      detected in the target binary
    - `AFL_PERSISTENT` enforces persistent mode even if none was detected
      in the target binary

  - If you need an early forkserver in your target because of early
    constructors in your target, you can set `AFL_EARLY_FORKSERVER`.
    Note that this is not a compile time option but a runtime option :-)

  - Set `AFL_PIZZA_MODE` to 1 to enable the April 1st stats menu, set to -1
    to disable although it is 1st of April. 0 is the default and means enable
    on the 1st of April automatically.

  - If you need a specific interval to update fuzzer_stats file, you can
    set `AFL_FUZZER_STATS_UPDATE_INTERVAL` to the interval in seconds you'd
    the file to be updated.
    Note that will not be exact and with slow targets it can take seconds
    until there is a slice for the time test.

## 4) afl-fuzz的设置
`afl-fuzz`二进制文件接受几个选项，这些选项可以禁用一些完整性检查或改变工具的一些奇特（外来）的语义：

  - 设置`AFL_AUTORESUME`将恢复模糊运行（与提供`-i -`相同）对于现有的out文件夹，即使提供了不同的`-i`。在已经存在长时间测试过的out目录的测试中，没有这个设置，afl-fuzz将拒绝执行

  - 仅用于基准测试：`AFL_BENCH_JUST_ONE`会导致模糊器在处理完第一个队列条目后退出；`AFL_BENCH_UNTIL_CRASH`会导致它在找到第一个崩溃后很快退出。

  - `AFL_CMPLOG_ONLY_NEW`只会对新发现的测试用例执行昂贵的cmplog特性，而不是对启动时加载的测试用例（`-i in`）。当恢复模糊会话时，设置这个特性很重要。

  - `AFL_IGNORE_SEED_PROBLEMS`将跳过种子中的崩溃和超时，而不是退出。

  - 设置`AFL_CRASH_EXITCODE`设置AFL++将作为崩溃处理的退出代码。例如，如果设置了`AFL_CRASH_EXITCODE='-1'`，每个输入导致`-1`返回代码（即调用了`exit(-1)`），都会被视为发生了崩溃。如果你在寻找更高级别的错误条件，其中你的目标仍然优雅地退出，这可能会有益。

  - 将`AFL_CUSTOM_MUTATOR_LIBRARY`设置为带有afl_custom_fuzz()的共享库，将通过这个库创建额外的突变。如果afl-fuzz是用Python编译的（这在构建afl-fuzz时会自动检测），将`AFL_PYTHON_MODULE`设置为Python模块也可以提供额外的突变。如果也设置了`AFL_CUSTOM_MUTATOR_ONLY`，所有的突变将仅由自定义突变器执行。这个特性允许配置自定义突变器，这对于模糊测试XML或其他高度灵活的结构化输入非常有帮助。详情请参见[custom_mutators.md](custom_mutators.md)。

  - 设置`AFL_CYCLE_SCHEDULES`将在每次完成一个周期时切换到不同的调度。

  - 设置`AFL_DEBUG_CHILD`将不抑制子输出。这让你看到子的所有输出，使设置问题明显。例如，在unicornafl马甲中，你可能会看到python堆栈跟踪。你也可能会看到其他日志，表明为什么forkserver无法启动。虽然不好看，但对于调试目的很有用。注意`AFL_DEBUG_CHILD_OUTPUT`已经被弃用。

  - 设置`AFL_DISABLE_TRIM`告诉afl-fuzz不要修剪测试用例。这通常是个坏主意！

  - 设置`AFL_KEEP_TIMEOUTS`将保留运行时间较长的输入，如果它们达到新的覆盖范围

  - 相反，如果你对任何超时都不感兴趣，你可以设置`AFL_IGNORE_TIMEOUTS`来获得一点速度。

  - `AFL_EXIT_ON_SEED_ISSUES`将恢复原始的afl-fuzz行为，它不允许在初始-i语料库中有崩溃或超时种子。

  - `AFL_CRASHING_SEEDS_AS_NEW_CRASH`将把崩溃的种子视为新的崩溃。这些崩溃将被写入崩溃文件夹，作为op:dry_run，和orig:<seed_file_name>。

  - `AFL_EXIT_ON_TIME`导致afl-fuzz在指定的时间段内没有找到新的路径时终止。对于某些类型的自动化工作可能很方便。

  - `AFL_EXIT_WHEN_DONE`导致afl-fuzz在所有现有路径都被模糊处理，并且一段时间内没有新的发现时终止。这通常会通过UI中的周期计数器变为绿色来指示。对于某些类型的自动化工作可能很方便。

  - 设置`AFL_EXPAND_HAVOC_NOW`将开始扩展的havoc模式，包括昂贵的突变。否则，afl-fuzz会在认为有用时自动启用这个模式。

  - `AFL_FAST_CAL`保持校准阶段大约快2.5倍（尽管不太精确），这可以帮助在针对慢目标开始会话时。`AFL_CAL_FAST`也可以。
  - 设置`AFL_FORCE_UI`将强制在屏幕上绘制UI，即使没有检测到有效的终端（对于虚拟控制台）。

  - 设置`AFL_FORKSRV_INIT_TMOUT`允许你指定等待forkserver启动的不同超时时间。指定的值是新的超时时间，以毫秒为单位。默认值是`-t`值乘以`config.h`中的`FORK_WAIT_MULT`（通常为10），所以对于`-t 100`，默认会等待`1000`毫秒。`AFL_FORKSRV_INIT_TMOUT`值不会被乘以。它覆盖了afl-fuzz等待目标启动的初始超时时间。在这里设置不同的时间是有用的，如果目标启动时间非常慢，例如，当进行全系统模糊测试或模拟时，但你不希望实际运行等待超时太长。

  - 设置`AFL_HANG_TMOUT`允许你指定决定特定测试用例是否为"挂起"的不同超时时间。默认值是1秒或`-t`参数的值，取较大者。如果你非常关心慢输入，或者如果你不希望AFL++花费太多时间对那些东西进行分类，并且只是快速地将所有超时放入那个箱子，那么降低值可能是有用的。

  - 如果你是Jakub，你可能需要`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`。其他人不需要申请，除非他们也想禁用`/proc/sys/kernel/core_pattern`检查。

  - 如果afl-fuzz在模糊测试会话期间（不是在启动时）遇到不正确的模糊测试设置，它将终止。如果你不希望这样，那么你可以设置`AFL_IGNORE_PROBLEMS`。如果你还想忽略来自后期加载库的覆盖率，你可以设置`AFL_IGNORE_PROBLEMS_COVERAGE`。

  - 当使用多个afl-fuzz或使用`-F`运行时，设置`AFL_IMPORT_FIRST`会使模糊器在做任何其他事情之前从其他实例导入测试用例。这使得UI中的"own finds"计数器更准确。

  - 当使用多个afl-fuzz或使用`-F`运行时，设置`AFL_FINAL_SYNC`将导致模糊器在终止时执行最后的测试用例导入。这对于`-M`主模糊器有益，以确保它具有所有唯一的测试用例，因此你只需要对这个单一的队列进行`afl-cmin`。

  - 设置`AFL_INPUT_LEN_MIN`和`AFL_INPUT_LEN_MAX`是afl-fuzz -g/-G命令行选项的替代方法，用于控制生成的模糊输入的最小/最大值。

  - `AFL_KILL_SIGNAL`：设置要在超时时发送给子进程的信号ID。除非你实现了自己的目标或插桩，否则你可能不需要设置它。默认情况下，超时和退出时，将向子进程发送`SIGKILL`（`AFL_KILL_SIGNAL=9`）。

  - `AFL_FORK_SERVER_KILL_SIGNAL`：设置在AFL++终止时发送给fork server的信号ID。除非你实现了你自己的fork server，否则你可能不需要设置它。默认情况下，将向fork server发送`SIGTERM`（`AFL_FORK_SERVER_KILL_SIGNAL=15`）。如果只提供了`AFL_KILL_SIGNAL`，`AFL_FORK_SERVER_KILL_SIGNAL`将被设置为与`AFL_KILL_SIGNAL`相同的值，以提供向后兼容性。如果也设置了`AFL_FORK_SERVER_KILL_SIGNAL`，它将优先。

  - 注意：无法捕获的信号，如`SIGKILL`，会导致fork server的子进程成为孤儿，并使它们处于僵尸状态。

  - `AFL_MAP_SIZE`设置afl-analyze，afl-fuzz，afl-showmap和afl-tmin创建的共享映射的大小，以从目标收集插桩数据。这必须等于或大于目标编译的大小。

  - 设置 `AFL_MAX_DET_EXTRAS` 将改变 `-x` 字典和 LTO autodict（结合使用）中元素数量的阈值，超过这个阈值，概率模式将启动。在概率模式下，不是所有的字典条目都会一直用于模糊突变，以避免减慢模糊测试的速度。默认的计数是 `200` 个元素。所以对于第 201 个元素，有 1/201 的机会，字典条目之一将不会被直接使用。

  - 设置 `AFL_NO_AFFINITY` 将禁止尝试在 Linux 系统上绑定到特定的 CPU 核心。这会减慢速度，但是让你运行更多的 afl-fuzz 实例，比较谨慎（如果你真的想要的话）。

  - `AFL_NO_ARITH` 会导致 AFL++ 跳过大部分的确定性算术。这可以用来加速文本文件格式的模糊测试。

  - 设置 `AFL_NO_AUTODICT` 将不会加载编译到目标中的 LTO 生成的自动字典。

  - 设置 `AFL_NO_COLOR` 或 `AFL_NO_COLOUR` 将在配置了 USE_COLOR 和非 ALWAYS_COLORED 时，省略用于着色控制台输出的控制序列。

  - 显示在屏幕底部的 CPU 小部件相当简单，可能会过早地抱怨高负载，特别是在核心计数低的系统上。为了避免 CPU 使用率非常高时的惊人红色，你可以设置 `AFL_NO_CPU_RED`。

  - 设置 `AFL_NO_FORKSRV` 禁用 forkserver 优化，回退到对每个测试输入进行 fork + execve() 调用。这主要在处理不规则的库时有用，这些库在初始化时（在插桩有机会运行之前）创建线程或做其他疯狂的事情。

    注意，这个设置抑制了启动 forkserver 时通常进行的一些用户友好的诊断，并导致了相当大的性能下降。

  - `AFL_NO_SNAPSHOT` 将建议 afl-fuzz 不使用快照功能，如果加载了快照 lkm。

  - 设置 `AFL_NO_UI` 将完全禁止 UI，并只定期打印一些基本的统计信息。当 afl-fuzz 的输出被重定向到文件或管道时，这种行为也会自动触发。

  - 设置 `AFL_NO_STARTUP_CALIBRATION` 将跳过所有起始种子的初始校准，并立即开始模糊测试。小心使用，这会降低模糊测试的性能！

  - 设置 `AFL_NO_WARN_INSTABILITY` 将抑制不稳定性警告。

  - 在 QEMU 模式（-Q）和 FRIDA 模式（-O）中，`AFL_PATH` 将被搜索 afl-qemu-trace 和 afl-frida-trace.so。

  - 如果你正在使用持久模式（你应该看看 [instrumentation/README.persistent_mode.md](../instrumentation/README.persistent_mode.md)），一些目标保持固有状态，因此检测到的崩溃测试用例在给出测试用例时不会再次崩溃目标。为了能够重新触发这些崩溃，你可以使用 `AFL_PERSISTENT_RECORD` 变量，该变量的值为崩溃前保留多少个先前的模糊用例。如果设置为例如 10，那么前 9 个输入将被写入 out/default/crashes 作为 RECORD:000000,cnt:000000 到 RECORD:000000,cnt:000008 和 RECORD:000000,cnt:000009 是崩溃用例。注意：这个选项需要首先在 config.h 中启用！

  - 注意 `AFL_POST_LIBRARY` 已被弃用，改用 `AFL_CUSTOM_MUTATOR_LIBRARY`。

  - 设置 `AFL_PRELOAD` 会导致 AFL++ 为目标二进制文件设置 `LD_PRELOAD`，而不会干扰 afl-fuzz 进程本身。这在其他事情中很有用，例如引导 libdislocator.so。

  - 在 QEMU 模式（-Q）中，设置 `AFL_QEMU_CUSTOM_BIN` 将导致 afl-fuzz 跳过在你的命令行前添加 `afl-qemu-trace`。如果你希望使用自定义的 afl-qemu-trace 或者需要修改 afl-qemu-trace 的参数，使用这个。

  - `AFL_SHUFFLE_QUEUE` 在启动时随机重新排序输入队列。一些用户为了非正统的并行模糊测试设置而请求，但否则不建议这样做。

  - 在 afl-fuzz 之上开发自定义工具时，你可以使用 `AFL_SKIP_BIN_CHECK` 来抑制对非工具二进制文件和 shell 脚本的检查；并且可以结合 `-n` 设置使用 `AFL_DUMB_FORKSRV` 来指示 afl-fuzz 仍然遵循 fork server 协议，而不期望返回任何工具数据。注意，这也会关闭自动映射大小检测。

  - 设置 `AFL_SKIP_CPUFREQ` 跳过对 CPU 缩放策略的检查。如果你不能改变默认设置（例如，没有系统的 root 访问权限）并且可以接受一些性能损失，这是有用的。

  - 设置 `AFL_STATSD` 启用 StatsD 指标收集。默认情况下，AFL++ 将通过 UDP 向 127.0.0.1:8125 发送这些指标。主机和端口可以分别通过 `AFL_STATSD_HOST` 和 `AFL_STATSD_PORT` 进行配置。要启用标签（banner 和 afl_version），你应该提供与你的 StatsD 服务器匹配的 `AFL_STATSD_TAGS_FLAVOR`（参见 `AFL_STATSD_TAGS_FLAVOR`）。

  - 将 `AFL_STATSD_TAGS_FLAVOR` 设置为 `dogstatsd`、`influxdb`、`librato` 或 `signalfx` 中的一个，允许你为你的模糊实例添加标签。这在运行多个实例时特别有用（例如 `-M/-S`）。应用的标签是 `banner` 和 `afl_version`。`banner` 对应于通过 `-M/-S` 提供的模糊器的名称。`afl_version` 对应于当前运行的 AFL++ 版本（例如 `++3.0c`）。默认（空/不存在）将不会向指标添加标签。有关更多信息，请参见 [rpc_statsd.md](rpc_statsd.md)。

  - `AFL_SYNC_TIME` 允许你指定模糊实例同步之间的不同最小时间（以分钟为单位）。默认同步时间是 30 分钟，注意对于 -M 主节点，时间减半。

  - 设置 `AFL_TARGET_ENV` 会导致 AFL++ 为目标二进制文件设置额外的环境变量。示例：`AFL_TARGET_ENV="VAR1=1 VAR2='a b c'" afl-fuzz ... `。这主要存在于像 `LD_LIBRARY_PATH` 这样的事情，但理论上它可以允许模糊测试 AFL++ 本身（使用一些 AFL_ 变量的 'target' AFL++ 会破坏 'fuzzer' AFL++ 的工作）。注意，当使用 QEMU 模式时，`AFL_TARGET_ENV` 环境变量将适用于 QEMU，以及目标二进制文件。因此，在这种情况下，你可能希望使用 QEMU 的 `QEMU_SET_ENV` 环境变量（参见 QEMU 的文档，因为格式与 `AFL_TARGET_ENV` 不同）来将环境变量应用到目标而不是 QEMU。

  - `AFL_TESTCACHE_SIZE` 允许你覆盖 config.h 中 `#define TESTCASE_CACHE` 的大小。推荐的值是 50-250MB - 或者如果你的模糊测试找到了大量的路径用于大输入，那么更多。

  - `AFL_TMPDIR` 用于写入 `.cur_input` 文件（如果存在），否则在正常的输出目录中。你可以使用这个来指向 ramdisk/tmpfs。这会增加一小部分速度，但也会减少 SSD 的压力。

  - 设置 `AFL_TRY_AFFINITY` 尝试尝试在 Linux 系统上绑定到特定的 CPU 核心，但如果失败不会终止。

  - 以下环境变量只有在你实现了自己的 forkserver 或持久模式，或者如果 __AFL_LOOP 或 __AFL_INIT 在共享库中而不是主二进制文件中时才需要：
    - `AFL_DEFER_FORKSRV` 强制延迟 forkserver，即使在目标二进制文件中没有检测到
    - `AFL_PERSISTENT` 强制持久模式，即使在目标二进制文件中没有检测到

  - 如果你的目标中需要一个早期的 forkserver，因为你的目标中有早期的构造函数，你可以设置 `AFL_EARLY_FORKSERVER`。注意，这不是一个编译时选项，而是一个运行时选项 :-)

  - 将 `AFL_PIZZA_MODE` 设置为 1 以启用 4 月 1 日的统计菜单，即使是 4 月 1 日也设置为 -1 以禁用。0 是默认值，意味着在 4 月 1 日自动启用。

  - 如果你需要一个特定的间隔来更新 fuzzer_stats 文件，你可以将 `AFL_FUZZER_STATS_UPDATE_INTERVAL` 设置为你希望文件更新的秒数间隔。请注意，这不会是准确的，对于慢目标，可能需要几秒钟才能有时间测试的切片。
## 5) Settings for afl-qemu-trace

The QEMU wrapper used to instrument binary-only code supports several settings:

  - Setting `AFL_COMPCOV_LEVEL` enables the CompareCoverage tracing of all cmp
    and sub in x86 and x86_64 and memory comparison functions (e.g., strcmp,
    memcmp, ...) when libcompcov is preloaded using `AFL_PRELOAD`. More info at
    [qemu_mode/libcompcov/README.md](../qemu_mode/libcompcov/README.md).

    There are two levels at the moment, `AFL_COMPCOV_LEVEL=1` that instruments
    only comparisons with immediate values / read-only memory and
    `AFL_COMPCOV_LEVEL=2` that instruments all the comparisons. Level 2 is more
    accurate but may need a larger shared memory.

  - `AFL_DEBUG` will print the found entry point for the binary to stderr. Use
    this if you are unsure if the entry point might be wrong - but use it
    directly, e.g., `afl-qemu-trace ./program`.

  - `AFL_ENTRYPOINT` allows you to specify a specific entry point into the
    binary (this can be very good for the performance!). The entry point is
    specified as hex address, e.g., `0x4004110`. Note that the address must be
    the address of a basic block.

  - Setting `AFL_INST_LIBS` causes the translator to also instrument the code
    inside any dynamically linked libraries (notably including glibc).

  - You can use `AFL_QEMU_INST_RANGES=0xaaaa-0xbbbb,0xcccc-0xdddd` to just
    instrument specific memory locations, e.g. a specific library.
    Excluding ranges takes priority over any included ranges or `AFL_INST_LIBS`.

  - You can use `AFL_QEMU_EXCLUDE_RANGES=0xaaaa-0xbbbb,0xcccc-0xdddd` to **NOT**
    instrument specific memory locations, e.g. a specific library.
    Excluding ranges takes priority over any included ranges or `AFL_INST_LIBS`.

  - It is possible to set `AFL_INST_RATIO` to skip the instrumentation on some
    of the basic blocks, which can be useful when dealing with very complex
    binaries.

  - Setting `AFL_QEMU_COMPCOV` enables the CompareCoverage tracing of all cmp
    and sub in x86 and x86_64. This is an alias of `AFL_COMPCOV_LEVEL=1` when
    `AFL_COMPCOV_LEVEL` is not specified.

  - With `AFL_QEMU_FORCE_DFL`, you force QEMU to ignore the registered signal
    handlers of the target.

  - When the target is i386/x86_64, you can specify the address of the function
    that has to be the body of the persistent loop using
    `AFL_QEMU_PERSISTENT_ADDR=start addr`.

  - With `AFL_QEMU_PERSISTENT_GPR=1`, QEMU will save the original value of
    general purpose registers and restore them in each persistent cycle.

  - Another modality to execute the persistent loop is to specify also the
    `AFL_QEMU_PERSISTENT_RET=end addr` environment variable. With this variable
    assigned, instead of patching the return address, the specified instruction
    is transformed to a jump towards `start addr`.

  - With `AFL_QEMU_PERSISTENT_RETADDR_OFFSET`, you can specify the offset from
    the stack pointer in which QEMU can find the return address when `start
    addr` is hit.

  - With `AFL_USE_QASAN`, you can enable QEMU AddressSanitizer for dynamically
    linked binaries.

  - The underlying QEMU binary will recognize any standard "user space
    emulation" variables (e.g., `QEMU_STACK_SIZE`), but there should be no
    reason to touch them.

  - Normally a `README.txt` is written to the `crashes/` directory when a first
    crash is found. Setting `AFL_NO_CRASH_README` will prevent this. Useful when
    counting crashes based on a file count in that directory.

## 7) Settings for afl-frida-trace

The FRIDA wrapper used to instrument binary-only code supports many of the same
options as `afl-qemu-trace`, but also has a number of additional advanced
options. These are listed in brief below (see
[frida_mode/README.md](../frida_mode/README.md) for more details). These
settings are provided for compatibility with QEMU mode, the preferred way to
configure FRIDA mode is through its [scripting](../frida_mode/Scripting.md)
support.

* `AFL_FRIDA_DEBUG_MAPS` - See `AFL_QEMU_DEBUG_MAPS`
* `AFL_FRIDA_DRIVER_NO_HOOK` - See `AFL_QEMU_DRIVER_NO_HOOK`. When using the
  QEMU driver to provide a `main` loop for a user provided
  `LLVMFuzzerTestOneInput`, this option configures the driver to read input from
  `stdin` rather than using in-memory test cases.
* `AFL_FRIDA_EXCLUDE_RANGES` - See `AFL_QEMU_EXCLUDE_RANGES`
* `AFL_FRIDA_INST_COVERAGE_FILE` - File to write DynamoRio format coverage
  information (e.g., to be loaded within IDA lighthouse).
* `AFL_FRIDA_INST_DEBUG_FILE` - File to write raw assembly of original blocks
  and their instrumented counterparts during block compilation.
* `AFL_FRIDA_INST_JIT` - Enable the instrumentation of Just-In-Time compiled
  code. Code is considered to be JIT if the executable segment is not backed by
  a file.
* `AFL_FRIDA_INST_NO_DYNAMIC_LOAD` - Don't instrument the code loaded late at
  runtime. Strictly limits instrumentation to what has been included.
* `AFL_FRIDA_INST_NO_OPTIMIZE` - Don't use optimized inline assembly coverage
  instrumentation (the default where available). Required to use
  `AFL_FRIDA_INST_TRACE`.
* `AFL_FRIDA_INST_NO_BACKPATCH` - Disable backpatching. At the end of executing
  each block, control will return to FRIDA to identify the next block to
  execute.
* `AFL_FRIDA_INST_NO_PREFETCH` - Disable prefetching. By default, the child will
  report instrumented blocks back to the parent so that it can also instrument
  them and they be inherited by the next child on fork, implies
  `AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH`.
* `AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH` - Disable prefetching of stalker
  backpatching information. By default, the child will report applied
  backpatches to the parent so that they can be applied and then be inherited by
  the next child on fork.
* `AFL_FRIDA_INST_RANGES` - See `AFL_QEMU_INST_RANGES`
* `AFL_FRIDA_INST_SEED` - Sets the initial seed for the hash function used to
  generate block (and hence edge) IDs. Setting this to a constant value may be
  useful for debugging purposes, e.g., investigating unstable edges.
* `AFL_FRIDA_INST_TRACE` - Log to stdout the address of executed blocks, implies
  `AFL_FRIDA_INST_NO_OPTIMIZE`.
* `AFL_FRIDA_INST_TRACE_UNIQUE` - As per `AFL_FRIDA_INST_TRACE`, but each edge
  is logged only once, requires `AFL_FRIDA_INST_NO_OPTIMIZE`.
* `AFL_FRIDA_INST_UNSTABLE_COVERAGE_FILE` - File to write DynamoRio format
  coverage information for unstable edges (e.g., to be loaded within IDA
  lighthouse).
* `AFL_FRIDA_JS_SCRIPT` - Set the script to be loaded by the FRIDA scripting
  engine. See [frida_mode/Scripting.md](../frida_mode/Scripting.md) for details.
* `AFL_FRIDA_OUTPUT_STDOUT` - Redirect the standard output of the target
  application to the named file (supersedes the setting of `AFL_DEBUG_CHILD`)
* `AFL_FRIDA_OUTPUT_STDERR` - Redirect the standard error of the target
  application to the named file (supersedes the setting of `AFL_DEBUG_CHILD`)
* `AFL_FRIDA_PERSISTENT_ADDR` - See `AFL_QEMU_PERSISTENT_ADDR`
* `AFL_FRIDA_PERSISTENT_CNT` - See `AFL_QEMU_PERSISTENT_CNT`
* `AFL_FRIDA_PERSISTENT_DEBUG` - Insert a Breakpoint into the instrumented code
  at `AFL_FRIDA_PERSISTENT_HOOK` and `AFL_FRIDA_PERSISTENT_RET` to allow the
  user to detect issues in the persistent loop using a debugger.
* `AFL_FRIDA_PERSISTENT_HOOK` - See `AFL_QEMU_PERSISTENT_HOOK`
* `AFL_FRIDA_PERSISTENT_RET` - See `AFL_QEMU_PERSISTENT_RET`
* `AFL_FRIDA_SECCOMP_FILE` - Write a log of any syscalls made by the target to
  the specified file.
* `AFL_FRIDA_STALKER_ADJACENT_BLOCKS` - Configure the number of adjacent blocks
  to fetch when generating instrumented code. By fetching blocks in the same
  order they appear in the original program, rather than the order of execution
  should help reduce locality and adjacency. This includes allowing us to
  vector between adjacent blocks using a NOP slide rather than an immediate
  branch.
* `AFL_FRIDA_STALKER_IC_ENTRIES` - Configure the number of inline cache entries
  stored along-side branch instructions which provide a cache to avoid having to
  call back into FRIDA to find the next block. Default is 32.
* `AFL_FRIDA_STATS_FILE` - Write statistics information about the code being
  instrumented to the given file name. The statistics are written only for the
  child process when new block is instrumented (when the
  `AFL_FRIDA_STATS_INTERVAL` has expired). Note that just because a new path is
  found does not mean a new block needs to be compiled. It could be that the
  existing blocks instrumented have been executed in a different order.
* `AFL_FRIDA_STATS_INTERVAL` - The maximum frequency to output statistics
  information. Stats will be written whenever they are updated if the given
  interval has elapsed since last time they were written.
* `AFL_FRIDA_TRACEABLE` - Set the child process to be traceable by any process
  to aid debugging and overcome the restrictions imposed by YAMA. Supported on
  Linux only. Permits a non-root user to use `gcore` or similar to collect a
  core dump of the instrumented target. Note that in order to capture the core
  dump you must set a sufficient timeout (using `-t`) to avoid `afl-fuzz`
  killing the process whilst it is being dumped.

## 8) Settings for afl-cmin

The corpus minimization script offers very little customization:

  - `AFL_ALLOW_TMP` permits this and some other scripts to run in /tmp. This is
    a modest security risk on multi-user systems with rogue users, but should be
    safe on dedicated fuzzing boxes.

  - `AFL_KEEP_TRACES` makes the tool keep traces and other metadata used for
    minimization and normally deleted at exit. The files can be found in the
    `<out_dir>/.traces/` directory.

  - Setting `AFL_PATH` offers a way to specify the location of afl-showmap and
    afl-qemu-trace (the latter only in `-Q` mode).

  - `AFL_PRINT_FILENAMES` prints each filename to stdout, as it gets processed.
    This can help when embedding `afl-cmin` or `afl-showmap` in other scripts.

## 8) afl-cmin 的设置

语料库最小化脚本提供的自定义选项非常少：

  - `AFL_ALLOW_TMP` 允许此脚本和一些其他脚本在 /tmp 中运行。这在具有恶意用户的多用户系统上是一个适度的安全风险，但在专用的模糊测试箱上应该是安全的。

  - `AFL_KEEP_TRACES` 使工具保留用于最小化的跟踪和其他元数据，并通常在退出时删除。文件可以在 `<out_dir>/.traces/` 目录中找到。

  - 设置 `AFL_PATH` 提供了一种指定 afl-showmap 和 afl-qemu-trace（后者仅在 `-Q` 模式下）位置的方法。

  - `AFL_PRINT_FILENAMES` 在处理时将每个文件名打印到 stdout。这在将 `afl-cmin` 或 `afl-showmap` 嵌入到其他脚本中时可能有所帮助。
## 9) Settings for afl-tmin

Virtually nothing to play with. Well, in QEMU mode (`-Q`), `AFL_PATH` will be
searched for afl-qemu-trace. In addition to this, `TMPDIR` may be used if a
temporary file can't be created in the current working directory.

You can specify `AFL_TMIN_EXACT` if you want afl-tmin to require execution paths
to match when minimizing crashes. This will make minimization less useful, but
may prevent the tool from "jumping" from one crashing condition to another in
very buggy software. You probably want to combine it with the `-e` flag.

## 9) afl-tmin 的设置

实际上没有什么可设置的。在 QEMU 模式（`-Q`）下，将搜索 `AFL_PATH` 以查找 afl-qemu-trace。此外，如果无法在当前工作目录中创建临时文件，可能会使用 `TMPDIR`。

如果你希望 afl-tmin 在最小化崩溃时要求执行路径匹配，你可以指定 `AFL_TMIN_EXACT`。这将使最小化变得不那么有用，但可能防止工具在非常有问题的软件中从一个崩溃条件"跳跃"到另一个崩溃条件。你可能希望将其与 `-e` 标志结合使用。

## 10) Settings for afl-analyze

You can set `AFL_ANALYZE_HEX` to get file offsets printed as hexadecimal instead
of decimal.

## 11) Settings for libdislocator

The library honors these environment variables:

  - `AFL_ALIGNED_ALLOC=1` will force the alignment of the allocation size to
    `max_align_t` to be compliant with the C standard.

  - `AFL_LD_HARD_FAIL` alters the behavior by calling `abort()` on excessive
    allocations, thus causing what AFL++ would perceive as a crash. Useful for
    programs that are supposed to maintain a specific memory footprint.

  - `AFL_LD_LIMIT_MB` caps the size of the maximum heap usage permitted by the
    library, in megabytes. The default value is 1 GB. Once this is exceeded,
    allocations will return NULL.

  - `AFL_LD_NO_CALLOC_OVER` inhibits `abort()` on `calloc()` overflows. Most of
    the common allocators check for that internally and return NULL, so it's a
    security risk only in more exotic setups.

  - `AFL_LD_VERBOSE` causes the library to output some diagnostic messages that
    may be useful for pinpointing the cause of any observed issues.

## 11) Settings for libtokencap

This library accepts `AFL_TOKEN_FILE` to indicate the location to which the
discovered tokens should be written.

## 12) Third-party variables set by afl-fuzz & other tools

Several variables are not directly interpreted by afl-fuzz, but are set to
optimal values if not already present in the environment:

  - By default, `ASAN_OPTIONS` are set to (among others):

    ```
    abort_on_error=1
    detect_leaks=0
    malloc_context_size=0
    symbolize=0
    allocator_may_return_null=1
    ```

    If you want to set your own options, be sure to include `abort_on_error=1` -
    otherwise, the fuzzer will not be able to detect crashes in the tested app.
    Similarly, include `symbolize=0`, since without it, AFL++ may have
    difficulty telling crashes and hangs apart.

  - Similarly, the default `LSAN_OPTIONS` are set to:

    ```
    exit_code=23
    fast_unwind_on_malloc=0
    symbolize=0
    print_suppressions=0
    ```

    Be sure to include the first ones for LSAN and MSAN when customizing
    anything, since some MSAN and LSAN versions don't call `abort()` on error,
    and we need a way to detect faults.

  - In the same vein, by default, `MSAN_OPTIONS` are set to:

    ```
    exit_code=86 (required for legacy reasons)
    abort_on_error=1
    symbolize=0
    msan_track_origins=0
    allocator_may_return_null=1
    ```

  - By default, `LD_BIND_NOW` is set to speed up fuzzing by forcing the linker
    to do all the work before the fork server kicks in. You can override this by
    setting `LD_BIND_LAZY` beforehand, but it is almost certainly pointless.
