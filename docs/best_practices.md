# Best practices

## Contents

### Targets

- [Best practices](#best-practices)
  - [Contents](#contents)
    - [Targets](#targets)
    - [Improvements](#improvements)
  - [Targets](#targets-1)
    - [Fuzzing a target with source code available](#fuzzing-a-target-with-source-code-available)
    - [Fuzzing a target with dlopen instrumented libraries](#fuzzing-a-target-with-dlopen-instrumented-libraries)
    - [Fuzzing a binary-only target](#fuzzing-a-binary-only-target)
    - [Fuzzing a GUI program](#fuzzing-a-gui-program)
    - [Fuzzing a network service](#fuzzing-a-network-service)
  - [Improvements](#improvements-1)
    - [Improving speed](#improving-speed)
    - [Improving stability](#improving-stability)

### Improvements

* [Improving speed](#improving-speed)
* [Improving stability](#improving-stability)

## Targets

### Fuzzing a target with source code available

To learn how to fuzz a target if source code is available, see
[fuzzing_in_depth.md](fuzzing_in_depth.md).
要了解如何在源代码可用的情况下对目标进行模糊测试，请参阅[fuzzing_in_depth.md](fuzzing_in_depth.md).

### Fuzzing a target with dlopen instrumented libraries
对一个使用dlopen加载插桩动态库的被测对象进行模糊测试

If a source code based fuzzing target loads instrumented libraries with
dlopen() after the forkserver has been activated and non-colliding coverage
instrumentation is used (PCGUARD (which is the default), or LTO), then this
an issue, because this would enlarge the coverage map, but afl-fuzz doesn't
know about it.
如果一个基于源代码的模糊测试目标在forkserver启动后，使用dlopen()加载插桩库，并使用非冲突覆盖插桩（PCGUARD（这是默认的）或LTO），那么这就是一个问题，因为这会扩大coverage map，但afl-fuzz并不知道这一点。

The solution is to use `AFL_PRELOAD` for all dlopen()'ed libraries to
ensure that all coverage targets are present on startup in the target,
even if accessed only later with dlopen().
解决方案是对所有dlopen()的库使用`AFL_PRELOAD`，以确保所有的覆盖目标在目标启动时就存在，即使只在稍后通过dlopen()访问。

For PCGUARD instrumentation `abort()` is called if this is detected, for LTO
there will either be no coverage for the instrumented dlopen()'ed libraries or
you will see lots of crashes in the UI.
对于PCGUARD插桩，如果检测到这个问题，将调用`abort()`。对于LTO，要么插桩的dlopen()的库没有覆盖，要么你会在UI中看到很多崩溃。

Note that this is not an issue if you use the inferiour `afl-gcc-fast`,
`afl-gcc` or`AFL_LLVM_INSTRUMENT=CLASSIC/NGRAM/CTX afl-clang-fast`
instrumentation.
请注意，如果你使用较差的`afl-gcc-fast`，`afl-gcc`或`AFL_LLVM_INSTRUMENT=CLASSIC/NGRAM/CTX afl-clang-fast`插桩，这不是一个问题。

### Fuzzing a binary-only target
对二进制进行fuzz

For a comprehensive guide, see
[fuzzing_binary-only_targets.md](fuzzing_binary-only_targets.md).

### Fuzzing a GUI program
对GUI进行fuzz

If the GUI program can read the fuzz data from a file (via the command line, a
fixed location or via an environment variable) without needing any user
interaction, then it would be suitable for fuzzing.
如果GUI程序不需要任何用户交互就能(通过命令行、固定位置或环境变量)从文件中读取模糊测试数据，那么它就适合进行模糊测试。

Otherwise, it is not possible without modifying the source code - which is a
very good idea anyway as the GUI functionality is a huge CPU/time overhead for
the fuzzing.
否则，不修改源代码是不可能的 — — 无论如何这都是一个很好的主意，因为GUI功能对模糊测试来说是一个巨大的CPU/时间开销。

So create a new `main()` that just reads the test case and calls the
functionality for processing the input that the GUI program is using.
因此，创建一个新的`main()`，它只读取测试用例，并调用该功能来处理GUI程序正在使用的输入。

### Fuzzing a network service
对网络服务进行模糊测试

Fuzzing a network service does not work "out of the box".
对网络服务进行模糊测试并不能“开箱即用”。

Using a network channel is inadequate for several reasons:
使用网络通道有几个不足之处：
- it has a slow-down of x10-20 on the fuzzing speed
- 它会使模糊测试速度减慢10-20倍
- it does not scale to fuzzing multiple instances easily,
- 它不容易扩展到多实例模糊测试，
- instead of one initial data packet often a back-and-forth interplay of packets
  is needed for stateful protocols (which is totally unsupported by most
  coverage aware fuzzers).
- 对于有状态的协议，通常需要多个数据包的来回交互，而不是一个初始数据包（这是大多数覆盖率感知的模糊测试器完全不支持的）。

The established method to fuzz network services is to modify the source code to
read from a file or stdin (fd 0) (or even faster via shared memory, combine this
with persistent mode
[instrumentation/README.persistent_mode.md](../instrumentation/README.persistent_mode.md)
and you have a performance gain of x10 instead of a performance loss of over x10
对网络服务进行模糊测试的既定方法是修改源代码，以从文件或标准输入（文件描述符0）读取（或者通过共享内存更快，将其与持久模式结合使用，你将获得10倍的性能提升，而不是超过10倍的性能损失 
- that is a x100 difference!).
- 这是100倍的差异！）。

If modifying the source is not an option (e.g., because you only have a binary
and perform binary fuzzing) you can also use a shared library with AFL_PRELOAD
to emulate the network. This is also much faster than the real network would be.
See [utils/socket_fuzzing/](../utils/socket_fuzzing/).
如果修改源代码不是一个选项（例如，因为你只有一个二进制文件并进行二进制模糊测试），你也可以使用 AFL_PRELOAD 的共享库来模拟网络。这也比真实的网络要快得多。参见 [utils/socket_fuzzing/](../utils/socket_fuzzing/)。

There is an outdated AFL++ branch that implements networking if you are
desperate though:
[https://github.com/AFLplusplus/AFLplusplus/tree/networking](https://github.com/AFLplusplus/AFLplusplus/tree/networking)
如果你非常需要的话，有一个过时的 AFL++ 分支实现了网络功能：[https://github.com/AFLplusplus/AFLplusplus/tree/networking](https://github.com/AFLplusplus/AFLplusplus/tree/networking) 
- however, a better option is AFLnet
([https://github.com/aflnet/aflnet](https://github.com/aflnet/aflnet)) which
allows you to define network state with different type of data packets.
- 然而，一个更好的选择是 AFLnet ([https://github.com/aflnet/aflnet](https://github.com/aflnet/aflnet))，它允许你用不同类型的数据包定义网络状态。

## Improvements

### Improving speed
提高速度

1. Use [llvm_mode](../instrumentation/README.llvm.md): afl-clang-lto (llvm >=
   11) or afl-clang-fast (llvm >= 9 recommended).
   使用 [llvm_mode](../instrumentation/README.llvm.md): afl-clang-lto (llvm >= 11) 或 afl-clang-fast (推荐 llvm >= 9)。
2. Use [persistent mode](../instrumentation/README.persistent_mode.md) (x2-x20
   speed increase).
   使用 [persistent mode](../instrumentation/README.persistent_mode.md) (可以提高2-20倍的速度)。
3. Instrument just what you are interested in, see
   [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md).
   只对你感兴趣的部分进行插桩，参见 [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md)。
4. If you do not use shmem persistent mode, use `AFL_TMPDIR` to put the input
   file directory on a tempfs location, see
   [env_variables.md](env_variables.md).
   如果你没有使用 shmem 持久模式，使用 `AFL_TMPDIR` 将输入文件目录放在 tempfs 位置，参见 [env_variables.md](env_variables.md)。
5. Improve Linux kernel performance: modify `/etc/default/grub`, set
   `GRUB_CMDLINE_LINUX_DEFAULT="ibpb=off ibrs=off kpti=off l1tf=off mds=off
   mitigations=off no_stf_barrier noibpb noibrs nopcid nopti
   nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off
   spec_store_bypass_disable=off spectre_v2=off stf_barrier=off"`; then
   `update-grub` and `reboot` (warning: makes the system less secure).
   提高 Linux 内核性能：修改 `/etc/default/grub`，设置 `GRUB_CMDLINE_LINUX_DEFAULT="ibpb=off ibrs=off kpti=off l1tf=off mds=off mitigations=off no_stf_barrier noibpb noibrs nopcid nopti nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off spec_store_bypass_disable=off spectre_v2=off stf_barrier=off"`；然后 `update-grub` 并 `reboot` (警告：这会降低系统的安全性)。
6. Running on an `ext2` filesystem with `noatime` mount option will be a bit
   faster than on any other journaling filesystem.
   在带有 `noatime` 挂载选项的 `ext2` 文件系统上运行会比在任何其他日志文件系统上快一点。
7. Use your cores
   ([fuzzing_in_depth.md:3c) Using multiple cores](fuzzing_in_depth.md#c-using-multiple-cores))!
   使用多核心 ([fuzzing_in_depth.md:3c) Using multiple cores](fuzzing_in_depth.md#c-using-multiple-cores))!

### Improving stability
提升稳定性

For fuzzing, a 100% stable target that covers all edges is the best case. A 90%
stable target that covers all edges is, however, better than a 100% stable
target that ignores 10% of the edges.
对于模糊测试，覆盖所有边缘的 100% 稳定目标是最好的情况。但是，覆盖所有边缘的 90% 稳定目标比忽略 10% 边缘的 100% 稳定目标要好。

With instability, you basically have a partial coverage loss on an edge, with
ignored functions you have a full loss on that edges.
在不稳定时,基本上是在某个边上丢失部分覆盖率;若是忽略某个函数,则这条边的覆盖率将会全部丢失

There are functions that are unstable, but also provide value to coverage, e.g.,
init functions that use fuzz data as input. If, however, a function that has
nothing to do with the input data is the source of instability, e.g., checking
jitter, or is a hash map function etc., then it should not be instrumented.
即使有一些函数不稳定,但也提供了覆盖率,例如使用模糊数据作为输入的初始化函数。然而，如果导致不稳定性的函数与输入数据无关，例如检查抖动或是哈希映射函数等，则不应进行插桩。

To be able to exclude these functions (based on AFL++'s measured stability), the
following process will allow to identify functions with variable edges.
为了能够排除这些函数（基于AFL++的稳定性测量），以下过程将允许识别具有可变边缘的函数。

Note that this is only useful for non-persistent targets!
If a persistent target is unstable whereas when run non-persistent is fine,
then this means that the target is keeping internal state, which is bad for
fuzzing. Fuzz such targets **without** persistent mode.
请注意，这只对非持久性目标有用！
如果一个目标在non-persistent时是稳定的，而在persistent时是不稳定的，
那么这意味着目标在保持内部状态，这对模糊测试是不利的。对这样的目标进行模糊测试时，**不要**使用persistent模式。

Four steps are required to do this and it also requires quite some knowledge of
coding and/or disassembly and is effectively possible only with `afl-clang-fast`
`PCGUARD` and `afl-clang-lto` `LTO` instrumentation.
要做到这一点需要四个步骤，而且还需要相当多的编程和/或反汇编知识，实际上只有在使用 `afl-clang-fast` 的 `PCGUARD` 和 `afl-clang-lto` 的 `LTO` 插桩时才可能实现。

  1. Instrument to be able to find the responsible function(s):
  为了找到负责的函数，需要进行插桩：

     a) For LTO instrumented binaries, this can be documented during compile
        time, just set `export AFL_LLVM_DOCUMENT_IDS=/path/to/a/file`. This file
        will have one assigned edge ID and the corresponding function per line.
     a) 对于 LTO 插桩的二进制文件，可以在编译时进行记录，只需设置 export AFL_LLVM_DOCUMENT_IDS=/path/to/a/file。这个文件将会有一个分配的边缘 ID 和每行对应的函数。 

     b) For PCGUARD instrumented binaries, it is much more difficult. Here you
        can either modify the `__sanitizer_cov_trace_pc_guard` function in
        `instrumentation/afl-llvm-rt.o.c` to write a backtrace to a file if the
        ID in `__afl_area_ptr[*guard]` is one of the unstable edge IDs. (Example
        code is already there). Then recompile and reinstall `llvm_mode` and
        rebuild your target. Run the recompiled target with `afl-fuzz` for a
        while and then check the file that you wrote with the backtrace
        information. Alternatively, you can use `gdb` to hook
        `__sanitizer_cov_trace_pc_guard_init` on start, check to which memory
        address the edge ID value is written, and set a write breakpoint to that
        address (`watch 0x.....`).
      b) 对于 PCGUARD 插桩的二进制文件，这要困难得多。在这里，你可以修改 instrumentation/afl-llvm-rt.o.c 中的 __sanitizer_cov_trace_pc_guard 函数，如果 __afl_area_ptr[*guard] 中的 ID 是不稳定边缘 ID 的一个，就将回溯信息写入一个文件。（已经有示例代码）。然后重新编译和重新安装 llvm_mode 并重建你的目标。运行重新编译的目标与 afl-fuzz 一段时间，然后检查你写入回溯信息的文件。或者，你可以使用 gdb 在开始时挂钩 __sanitizer_cov_trace_pc_guard_init，检查边缘 ID 值被写入到哪个内存地址，并设置一个写入断点到那个地址（watch 0x.....）。

     c) In other instrumentation types, this is not possible. So just recompile
        with the two mentioned above. This is just for identifying the functions
        that have unstable edges.
     c) 在其他插桩类型中，这是不可能的。所以只需用上述两种重新编译。这只是为了识别具有不稳定边缘的函数。

  2. Identify which edge ID numbers are unstable.

     Run the target with `export AFL_DEBUG=1` for a few minutes then terminate.
     The out/fuzzer_stats file will then show the edge IDs that were identified
     as unstable in the `var_bytes` entry. You can match these numbers directly
     to the data you created in the first step. Now you know which functions are
     responsible for the instability

  3. Create a text file with the filenames/functions

     Identify which source code files contain the functions that you need to
     remove from instrumentation, or just specify the functions you want to skip
     for instrumentation. Note that optimization might inline functions!

     Follow this document on how to do this:
     [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md).

     If `PCGUARD` is used, then you need to follow this guide (needs llvm 12+!):
     [https://clang.llvm.org/docs/SanitizerCoverage.html#partially-disabling-instrumentation](https://clang.llvm.org/docs/SanitizerCoverage.html#partially-disabling-instrumentation)

     Only exclude those functions from instrumentation that provide no value for
     coverage - that is if it does not process any fuzz data directly or
     indirectly (e.g., hash maps, thread management etc.). If, however, a
     function directly or indirectly handles fuzz data, then you should not put
     the function in a deny instrumentation list and rather live with the
     instability it comes with.

  4. Recompile the target

     Recompile, fuzz it, be happy :)

     This link explains this process for
     [Fuzzbench](https://github.com/google/fuzzbench/issues/677).
