# GCC-based instrumentation for afl-fuzz

For the general instruction manual, see [docs/README.md](../docs/README.md).

For the LLVM-based instrumentation, see [README.llvm.md](README.llvm.md).

This document describes how to build and use `afl-gcc-fast` and `afl-g++-fast`,
which instrument the target with the help of gcc plugins.

TL;DR:
简而言之：
* Check the version of your gcc compiler: `gcc --version`
* 检查你的gcc编译器的版本：`gcc --version`
* `apt-get install gcc-VERSION-plugin-dev` or similar to install headers for gcc
  plugins.
* 使用`apt-get install gcc-VERSION-plugin-dev`或类似命令来安装gcc插件的头文件。
* `gcc` and `g++` must match the gcc-VERSION you installed headers for. You can
  set `AFL_CC`/`AFL_CXX` to point to these!
* `gcc`和`g++`必须与你安装头文件的gcc-VERSION匹配。你可以设置`AFL_CC`/`AFL_CXX`来指向它们！
* `make`
* Just use `afl-gcc-fast`/`afl-g++-fast` normally like you would do with
  `afl-clang-fast`.
* 正常使用`afl-gcc-fast`/`afl-g++-fast`，就像你使用`afl-clang-fast`一样。

## 1) Introduction

The code in this directory allows to instrument programs for AFL++ using true
compiler-level instrumentation, instead of the more crude assembly-level
rewriting approach taken by afl-gcc and afl-clang. This has several interesting
properties:
这个目录中的代码允许使用真正的编译器级别的工具对AFL++程序进行插桩，而不是采用afl-gcc和afl-clang所采用的更粗糙的汇编级别的重写方法。这具有几个有趣的特性：

- The compiler can make many optimizations that are hard to pull off when
  manually inserting assembly. As a result, some slow, CPU-bound programs will
  run up to around faster.
- 编译器可以进行许多优化，这在手动插入汇编时很难实现。因此，一些慢速的、受CPU限制的程序将运行得更快。

  The gains are less pronounced for fast binaries, where the speed is limited
  chiefly by the cost of creating new processes. In such cases, the gain will
  probably stay within 10%.
  对于快速的二进制文件，增益不太明显，因为速度主要受创建新进程的成本限制。在这种情况下，增益可能会保持在10%以内。

- The instrumentation is CPU-independent. At least in principle, you should be
  able to rely on it to fuzz programs on non-x86 architectures (after building
  `afl-fuzz` with `AFL_NOX86=1`).
- 插桩是CPU无关的。至少在原则上，你应该能够依赖它来在非x86架构上模糊测试程序（在用`AFL_NOX86=1`构建`afl-fuzz`之后）。

- Because the feature relies on the internals of GCC, it is gcc-specific and
  will *not* work with LLVM (see [README.llvm.md](README.llvm.md) for an
  alternative).
- 因为这个特性依赖于GCC的内部，它是gcc特有的，将*不*适用于LLVM（参见[README.llvm.md](README.llvm.md)以获取替代方案）。


Once this implementation is shown to be sufficiently robust and portable, it
will probably replace afl-gcc. For now, it can be built separately and co-exists
with the original code.
一旦这个实现被证明足够稳健和可移植，它可能会取代afl-gcc。现在，它可以单独构建，并与原始代码共存。

The idea and much of the implementation comes from Laszlo Szekeres.
这个想法和大部分的实现来自Laszlo Szekeres。

## 2) How to use

In order to leverage this mechanism, you need to have modern enough GCC (>=
version 4.5.0) and the plugin development headers installed on your system. That
should be all you need. On Debian machines, these headers can be acquired by
installing the `gcc-VERSION-plugin-dev` packages.
为了利用这个机制，你需要在你的系统上安装足够新的GCC（>=version 4.5.0）和plugin开发头文件。这应该是你所需要的全部。在Debian机器上，可以通过安装`gcc-VERSION-plugin-dev`包来获取这些头文件。

To build the instrumentation itself, type `make`. This will generate binaries
called `afl-gcc-fast` and `afl-g++-fast` in the parent directory.
要构建插桩本身，输入`make`。这将在父目录中生成名为`afl-gcc-fast`和`afl-g++-fast`的二进制文件。

The gcc and g++ compiler links have to point to gcc-VERSION - or set these by
pointing the environment variables `AFL_CC`/`AFL_CXX` to them. If the `CC`/`CXX`
environment variables have been set, those compilers will be preferred over
those from the `AFL_CC`/`AFL_CXX` settings.
gcc和g++编译器的链接必须指向gcc-VERSION - 或者通过将环境变量`AFL_CC`/`AFL_CXX`指向它们来设置。如果已经设置了`CC`/`CXX`环境变量，那么这些编译器将优先于`AFL_CC`/`AFL_CXX`设置中的编译器。

Once this is done, you can instrument third-party code in a way similar to the
standard operating mode of AFL++, e.g.:
一旦完成这些，你可以以类似于AFL++的标准操作模式的方式对第三方代码进行插桩，例如：

```
  CC=/path/to/afl/afl-gcc-fast
  CXX=/path/to/afl/afl-g++-fast
  export CC CXX
  ./configure [...options...]
  make
```

Note: We also used `CXX` to set the C++ compiler to `afl-g++-fast` for C++ code.
注意：我们也使用了`CXX`来将C++编译器设置为`afl-g++-fast`以用于C++代码。

The tool honors roughly the same environmental variables as `afl-gcc` (see
[docs/env_variables.md](../docs/env_variables.md). This includes
`AFL_INST_RATIO`, `AFL_USE_ASAN`, `AFL_HARDEN`, and `AFL_DONT_OPTIMIZE`.
这个工具遵循与`afl-gcc`大致相同的环境变量（参见[docs/env_variables.md](../docs/env_variables.md)）。这包括`AFL_INST_RATIO`，`AFL_USE_ASAN`，`AFL_HARDEN`，和`AFL_DONT_OPTIMIZE`。

Note: if you want the GCC plugin to be installed on your system for all users,
you need to build it before issuing 'make install' in the parent directory.
注意：如果你想要GCC插件被安装在你的系统上供所有用户使用，你需要在在父目录中执行'make install'之前构建它。

## 3) Gotchas, feedback, bugs
注意事项，反馈，错误

This is an early-stage mechanism, so field reports are welcome. You can send bug
reports to afl@aflplus.plus.
这是一个早期阶段的机制，所以欢迎提供实地报告。你可以将错误报告发送到afl@aflplus.plus。

## 4) Bonus feature #1: deferred initialization
额外特性 #1：延迟初始化

See
[README.persistent_mode.md#3) Deferred initialization](README.persistent_mode.md#3-deferred-initialization).

## 5) Bonus feature #2: persistent mode
额外特性 #2：持久模式

See
[README.persistent_mode.md#4) Persistent mode](README.persistent_mode.md#4-persistent-mode).

## 6) Bonus feature #3: selective instrumentation
额外特性 #3：选择性插桩

It can be more effective to fuzzing to only instrument parts of the code. For
details, see [README.instrument_list.md](README.instrument_list.md).
只对代码的部分进行插桩可能会使模糊测试更有效。详情请参见[README.instrument_list.md](README.instrument_list.md)。

## 7) Bonus feature #4: CMPLOG
额外特性 #4：CMPLOG

The gcc_plugin also support CMPLOG/Redqueen, just set `AFL_GCC_CMPLOG` before
instrumenting the target.
Read more about this in the llvm document.
gcc_plugin也支持CMPLOG/Redqueen，只需在对目标进行插桩之前设置`AFL_GCC_CMPLOG`。
在llvm文档中有关于这个的更多阅读。

