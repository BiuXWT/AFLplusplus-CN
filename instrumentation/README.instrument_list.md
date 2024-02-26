# Using AFL++ with partial instrumentation
使用部分插桩的AFL++

This file describes two different mechanisms to selectively instrument only
specific parts in the target.
这个文件描述了两种不同的机制，来完成选择性地对目标中的特定部分进行插桩的目的

Both mechanisms work for LLVM and GCC_PLUGIN, but not for afl-clang/afl-gcc.
这两种机制都适用于LLVM和GCC_PLUGIN，但不适用于afl-clang/afl-gcc

## 1) Description and purpose

When building and testing complex programs where only a part of the program is
the fuzzing target, it often helps to only instrument the necessary parts of the
program, leaving the rest uninstrumented. This helps to focus the fuzzer on the
important parts of the program, avoiding undesired noise and disturbance by
uninteresting code being exercised.

For this purpose, "partial instrumentation" support is provided by AFL++ that
allows to specify what should be instrumented and what not.

Both mechanisms for partial instrumentation can be used together.

## 1) 描述和目的

在构建和测试复杂程序时，只有程序的一部分是模糊测试的目标，通常只对程序的必要部分进行插桩，而让其余部分保持未插桩，这往往会有所帮助。这有助于将模糊测试器的焦点集中在程序的重要部分，避免因执行无趣的代码而产生不希望的噪声和干扰。

为此，AFL++提供了"部分插桩"支持，允许指定应该插桩什么，不应该插桩什么。

两种部分插桩的机制可以一起使用。
## 2) Selective instrumentation with __AFL_COVERAGE_... directives

In this mechanism, the selective instrumentation is done in the source code.

After the includes, a special define has to be made, e.g.:

```
#include <stdio.h>
#include <stdint.h>
// ...

__AFL_COVERAGE();  // <- required for this feature to work
```

If you want to disable the coverage at startup until you specify coverage should
be started, then add `__AFL_COVERAGE_START_OFF();` at that position.

From here on out, you have the following macros available that you can use in
any function where you want:

* `__AFL_COVERAGE_ON();` - Enable coverage from this point onwards.
* `__AFL_COVERAGE_OFF();` - Disable coverage from this point onwards.
* `__AFL_COVERAGE_DISCARD();` - Reset all coverage gathered until this point.
* `__AFL_COVERAGE_SKIP();` - Mark this test case as unimportant. Whatever
  happens, afl-fuzz will ignore it.

A special function is `__afl_coverage_interesting`. To use this, you must define
`void __afl_coverage_interesting(u8 val, u32 id);`. Then you can use this
function globally, where the `val` parameter can be set by you, the `id`
parameter is for afl-fuzz and will be overwritten. Note that useful parameters
for `val` are: 1, 2, 3, 4, 8, 16, 32, 64, 128. A value of, e.g., 33 will be seen
as 32 for coverage purposes.

## 2) 使用__AFL_COVERAGE_...指令进行选择性插桩

在这种机制中，选择性插桩是在源代码中完成的。

在包含文件之后，需要做一个特殊的定义，例如：

```c
#include <stdio.h>
#include <stdint.h>
// ...

__AFL_COVERAGE();  // <- 这是使此功能工作所必需的
```

如果你想在启动时禁用覆盖率，直到你指定应该开始覆盖率，那么在那个位置添加`__AFL_COVERAGE_START_OFF();`。

从这里开始，你有以下可用的宏，你可以在任何你想要的函数中使用它们：

* `__AFL_COVERAGE_ON();` - 从这一点开始启用覆盖率。
* `__AFL_COVERAGE_OFF();` - 从这一点开始禁用覆盖率。
* `__AFL_COVERAGE_DISCARD();` - 重置到这一点为止收集的所有覆盖率。
* `__AFL_COVERAGE_SKIP();` - 将这个测试用例标记为不重要。无论发生什么，afl-fuzz都会忽略它。

一个特殊的函数是`__afl_coverage_interesting`。要使用这个，你必须定义`void __afl_coverage_interesting(u8 val, u32 id);`。然后你可以在全局范围内使用这个函数，其中`val`参数可以由你设置，`id`参数是为afl-fuzz准备的，将被覆盖。注意，对于`val`的有用参数是：1, 2, 3, 4, 8, 16, 32, 64, 128。例如，33的值将被视为覆盖目的的32。
## 3) Selective instrumentation with AFL_LLVM_ALLOWLIST/AFL_LLVM_DENYLIST

This feature is equivalent to llvm 12 sancov feature and allows to specify on a
filename and/or function name level to instrument these or skip them.

### 3a) How to use the partial instrumentation mode

In order to build with partial instrumentation, you need to build with
afl-clang-fast/afl-clang-fast++ or afl-clang-lto/afl-clang-lto++. The only
required change is that you need to set either the environment variable
`AFL_LLVM_ALLOWLIST` or `AFL_LLVM_DENYLIST` set with a filename.

That file should contain the file names or functions that are to be instrumented
(`AFL_LLVM_ALLOWLIST`) or are specifically NOT to be instrumented
(`AFL_LLVM_DENYLIST`).

GCC_PLUGIN: you can use either `AFL_LLVM_ALLOWLIST` or `AFL_GCC_ALLOWLIST` (or
the same for `_DENYLIST`), both work.

For matching to succeed, the function/file name that is being compiled must end
in the function/file name entry contained in this instrument file list. That is
to avoid breaking the match when absolute paths are used during compilation.

**NOTE:** In builds with optimization enabled, functions might be inlined and
would not match!

For example, if your source tree looks like this:

```
project/
project/feature_a/a1.cpp
project/feature_a/a2.cpp
project/feature_b/b1.cpp
project/feature_b/b2.cpp
```

And you only want to test feature_a, then create an "instrument file list" file
containing:

```
feature_a/a1.cpp
feature_a/a2.cpp
```

However, if the "instrument file list" file contains only this, it works as
well:

```
a1.cpp
a2.cpp
```

But it might lead to files being unwantedly instrumented if the same filename
exists somewhere else in the project directories.

You can also specify function names. Note that for C++ the function names must
be mangled to match! `nm` can print these names.

AFL++ is able to identify whether an entry is a filename or a function. However,
if you want to be sure (and compliant to the sancov allow/blocklist format), you
can specify source file entries like this:

```
src: *malloc.c
```

And function entries like this:

```
fun: MallocFoo
```

Note that whitespace is ignored and comments (`# foo`) are supported.

### 3b) UNIX-style pattern matching

You can add UNIX-style pattern matching in the "instrument file list" entries.
See `man fnmatch` for the syntax. Do not set any of the `fnmatch` flags.
## 3) 使用AFL_LLVM_ALLOWLIST/AFL_LLVM_DENYLIST进行选择性插桩

这个特性等同于llvm 12的sancov特性，允许在文件名和/或函数名级别指定要插桩的部分或跳过的部分。

### 3a) 如何使用部分插桩模式

为了使用部分插桩进行构建，你需要使用afl-clang-fast/afl-clang-fast++或afl-clang-lto/afl-clang-lto++进行构建。唯一需要改变的是，你需要设置环境变量`AFL_LLVM_ALLOWLIST`或`AFL_LLVM_DENYLIST`，并设置一个文件名。

该文件应包含要进行插桩（`AFL_LLVM_ALLOWLIST`）或特别不进行插桩（`AFL_LLVM_DENYLIST`）的文件名或函数。

GCC_PLUGIN：你可以使用`AFL_LLVM_ALLOWLIST`或`AFL_GCC_ALLOWLIST`（或对于`_DENYLIST`也是一样），两者都可以。

为了匹配成功，正在编译的函数/文件名必须以此插桩文件列表中包含的函数/文件名条目结束。这是为了避免在编译过程中使用绝对路径时破坏匹配。

**注意：**在启用优化的构建中，函数可能会被内联，因此不会匹配！

例如，如果你的源代码树看起来像这样：

```
project/
project/feature_a/a1.cpp
project/feature_a/a2.cpp
project/feature_b/b1.cpp
project/feature_b/b2.cpp
```

如果你只想测试feature_a，那么创建一个包含以下内容的"插桩文件列表"文件：

```
feature_a/a1.cpp
feature_a/a2.cpp
```

然而，如果"插桩文件列表"文件只包含这些，它也可以工作：

```
a1.cpp
a2.cpp
```

但是，如果项目目录中其他地方存在相同的文件名，可能会导致不希望进行插桩的文件被插桩。

你也可以指定函数名。注意，对于C++，函数名必须被改编才能匹配！`nm`可以打印这些名字。

AFL++能够识别一个条目是文件名还是函数。然而，如果你想要确定（并符合sancov allow/blocklist格式），你可以像这样指定源文件条目：

```
src: *malloc.c
```

并像这样指定函数条目：

```
fun: MallocFoo
```

注意，空白字符会被忽略，同时支持注释（`# foo`）。

### 3b) UNIX风格的模式匹配

你可以在"插桩文件列表"条目中添加UNIX风格的模式匹配。关于语法，请参见`man fnmatch`。不要设置任何`fnmatch`标志。