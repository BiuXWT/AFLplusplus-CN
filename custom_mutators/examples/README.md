# Examples for the custom mutator

These are example and helper files for the custom mutator feature.
See [docs/custom_mutators.md](../../docs/custom_mutators.md) for more information

Note that if you compile with python3.7 you must use python3 scripts, and if
you use python2.7 to compile python2 scripts!

simple_example.c - most simplest example. generates a random sized buffer
          filled with 'A'

example.c - this is a simple example written in C and should be compiled to a
          shared library. Use make to compile it and produce libexamplemutator.so

example.py - this is the template you can use, the functions are there but they
           are empty

post_library_gif.so.c - fix a fuzz input to ensure it is valid for GIF

post_library_png.so.c - fix a fuzz input to ensure it is valid for PNG

simple-chunk-replace.py - this is a simple example where chunks are replaced

common.py - this can be used for common functions and helpers.
          the examples do not use this though. But you can :)

wrapper_afl_min.py - mutation of XML documents, loads XmlMutatorMin.py

XmlMutatorMin.py - module for XML mutation

custom_mutator_helpers.h is an header that defines some helper routines
like surgical_havoc_mutate() that allow to perform a randomly chosen
mutation from a subset of the havoc mutations.
If you do so, you have to specify -I /path/to/AFLplusplus/include when
compiling.

elf_header_mutator.c - example ELF header mutator based on 
 [LibGolf](https://github.com/xcellerator/libgolf/)

# 自定义变异器示例

这些是用于自定义变异器功能的示例和辅助文件。
请查看 [docs/custom_mutators.md](../../docs/custom_mutators.md) 获取更多信息。

请注意，如果使用 python3.7 编译，必须使用 python3 脚本，如果使用 python2.7 编译，则使用 python2 脚本！

- simple_example.c - 最简单的示例。生成一个填充了 'A' 的随机大小缓冲区。

- example.c - 这是一个用 C 编写的简单示例，应该编译为共享库。使用 make 进行编译并生成 libexamplemutator.so。

- example.py - 这是您可以使用的模板，其中函数已存在但为空。

- post_library_gif.so.c - 修复模糊输入以确保其对 GIF 有效。

- post_library_png.so.c - 修复模糊输入以确保其对 PNG 有效。

- simple-chunk-replace.py - 这是一个简单的示例，其中替换了块。

- common.py - 可以用于常见函数和辅助功能。示例未使用此文件，但您可以使用它 :)

- wrapper_afl_min.py - 对 XML 文档进行变异，加载 XmlMutatorMin.py。

- XmlMutatorMin.py - 用于 XML 变异的模块。

- custom_mutator_helpers.h 是一个定义了一些辅助例程的头文件，比如 surgical_havoc_mutate()，它允许从混沌变异的子集中随机选择一个变异。如果这样做，编译时必须指定 -I /path/to/AFLplusplus/include。

- elf_header_mutator.c - 基于 [LibGolf](https://github.com/xcellerator/libgolf/) 的示例 ELF 标头变异器。