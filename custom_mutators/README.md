# Custom Mutators

Custom mutators enhance and alter the mutation strategies of AFL++.
For further information and documentation on how to write your own, read [the docs](../docs/custom_mutators.md).

自定义变异器增强并改变了AFL++的变异策略。有关如何编写的详细信息和文档，请阅读[文档](../docs/custom_mutators.md)。
## Examples

The `./examples` folder contains examples for custom mutators in python and C.

`./examples` 文件夹包含如何编写C和Python自定义变异器的示例.
## Rust

In `./rust`, you will find rust bindings, including a simple example in `./rust/example` and an example for structured fuzzing, based on lain, in`./rust/example_lain`.

在`./rust`目录中，您将找到 Rust 绑定，其中包括`./rust/example`中的一个简单示例以及基于 lain 的结构化模糊测试的示例在`./rust/example_lain`中。
## Production-Ready Custom Mutators

This directory holds ready to use custom mutators.
Just type "make" in the individual subdirectories.

Use with e.g.

`AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/radamsa/radamsa-mutator.so afl-fuzz ....`

and add `AFL_CUSTOM_MUTATOR_ONLY=1` if you only want to use the custom mutator.

Multiple custom mutators can be used by separating their paths with `:` in the environment variable.

## 适用于生产环境的自定义变异器

该目录包含可立即使用的自定义变异器。
只需在各个子目录中输入 "make"。

例如使用：

`AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/radamsa/radamsa-mutator.so afl-fuzz ....`

如果只想使用自定义变异器，请添加 `AFL_CUSTOM_MUTATOR_ONLY=1`。

可以通过在环境变量中用 `:` 分隔它们的路径来使用多个自定义变异器。
### The AFL++ grammar agnostic grammar mutator

In `./autotokens` you find a token-level fuzzer that does not need to know
anything about the grammar of an input as long as it is in ascii and allows
whitespace.
It is very fast and effective.

If you are looking for an example of how to effectively create a custom
mutator take a look at this one.

### AFL++ 语法不可知的语法变异器

在`./autotokens`目录中，您会找到一个令牌级别的模糊测试工具，它不需要了解输入的语法，只要它是 ASCII 格式并允许空格即可。
它非常快速和有效。

如果您正在寻找一个有效创建自定义变异器的示例，请查看这个。
### The AFL++ Grammar Mutator

If you use git to clone AFL++, then the following will incorporate our
excellent grammar custom mutator:

```sh
git submodule update --init
```

Read the README in the [Grammar-Mutator] repository on how to use it.

[Grammar-Mutator]: https://github.com/AFLplusplus/Grammar-Mutator

Note that this custom mutator is not very good though!

### AFL++ 语法变异器

如果您使用git克隆AFL++，则以下操作将包含我们优秀的语法自定义变异器：

```sh
git submodule update --init
```

阅读[Grammar-Mutator]存储库中的README以了解如何使用它。

[Grammar-Mutator]: https://github.com/AFLplusplus/Grammar-Mutator

请注意，这个自定义变异器并不是很好！
### Other Mutators

atnwalk and gramatron are grammar custom mutators. Example grammars are
provided.

honggfuzz, libfuzzer and  libafl are partial implementations based on the
mutator implementations of the respective fuzzers. 
More for playing than serious usage.

radamsa is slow and not very good.

### 其他变异器

atnwalk 和 gramatron 是基于语法的自定义变异器。提供了示例语法。

honggfuzz、libfuzzer 和 libafl 是基于相应模糊测试工具的变异器实现的部分实现。
更适合娱乐而非严肃用途。

radamsa 较慢且效果不是很好。
## 3rd Party Custom Mutators

第三方变异器
### Superion Mutators

Adrian Tiron ported the Superion grammar fuzzer to AFL++, it is WIP and
requires cmake (among other things):
[https://github.com/adrian-rt/superion-mutator](https://github.com/adrian-rt/superion-mutator)

### Superion 变异器

Adrian Tiron 将 Superion 语法模糊测试工具移植到 AFL++，目前仍在进行中，并且需要使用 cmake（等其他工具）：

[https://github.com/adrian-rt/superion-mutator](https://github.com/adrian-rt/superion-mutator)
### libprotobuf Mutators

There are three WIP protobuf projects, that require work to be working though:

ASN.1 example:
[https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/src/mutator](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/src/mutator)

transforms protobuf raw:
[https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator](https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator)

has a transform function you need to fill for your protobuf format, however
needs to be ported to the updated AFL++ custom mutator API (not much work):
[https://github.com/thebabush/afl-libprotobuf-mutator](https://github.com/thebabush/afl-libprotobuf-mutator)

same as above but is for current AFL++:
[https://github.com/P1umer/AFLplusplus-protobuf-mutator](https://github.com/P1umer/AFLplusplus-protobuf-mutator)

### libprotobuf 变异器

有三个正在进行中的 protobuf 项目，尽管需要一些工作才能正常工作：

ASN.1 示例:
[https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/src/mutator](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/src/mutator)

transforms protobuf raw:
[https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator](https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator)

有一个您需要为您的 protobuf 格式填充的转换函数，但是需要移植到更新的 AFL++ 自定义变异器 API（工作量不大）：
[https://github.com/thebabush/afl-libprotobuf-mutator](https://github.com/thebabush/afl-libprotobuf-mutator)

与上述相同，但适用于当前的 AFL++ 版本：
[https://github.com/P1umer/AFLplusplus-protobuf-mutator](https://github.com/P1umer/AFLplusplus-protobuf-mutator)