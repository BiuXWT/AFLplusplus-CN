# Custom Mutators in AFL++

This file describes how you can implement custom mutations to be used in AFL.
For now, we support C/C++ library and Python module, collectively named as the
custom mutator.

There is also experimental support for Rust in `custom_mutators/rust`. For
documentation, refer to that directory. Run `cargo doc -p custom_mutator --open`
in that directory to view the documentation in your web browser.

Implemented by
- C/C++ library (`*.so`): Khaled Yakdan from Code Intelligence
  (<yakdan@code-intelligence.de>)
- Python module: Christian Holler from Mozilla (<choller@mozilla.com>)

此文件描述了如何实现用于AFL中的自定义变异。目前，我们支持C/C++库和Python模块，统称为自定义变异器。

我们还对Rust提供了实验性支持，在`custom_mutators/rust`中。有关文档，请参阅该目录。在该目录中运行`cargo doc -p custom_mutator --open`可以在你的网络浏览器中查看文档。

实现者
- C/C++库（`*.so`）：来自Code Intelligence的Khaled Yakdan（<yakdan@code-intelligence.de>）
- Python模块：来自Mozilla的Christian Holler（<choller@mozilla.com>）
## 1) Introduction

Custom mutators can be passed to `afl-fuzz` to perform custom mutations on test
cases beyond those available in AFL. For example, to enable structure-aware
fuzzing by using libraries that perform mutations according to a given grammar.

The custom mutator is passed to `afl-fuzz` via the `AFL_CUSTOM_MUTATOR_LIBRARY`
or `AFL_PYTHON_MODULE` environment variable, and must export a fuzz function.
Now AFL++ also supports multiple custom mutators which can be specified in the
same `AFL_CUSTOM_MUTATOR_LIBRARY` environment variable like this.

```bash
export AFL_CUSTOM_MUTATOR_LIBRARY="full/path/to/mutator_first.so;full/path/to/mutator_second.so"
```

For details, see [APIs](#2-apis) and [Usage](#3-usage).

The custom mutation stage is set to be the first non-deterministic stage (right
before the havoc stage).

Note: If `AFL_CUSTOM_MUTATOR_ONLY` is set, all mutations will solely be
performed with the custom mutator.

自定义变异器可以传递给`afl-fuzz`，以在AFL可用的测试用例变异之外执行自定义变异。例如，通过使用根据给定语法执行变异的库来启用结构感知的模糊测试。

自定义变异器通过`AFL_CUSTOM_MUTATOR_LIBRARY`或`AFL_PYTHON_MODULE`环境变量传递给`afl-fuzz`，并且必须导出一个fuzz函数。现在，AFL++也支持多个自定义变异器，可以在同一个`AFL_CUSTOM_MUTATOR_LIBRARY`环境变量中像这样指定。

```bash
export AFL_CUSTOM_MUTATOR_LIBRARY="full/path/to/mutator_first.so;full/path/to/mutator_second.so"
```

详情请参见[APIs](#2-apis)和[Usage](#3-usage)。

自定义变异阶段被设置为第一个非确定性阶段（紧接在havoc阶段之前）。

注意：如果设置了`AFL_CUSTOM_MUTATOR_ONLY`，所有的变异将仅通过自定义变异器执行。
## 2) APIs

**IMPORTANT NOTE**: If you use our C/C++ API and you want to increase the size
of an **out_buf buffer, you have to use `afl_realloc()` for this, so include
`include/alloc-inl.h` - otherwise afl-fuzz will crash when trying to free
your buffers.

**重要提示**：如果你使用我们的C/C++ API，并且你想要增加`**out_buf`缓冲区的大小，你必须使用`afl_realloc()`来实现这一点，因此需要包含`include/alloc-inl.h`——否则，当尝试释放你的缓冲区时，afl-fuzz将会崩溃。
C/C++:

```c
void *afl_custom_init(afl_state_t *afl, unsigned int seed);
unsigned int afl_custom_fuzz_count(void *data, const unsigned char *buf, size_t buf_size);
void afl_custom_splice_optout(void *data);
size_t afl_custom_fuzz(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf, unsigned char *add_buf, size_t add_buf_size, size_t max_size);
const char *afl_custom_describe(void *data, size_t max_description_len);
size_t afl_custom_post_process(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf);
int afl_custom_init_trim(void *data, unsigned char *buf, size_t buf_size);
size_t afl_custom_trim(void *data, unsigned char **out_buf);
int afl_custom_post_trim(void *data, unsigned char success);
size_t afl_custom_havoc_mutation(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf, size_t max_size);
unsigned char afl_custom_havoc_mutation_probability(void *data);
unsigned char afl_custom_queue_get(void *data, const unsigned char *filename);
void (*afl_custom_fuzz_send)(void *data, const u8 *buf, size_t buf_size);
u8 afl_custom_queue_new_entry(void *data, const unsigned char *filename_new_queue, const unsigned int *filename_orig_queue);
const char* afl_custom_introspection(my_mutator_t *data);
void afl_custom_deinit(void *data);
```

Python:

```python
def init(seed):
    pass

def fuzz_count(buf):
    return cnt

def splice_optout():
    pass

def fuzz(buf, add_buf, max_size):
    return mutated_out

def describe(max_description_length):
    return "description_of_current_mutation"

def post_process(buf):
    return out_buf

def init_trim(buf):
    return cnt

def trim():
    return out_buf

def post_trim(success):
    return next_index

def havoc_mutation(buf, max_size):
    return mutated_out

def havoc_mutation_probability():
    return probability # int in [0, 100]

def queue_get(filename):
    return True

def fuzz_send(buf):
    pass

def queue_new_entry(filename_new_queue, filename_orig_queue):
    return False

def introspection():
    return string

def deinit():  # optional for Python
    pass
```

### Custom Mutation

- `init` (optional in Python):

    This method is called when AFL++ starts up and is used to seed RNG and set
    up buffers and state.

- `queue_get` (optional):

    This method determines whether AFL++ should fuzz the current
    queue entry or not: all defined custom mutators as well as
    all AFL++'s mutators.

- `fuzz_count` (optional):

    When a queue entry is selected to be fuzzed, afl-fuzz selects the number of
    fuzzing attempts with this input based on a few factors. If, however, the
    custom mutator wants to set this number instead on how often it is called
    for a specific queue entry, use this function. This function is most useful
    if `AFL_CUSTOM_MUTATOR_ONLY` is **not** used.

- `splice_optout` (optional):

    If this function is present, no splicing target is passed to the `fuzz`
    function. This saves time if splicing data is not needed by the custom
    fuzzing function.
    This function is never called, just needs to be present to activate.

- `fuzz` (optional):

    This method performs your custom mutations on a given input.
    The add_buf is the contents of another queue item that can be used for
    splicing - or anything else - and can also be ignored. If you are not
    using this additional data then define `splice_optout` (see above).
    This function is optional.
    Returing a length of 0 is valid and is interpreted as skipping this
    one mutation result.
    For non-Python: the returned output buffer is under **your** memory
    management!

- `describe` (optional):

    When this function is called, it shall describe the current test case,
    generated by the last mutation. This will be called, for example, to name
    the written test case file after a crash occurred. Using it can help to
    reproduce crashing mutations.

- `havoc_mutation` and `havoc_mutation_probability` (optional):

    `havoc_mutation` performs a single custom mutation on a given input. This
    mutation is stacked with other mutations in havoc. The other method,
    `havoc_mutation_probability`, returns the probability that `havoc_mutation`
    is called in havoc. By default, it is 6%.

- `post_process` (optional):

    For some cases, the format of the mutated data returned from the custom
    mutator is not suitable to directly execute the target with this input. For
    example, when using libprotobuf-mutator, the data returned is in a protobuf
    format which corresponds to a given grammar. In order to execute the target,
    the protobuf data must be converted to the plain-text format expected by the
    target. In such scenarios, the user can define the `post_process` function.
    This function is then transforming the data into the format expected by the
    API before executing the target.

    This can return any python object that implements the buffer protocol and
    supports PyBUF_SIMPLE. These include bytes, bytearray, etc.

    You can decide in the post_process mutator to not send the mutated data
    to the target, e.g. if it is too short, too corrupted, etc. If so,
    return a NULL buffer and zero length (or a 0 length string in Python).

    NOTE: Do not make any random changes to the data in this function!

    PERFORMANCE for C/C++: If possible make the changes in-place (so modify
    the `*data` directly, and return it as `*outbuf = data`.

- `fuzz_send` (optional):

    This method can be used if you want to send data to the target yourself,
    e.g. via IPC. This replaces some usage of utils/afl_proxy but requires
    that you start the target with afl-fuzz.
    Example: [custom_mutators/examples/custom_send.c](../custom_mutators/examples/custom_send.c)

- `queue_new_entry` (optional):

    This methods is called after adding a new test case to the queue. If the
    contents of the file was changed, return True, False otherwise.

- `introspection` (optional):

    This method is called after a new queue entry, crash or timeout is
    discovered if compiled with INTROSPECTION. The custom mutator can then
    return a string (const char *) that reports the exact mutations used.

- `deinit` (optional in Python):

    The last method to be called, deinitializing the state.

Note that there are also three functions for trimming as described in the next
section.

- `init`（在Python中可选）：

    当AFL++启动时会调用此方法，用于初始化随机数生成器、设置缓冲区和状态。

- `queue_get`（可选）：

    此方法决定AFL++是否应该模糊当前队列条目：所有定义的自定义变异器以及所有AFL++的变异器。

- `fuzz_count`（可选）：

    当一个队列条目被选中进行模糊测试时，afl-fuzz会基于几个因素选择使用此输入的模糊测试尝试次数。然而，如果自定义变异器想要设置它针对特定队列条目被调用的次数，使用这个函数。如果没有使用`AFL_CUSTOM_MUTATOR_ONLY`，这个函数最有用。

- `splice_optout`（可选）：

    如果存在这个函数，就不会将任何拼接目标传递给`fuzz`函数。如果自定义模糊函数不需要拼接数据，这可以节省时间。此函数从不被调用，只需要存在以激活。

- `fuzz`（可选）：

    此方法对给定输入执行自定义变异。add_buf是另一个队列项的内容，可以用于拼接 - 或任何其他用途 - 也可以忽略。如果你不使用这些额外数据，则定义`splice_optout`（见上文）。此函数是可选的。返回长度为0是有效的，被解释为跳过这一次变异结果。对于非Python：返回的输出缓冲区由**你**管理内存！

- `describe`（可选）：

    调用此函数时，它应描述由最后一次变异生成的当前测试用例。例如，在发生崩溃后，这将被调用来命名写入的测试用例文件。使用它可以帮助重现崩溃的变异。

- `havoc_mutation` 和 `havoc_mutation_probability`（可选）：

    `havoc_mutation`对给定输入执行单一自定义变异。这种变异与havoc中的其他变异堆叠。另一个方法，`havoc_mutation_probability`，返回在havoc中调用`havoc_mutation`的概率。默认情况下，它是6%。

- `post_process`（可选）：

    在某些情况下，从自定义变异器返回的变异数据的格式不适合直接执行目标输入。例如，使用libprotobuf-mutator时，返回的数据是符合给定语法的protobuf格式。为了执行目标，必须将protobuf数据转换为目标期望的纯文本格式。在这种情况下，用户可以定义`post_process`函数。然后，此函数将数据转换为执行目标之前API期望的格式。

    这可以返回任何实现了缓冲协议并支持PyBUF_SIMPLE的python对象。这些包括bytes、bytearray等。

    你可以决定在post_process变异器中不向目标发送变异数据，例如，如果它太短、太损坏等。如果是这样，返回一个NULL缓冲区和零长度（或在Python中返回一个0长度字符串）。

    注意：不要在这个函数中对数据进行任何随机更改！

    性能对于C/C++：如果可能的话，请就地进行更改（所以直接修改`*data`，并将其返回为`*outbuf = data`）。

- `fuzz_send`（可选）：

    如果你想自己发送数据给目标，例如通过IPC，可以使用这个方法。这替代了一些utils/afl_proxy的用途，但要求你用afl-fuzz启动目标。
    示例：[custom_mutators/examples/custom_send.c](../custom_mutators/examples/custom_send.c)

- `queue_new_entry`（可选）：

    在队列中添加新测试用例后调用此方法。如果文件内容发生了变化，返回True，否则返回False。

- `introspection`（可选）：

    如果编译时带有INTROSPECTION，在发现新的队列条目、崩溃或超时时调用此方法。然后自定义变异器可以返回一个字符串（const char *），报告所使用的确切变异。

- `deinit`（在Python中可选）：

    被调用的最后一个方法，用于反初始化状态。

注意，接下来的部分还描述了三个用于裁剪的函数。
### Trimming Support

The generic trimming routines implemented in AFL++ can easily destroy the
structure of complex formats, possibly leading to a point where you have a lot
of test cases in the queue that your Python module cannot process anymore but
your target application still accepts. This is especially the case when your
target can process a part of the input (causing coverage) and then errors out on
the remaining input.

In such cases, it makes sense to implement a custom trimming routine. The API
consists of multiple methods because after each trimming step, we have to go
back into the C code to check if the coverage bitmap is still the same for the
trimmed input. Here's a quick API description:

- `init_trim` (optional):

    This method is called at the start of each trimming operation and receives
    the initial buffer. It should return the amount of iteration steps possible
    on this input (e.g., if your input has n elements and you want to remove
    them one by one, return n, if you do a binary search, return log(n), and so
    on).

    If your trimming algorithm doesn't allow to determine the amount of
    (remaining) steps easily (esp. while running), then you can alternatively
    return 1 here and always return 0 in `post_trim` until you are finished and
    no steps remain. In that case, returning 1 in `post_trim` will end the
    trimming routine. The whole current index/max iterations stuff is only used
    to show progress.

- `trim` (optional)

    This method is called for each trimming operation. It doesn't have any
    arguments because there is already the initial buffer from `init_trim` and
    we can memorize the current state in the data variables. This can also save
    reparsing steps for each iteration. It should return the trimmed input
    buffer.

- `post_trim` (optional)

    This method is called after each trim operation to inform you if your
    trimming step was successful or not (in terms of coverage). If you receive a
    failure here, you should reset your input to the last known good state. In
    any case, this method must return the next trim iteration index (from 0 to
    the maximum amount of steps you returned in `init_trim`).

Omitting any of three trimming methods will cause the trimming to be disabled
and trigger a fallback to the built-in default trimming routine.

AFL++中实现的通用裁剪程序很容易破坏复杂格式的结构，可能会导致一个问题，即队列中有大量测试用例，您的Python模块无法再处理，但您的目标应用程序仍然接受。特别是当您的目标可以处理输入的一部分（引起覆盖）然后在剩余输入上出错时。

在这种情况下，实现一个自定义裁剪程序是有意义的。API由多个方法组成，因为在每个裁剪步骤之后，我们必须回到C代码中检查裁剪后的输入是否仍然保持相同的覆盖率位图。这里是一个快速的API描述：

- `init_trim`（可选）：

    每次裁剪操作开始时调用此方法，并接收初始缓冲区。它应返回此输入可能的迭代步骤数量（例如，如果您的输入有n个元素，您想逐个移除它们，返回n，如果您执行二进制搜索，返回log(n)等等）。

    如果您的裁剪算法不允许轻易确定（剩余的）步骤数量（特别是在运行时），那么您可以选择在这里返回1，并且在`post_trim`中总是返回0，直到您完成并且没有剩余步骤。在这种情况下，`post_trim`中返回1将结束裁剪程序。整个当前索引/最大迭代次数的东西只是用来显示进度。

- `trim`（可选）

    每次裁剪操作时调用此方法。它没有任何参数，因为已经有了来自`init_trim`的初始缓冲区，我们可以在数据变量中记住当前状态。这也可以节省每次迭代的重新解析步骤。它应返回裁剪后的输入缓冲区。

- `post_trim`（可选）

    每次裁剪操作后调用此方法，以通知您裁剪步骤是否成功（就覆盖率而言）。如果在这里收到失败，您应该将输入重置为最后已知的良好状态。无论如何，此方法必须返回下一个裁剪迭代索引（从0到您在`init_trim`中返回的最大步骤数量）。

省略这三种裁剪方法中的任何一种都将导致裁剪被禁用，并触发回退到内置的默认裁剪程序。
### Environment Variables

Optionally, the following environment variables are supported:

- `AFL_CUSTOM_MUTATOR_ONLY`

    Disable all other mutation stages. This can prevent broken test cases (those
    that your Python module can't work with anymore) to fill up your queue. Best
    combined with a custom trimming routine (see below) because trimming can
    cause the same test breakage like havoc and splice.

- `AFL_PYTHON_ONLY`

    Deprecated and removed, use `AFL_CUSTOM_MUTATOR_ONLY` instead.

- `AFL_DEBUG`

    When combined with `AFL_NO_UI`, this causes the C trimming code to emit
    additional messages about the performance and actions of your custom
    trimmer. Use this to see if it works :)

可选地，支持以下环境变量：

- `AFL_CUSTOM_MUTATOR_ONLY`

    禁用所有其他变异阶段。这可以防止破损的测试用例（那些您的Python模块无法再处理的用例）填满您的队列。最好与自定义裁剪程序（见下文）结合使用，因为裁剪可能会导致和havoc及splice一样的测试破坏。

- `AFL_PYTHON_ONLY`

    已弃用并移除，改用`AFL_CUSTOM_MUTATOR_ONLY`。

- `AFL_DEBUG`

    当与`AFL_NO_UI`结合使用时，这会导致C裁剪代码发出有关您的自定义裁剪器的性能和行为的额外消息。使用它来查看它是否工作 :)
## 3) Usage

### Prerequisite

For Python mutators, the python 3 or 2 development package is required. On
Debian/Ubuntu/Kali it can be installed like this:

```bash
sudo apt install python3-dev
# or
sudo apt install python-dev
```

Then, AFL++ can be compiled with Python support. The AFL++ Makefile detects
Python3 through `python-config`/`python3-config` if it is in the PATH and
compiles `afl-fuzz` with the feature if available.

Note: for some distributions, you might also need the package `python[3]-apt`.
In case your setup is different, set the necessary variables like this:
`PYTHON_INCLUDE=/path/to/python/include LDFLAGS=-L/path/to/python/lib make`.

先决条件

对于Python变异器，需要Python 3或2的开发包。在Debian/Ubuntu/Kali上，可以这样安装：

```bash
sudo apt install python3-dev
# 或
sudo apt install python-dev
```

然后，可以编译支持Python的AFL++。如果`python-config`/`python3-config`在PATH中，AFL++的Makefile会通过它检测Python3，并在可用时编译具有该功能的`afl-fuzz`。

注意：对于某些发行版，您可能还需要`python[3]-apt`包。如果您的设置不同，请像这样设置必要的变量：`PYTHON_INCLUDE=/path/to/python/include LDFLAGS=-L/path/to/python/lib make`。
### Helpers

For C/C++ custom mutators you get a pointer to `afl_state_t *afl` in the
`afl_custom_init()` which contains all information that you need.
Note that if you access it, you need to recompile your custom mutator if
you update AFL++ because the structure might have changed!

For mutators written in Python, Rust, GO, etc. there are a few environment
variables set to help you to get started:

`AFL_CUSTOM_INFO_PROGRAM` - the program name of the target that is executed.
If your custom mutator is used with modes like Qemu (`-Q`), this will still
contain the target program, not afl-qemu-trace.

`AFL_CUSTOM_INFO_PROGRAM_INPUT` - if the `-f` parameter is used with afl-fuzz
then this value is found in this environment variable.

`AFL_CUSTOM_INFO_PROGRAM_ARGV` - this contains the parameters given to the
target program and still has the `@@` identifier in there.

Note: If `AFL_CUSTOM_INFO_PROGRAM_INPUT` is empty and `AFL_CUSTOM_INFO_PROGRAM_ARGV`
is either empty or does not contain `@@` then the target gets the input via
`stdin`.

`AFL_CUSTOM_INFO_OUT` - This is the output directory for this fuzzer instance,
so if `afl-fuzz` was called with `-o out -S foobar`, then this will be set to
`out/foobar`.

对于C/C++自定义变异器，你在`afl_custom_init()`中获得一个指向`afl_state_t *afl`的指针，其中包含你所需要的所有信息。请注意，如果你访问它，需要在更新AFL++时重新编译你的自定义变异器，因为结构可能已经发生了变化！

对于用Python、Rust、GO等编写的变异器，有一些环境变量可以帮助你入门：

`AFL_CUSTOM_INFO_PROGRAM` - 执行的目标程序的程序名。如果你的自定义变异器与诸如Qemu（`-Q`）之类的模式一起使用，这仍将包含目标程序，而不是afl-qemu-trace。

`AFL_CUSTOM_INFO_PROGRAM_INPUT` - 如果使用`afl-fuzz`的`-f`参数，则此值可在此环境变量中找到。

`AFL_CUSTOM_INFO_PROGRAM_ARGV` - 这包含传递给目标程序的参数，并且仍然包含`@@`标识符。

注意：如果`AFL_CUSTOM_INFO_PROGRAM_INPUT`为空，而`AFL_CUSTOM_INFO_PROGRAM_ARGV`为空或不包含`@@`，则目标通过`stdin`接收输入。

`AFL_CUSTOM_INFO_OUT` - 这是此fuzzer实例的输出目录，因此如果使用`-o out -S foobar`调用`afl-fuzz`，则它将设置为`out/foobar`。
### Custom Mutator Preparation

For C/C++ mutators, the source code must be compiled as a shared object:

```bash
gcc -shared -Wall -O3 example.c -o example.so
```

Note that if you specify multiple custom mutators, the corresponding functions
will be called in the order in which they are specified. E.g., the first
`post_process` function of `example_first.so` will be called and then that of
`example_second.so`.

自定变异器准备
对于C/C++变异器，源代码必须编译为共享对象：

```bash
gcc -shared -Wall -O3 example.c -o example.so
```

请注意，如果指定了多个自定义变异器，相应的函数将按照指定的顺序调用。例如，将首先调用`example_first.so`的第一个`post_process`函数，然后调用`example_second.so`的。
### Run
运行

C/C++

```bash
export AFL_CUSTOM_MUTATOR_LIBRARY="/full/path/to/example_first.so;/full/path/to/example_second.so"
afl-fuzz /path/to/program
```

Python

```bash
export PYTHONPATH=`dirname /full/path/to/example.py`
export AFL_PYTHON_MODULE=example
afl-fuzz /path/to/program
```

## 4) Example
示例

See [example.c](../custom_mutators/examples/example.c) and
[example.py](../custom_mutators/examples/example.py).

## 5) Other Resources

- AFL libprotobuf mutator
    - [bruce30262/libprotobuf-mutator_fuzzing_learning](https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator)
    - [thebabush/afl-libprotobuf-mutator](https://github.com/thebabush/afl-libprotobuf-mutator)
- [XML Fuzzing@NullCon 2017](https://www.agarri.fr/docs/XML_Fuzzing-NullCon2017-PUBLIC.pdf)
    - [A bug detected by AFL + XML-aware mutators](https://bugs.chromium.org/p/chromium/issues/detail?id=930663)
