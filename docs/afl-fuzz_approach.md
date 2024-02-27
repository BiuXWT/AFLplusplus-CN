# The afl-fuzz approach
fuzz-方法

AFL++ is a brute-force fuzzer coupled with an exceedingly simple but rock-solid
instrumentation-guided genetic algorithm. It uses a modified form of edge
coverage to effortlessly pick up subtle, local-scale changes to program control
flow.
AFL++ 是一个暴力破解的模糊器，配合一个极其简单但坚如磐石的插桩引导的遗传算法。它使用一种修改过的边缘覆盖形式，能够轻松捕获到程序控制流的微妙的局部规模变化。

Note: If you are interested in a more current up-to-date deep dive how AFL++
works then we commend this blog post:
[https://blog.ritsec.club/posts/afl-under-hood/](https://blog.ritsec.club/posts/afl-under-hood/)
注意:如果您对afl++的最新深入了解感兴趣
那么我们推荐这篇博客文章:[https://blog.ritsec.club/posts/afl-under-hood/](https://blog.ritsec.club/posts/afl-under-hood/)


Simplifying a bit, the overall algorithm can be summed up as:
简化一下，整个算法可以总结为：

1) Load user-supplied initial test cases into the queue.
将用户提供的初始测试用例加载到队列中。

2) Take the next input file from the queue.
从队列中取出下一个输入文件。

3) Attempt to trim the test case to the smallest size that doesn't alter the
   measured behavior of the program.
尝试将测试用例裁剪到不改变程序测量行为的最小大小。

4) Repeatedly mutate the file using a balanced and well-researched variety of
   traditional fuzzing strategies.
使用平衡且研究充分的各种传统模糊策略，反复对文件进行突变。

5) If any of the generated mutations resulted in a new state transition recorded
   by the instrumentation, add mutated output as a new entry in the queue.
如果任何生成的突变导致插桩记录的新状态转换，将突变输出添加为队列中的新条目。

6) Go to 2.

The discovered test cases are also periodically culled to eliminate ones that
have been obsoleted by newer, higher-coverage finds; and undergo several other
instrumentation-driven effort minimization steps.
发现的测试用例也会定期被剔除，以消除那些已经被新的、覆盖率更高的发现所取代的用例；并且还会经历几个其他的由插桩驱动的努力最小化步骤。

As a side result of the fuzzing process, the tool creates a small,
self-contained corpus of interesting test cases. These are extremely useful for
seeding other, labor- or resource-intensive testing regimes - for example, for
stress-testing browsers, office applications, graphics suites, or closed-source
tools.
作为模糊处理过程的一个副产品，该工具会创建一个小型的、自包含的有趣测试用例语料库。这些对于为其他劳动或资源密集型的测试制度提供种子非常有用 - 例如，用于压力测试浏览器、办公应用、图形套件或闭源工具。

The fuzzer is thoroughly tested to deliver out-of-the-box performance far
superior to blind fuzzing or coverage-only tools.
这个模糊器经过了彻底的测试，其开箱即用的性能远超于盲目模糊或仅关注覆盖率的工具。

## Understanding the status screen

This section provides an overview of the status screen - plus tips for
troubleshooting any warnings and red text shown in the UI.
这一部分将提供状态屏幕的概述，以及解决用户界面中显示的任何警告和红色文本的提示。

For the general instruction manual, see [README.md](README.md).
通用的手册参照[README.md](README.md).

### A note about colors

The status screen and error messages use colors to keep things readable and
attract your attention to the most important details. For example, red almost
always means "consult this doc" :-)
状态屏幕和错误消息使用颜色来保持内容的可读性，并吸引您注意最重要的细节。例如，红色几乎总是意味着“请查阅这个文档” :-)

Unfortunately, the UI will only render correctly if your terminal is using
traditional un*x palette (white text on black background) or something close to
that.
不幸的是，只有当您的终端使用传统的 un\*x 调色板（白色文本在黑色背景上）或者接近这样的设置时，用户界面才能正确地呈现。如果您的终端设置与此不同，可能会影响到界面的正确显示

If you are using inverse video, you may want to change your settings, say:
如果你正在使用反转视频，你可能想要改变你的设置，比如说：

- For GNOME Terminal, go to `Edit > Profile` preferences, select the "colors"
  tab, and from the list of built-in schemes, choose "white on black".
- 对于 GNOME 终端，转到 `Edit > Profile` 首选项，选择 "colors" 标签页，在内置方案列表中选择 "white on black"。
- For the MacOS X Terminal app, open a new window using the "Pro" scheme via the
  `Shell > New Window` menu (or make "Pro" your default).
- 对于 MacOS X 的 Terminal 应用，通过 `Shell > New Window` 菜单使用 "Pro" 方案打开一个新窗口（或者将 "Pro" 设为默认）。

Alternatively, if you really like your current colors, you can edit config.h to
comment out USE_COLORS, then do `make clean all`.

We are not aware of any other simple way to make this work without causing other
side effects - sorry about that.

With that out of the way, let's talk about what's actually on the screen...

### The status bar
状态

```
american fuzzy lop ++3.01a (default) [fast] {0}
```

The top line shows you which mode afl-fuzz is running in (normal: "american
fuzzy lop", crash exploration mode: "peruvian rabbit mode") and the version of
AFL++. Next to the version is the banner, which, if not set with -T by hand,
will either show the binary name being fuzzed, or the -M/-S main/secondary name
for parallel fuzzing. Second to last is the power schedule mode being run
(default: fast). Finally, the last item is the CPU id.
上面的一行显示了 `afl-fuzz` 运行的模式(普通:"american fuzzy lop"，crash查找模式:"peruvian rabbit mode")和afl++的版本。紧挨着版本号的是横幅，如果没有手动设置-T，就会显示要进行模糊测试的二进制程序名称，或者显示并行模糊测试的-M/-S主/次程序名称。倒数第二是正在运行的性能调度模式(默认:fast)。最后一项是CPU id。

### Process timing
运行时间

```
  +----------------------------------------------------+
  |        run time : 0 days, 8 hrs, 32 min, 43 sec    |
  |   last new find : 0 days, 0 hrs, 6 min, 40 sec     |
  | last uniq crash : none seen yet                    |
  |  last uniq hang : 0 days, 1 hrs, 24 min, 32 sec    |
  +----------------------------------------------------+
```

This section is fairly self-explanatory: it tells you how long the fuzzer has
been running and how much time has elapsed since its most recent finds. This is
broken down into "paths" (a shorthand for test cases that trigger new execution
patterns), crashes, and hangs.
这部分的内容不言自明:它会告诉你模糊器已经运行了多长时间，以及从最近一次发现到现在已经过去了多长时间。这被分解为“路径”(触发新执行模式的测试用例的简写)、崩溃和挂起。

When it comes to timing: there is no hard rule, but most fuzzing jobs should be
expected to run for days or weeks; in fact, for a moderately complex project,
the first pass will probably take a day or so. Every now and then, some jobs
will be allowed to run for months.
在测试时间方面，没有硬性规定，但大多数模糊测试作业都应该运行数天或数周;事实上，对于一个适度复杂的项目，第一步可能需要一天左右的时间。并且应该时不时的让一些测试运行数月

There's one important thing to watch out for: if the tool is not finding new
paths within several minutes of starting, you're probably not invoking the
target binary correctly and it never gets to parse the input files that are
thrown at it; other possible explanations are that the default memory limit
(`-m`) is too restrictive and the program exits after failing to allocate a
buffer very early on; or that the input files are patently invalid and always
fail a basic header check.
有一件重要的事情要注意:如果该工具不能在启动几分钟内找到新路径，则可能没有正确调用目标二进制文件，并且它永远无法解析扔给它的输入文件;其他可能的解释是，默认的内存限制(' -m ')限制太大，程序在很早就分配缓冲区失败后退出;或者输入文件明显无效，基本的头文件检查总是失败。

If there are no new paths showing up for a while, you will eventually see a big
red warning in this section, too :-)
如果暂时没有新路径出现，您最终将在该部分中看到一个红色的大警告😃

### Overall results
总体结果

```
  +-----------------------+
  |  cycles done : 0      |
  |  total paths : 2095   |
  | uniq crashes : 0      |
  |   uniq hangs : 19     |
  +-----------------------+
```

The first field in this section gives you the count of queue passes done so far
- that is, the number of times the fuzzer went over all the interesting test
  cases discovered so far, fuzzed them, and looped back to the very beginning.
  Every fuzzing session should be allowed to complete at least one cycle; and
  ideally, should run much longer than that.

As noted earlier, the first pass can take a day or longer, so sit back and
relax.
这部分的第一个字段给出了到目前为止完成的队列传递次数
 - 也就是说，模糊测试器对到目前为止发现的所有感兴趣的测试用例进行了多少次的复查，对它们进行了模糊处理，
 并回到了最开始的地方。每个模糊测试会话都应该至少完成一次循环；理想情况下，应该运行的时间要长得多。

如前所述，第一次传递可能需要一天或更长时间，所以坐下来放松一下。

To help make the call on when to hit `Ctrl-C`, the cycle counter is color-coded.
It is shown in magenta during the first pass, progresses to yellow if new finds
are still being made in subsequent rounds, then blue when that ends - and
finally, turns green after the fuzzer hasn't been seeing any action for a longer
while.
为了帮助你决定何时按下 `Ctrl-C`，循环计数器是用颜色编码的。在第一轮中，它显示为洋红色，
如果在后续轮次中仍然发现新的内容，它会变为黄色，然后在那结束时变为蓝色 - 最后，在模糊测试器长时间没有任何动作后，它会变为绿色。

The remaining fields in this part of the screen should be pretty obvious:
there's the number of test cases ("paths") discovered so far, and the number of
unique faults. The test cases, crashes, and hangs can be explored in real-time
by browsing the output directory, see
[#interpreting-output](#interpreting-output).

这个屏幕部分中其余的字段应该相当明显：迄今为止发现的测试案例（“路径”）数量和特有错误数量。可以通过浏览输出目录实时浏览测试案例、崩溃和挂起情况，请参见 [#interpreting-output](#interpreting-output)。
### Cycle progress

```
  +-------------------------------------+
  |  now processing : 1296 (61.86%)     |
  | paths timed out : 0 (0.00%)         |
  +-------------------------------------+
```

This box tells you how far along the fuzzer is with the current queue cycle: it
shows the ID of the test case it is currently working on, plus the number of
inputs it decided to ditch because they were persistently timing out.
这个框告诉你模糊测试器在当前队列周期中的进度：它显示了它当前正在处理的测试用例的ID，以及它决定放弃的输入数量，因为它们一直在超时。

The "*" suffix sometimes shown in the first line means that the currently
processed path is not "favored" (a property discussed later on).

第一行有时显示的"*"后缀意味着当前处理的路径不是"优选的"（稍后将讨论的属性）。
### Map coverage

```
  +--------------------------------------+
  |    map density : 10.15% / 29.07%     |
  | count coverage : 4.03 bits/tuple     |
  +--------------------------------------+
```

The section provides some trivia about the coverage observed by the
instrumentation embedded in the target binary.

The first line in the box tells you how many branch tuples already were hit, in
proportion to how much the bitmap can hold. The number on the left describes the
current input; the one on the right is the value for the entire input corpus.

Be wary of extremes:

- Absolute numbers below 200 or so suggest one of three things: that the program
  is extremely simple; that it is not instrumented properly (e.g., due to being
  linked against a non-instrumented copy of the target library); or that it is
  bailing out prematurely on your input test cases. The fuzzer will try to mark
  this in pink, just to make you aware.
- Percentages over 70% may very rarely happen with very complex programs that
  make heavy use of template-generated code. Because high bitmap density makes
  it harder for the fuzzer to reliably discern new program states, we recommend
  recompiling the binary with `AFL_INST_RATIO=10` or so and trying again (see
  [env_variables.md](env_variables.md)). The fuzzer will flag high percentages
  in red. Chances are, you will never see that unless you're fuzzing extremely
  hairy software (say, v8, perl, ffmpeg).

The other line deals with the variability in tuple hit counts seen in the
binary. In essence, if every taken branch is always taken a fixed number of
times for all the inputs that were tried, this will read `1.00`. As we manage to
trigger other hit counts for every branch, the needle will start to move toward
`8.00` (every bit in the 8-bit map hit), but will probably never reach that
extreme.

Together, the values can be useful for comparing the coverage of several
different fuzzing jobs that rely on the same instrumented binary.

### 位图覆盖率

```
  +--------------------------------------+
  |    map density : 10.15% / 29.07%     |
  | count coverage : 4.03 bits/tuple     |
  +--------------------------------------+
```

这一部分提供了一些关于目标二进制文件中嵌入的插桩观察到的覆盖率的小知识。

框中的第一行告诉你已经被命中的分支元组有多少，与位图可以容纳的比例。左边的数字描述的是当前的输入；右边的是整个输入语料库的值。

要警惕极端情况：

- 绝对数字低于200左右可能表明三种情况之一：程序极其简单；没有正确地进行插桩（例如，由于链接到未进行插桩的目标库的副本）；或者它在你的输入测试用例上过早地退出。模糊测试器会尝试用粉红色标记这一点，以引起你的注意。
- 百分比超过70%可能在使用模板生成代码的非常复杂的程序中非常罕见。因为高位图密度使得模糊测试器难以可靠地识别新的程序状态，我们建议用`AFL_INST_RATIO=10`左右重新编译二进制文件并再试一次（参见[env_variables.md](env_variables.md)）。模糊测试器会用红色标记高百分比。除非你正在对极其复杂的软件（比如，v8，perl，ffmpeg）进行模糊测试，否则你可能永远不会看到这一点。

另一行处理的是在二进制文件中看到的元组命中计数的可变性。本质上，如果每个被采取的分支对于所有尝试过的输入总是被采取固定的次数，这将读取`1.00`。当我们设法触发每个分支的其他命中计数时，指针将开始向`8.00`移动（8位图中的每一位都被击中），但可能永远不会达到那个极端。

总的来说，这些值可以用于比较依赖同一插桩二进制文件的几个不同模糊测试工作的覆盖率。
### Stage progress

```
  +-------------------------------------+
  |  now trying : interest 32/8         |
  | stage execs : 3996/34.4k (11.62%)   |
  | total execs : 27.4M                 |
  |  exec speed : 891.7/sec             |
  +-------------------------------------+
```

This part gives you an in-depth peek at what the fuzzer is actually doing right
now. It tells you about the current stage, which can be any of:

- calibration - a pre-fuzzing stage where the execution path is examined to
  detect anomalies, establish baseline execution speed, and so on. Executed very
  briefly whenever a new find is being made.
- trim L/S - another pre-fuzzing stage where the test case is trimmed to the
  shortest form that still produces the same execution path. The length (L) and
  stepover (S) are chosen in general relationship to file size.
- bitflip L/S - deterministic bit flips. There are L bits toggled at any given
  time, walking the input file with S-bit increments. The current L/S variants
  are: `1/1`, `2/1`, `4/1`, `8/8`, `16/8`, `32/8`.
- arith L/8 - deterministic arithmetics. The fuzzer tries to subtract or add
  small integers to 8-, 16-, and 32-bit values. The stepover is always 8 bits.
- interest L/8 - deterministic value overwrite. The fuzzer has a list of known
  "interesting" 8-, 16-, and 32-bit values to try. The stepover is 8 bits.
- extras - deterministic injection of dictionary terms. This can be shown as
  "user" or "auto", depending on whether the fuzzer is using a user-supplied
  dictionary (`-x`) or an auto-created one. You will also see "over" or
  "insert", depending on whether the dictionary words overwrite existing data or
  are inserted by offsetting the remaining data to accommodate their length.
- havoc - a sort-of-fixed-length cycle with stacked random tweaks. The
  operations attempted during this stage include bit flips, overwrites with
  random and "interesting" integers, block deletion, block duplication, plus
  assorted dictionary-related operations (if a dictionary is supplied in the
  first place).
- splice - a last-resort strategy that kicks in after the first full queue cycle
  with no new paths. It is equivalent to 'havoc', except that it first splices
  together two random inputs from the queue at some arbitrarily selected
  midpoint.
- sync - a stage used only when `-M` or `-S` is set (see
  [fuzzing_in_depth.md:3c) Using multiple cores](fuzzing_in_depth.md#c-using-multiple-cores)).
  No real fuzzing is involved, but the tool scans the output from other fuzzers
  and imports test cases as necessary. The first time this is done, it may take
  several minutes or so.

The remaining fields should be fairly self-evident: there's the exec count
progress indicator for the current stage, a global exec counter, and a benchmark
for the current program execution speed. This may fluctuate from one test case
to another, but the benchmark should be ideally over 500 execs/sec most of the
time - and if it stays below 100, the job will probably take very long.

The fuzzer will explicitly warn you about slow targets, too. If this happens,
see the [best_practices.md#improving-speed](best_practices.md#improving-speed)
for ideas on how to speed things up.

### 阶段进度

```
  +-------------------------------------+
  |  现在尝试 : interest 32/8           |
  | 阶段执行 : 3996/34.4k (11.62%)      |
  | 总执行 : 27.4M                      |
  |  执行速度 : 891.7/sec               |
  +-------------------------------------+
```

这部分让你深入了解模糊器现在实际上正在做什么。它告诉你当前的阶段，可以是以下任何一个：

- 校准 - 一种预模糊阶段，其中检查执行路径以检测异常，建立基线执行速度等。每次发现新的内容时都会非常简短地执行。
- trim L/S - 另一种预模糊阶段，其中将测试用例修剪为仍然产生相同执行路径的最短形式。长度（L）和步进（S）通常与文件大小有关。
- bitflip L/S - 确定性位翻转。在任何给定时间，都有 L 位在切换，以 S 位增量遍历输入文件。当前的 L/S 变体是：`1/1`，`2/1`，`4/1`，`8/8`，`16/8`，`32/8`。
- arith L/8 - 确定性算术。模糊器试图从 8-，16- 和 32-位值中减去或添加小整数。步进总是 8 位。
- interest L/8 - 确定性值覆盖。模糊器有一个已知的 "有趣" 的 8-，16- 和 32-位值的列表来尝试。步进是 8 位。
- extras - 确定性注入字典项。这可以显示为 "user" 或 "auto"，取决于模糊器是使用用户提供的字典（`-x`）还是自动创建的字典。你还会看到 "over" 或 "insert"，取决于字典词是否覆盖现有数据或通过偏移剩余数据以适应其长度。
- havoc - 一种带有堆叠随机调整的固定长度循环。在此阶段尝试的操作包括位翻转，用随机和 "有趣" 的整数覆盖，块删除，块复制，以及各种与字典相关的操作（如果首先提供了字典）。
- splice - 在没有新路径的第一个完整队列周期后启动的最后手段策略。它等同于 'havoc'，除了它首先在某个任意选择的中点将队列中的两个随机输入拼接在一起。
- sync - 仅在设置 `-M` 或 `-S` 时使用的阶段（参见 [fuzzing_in_depth.md:3c) 使用多核](fuzzing_in_depth.md#c-using-multiple-cores)）。没有涉及真正的模糊测试，但是该工具扫描其他模糊器的输出并根据需要导入测试用例。第一次这样做时，可能需要几分钟左右。

其余字段应该相当明显：有当前阶段的执行计数进度指示器，全局执行计数器，以及当前程序执行速度的基准。这可能会从一个测试用例到另一个测试用例波动，但是大部分时间，基准 ideally 应该超过 500 execs/sec - 如果它始终低于 100，那么工作可能会花费很长时间。

模糊器也会明确警告你关于慢目标。如果发生这种情况，参见 [best_practices.md#improving-speed](best_practices.md#improving-speed) 以获取如何加快速度的想法。
### Findings in depth

```
  +--------------------------------------+
  | favored paths : 879 (41.96%)         |
  |  new edges on : 423 (20.19%)         |
  | total crashes : 0 (0 unique)         |
  |  total tmouts : 24 (19 unique)       |
  +--------------------------------------+
```

This gives you several metrics that are of interest mostly to complete nerds.
The section includes the number of paths that the fuzzer likes the most based on
a minimization algorithm baked into the code (these will get considerably more
air time), and the number of test cases that actually resulted in better edge
coverage (versus just pushing the branch hit counters up). There are also
additional, more detailed counters for crashes and timeouts.

Note that the timeout counter is somewhat different from the hang counter; this
one includes all test cases that exceeded the timeout, even if they did not
exceed it by a margin sufficient to be classified as hangs.

### 发现的深度

```
  +--------------------------------------+
  | 偏爱路径 : 879 (41.96%)              |
  |  新边缘数 : 423 (20.19%)             |
  | 总崩溃数 : 0 (0 个唯一的)            |
  |  总超时数 : 24 (19 个唯一的)         |
  +--------------------------------------+
```

这部分给你提供了专业人士感兴趣的数据。这一部分包括模糊器感兴趣的路径数量，这是基于代码中内置的最小化算法（这些将获得更多的空中时间），以及实际上导致更好的边缘覆盖率的测试用例数量（而不仅仅是推动分支命中计数器上升）。还有关于崩溃和超时的更详细的计数器。

注意，超时计数器与挂起计数器有些不同；这个包括所有超过超时的测试用例，即使它们没有超过足够的边际被分类为挂起。
### Fuzzing strategy yields

```
  +-----------------------------------------------------+
  |   bit flips : 57/289k, 18/289k, 18/288k             |
  |  byte flips : 0/36.2k, 4/35.7k, 7/34.6k             |
  | arithmetics : 53/2.54M, 0/537k, 0/55.2k             |
  |  known ints : 8/322k, 12/1.32M, 10/1.70M            |
  |  dictionary : 9/52k, 1/53k, 1/24k                   |
  |havoc/splice : 1903/20.0M, 0/0                       |
  |py/custom/rq : unused, 53/2.54M, unused              |
  |    trim/eff : 20.31%/9201, 17.05%                   |
  +-----------------------------------------------------+
```

This is just another nerd-targeted section keeping track of how many paths were
netted, in proportion to the number of execs attempted, for each of the fuzzing
strategies discussed earlier on. This serves to convincingly validate
assumptions about the usefulness of the various approaches taken by afl-fuzz.

The trim strategy stats in this section are a bit different than the rest. The
first number in this line shows the ratio of bytes removed from the input files;
the second one corresponds to the number of execs needed to achieve this goal.
Finally, the third number shows the proportion of bytes that, although not
possible to remove, were deemed to have no effect and were excluded from some of
the more expensive deterministic fuzzing steps.

Note that when deterministic mutation mode is off (which is the default because
it is not very efficient) the first five lines display "disabled (default,
enable with -D)".

Only what is activated will have counter shown.

### 模糊策略

```
  +-----------------------------------------------------+
  |   位翻转 : 57/289k, 18/289k, 18/288k                |
  |  字节翻转 : 0/36.2k, 4/35.7k, 7/34.6k               |
  | 算术运算 : 53/2.54M, 0/537k, 0/55.2k                |
  |  已知整数 : 8/322k, 12/1.32M, 10/1.70M              |
  |  字典项 : 9/52k, 1/53k, 1/24k                       |
  |havoc/splice : 1903/20.0M, 0/0                      |
  |py/custom/rq : 未使用, 53/2.54M, 未使用               |
  |    trim/eff : 20.31%/9201, 17.05%                  |
  +-----------------------------------------------------+
```

这只是另一个针对专业人士的部分，跟踪了每种模糊策略尝试的执行次数与获取的路径数量的比例。这有助于有力地验证关于 afl-fuzz 采取的各种方法的有效性的假设。

这一部分中的 trim 策略统计数据与其余部分略有不同。这一行的第一个数字显示了从输入文件中移除的字节的比例；第二个数字对应于实现这个目标所需的执行次数。最后，第三个数字显示了虽然无法移除，但被认为没有效果并且被排除在一些更昂贵的确定性模糊步骤之外的字节的比例。

注意，当确定性突变模式关闭时（这是默认的，因为它不是很有效），前五行显示 "disabled (default, enable with -D)"。

只有激活的内容才会显示计数器。

### Path geometry

```
  +---------------------+
  |    levels : 5       |
  |   pending : 1570    |
  |  pend fav : 583     |
  | own finds : 0       |
  |  imported : 0       |
  | stability : 100.00% |
  +---------------------+
```

The first field in this section tracks the path depth reached through the guided
fuzzing process. In essence: the initial test cases supplied by the user are
considered "level 1". The test cases that can be derived from that through
traditional fuzzing are considered "level 2"; the ones derived by using these as
inputs to subsequent fuzzing rounds are "level 3"; and so forth. The maximum
depth is therefore a rough proxy for how much value you're getting out of the
instrumentation-guided approach taken by afl-fuzz.

The next field shows you the number of inputs that have not gone through any
fuzzing yet. The same stat is also given for "favored" entries that the fuzzer
really wants to get to in this queue cycle (the non-favored entries may have to
wait a couple of cycles to get their chance).

Next is the number of new paths found during this fuzzing section and imported
from other fuzzer instances when doing parallelized fuzzing; and the extent to
which identical inputs appear to sometimes produce variable behavior in the
tested binary.

That last bit is actually fairly interesting: it measures the consistency of
observed traces. If a program always behaves the same for the same input data,
it will earn a score of 100%. When the value is lower but still shown in purple,
the fuzzing process is unlikely to be negatively affected. If it goes into red,
you may be in trouble, since AFL++ will have difficulty discerning between
meaningful and "phantom" effects of tweaking the input file.

Now, most targets will just get a 100% score, but when you see lower figures,
there are several things to look at:

- The use of uninitialized memory in conjunction with some intrinsic sources of
  entropy in the tested binary. Harmless to AFL, but could be indicative of a
  security bug.
- Attempts to manipulate persistent resources, such as left over temporary files
  or shared memory objects. This is usually harmless, but you may want to
  double-check to make sure the program isn't bailing out prematurely. Running
  out of disk space, SHM handles, or other global resources can trigger this,
  too.
- Hitting some functionality that is actually designed to behave randomly.
  Generally harmless. For example, when fuzzing sqlite, an input like `select
  random();` will trigger a variable execution path.
- Multiple threads executing at once in semi-random order. This is harmless when
  the 'stability' metric stays over 90% or so, but can become an issue if not.
  Here's what to try:
  * Use afl-clang-fast from [instrumentation](../instrumentation/) - it uses a
    thread-local tracking model that is less prone to concurrency issues,
  * See if the target can be compiled or run without threads. Common
    `./configure` options include `--without-threads`, `--disable-pthreads`, or
    `--disable-openmp`.
  * Replace pthreads with GNU Pth (https://www.gnu.org/software/pth/), which
    allows you to use a deterministic scheduler.
- In persistent mode, minor drops in the "stability" metric can be normal,
  because not all the code behaves identically when re-entered; but major dips
  may signify that the code within `__AFL_LOOP()` is not behaving correctly on
  subsequent iterations (e.g., due to incomplete clean-up or reinitialization of
  the state) and that most of the fuzzing effort goes to waste.

The paths where variable behavior is detected are marked with a matching entry
in the `<out_dir>/queue/.state/variable_behavior/` directory, so you can look
them up easily.

以下是你请求的翻译：

### 路径几何

```
  +---------------------+
  |    层级 : 5         |
  |   待处理 : 1570     |
  |  待处理且感兴趣 : 583   |
  | 自我发现 : 0        |
  |  导入 : 0           |
  | 稳定性 : 100.00%    |
  +---------------------+
```

这一部分的第一个字段跟踪了通过引导模糊过程达到的路径深度。本质上：用户提供的初始测试用例被认为是 "层级 1"。可以通过传统模糊从中派生的测试用例被认为是 "层级 2"；通过将这些作为输入用于后续模糊轮次派生的测试用例是 "层级 3"；依此类推。因此，最大深度大致代表了你从 afl-fuzz 采取的引导工具方法中获得的价值。

下一个字段向你显示了尚未经过任何模糊处理的输入数量。这个队列周期中模糊器真正想要到达的 "感兴趣" 条目也给出了相同的统计数据（非感兴趣条目可能需要等待几个周期才有机会）。

接下来是在这个模糊部分期间找到的新路径数量，以及在进行并行模糊时从其他模糊实例导入的数量；以及相同输入有时在被测试的二进制文件中产生可变行为的程度。

最后一点实际上非常有趣：它测量了观察到的跟踪的一致性。如果一个程序对于相同的输入数据总是表现相同，它将获得 100% 的分数。当值较低但仍然显示为紫色时，模糊过程不太可能受到负面影响。如果它变为红色，你可能会遇到麻烦，因为 AFL++ 将很难区分调整输入文件的有意义和 "幻影" 效果。

现在，大多数目标都会得到 100% 的分数，但是当你看到较低的数字时，有几件事要看：

- 在测试的二进制文件中使用未初始化的内存与一些内在的熵源。对 AFL 无害，但可能表明存在安全漏洞。
- 尝试操作持久资源，如剩余的临时文件或共享内存对象。这通常是无害的，但你可能想要仔细检查以确保程序没有过早退出。磁盘空间、SHM 句柄或其他全局资源的耗尽也可能触发这个。
- 触发一些实际上设计为随机行为的功能。通常无害。例如，当模糊 sqlite 时，像 `select random();` 这样的输入将触发可变执行路径。
- 多个线程同时以半随机顺序执行。当 '稳定性' 指标保持在 90% 或更高时，这是无害的，但如果不是，可能会成为问题。这里是你可以尝试的：
  * 使用来自 [instrumentation](../instrumentation/) 的 afl-clang-fast - 它使用一个对并发问题不太敏感的线程局部跟踪模型，
  * 看看目标是否可以在没有线程的情况下编译或运行。常见的 `./configure` 选项包括 `--without-threads`，`--disable-pthreads` 或 `--disable-openmp`。
  * 用 GNU Pth (https://www.gnu.org/software/pth/) 替换 pthreads，这允许你使用一个确定性的调度器。
- 在持久模式中，"稳定性" 指标的微小下降可能是正常的，因为并非所有的代码在重新进入时都表现相同；但是大的下降可能表明 `__AFL_LOOP()` 内的代码在后续迭代中的行为不正确（例如，由于状态的清理或重新初始化不完全）并且大部分的模糊努力都浪费了。

检测到可变行为的路径被标记为与 `<out_dir>/queue/.state/variable_behavior/` 目录中的匹配条目，所以你可以轻松地查找它们。
### CPU load

```
  [cpu: 25%]
```

This tiny widget shows the apparent CPU utilization on the local system. It is
calculated by taking the number of processes in the "runnable" state, and then
comparing it to the number of logical cores on the system.

If the value is shown in green, you are using fewer CPU cores than available on
your system and can probably parallelize to improve performance; for tips on how
to do that, see
[fuzzing_in_depth.md:3c) Using multiple cores](fuzzing_in_depth.md#c-using-multiple-cores).

If the value is shown in red, your CPU is *possibly* oversubscribed, and running
additional fuzzers may not give you any benefits.

Of course, this benchmark is very simplistic; it tells you how many processes
are ready to run, but not how resource-hungry they may be. It also doesn't
distinguish between physical cores, logical cores, and virtualized CPUs; the
performance characteristics of each of these will differ quite a bit.

If you want a more accurate measurement, you can run the `afl-gotcpu` utility
from the command line.

### CPU 负载

```
  [cpu: 25%]
```

这个小部件显示了本地系统上明显的 CPU 利用率。它是通过取 "可运行" 状态的进程数量，然后将其与系统上的逻辑核心数量进行比较来计算的。

如果值显示为绿色，你使用的 CPU 核心数量少于系统上可用的核心数量，你可能可以并行化以提高性能；关于如何做到这一点的提示，参见 [fuzzing_in_depth.md:3c) 使用多核](fuzzing_in_depth.md#c-using-multiple-cores)。

如果值显示为红色，你的 CPU *可能* 超额订阅，运行额外的模糊器可能不会给你带来任何好处。

当然，这个基准测试非常简单；它告诉你有多少进程准备运行，但不告诉你它们可能有多缺资源。它也不区分物理核心、逻辑核心和虚拟化的 CPU；这些每一个的性能特性都会有很大的不同。

如果你想要更准确的测量，你可以在命令行中运行 `afl-gotcpu` 工具。
## Interpreting output

See [#understanding-the-status-screen](#understanding-the-status-screen) for
information on how to interpret the displayed stats and monitor the health of
the process. Be sure to consult this file especially if any UI elements are
highlighted in red.

The fuzzing process will continue until you press Ctrl-C. At a minimum, you want
to allow the fuzzer to at least one queue cycle without any new finds, which may
take anywhere from a couple of hours to a week or so.

There are three subdirectories created within the output directory and updated
in real-time:

- queue/   - test cases for every distinctive execution path, plus all the
             starting files given by the user. This is the synthesized corpus.

             Before using this corpus for any other purposes, you can shrink
             it to a smaller size using the afl-cmin tool. The tool will find
             a smaller subset of files offering equivalent edge coverage.

- crashes/ - unique test cases that cause the tested program to receive a fatal
             signal (e.g., SIGSEGV, SIGILL, SIGABRT). The entries are grouped by
             the received signal.

- hangs/   - unique test cases that cause the tested program to time out. The
             default time limit before something is classified as a hang is the
             larger of 1 second and the value of the -t parameter. The value can
             be fine-tuned by setting AFL_HANG_TMOUT, but this is rarely
             necessary.

Crashes and hangs are considered "unique" if the associated execution paths
involve any state transitions not seen in previously-recorded faults. If a
single bug can be reached in multiple ways, there will be some count inflation
early in the process, but this should quickly taper off.

The file names for crashes and hangs are correlated with the parent,
non-faulting queue entries. This should help with debugging.

## 解释输出

有关如何解释显示的统计信息以及监视进程健康状况的信息，请参阅 [#understanding-the-status-screen](#understanding-the-status-screen)。确保查阅此文件，特别是如果任何 UI 元素以红色突出显示。

模糊测试进程将持续进行，直到按下 Ctrl-C。至少，您应该允许模糊器至少完成一个没有任何新的发现的队列循环，这可能需要从几个小时到一周左右的时间。

在输出目录中创建了三个子目录，并实时更新：

- queue/   - 包括每个独特执行路径的测试案例，以及用户提供的所有起始文件。这是合成的语料库。

             在将此语料库用于其他目的之前，您可以使用 afl-cmin 工具将其缩小到较小的大小。该工具将找到提供等效边缘覆盖的文件的较小子集。

- crashes/ - 导致被测试程序接收致命信号（例如，SIGSEGV、SIGILL、SIGABRT）的唯一测试案例。条目按接收到的信号分组。

- hangs/   - 导致被测试程序超时的唯一测试案例。在被分类为挂起之前的默认时间限制是 1 秒和 -t 参数值中较大的那个。该值可以通过设置 AFL_HANG_TMOUT 进行微调，但这很少是必要的。

如果相关的执行路径涉及以前记录的故障中未见的任何状态转换，则将崩溃和挂起视为“唯一”。如果可以通过多种方式达到单个错误，那么在进程早期可能会存在一些计数膨胀，但这应该迅速减少。

崩溃和挂起的文件名与父项、非故障队列条目相关联。这应有助于调试。
## Visualizing

If you have gnuplot installed, you can also generate some pretty graphs for any
active fuzzing task using afl-plot. For an example of how this looks like, see
[https://lcamtuf.coredump.cx/afl/plot/](https://lcamtuf.coredump.cx/afl/plot/).

You can also manually build and install afl-plot-ui, which is a helper utility
for showing the graphs generated by afl-plot in a graphical window using GTK.
You can build and install it as follows:

```shell
sudo apt install libgtk-3-0 libgtk-3-dev pkg-config
cd utils/plot_ui
make
cd ../../
sudo make install
```

To learn more about remote monitoring and metrics visualization with StatsD, see
[rpc_statsd.md](rpc_statsd.md).

## 可视化

如果已经安装了 gnuplot，您还可以使用 afl-plot 为任何正在进行的模糊测试任务生成一些漂亮的图表。有关演示的示例，请参阅 [https://lcamtuf.coredump.cx/afl/plot/](https://lcamtuf.coredump.cx/afl/plot/)。

您还可以手动构建和安装 afl-plot-ui，这是一个辅助工具，用于在使用 GTK 的图形窗口中显示 afl-plot 生成的图表。您可以按照以下步骤构建和安装：

```shell
sudo apt install libgtk-3-0 libgtk-3-dev pkg-config
cd utils/plot_ui
make
cd ../../
sudo make install
```

要了解有关使用 StatsD 进行远程监控和度量可视化的更多信息，请参阅 [rpc_statsd.md](rpc_statsd.md)。
### Addendum: status and plot files

For unattended operation, some of the key status screen information can be also
found in a machine-readable format in the fuzzer_stats file in the output
directory. This includes:

- `start_time`        - unix time indicating the start time of afl-fuzz
- `last_update`       - unix time corresponding to the last update of this file
- `run_time`          - run time in seconds to the last update of this file
- `fuzzer_pid`        - PID of the fuzzer process
- `cycles_done`       - queue cycles completed so far
- `cycles_wo_finds`   - number of cycles without any new paths found
- `time_wo_finds`     - longest time in seconds no new path was found
- `execs_done`        - number of execve() calls attempted
- `execs_per_sec`     - overall number of execs per second
- `corpus_count`      - total number of entries in the queue
- `corpus_favored`    - number of queue entries that are favored
- `corpus_found`      - number of entries discovered through local fuzzing
- `corpus_imported`   - number of entries imported from other instances
- `max_depth`         - number of levels in the generated data set
- `cur_item`          - currently processed entry number
- `pending_favs`      - number of favored entries still waiting to be fuzzed
- `pending_total`     - number of all entries waiting to be fuzzed
- `corpus_variable`   - number of test cases showing variable behavior
- `stability`         - percentage of bitmap bytes that behave consistently
- `bitmap_cvg`        - percentage of edge coverage found in the map so far
- `saved_crashes`     - number of unique crashes recorded
- `saved_hangs`       - number of unique hangs encountered
- `last_find`         - seconds since the last find was found
- `last_crash`        - seconds since the last crash was found
- `last_hang`         - seconds since the last hang was found
- `execs_since_crash` - execs since the last crash was found
- `exec_timeout`      - the -t command line value
- `slowest_exec_ms`   - real time of the slowest execution in ms
- `peak_rss_mb`       - max rss usage reached during fuzzing in MB
- `edges_found`       - how many edges have been found
- `var_byte_count`    - how many edges are non-deterministic
- `afl_banner`        - banner text (e.g., the target name)
- `afl_version`       - the version of AFL++ used
- `target_mode`       - default, persistent, qemu, unicorn, non-instrumented
- `command_line`      - full command line used for the fuzzing session

Most of these map directly to the UI elements discussed earlier on.

On top of that, you can also find an entry called `plot_data`, containing a
plottable history for most of these fields. If you have gnuplot installed, you
can turn this into a nice progress report with the included `afl-plot` tool.

### 附录：状态和图表文件

对于无人值守操作，一些关键的状态屏幕信息也可以在输出目录中的 fuzzer_stats 文件中以机器可读的格式找到。其中包括：

- `start_time`        - 表示 afl-fuzz 启动时间的 Unix 时间
- `last_update`       - 对应于此文件的最后更新的 Unix 时间
- `run_time`          - 到此文件的最后更新的运行时间（以秒为单位）
- `fuzzer_pid`        - 模糊器进程的 PID
- `cycles_done`       - 到目前为止完成的队列循环数
- `cycles_wo_finds`   - 没有找到任何新路径的循环次数
- `time_wo_finds`     - 在没有找到新路径的情况下的最长时间（以秒为单位）
- `execs_done`        - 尝试的 execve() 调用次数
- `execs_per_sec`     - 每秒的总 execs 数
- `corpus_count`      - 队列中的总条目数
- `corpus_favored`    - 有利队列中的条目数
- `corpus_found`      - 通过本地模糊测试发现的条目数
- `corpus_imported`   - 从其他实例导入的条目数
- `max_depth`         - 生成数据集中的层级数
- `cur_item`          - 当前处理的条目编号
- `pending_favs`      - 仍在等待进行模糊测试的有利条目数
- `pending_total`     - 所有等待进行模糊测试的条目数
- `corpus_variable`   - 显示可变行为的测试用例数
- `stability`         - 行为一致的位图字节的百分比
- `bitmap_cvg`        - 到目前为止在位图中找到的边缘覆盖的百分比
- `saved_crashes`     - 记录的唯一崩溃数
- `saved_hangs`       - 遇到的唯一挂起数
- `last_find`         - 自上次发现以来的秒数
- `last_crash`        - 自上次崩溃以来的秒数
- `last_hang`         - 自上次挂起以来的秒数
- `execs_since_crash` - 自上次崩溃以来的 execs 数
- `exec_timeout`      - -t 命令行值
- `slowest_exec_ms`   - 最慢执行的实时时间（以毫秒为单位）
- `peak_rss_mb`       - 在模糊测试期间达到的最大 RSS 使用量（以 MB 为单位）
- `edges_found`       - 发现了多少边缘
- `var_byte_count`    - 多少边缘是非确定性的
- `afl_banner`        - 横幅文本（例如，目标名称）
- `afl_version`       - 使用的 AFL++ 版本
- `target_mode`       - 默认、持久、qemu、unicorn、非仪器化
- `command_line`      - 用于模糊测试会话的完整命令行

这些大部分直接对应于先前讨论的 UI 元素。

此外，您还可以找到一个名为 `plot_data` 的条目，其中包含大多数这些字段的可绘制历史记录。如果已安装 gnuplot，可以使用附带的 `afl-plot` 工具将其转换为一个漂亮的进度报告。
### Addendum: automatically sending metrics with StatsD

In a CI environment or when running multiple fuzzers, it can be tedious to log
into each of them or deploy scripts to read the fuzzer statistics. Using
`AFL_STATSD` (and the other related environment variables `AFL_STATSD_HOST`,
`AFL_STATSD_PORT`, `AFL_STATSD_TAGS_FLAVOR`) you can automatically send metrics
to your favorite StatsD server. Depending on your StatsD server, you will be
able to monitor, trigger alerts, or perform actions based on these metrics
(e.g.: alert on slow exec/s for a new build, threshold of crashes, time since
last crash > X, etc.).

The selected metrics are a subset of all the metrics found in the status and in
the plot file. The list is the following: `cycle_done`, `cycles_wo_finds`,
`execs_done`,`execs_per_sec`, `corpus_count`, `corpus_favored`, `corpus_found`,
`corpus_imported`, `max_depth`, `cur_item`, `pending_favs`, `pending_total`,
`corpus_variable`, `saved_crashes`, `saved_hangs`, `total_crashes`,
`slowest_exec_ms`, `edges_found`, `var_byte_count`, `havoc_expansion`. Their
definitions can be found in the addendum above.

When using multiple fuzzer instances with StatsD, it is *strongly* recommended
to setup the flavor (`AFL_STATSD_TAGS_FLAVOR`) to match your StatsD server. This
will allow you to see individual fuzzer performance, detect bad ones, see the
progress of each strategy...

### 附录：使用 StatsD 自动发送度量数据

在 CI 环境或运行多个模糊器时，登录到每个模糊器或部署脚本以读取模糊器统计信息可能会很繁琐。通过使用 `AFL_STATSD`（以及其他相关的环境变量 `AFL_STATSD_HOST`、`AFL_STATSD_PORT`、`AFL_STATSD_TAGS_FLAVOR`），您可以自动将度量数据发送到您喜爱的 StatsD 服务器。根据您的 StatsD 服务器，您将能够监视、触发警报或基于这些度量数据执行操作（例如：在新构建中对慢执行/s触发警报，崩溃阈值，自上次崩溃以来的时间 > X 等）。

选择的度量数据是状态文件和图表文件中所有度量数据的子集。列表如下：`cycle_done`、`cycles_wo_finds`、`execs_done`、`execs_per_sec`、`corpus_count`、`corpus_favored`、`corpus_found`、`corpus_imported`、`max_depth`、`cur_item`、`pending_favs`、`pending_total`、`corpus_variable`、`saved_crashes`、`saved_hangs`、`total_crashes`、`slowest_exec_ms`、`edges_found`、`var_byte_count`、`havoc_expansion`。它们的定义可以在上述附录中找到。

在使用带有 StatsD 的多个模糊器实例时，*强烈建议*设置标签风格（`AFL_STATSD_TAGS_FLAVOR`）以匹配您的 StatsD 服务器。这将允许您查看各个模糊器的性能，检测不良模糊器，查看每个策略的进展等。