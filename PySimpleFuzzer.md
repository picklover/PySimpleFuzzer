## Preface

最近看到了一篇博客 [Build simple fuzzer](https://carstein.github.io/2020/04/18/writing-simple-fuzzer-1.html)写的十分清晰易懂, 其中有句话说的很好 ''if you really want to understand something you should try to disassemble/recreate it."

这里我就按照该博客的思路一点一点写一个简单的fuzzer, 用python写当然只能用来把玩 执行效率限制了它不可能用于现实场景的fuzz 因为fuzz原理并不复杂 但是是一个高度依赖计算量的任务.

## Resource

- EXIF 格式是在JPEG格式中插入一些辅助信息如缩略图,所以后缀仍是.jpg 可以被JPG图片查看器打开
- exif library [EXIF解析库](https://github.com/mkttanabe/exif)
- 用于变异的正常原始图像 ``Cannon_40D.jpg``
- ``pip install python-ptrace``

## First Fuzzer

### 源码

```python
#!/usr/bin/env python3
import sys
import random
from ptrace import debugger
import signal

FLIP_PERCENT = 0.01
SOI_SIZE = 2
EOI_SIZE = 2

def get_bytes(filename):
    f = open(filename,'rb').read()
    return bytearray(f)

def create_new(data):
    with open('data/mutated.jpg','wb+') as f:
        f.write(data)

def bit_flip(data):
    num_of_flips = int((len(data) - SOI_SIZE - EOI_SIZE)* FLIP_PERCENT)
    
    indexes = range(2,len(data)-2)
    chosen_indexes = []
    for i in range(0,num_of_flips):
        chosen_indexes.append(random.choice(indexes))
    
    digites = range(0,8)
    for x in chosen_indexes:
        chosen_digit = random.choice(digites)
        # flip the bit
        data[x] = (data[x] ^ (1 << chosen_digit))     



def execute_fuzz(dbg, data, counter):
  cmd = ['exif/exif', 'data/mutated.jpg']
  pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  proc.cont()

  try:
    sig = dbg.waitSignals()
  except:
    return

  if sig.signum == signal.SIGSEGV:
  
    proc.detach()
    with open("./crashes/crash.{}.jpg".format(counter), "wb+") as f:
      f.write(data)


if len(sys.argv) < 2:
    print("Usage: JPEGfuzz.py <valid_jpg>")
else:
    filename = sys.argv[1]
    orig_data = get_bytes(filename)
    dbg = debugger.PtraceDebugger()
    
    for i in range(0,10000):
        data = orig_data[:]
        bit_flip(data)
        create_new(data)
        execute_fuzz(dbg,data,i)
    dbg.quit()

```

### 执行

初始环境如下:

crashes和data文件夹皆为空

![image-20220316155250365](https://raw.githubusercontent.com/picklover/BlogImages/main/img/image-20220316155250365.png?token=AJ7SDVVXOC3SM3PDLABYBNTCGGLZO)![image-20220316155341809](https://raw.githubusercontent.com/picklover/BlogImages/main/img/image-20220316155341809.png?token=AJ7SDVWYS724H4KOKXP6RS3CGGL4G)

exif 是 EXIF 解析库编译出来的二进制可执行文件

当exif正常解析时结果如下:

![image-20220316155540746](https://raw.githubusercontent.com/picklover/BlogImages/main/img/image-20220316155540746.png?token=AJ7SDVRRZX7NUE37Z6LFNQDCGGMDU)

执行fuzzer:

![image-20220316155824193](https://raw.githubusercontent.com/picklover/BlogImages/main/img/image-20220316155824193.png?token=AJ7SDVTNWZNUKZZU2NMSRN3CGGMN2)

发现fuzzer正常执行,并且生成了522个变异后jpg文件 这些文件都令exif解析程序产生segment fault.

简单测试一下,选择其中图片,调用exif程序尝试解析:

![image-20220316160133729](https://raw.githubusercontent.com/picklover/BlogImages/main/img/image-20220316160133729.png?token=AJ7SDVTLKF7S3IKNVXNFZPLCGGMZW)

### 原理窥探

#### Main parts of fuzzer

fuzzing 基本的原则其实相当简单: 喂给一个程序随机的数据,观察它是否崩溃,然后更改一点数据,再重复喂给程序 again and again.

每个fuzzer至少有两个主要模块,变异模块和执行引擎

```python
if len(sys.argv) < 2:
    print("Usage: JPEGfuzz.py <valid_jpg>")
else:
    filename = sys.argv[1]
    orig_data = get_bytes(filename)
    dbg = debugger.PtraceDebugger()
    
    for i in range(0,10000):
        data = orig_data[:]
        bit_flip(data)
        create_new(data)
        execute_fuzz(dbg,data,i)
    dbg.quit()
```

这是我们fuzzer的主要框架(main函数 我没有单独写成一个函数) 将输入的jpg文件数据读入内存,然后调用bit_flip函数对数据进行位反转操作,然后create_new把更改后的数据写入到一个临时jpg文件中, 然后execute_fuzz函数是执行引擎,调用exif程序 给它临时的jpg变异文件 观察是否会令程序产生段错误,如果这样就把文件保存到crash文件夹下

#### mutate module

我们这个简单fuzzer的变异策略十分简单清晰: 随机选择一定数量的字节,然后随机在该字节中翻转一些bit,如下:

```python
def bit_flip(data):
    num_of_flips = int((len(data) - SOI_SIZE - EOI_SIZE)* FLIP_PERCENT)
    
    indexes = range(2,len(data)-2)
    chosen_indexes = []
    for i in range(0,num_of_flips):
        chosen_indexes.append(random.choice(indexes))
    
    digites = range(0,8)
    for x in chosen_indexes:
        chosen_digit = random.choice(digites)
        # flip the bit
        data[x] = (data[x] ^ (1 << chosen_digit))   
```

其中 num_of_flips 是我们要选择多少字节进行改动,FLIP_PERCENT是占比总字节多少的常量,这里为1%

通过``m^(1<<n)`` 可以翻转m字节中第n位

SOI_SIZE 和 EOI_SIZE 是常量 皆为两个字节, 这是jpeg文件格式的识别符 就像PE文件的 MZ标识 我们并不想更改这个标识符 所以把它俩扣除 该识别符在jpeg文件的位置是起始和末尾:

![image-20220316162429855](https://raw.githubusercontent.com/picklover/BlogImages/main/img/image-20220316162429855.png?token=AJ7SDVWH7GW4FVK5QE32BD3CGGPP2)

我们fuzz过程也不会更改SOI和EOI

#### execute engine

```python
def execute_fuzz(dbg, data, counter):
  cmd = ['exif/exif', 'data/mutated.jpg']
  pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  proc.cont()

  try:
    sig = dbg.waitSignals()
  except:
    return

  if sig.signum == signal.SIGSEGV:
  
    proc.detach()
    with open("./crashes/crash.{}.jpg".format(counter), "wb+") as f:
      f.write(data)
```

我们没有使用常规的``execv`` ``Popen`` ``run``此类函数, 使用这些要求我们读取程序执行结果然后parse 输出看看其中是否有``Segmentation Fault``这样的字符串 或者返回值

我们使用python-ptrace库提供的结构化输出方式,通过返回sig中是否为``SIGSEGV``来判断

我们创建了一个debugger,让子进程被调试,debugger捕获其收到的内核发来的signal

如果是段错误 我们就把引起错误的数据记录到crash文件夹下

## Extend one mutated method

我们创建的第一个简单fuzzer使用的变异算法仅仅是位翻转, 这里引入另一种策略``magic nums``

一些常见的数据类型的最大值,最小值等是位于边界的 往往会引发溢出 所以策略就是:我们随机替换数据中的字节改成这些容易出问题的``magic nums`` 

```python
MAGIC_VALS = [
  [0xFF],
  [0x7F],
  [0x00],
  [0xFF, 0xFF], # 0xFFFF
  [0x00, 0x00], # 0x0000
  [0xFF, 0xFF, 0xFF, 0xFF], # 0xFFFFFFFF
  [0x00, 0x00, 0x00, 0x00], # 0x80000000
  [0x00, 0x00, 0x00, 0x80], # 0x80000000
  [0x00, 0x00, 0x00, 0x40], # 0x40000000
  [0xFF, 0xFF, 0xFF, 0x7F], # 0x7FFFFFFF
]

def magic(data, idx):
  picked_magic = random.choice(MAGIC_VALS)

  offset = 0
  for m in picked_magic:
    data[idx + offset] = m
    offset += 1
```

代码略作修改,也随机选择一种变异方法, 代码如下:

```python
#!/usr/bin/env python3
import sys
import random
from ptrace import debugger
import signal

FLIP_PERCENT = 0.01
SOI_SIZE = 2
EOI_SIZE = 2

MAGIC_VALS = [
  [0xFF],
  [0x7F],
  [0x00],
  [0xFF, 0xFF], # 0xFFFF
  [0x00, 0x00], # 0x0000
  [0xFF, 0xFF, 0xFF, 0xFF], # 0xFFFFFFFF
  [0x00, 0x00, 0x00, 0x00], # 0x80000000
  [0x00, 0x00, 0x00, 0x80], # 0x80000000
  [0x00, 0x00, 0x00, 0x40], # 0x40000000
  [0xFF, 0xFF, 0xFF, 0x7F], # 0x7FFFFFFF
]

def magic(data, idx):
  picked_magic = random.choice(MAGIC_VALS)

  offset = 0
  for m in picked_magic:
    data[idx + offset] = m
    offset += 1

def get_bytes(filename):
    f = open(filename,'rb').read()
    return bytearray(f)

def create_new(data):
    with open('data/mutated.jpg','wb+') as f:
        f.write(data)

def bit_flip_and_magic(data):
    num_of_flips = int((len(data) - SOI_SIZE - EOI_SIZE)* FLIP_PERCENT)
    
    indexes = range(2,len(data)-6)
    chosen_indexes = []
    methods = [0,1]
    for i in range(0,num_of_flips):
        chosen_indexes.append(random.choice(indexes))
    
    digites = range(0,8)
    for x in chosen_indexes:
        method = random.choice(methods)
        # magic method
        if method == 0:
            magic(data,x)
        # flip the bit method
        else:
            chosen_digit = random.choice(digites)
            data[x] = (data[x] ^ (1 << chosen_digit))     





def execute_fuzz(dbg, data, counter):
  cmd = ['exif/exif', 'data/mutated.jpg']
  pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  proc.cont()

  try:
    sig = dbg.waitSignals()
  except:
    return

  if sig.signum == signal.SIGSEGV:
  
    proc.detach()
    with open("./crashes/crash.{}.jpg".format(counter), "wb+") as f:
      f.write(data)


if len(sys.argv) < 2:
    print("Usage: JPEGfuzz.py <valid_jpg>")
else:
    filename = sys.argv[1]
    orig_data = get_bytes(filename)
    dbg = debugger.PtraceDebugger()
    
    for i in range(0,10000):
        data = orig_data[:]
        bit_flip_and_magic(data)
        create_new(data)
        execute_fuzz(dbg,data,i)
    dbg.quit()

```

我们单独测试一下,当仅使用```magic```方法时能fuzz出多少crash(不随机变异方法 只使用magic)

经测试 单独使用``magic``方法时 效果很好,产生了415个crash

![image-20220316172520676](https://raw.githubusercontent.com/picklover/BlogImages/main/img/image-20220316172520676.png?token=AJ7SDVQCE3OL4QAIWYVMWPDCGGWT4)

## summary

我们编写了一个简单的fuzzer, 效果比较理想 从中学习了fuzz的核心思想 后面会继续扩充fuzzer
