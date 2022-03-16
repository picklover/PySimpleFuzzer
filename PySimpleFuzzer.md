## preface

最近看到了一篇博客 [Build simple fuzzer](https://carstein.github.io/2020/04/18/writing-simple-fuzzer-1.html)写的十分清晰易懂, 其中有句话说的很好 ''if you really want to understand something you should try to disassemble/recreate it."

这里我就按照该博客的思路一点一点写一个简单的fuzzer, 用python写当然只能用来把玩 执行效率限制了它不可能用于现实场景的fuzz 因为fuzz原理并不复杂 但是是一个高度依赖计算量的任务.

## Resource

- EXIF 格式是在JPEG格式中插入一些辅助信息如缩略图,所以后缀仍是.jpg 可以被JPG图片查看器打开
- exif library [EXIF解析库](https://github.com/mkttanabe/exif)
- 用于变异的正常原始图像 ``Cannon_40D.jpg``
- ``pip install python-ptrace``

