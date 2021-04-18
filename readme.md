# ApkScanner
`ApkScanner`是一个病毒分析工具，可以支持`apk,dex,odex`的文件分析。

分析一个`apk`是否具有恶意行为，可以通过静态和动态的两个层面的行为来完成。

**静态层面主要有两个引擎**
* `engine` 是一个使用`c++`写的一个分析引擎，目前只支持`unix`的运行，暂时不支持`windows`系统。
* `apkscanner`是一个使用`python`写的一个分析引擎，这个引擎目的是加速app的分析。

**动态层面的分析**

在动态的分析层主要通过一个模拟器启动待测试app运行时的动态检测，通过运行时的行为监测并识别对应的特征实现。

## 为什么会有这个程序
很多时候在分析一个app是否是恶意的程序，需要经过一下几个步骤
* 病毒沙箱引擎（哈勃）获取到app的基本分析报告
* 自己分析
    * 使用模拟器或者者真机运行app
    * 观察是否有勒索信息，锁机等恶意行为来判定是否是恶意app
    * 逆向分析
上面的几个都是比较常规的动作，但是要想能获取到app的一些详细特征或者要想自己实现一个特征的提取会不知道怎么做。我们知道在windows中的病毒分析中，有一个检测规则工具`YARA`能识别的`PE`中的一些特征，只要你的规则写的准确，就能精确识别程序。`android`的分析工具中并未有这种比较精确的程序，很多都是检测`pkg,md5,一些厂商提供的api`来确定一个app是否是恶意。所以，我写这个工具的目的就是能提供一个工具能根据自己的规则来识别的app，达到类似`yara`的效果。

## 工具的特性
这个工具具有一些几个特征
* 可以提取待分析app特征 `engine` **需要在unix的系统下执行**
* 自定义规则识别app并输出对应的规则信息
* 一些在线沙箱查询api操作，这个需要填写`config/user.conf`文件
* 输出一个详细的app分析报告
    * app的基本信息
    * app的四大组件信息
    * 被规则匹配中的方法信息

使用`androguard`的人都知道这个程序在分析app的是特别耗内存，如果一个大的app在就是吃光电脑的内存，为了加速对一个APP的分析

重新设计了一个分析引擎，可以尽可能的减少对内存的消耗。不止如此，`apkscanner`的目的是分析恶意软件的行为，内置了200+的恶意家族的特征，可以在运行时分析出已知的病毒家族和记录未知的apk的特征，使用者可以自己将对应的app病毒家族命名记录到提取的特征中。


## apk分析
`apk`的分析借鉴的`androguard`的分析思路来实现分析，主要功能
* dex的分析
* odex的分析
* AndroidManifest.xml的分析
* 签名信息的分析

## engine
> 仅支持apk检测，不支持dex,odex

引擎是一个使用c++写的app特征提取识别工具，目前只能在`unix`的系统下运行，主要功能
* 扫描apk并根据现有的规则特征`200+`的恶意家族识别先用的特征
* 对于未知的app特征会给出`unknow`的标识同时给出对应的识别特征码，使用者可以自己填写这个家族的命名

