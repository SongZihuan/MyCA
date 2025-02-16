# Huan-MyCA
## 介绍
这是一个简单的 CA 工具，可以生成自签名CA（根CA）、中间CA、终端证书（由CA签名）或自签名终端证书。
其中，终端证书支持添加域名、IP。

## 构建
使用`go build`命令进行构建，具体如下：
```shell
$ go build github.com/SongZihuan/MyCA/src/cmd/myca/mycav1
```

当然，你可以添加参数来优化构建目标：
```shell
$ go build -trimpath -ldflags='-s -w' github.com/SongZihuan/MyCA/src/cmd/myca/mycav1
```

具体编译参数可参见`go`的相关文档。

## 运行
编译完成后，在对应平台执行可执行程序文件即可。支持下列参数：
```text
Usage:
  -h    show help
  -help
        show help
  -home string
        set home directory (default "~/.myca")
  -v    show version
  -version
        show version
```

- `-h`和`-help`可显示帮助信息。
- `-v`和`-version`可显示版本信息。
- `-home`设置项目根目录，默认为用户家目录下的`.myca`文件夹。

## 协议
本软件基于 [MIT LICENSE](/LICENSE) 发布。
了解更多关于 MIT LICENSE , 请 [点击此处](https://mit-license.song-zh.com) 。