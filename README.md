# TInjector

劫持Zygote实现App启动前注入so
![1](https://github.com/Mrack/TInjector/assets/15072171/b6afd749-55c8-4a9b-872a-4001fd3772fa)

## Features
- Zygote spawn模式
- Android 9 - 13
- Arm64-v8a
- Remap 隐藏 so

## TODO
- 支持usap模式
- ...

## Build and Usage
Build:
  ```shell
  git clone https://github.com/mrack/TInjector.git
  cd TInjector
  ndk-build (Add ndk-build to your env variables)
  adb shell mkdir /data/local/tmp/inject
  adb push libtcore.so /data/local/tmp/inject/
  adb push tinjector /data/local/tmp/inject/
  ```
  Usage:
   ```shell
  su
  cd /data/local/tmp/inject
  chmod 777 libtcore.so
  chmod +x tinjector
  ./tinjector -h
  
  Usage: ./tinject --hide -f -p <package name>  <so path>
  Options:
  -p <pkg> <so path>  Inject so to the specified package.
  -P <pid> <so path>  Inject so to the specified pid.
  --hide              Hide the injected module.
  -h                  Show this help.
  -f                  Spwan a new process and inject to it. only for android app.
  ```
  
  
