# Application.mk

# 指定要构建的 ABI
APP_ABI := arm64-v8a

# 指定目标平台版本
APP_PLATFORM := android-21

# 启用 C++11 支持
APP_CPPFLAGS := -frtti -fexceptions -std=c++11

# 设置 C 编译器标志
APP_CFLAGS := -std=c11

# 选项：启用构建调试版本
# APP_OPTIM := debug

# 选项：启用构建发布版本
# APP_OPTIM := release

# 指定链接器选项
APP_LDFLAGS := -Wl,--no-undefined

# 指定默认的 STL 实现（例如，使用 libc++）
#APP_STL := c++_shared
