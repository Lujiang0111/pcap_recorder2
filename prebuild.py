import os
import re
import shutil
import subprocess
import sys


# 复制目录
def copy_dir(src_dir, dst_dir) -> None:
    if not os.path.isdir(src_dir):
        return

    if not os.path.exists(dst_dir):
        os.makedirs(dst_dir)

    for item in os.listdir(src_dir):
        src_item = os.path.join(src_dir, item)
        dst_item = os.path.join(dst_dir, item)

        if os.path.isdir(src_item):
            copy_dir(src_item, dst_item)
        else:
            shutil.copy2(src_item, dst_item, follow_symlinks=False)


# 删除目录
def rm_dir(dir) -> None:
    if not os.path.exists(dir):
        return

    if os.path.isdir(dir):
        shutil.rmtree(dir)
    else:
        os.remove(dir)


# 创建符号链接指向.so文件
def create_so_link(dir) -> None:
    if not os.path.exists(dir):
        return

    # 查找所有以.so.开头的文件
    so_files = [
        f
        for f in os.listdir(dir)
        if os.path.isfile(os.path.join(dir, f)) and ".so." in f
    ]

    # 为每个.so文件创建符号链接
    for so_file in so_files:
        last_so_index = so_file.rfind(".so")
        link_name = so_file[:last_so_index] + ".so"

        if not os.path.isfile(os.path.join(dir, link_name)):
            subprocess.run(
                f"cd {dir} && ln -sf {so_file} {link_name}",
                shell=True,
            )


class Prebuild:
    __os_name = None
    __os_version = None
    __os_arch = None
    __build_type = "Debug"
    __trd_dir = None
    __dep_dir = None
    __lib_base_dir = None

    def main(self, args) -> None:
        param_cnt = len(args) - 1
        if param_cnt < 7:
            raise SystemExit(f"param cnt={param_cnt} to less")

        # 获取编译模式、依赖路径和库基路径
        self.__os_name = args[1]
        self.__os_version = args[2]
        self.__os_arch = args[3]
        self.__build_type = args[4]
        self.__trd_dir = os.path.join(args[5], "3rd")
        self.__dep_dir = os.path.join(args[6], "dep")
        self.__lib_base_dir = args[7]

        # 重建依赖目录
        rm_dir(self.__dep_dir)
        os.makedirs(self.__dep_dir)

        # 获取库名及其版本
        if param_cnt >= 8:
            libs = args[8].strip().split(" ")
            for i in range(1, len(libs), 2):
                lib_name = libs[i - 1].strip()
                lib_version = libs[i].strip()
                if not lib_name:
                    continue

                if not self.__copy_lib(lib_name, lib_version):
                    print(
                        f"{lib_name} v{lib_version} not found! put {lib_name} in {os.path.join(self.__trd_dir, lib_name)} or {os.path.join(self.__lib_base_dir, lib_name)}"
                    )

            # 创建符号链接
            create_so_link(os.path.join(self.__dep_dir, "lib"))

    # 复制库文件及其相关内容
    def __copy_lib(self, lib_name, lib_version) -> bool:
        # 先检查3rd文件夹有没有对应的库，如果有，直接退出
        trd_lib_dir = os.path.join(self.__trd_dir, lib_name)
        if os.path.exists(trd_lib_dir):
            # 复制include和lib
            copy_dir(
                os.path.join(trd_lib_dir, "include"),
                os.path.join(self.__dep_dir, "include", lib_name),
            )
            copy_dir(
                os.path.join(trd_lib_dir, "lib"), os.path.join(self.__dep_dir, "lib")
            )
            return True

        # 检查库路径有没有对应的库
        lib_dir = os.path.join(self.__lib_base_dir, lib_name)
        if not os.path.isdir(lib_dir):
            return False

        # 获取版本信息
        sub_dirs = [
            d for d in os.listdir(lib_dir) if os.path.isdir(os.path.join(lib_dir, d))
        ]

        if not sub_dirs:
            print(f"{lib_name} versions not found!")
            return False

        # 选择最新版本的库
        choose_version_dir = max(sub_dirs)
        choose_version = re.sub(r"^[^0-9]+", "", choose_version_dir)

        # 最新的版本低于要求的版本，报错
        if choose_version < lib_version:
            print(f"{lib_name} max version={choose_version} < {lib_version}!")
            return False

        # 打印最终选择的版本
        print(f"{lib_name} {lib_version} => choose {choose_version}")

        lib_os_version_dir = os.path.join(
            lib_dir, choose_version_dir, self.__os_name
        )
        lib_debug_dir = os.path.join(lib_os_version_dir, self.__os_arch)
        lib_debug_dir_exist = os.path.isdir(lib_debug_dir)
        lib_release_dir = os.path.join(
            lib_os_version_dir, f"{self.__os_arch}_release"
        )
        lib_release_dir_exist = os.path.isdir(lib_release_dir)

        # 没有lib文件，可能是纯头文件库，直接返回True
        if not lib_debug_dir_exist and not lib_release_dir_exist:
            return True

        lib_os_arch_dir = None
        if self.__build_type == "Release":
            lib_os_arch_dir = (
                lib_release_dir if lib_release_dir_exist else lib_debug_dir
            )
        else:
            lib_os_arch_dir = (
                lib_debug_dir if lib_debug_dir_exist else lib_release_dir
            )

        # 复制include和lib
        copy_dir(
            os.path.join(lib_os_arch_dir, "include"),
            os.path.join(self.__dep_dir, "include", lib_name),
        )
        copy_dir(
            os.path.join(lib_os_arch_dir, "lib"), os.path.join(self.__dep_dir, "lib")
        )
        return True


# 程序入口
if __name__ == "__main__":
    prebuild = Prebuild()
    prebuild.main(sys.argv)
