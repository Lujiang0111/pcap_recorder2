import os
import shutil
import subprocess
import sys
import pathlib


class Rebuild:
    __build_type = None
    __env_path = None

    def main(self, args) -> None:
        param_cnt = len(args) - 1
        if param_cnt > 0:
            self.__build_type = args[1]
        else:
            self.__build_type = "Debug"

        self.__env_path = pathlib.Path(__file__).resolve().parent.parent.parent.parent

        self.build(os.path.join(self.__env_path, "source", "lib", "lccl"))
        self.build(os.path.join(self.__env_path, "source", "lib", "pcap_dump"))
        self.build(os.path.join(self.__env_path, "source", "program", "pcap_recorder2"))

    def build(self, path) -> None:
        print(f"\033[33mmake project {os.path.basename(path)}...\033[0m")

        os.chdir(path)

        if os.path.exists("build"):
            shutil.rmtree("build")

        # 创建 build 目录
        os.makedirs("build", exist_ok=True)

        # 进入 build 目录
        os.chdir("build")

        if "win32" == sys.platform:
            cmake_generator = "Visual Studio 17 2022"
            cmake_arch = "x64"
            subprocess.run(
                ["cmake", "..", f"-G{cmake_generator}", f"-A{cmake_arch}"],
                check=True,
                shell=False,
            )
            subprocess.run(
                ["cmake", "--build", ".", "--config", self.__build_type],
                check=True,
                shell=False,
            )


if __name__ == "__main__":
    prebuild = Rebuild()
    prebuild.main(sys.argv)
