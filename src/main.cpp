#include <csignal>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include "lccl/log.h"
#include "recorder.h"

struct Param
{
    std::string input_file = "input.txt";
    bool promisc = false;
};

bool app_running = true;

static void SigIntHandler(int sig_num)
{
    signal(SIGINT, SigIntHandler);
    app_running = false;
}

static void ShowUsage()
{
    std::cerr << "\nUsage: ./pcap_recorder2 [-i input file]\n\n"
        << "-i\t\tcreate a file that contains several lines in\n"
        << "\t\t[ip] [port] [interface name / interface ip] [file duration(in second)] [cycle amount of files]\n"
        << "\t\te.g., input.txt\n"
        << "\t\t========================\n"
        << "\t\t224.5.6.7 23456 192.168.0.100 60 10\n"
        << "\t\t192.168.0.1 any 127.0.0.1 30 100\n"
        << "\t\tany 12345 enp5s0 120 30\n"
        << "\t\t========================\n";
}

static std::shared_ptr<Param> ParseParam(int argc, char **argv)
{
    std::shared_ptr<Param> param = std::make_shared<Param>();
    for (int index = 1; index < argc; ++index)
    {
        std::string curr_arg = argv[index];

        if ("--help" == curr_arg)
        {
            return nullptr;
        }

        if ("-i" == curr_arg)
        {
            if (index + 1 < argc)
            {
                std::string next_arg = argv[++index];
                param->input_file = next_arg;
            }
        }
        else if ("-m" == curr_arg)
        {
            param->promisc = true;
        }
    }

    return param;
}

int main(int argc, char **argv)
{
    signal(SIGINT, SigIntHandler);

    std::shared_ptr<Param> param = ParseParam(argc, argv);
    if (!param)
    {
        ShowUsage();
        return 0;
    }

    std::shared_ptr<Recorder> recorder = std::make_shared<Recorder>();
    if (!recorder->Init(param->input_file, param->promisc))
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Init recorder fail!");
        return 0;
    }

    while (app_running)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
