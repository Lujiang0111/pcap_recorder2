#include <csignal>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include "pcap_dump.h"
#include "lccl/log.h"
#include "lccl/utils/string_utils.h"

struct Param
{
    std::string input_file = "input.txt";
    std::string record_dir = "record";
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
        << "\t\t[ip] [port] [interface name / interface ip] [file duration(in second)] [cycle amount of files] [in/out/inout]\n"
        << "\t\te.g., input.txt\n"
        << "\t\t========================\n"
        << "\t\t224.5.6.7 23456 192.168.0.100 60 10 in\n"
        << "\t\t192.168.0.1 any 127.0.0.1 30 100 out\n"
        << "\t\tany 12345 enp5s0 120 30 inout\n"
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
            if (index + 1 >= argc)
            {
                return nullptr;
            }

            std::string next_arg = argv[++index];
            param->input_file = next_arg;
        }
        else if ("-m" == curr_arg)
        {
            param->promisc = true;
        }
        else if ("-d" == curr_arg)
        {
            if (index + 1 >= argc)
            {
                return nullptr;
            }

            std::string next_arg = argv[++index];
            param->record_dir = next_arg;
        }
    }

    return param;
}

static void LibPcapDumpLogCallback(void *opaque, pcapdump::LogLevels level, const char *file_name, int file_line, const char *content, size_t len)
{
    lccl::log::Levels lccl_level = lccl::log::Levels::kDebug;
    switch (level)
    {
    case pcapdump::LogLevels::kDebug:
        lccl_level = lccl::log::Levels::kDebug;
        break;
    case pcapdump::LogLevels::kInfo:
        lccl_level = lccl::log::Levels::kInfo;
        break;
    case pcapdump::LogLevels::kWarn:
        lccl_level = lccl::log::Levels::kWarn;
        break;
    case pcapdump::LogLevels::kError:
        lccl_level = lccl::log::Levels::kError;
        break;
    default:
        return;
    }

    lccl::log::DefaultLogger()->LogFmt(lccl_level, 1, true, file_name, file_line, "[libpcap_dump]: {:.{}}", content, len);
}

int main(int argc, char **argv)
{
    signal(SIGINT, SigIntHandler);

    pcapdump::SetLogCallback(LibPcapDumpLogCallback, nullptr);

    std::shared_ptr<Param> param = ParseParam(argc, argv);
    if (!param)
    {
        ShowUsage();
        return 0;
    }

    std::vector<std::shared_ptr<pcapdump::IDumper>> dumpers;

    std::ifstream fin(param->input_file.c_str());
    if (!fin.is_open())
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Can not open input file={}!", param->input_file);
        return false;
    }

    std::string origin_line;
    while (std::getline(fin, origin_line))
    {
        std::string line = lccl::TrimString(origin_line);
        if ((0 == line.length()) || ('#' == line[0]))
        {
            continue;
        }

        std::stringstream ss(line);
        std::string ip, port, interface_name;
        int64_t segment_interval = 0;
        size_t segment_size = 0;
        std::string io_str;
        if (!(ss >> ip >> port >> interface_name >> segment_interval >> segment_size >> io_str))
        {
            LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Line param not enough, line={}", line);
            continue;
        }

        std::shared_ptr<pcapdump::IDumper> dumper = pcapdump::CreateDumper();
        if (!dumper)
        {
            LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Create dumper fail, line={}", line);
            continue;
        }

        dumper->SetParam(pcapdump::IDumper::ParamNames::kIp, ip.c_str(), ip.length());
        dumper->SetParam(pcapdump::IDumper::ParamNames::kPort, port.c_str(), port.length());
        dumper->SetParam(pcapdump::IDumper::ParamNames::kInterface, interface_name.c_str(), interface_name.length());
        dumper->SetParam(pcapdump::IDumper::ParamNames::kPromisc, &param->promisc, sizeof(param->promisc));
        dumper->SetParam(pcapdump::IDumper::ParamNames::kSegmentInterval, &segment_interval, sizeof(segment_interval));
        dumper->SetParam(pcapdump::IDumper::ParamNames::kSegmentSize, &segment_size, sizeof(segment_size));
        dumper->SetParam(pcapdump::IDumper::ParamNames::kDumpDir, param->record_dir.c_str(), param->record_dir.length());
       
        int io_flag = 0;
        if ("out" == io_str)
        {
            io_flag = 2;
        }
        else if ("inout" == io_str)
        {
            io_flag = 3;
        }
        else
        {
            io_flag = 1;
        }
        dumper->SetParam(pcapdump::IDumper::ParamNames::kIoFlag, &io_flag, sizeof(io_flag));

        if (!dumper->Init())
        {
            LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Init dumper fail, line={}", line);
            continue;
        }
        dumpers.push_back(dumper);
    }

    while (app_running)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    dumpers.clear();

    return 0;
}
