#include <fstream>
#include <string>
#include "lccl/log.h"
#include "lccl/socket.h"
#include "lccl/utils/string_utils.h"
#include "recorder.h"

Recorder::Recorder()
{
    lccl::skt::InitEnv();
}

Recorder::~Recorder()
{
    Deinit();
    lccl::skt::DeinitEnv();
}

bool Recorder::Init(const std::string &input_file, bool promisc)
{
    param_ = std::make_shared<Param>();
    param_->input_file = input_file;
    param_->promisc = promisc;

    std::ifstream fin(param_->input_file.c_str());
    if (!fin.is_open())
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Can not open input file={}!", param_->input_file);
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

        std::shared_ptr<RecorderNode> recorder_node = std::make_shared<RecorderNode>();
        if (!recorder_node->Init(param_->promisc, line))
        {
            continue;
        }
        recorder_nodes_.push_back(recorder_node);
    }

    return true;
}

void Recorder::Deinit()
{
    recorder_nodes_.clear();
}
