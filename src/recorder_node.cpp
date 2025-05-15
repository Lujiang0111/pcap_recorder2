#include <sstream>
#include <vector>
#include "lccl/file.h"
#include "lccl/log.h"
#include "lccl/socket.h"
#include "lccl/utils/path_utils.h"
#include "recorder_node.h"

extern bool app_running;

RecorderNode::RecorderNode() :
    work_thread_state_(WorkThreadStates::kInit),
    pcap_(nullptr),
    pcap_link_type_(DLT_NULL),
    pcap_tstamp_precision_(1),
    pcap_dumper_(nullptr),
    pcap_dumper_prev_time_(0),
    file_name_idx_(0)
{
    memset(&pcap_bfp_, 0, sizeof(pcap_bfp_));
}

RecorderNode::~RecorderNode()
{
    Deinit();
}

bool RecorderNode::Init(bool promisc, const std::string &line)
{
    param_ = ParseParam(promisc, line);
    if (!param_)
    {
        return false;
    }

    file_dir_name_ = fmt::format("{}_{}_{}", param_->ip, param_->port, param_->if_ip);
    lccl::file::CreateDir(file_dir_name_.c_str(), false);

    work_thread_ = std::thread(&RecorderNode::WorkThread, this);
    return true;
}

void RecorderNode::Deinit()
{
    {
        std::lock_guard<std::mutex> lock(work_thread_wait_mutex_);
    }
    work_thread_wait_cond_.notify_all();

    if (work_thread_.joinable())
    {
        work_thread_.join();
    }

    param_ = nullptr;
}

static std::string DeviceIpToName(const std::string &device_ip)
{
    std::shared_ptr<lccl::skt::IAddr> device_addr = lccl::skt::CreateAddr(device_ip.c_str(), 0, true);
    if (!device_addr)
    {
        return "any";
    }

    sockaddr *device_sa = device_addr->GetNative();

    std::vector<char> pcap_errbuf(PCAP_ERRBUF_SIZE);
    pcap_if_t *all_devices = nullptr;
    pcap_findalldevs(&all_devices, &pcap_errbuf[0]);
    for (pcap_if_t *curr_device = all_devices; curr_device; curr_device = curr_device->next)
    {
        for (pcap_addr *curr_pcap_addr = curr_device->addresses; curr_pcap_addr; curr_pcap_addr = curr_pcap_addr->next)
        {
            if (0 == lccl::skt::CompareSa(device_sa, curr_pcap_addr->addr))
            {
                std::string device_name = curr_device->name;
                pcap_freealldevs(all_devices);
                return device_name;
            }
        }
    }
    pcap_freealldevs(all_devices);

    return "any";
}

std::shared_ptr<RecorderNode::Param> RecorderNode::ParseParam(bool promisc, const std::string &line)
{
    std::shared_ptr<Param> param = std::make_shared<Param>();

    std::stringstream ss(line);
    std::string port_string;
    if (!(ss >> param->ip >> port_string >> param->if_ip >> param->interval >> param->cycle_amount))
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Line param not enough, line={}", line);
        return nullptr;
    }

    param->port = ("any" == port_string) ? 0 : static_cast<uint16_t>(atoi(port_string.c_str()));

    lccl::skt::AddrTypes addr_type = lccl::skt::GetIpType(param->if_ip.c_str());
    switch (addr_type)
    {
    case lccl::skt::AddrTypes::kIpv4:
    case lccl::skt::AddrTypes::kIpv6:
        param->if_name = DeviceIpToName(param->if_ip);
        break;
    default:
        param->if_name = param->if_ip;
        break;
    }

    return param;
}

void RecorderNode::WorkThread()
{
    work_thread_state_ = WorkThreadStates::kDeinit;
    while (app_running)
    {
        work_thread_state_ret_.new_state = work_thread_state_;
        work_thread_state_ret_.sleep_ns = 0;

        switch (work_thread_state_)
        {
        case WorkThreadStates::kInit:
            WorkThreadInitState();
            break;
        case WorkThreadStates::kDeinit:
            WorkThreadDeinitState();
            break;
        case WorkThreadStates::kFail:
            WorkThreadFailState();
            break;
        case WorkThreadStates::kWorking:
            WorkThreadWorkingState();
            break;
        default:
            work_thread_state_ret_.new_state = WorkThreadStates::kFail;
            work_thread_state_ret_.sleep_ns = 0;
            break;
        }

        if (work_thread_state_ret_.sleep_ns > 0)
        {
            std::unique_lock<std::mutex> lock(work_thread_wait_mutex_);
            work_thread_wait_cond_.wait_for(lock, std::chrono::nanoseconds(work_thread_state_ret_.sleep_ns), [this] {return (!app_running); });
        }

        if (work_thread_state_ret_.new_state != work_thread_state_)
        {
            work_thread_state_ = work_thread_state_ret_.new_state;
        }
    }

    // 清理
    WorkThreadDeinitState();
}

void RecorderNode::WorkThreadInitState()
{
    std::vector<char> pcap_errbuf(PCAP_ERRBUF_SIZE);

    /* open the adapter */
    pcap_ = pcap_create(param_->if_name.c_str(), &pcap_errbuf[0]);
    if (!pcap_)
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Couldn't create pcap {}: {}",
            param_->if_name, &pcap_errbuf[0]);
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    if (0 != pcap_set_snaplen(pcap_, 65535))
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Couldn't set pcap snaplen={}: {}",
            65535, pcap_geterr(pcap_));
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    if (0 != pcap_set_promisc(pcap_, (param_->promisc) ? 1 : 0))
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Couldn't set pcap promisc={}: {}",
            param_->promisc, pcap_geterr(pcap_));
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    if (0 != pcap_set_tstamp_precision(pcap_, PCAP_TSTAMP_PRECISION_NANO))
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kWarn, "Couldn't set pcap timestamp precision={}: {}",
            "PCAP_TSTAMP_PRECISION_NANO", pcap_geterr(pcap_));
    }

    if (0 != pcap_activate(pcap_))
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Couldn't active pcap handle, {}", pcap_geterr(pcap_));
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    pcap_link_type_ = pcap_datalink(pcap_);
    if ((DLT_NULL != pcap_link_type_) && (DLT_EN10MB != pcap_link_type_))
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Device doesn't provide Ethernet headers - link type was {}", pcap_link_type_);
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    /* compile the filter */
    memset(&pcap_bfp_, 0, sizeof(pcap_bfp_));
    std::string filter_str = GetFilter();
    bpf_u_int32 netmask = 0;
    if (PCAP_ERROR == pcap_compile(pcap_, &pcap_bfp_, filter_str.c_str(), 0, netmask))
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Couldn't parse filter {}: {}", filter_str, pcap_geterr(pcap_));
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    /* set the filter */
    if (PCAP_ERROR == pcap_setfilter(pcap_, &pcap_bfp_))
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Couldn't install filter {}: {}", filter_str, pcap_geterr(pcap_));
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    /* set nonblock */
    if (PCAP_ERROR == pcap_setnonblock(pcap_, 1, &pcap_errbuf[0]))
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Couldn't set nonblock mode {}: {}", filter_str, &pcap_errbuf[0]);
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    pcap_tstamp_precision_ = (PCAP_TSTAMP_PRECISION_NANO == pcap_get_tstamp_precision(pcap_)) ? 1 : 1000;

    LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kInfo, "Init pcap device={} addr={}:{} filter={} successfully",
        param_->if_name, param_->ip, param_->port, filter_str);
    work_thread_state_ret_.new_state = WorkThreadStates::kWorking;
}

void RecorderNode::WorkThreadDeinitState()
{
    if (pcap_dumper_)
    {
        pcap_dump_close(pcap_dumper_);
        pcap_dumper_ = nullptr;
    }

    if (pcap_)
    {
        pcap_close(pcap_);
        pcap_ = nullptr;
    }

    work_thread_state_ret_.new_state = WorkThreadStates::kInit;
    work_thread_state_ret_.sleep_ns = 1000000LL;
}

void RecorderNode::WorkThreadFailState()
{
    WorkThreadDeinitState();
    work_thread_state_ret_.sleep_ns = 3 * 1000000000LL;
}

void RecorderNode::WorkThreadWorkingState()
{
    const u_char *packet = nullptr;
    struct pcap_pkthdr *pcap_header = nullptr;

    /* grab a packet */
    int ret = pcap_next_ex(pcap_, &pcap_header, &packet);
    if (ret < 0)
    {
        LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Get pcap error: {}", pcap_geterr(pcap_));
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    if (0 == ret)
    {
        work_thread_state_ret_.sleep_ns = 1000000LL;
        return;
    }

    time_t pcap_header_time = pcap_header->ts.tv_sec;
    if (!(pcap_dumper_) ||
        (pcap_header_time / param_->interval != pcap_dumper_prev_time_ / param_->interval))
    {
        std::tm time_tm;
#if defined(_MSC_VER)
        ::localtime_s(&time_tm, &pcap_header_time);
#else
        ::localtime_r(&pcap_header_time, &time_tm);
#endif

        std::string file_name = lccl::OsPathJoin(file_dir_name_,
            fmt::format("{}_{:04}_{:02}_{:02}_{:02}_{:02}_{:02}.pcap",
                file_name_idx_,
                time_tm.tm_year + 1900,
                time_tm.tm_mon + 1,
                time_tm.tm_mday,
                time_tm.tm_hour,
                time_tm.tm_min,
                time_tm.tm_sec));
        ++file_name_idx_;

        if (pcap_dumper_)
        {
            pcap_dump_close(pcap_dumper_);
        }

        pcap_dumper_ = pcap_dump_open(pcap_, file_name.c_str());
        if (!pcap_dumper_)
        {
            LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kError, "Pcap dumper open error: {}", pcap_geterr(pcap_));
            work_thread_state_ret_.new_state = WorkThreadStates::kFail;
            return;
        }

        file_names_.push_back(file_name);
        if (file_names_.size() > param_->cycle_amount)
        {
            const std::string &del_file_name = file_names_.front();
            LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kInfo, "New pcap file={}, del file={}",
                file_name, del_file_name);

            lccl::file::RemoveFile(del_file_name.c_str());
            file_names_.pop_front();
        }
        else
        {
            LCCL_DEFAULT_LOG_SYNC(lccl::log::Levels::kInfo, "New pcap file={}", file_name);
        }

        pcap_dumper_prev_time_ = pcap_header_time;
    }

    pcap_dump(reinterpret_cast<u_char *>(pcap_dumper_), pcap_header, packet);
}

std::string RecorderNode::GetFilter() const
{
    std::string filter_str;
    if ("any" != param_->ip)
    {
        if (filter_str.length() > 0)
        {
            filter_str += fmt::format(" and dst host {}", param_->ip);
        }
        else
        {
            filter_str += fmt::format("dst host {}", param_->ip);
        }
    }

    if (0 != param_->port)
    {
        if (filter_str.length() > 0)
        {
            filter_str += fmt::format(" and dst port {}", param_->port);
        }
        else
        {
            filter_str += fmt::format("dst port {}", param_->port);
        }
    }

    return filter_str;
}
