#ifndef PCAP_RECORDER2_INCLUDE_RECORDER_NODE_H_
#define PCAP_RECORDER2_INCLUDE_RECORDER_NODE_H_

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <thread>
#include "pcap.h"

class RecorderNode
{
public:
    struct Param
    {
        std::string ip;
        uint16_t port = 0;
        std::string if_ip;
        std::string if_name;
        bool promisc = false;
        int64_t interval = 30;
        size_t cycle_amount = 10;
    };

public:
    RecorderNode(const RecorderNode &) = delete;
    RecorderNode &operator=(const RecorderNode &) = delete;

    RecorderNode();
    virtual ~RecorderNode();

    bool Init(bool promisc, const std::string &line);
    void Deinit();

private:
    enum class WorkThreadStates
    {
        kInit = 0,
        kDeinit,
        kFail,
        kWorking,
    };

    struct WorkThreadStateRet
    {
        WorkThreadStates new_state = WorkThreadStates::kFail;
        int64_t sleep_ns = 0;
    };

private:
    std::shared_ptr<Param> ParseParam(bool promisc, const std::string &line);

    void WorkThread();
    void WorkThreadInitState();
    void WorkThreadDeinitState();
    void WorkThreadFailState();
    void WorkThreadWorkingState();

    std::string GetFilter() const;

private:
    std::shared_ptr<Param> param_;

    // 线程
    std::thread work_thread_;
    WorkThreadStates work_thread_state_;
    WorkThreadStateRet work_thread_state_ret_;
    std::mutex work_thread_wait_mutex_;
    std::condition_variable work_thread_wait_cond_;

    // pcap
    pcap_t *pcap_;
    int pcap_link_type_;
    bpf_program pcap_bfp_;
    int64_t pcap_tstamp_precision_;

    // pcap dump
    pcap_dumper_t *pcap_dumper_;
    int64_t pcap_dumper_prev_time_;

    // dump files
    std::string file_dir_name_;
    std::deque<std::string> file_names_;
    int file_name_idx_;
};

#endif // !PCAP_RECORDER2_INCLUDE_RECORDER_NODE_H_
