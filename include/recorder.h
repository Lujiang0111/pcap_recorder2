#ifndef PCAP_RECORDER2_INCLUDE_RECORDER_H_
#define PCAP_RECORDER2_INCLUDE_RECORDER_H_

#include <memory>
#include <string>
#include <vector>
#include "recorder_node.h"

class Recorder
{
public:
    struct Param
    {
        std::string input_file = "input.txt";
        bool promisc = false;
    };

public:
    Recorder(const Recorder &) = delete;
    Recorder &operator=(const Recorder &) = delete;

    Recorder();
    virtual ~Recorder();

    bool Init(const std::string &input_file, bool promisc);
    void Deinit();

private:
    std::shared_ptr<Param> param_;
    std::vector<std::shared_ptr<RecorderNode>> recorder_nodes_;
};

#endif // !PCAP_RECORDER2_INCLUDE_RECORDER_H_
