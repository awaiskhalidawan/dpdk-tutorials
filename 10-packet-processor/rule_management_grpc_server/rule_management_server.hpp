#pragma once
#include <string>
#include <memory>
#include <grpcpp/grpcpp.h>

using grpc::Server;

class rule_management_server {
    public:
    static rule_management_server& get_instance();

    void start(const std::string &server_address);

    void stop();

    private:
    rule_management_server() = default;

    std::unique_ptr<Server> server {nullptr};

    std::string server_address;
};

