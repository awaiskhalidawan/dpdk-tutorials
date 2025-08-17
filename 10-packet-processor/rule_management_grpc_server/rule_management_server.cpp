#include "rule_management_server.hpp"
#include <iostream>
#include <memory>
#include <string>

#include "rule_messages.grpc.pb.h"

using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReaderWriter;
using grpc::Status;
using grpc_cpp_server::RuleManager;
using grpc_cpp_server::RuleCreateRequest;
using grpc_cpp_server::RuleCreateResponse;
using grpc_cpp_server::RuleDeleteRequest;
using grpc_cpp_server::RuleDeleteResponse;

class RuleIngestorServiceImpl final : public RuleManager::Service {
public:
    Status StreamDataBidirectional1(ServerContext* context,
                                    ServerReaderWriter<RuleCreateResponse, RuleCreateRequest>* stream) override {
        RuleCreateRequest req;
        uint64_t server_id_counter = 1000;

        while (stream->Read(&req)) {
            std::cout << "[Server] Create request: " << req.rule_str()
                      << " client_id=" << req.rule_client_id() << std::endl;

            RuleCreateResponse resp;
            resp.set_rule_client_id(req.rule_client_id());
            resp.set_rule_server_id(++server_id_counter);

            std::cout << "[Server] Sending Create Response: client_id="
                      << resp.rule_client_id()
                      << " server_id=" << resp.rule_server_id() << std::endl;

            stream->Write(resp);
        }
        return Status::OK;
    }

    Status StreamDataBidirectional2(ServerContext* context,
                                    ServerReaderWriter<RuleDeleteResponse, RuleDeleteRequest>* stream) override {
        RuleDeleteRequest req;

        while (stream->Read(&req)) {
            std::cout << "[Server] Delete request: client_id=" << req.rule_client_id()
                      << " server_id=" << req.rule_server_id() << std::endl;

            RuleDeleteResponse resp;
            resp.set_rule_client_id(req.rule_client_id());
            resp.set_rule_server_id(req.rule_server_id());

            std::cout << "[Server] Sending Delete Response: client_id="
                      << resp.rule_client_id()
                      << " server_id=" << resp.rule_server_id() << std::endl;

            stream->Write(resp);
        }
        return Status::OK;
    }
};

rule_management_server& rule_management_server::get_instance() {
    static rule_management_server obj;
    return obj;
}

void rule_management_server::start(const std::string &server_address) {
    if (server) {
        std::cout << "Rule management server already listening on: " << this->server_address << std::endl;
        return;
    }

    this->server_address = server_address;
    RuleIngestorServiceImpl service;

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    server = builder.BuildAndStart();
    std::cout << "Rule management server listening on " << server_address << std::endl;

    server->Wait();
}

void rule_management_server::stop() {
    if (server) {
        std::cout << "Shuting down rule management server. " << std::endl;
        server->Shutdown();
    }
}

