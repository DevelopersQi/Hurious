#pragma once

#include <windows.h>

#include "../include/WfpControlProtocol.h"
#include "WfpDriverClient.h"
#include "WfpEngine.h"
#include "WfpPolicyCompiler.h"
#include "../broker/WfpTcpBrokerServer.h"
#include "../broker/WfpUdpBrokerServer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

namespace furious::wfp::ipc {

class PolicyStore final {
public:
    DWORD Set(const void* data, size_t size, furious::wfp::Engine* engine = nullptr) noexcept {
        if (furious::wfp::policy::ValidatePolicy(data, size) !=
            furious::wfp::policy::ValidationResult::Valid) {
            return ERROR_INVALID_DATA;
        }

        FURIOUS_WFP_POLICY_HEADER header = {};
        std::memcpy(&header, data, sizeof(header));

        std::vector<uint8_t> candidate;
        std::vector<furious::wfp::policy::CompiledApplicationRule> compiledCandidate;
        try {
            const auto* first = static_cast<const uint8_t*>(data);
            candidate.assign(first, first + size);
        } catch (...) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        const DWORD compileStatus = furious::wfp::policy::CompilePolicy(
            data, size, compiledCandidate);
        if (compileStatus != ERROR_SUCCESS) {
            return compileStatus;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (header.PolicyGeneration <= generation_) {
            return ERROR_REVISION_MISMATCH;
        }
        if (engine != nullptr) {
            const DWORD applyStatus = engine->ApplyApplicationPolicy(compiledCandidate);
            if (applyStatus != ERROR_SUCCESS) return applyStatus;
        }
        policy_.swap(candidate);
        compiledPolicy_.swap(compiledCandidate);
        generation_ = header.PolicyGeneration;
        return ERROR_SUCCESS;
    }

    DWORD CopySnapshot(std::vector<uint8_t>& output, uint64_t* generation = nullptr) const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        try {
            output = policy_;
        } catch (...) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        if (generation != nullptr) {
            *generation = generation_;
        }
        return ERROR_SUCCESS;
    }

    DWORD CopyCompiledSnapshot(
        std::vector<furious::wfp::policy::CompiledApplicationRule>& output) const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        try {
            output = compiledPolicy_;
        } catch (...) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        return ERROR_SUCCESS;
    }

    DWORD Clear(furious::wfp::Engine* engine = nullptr) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (engine != nullptr) {
            const std::vector<furious::wfp::policy::CompiledApplicationRule> empty;
            const DWORD applyStatus = engine->ApplyApplicationPolicy(empty);
            if (applyStatus != ERROR_SUCCESS) return applyStatus;
        }
        policy_.clear();
        compiledPolicy_.clear();
        return ERROR_SUCCESS;
    }

private:
    mutable std::mutex mutex_;
    std::vector<uint8_t> policy_;
    std::vector<furious::wfp::policy::CompiledApplicationRule> compiledPolicy_;
    uint64_t generation_ = 0;
};

inline PolicyStore& GetPolicyStore() noexcept {
    static PolicyStore store;
    return store;
}

inline DWORD CopyPolicySnapshot(std::vector<uint8_t>& output,
                                uint64_t* generation = nullptr) noexcept {
    return GetPolicyStore().CopySnapshot(output, generation);
}

inline DWORD CopyCompiledPolicySnapshot(
    std::vector<furious::wfp::policy::CompiledApplicationRule>& output) noexcept {
    return GetPolicyStore().CopyCompiledSnapshot(output);
}

inline furious::wfp::broker::TcpBrokerServer& GetTcpBrokerServer() noexcept {
    static furious::wfp::broker::TcpBrokerServer server;
    return server;
}
inline furious::wfp::broker::UdpBrokerServer& GetUdpBrokerServer() noexcept {
    static furious::wfp::broker::UdpBrokerServer server;
    return server;
}
inline DWORD StopBroker() noexcept {
    const DWORD clearStatus = furious::wfp::driver::ClearEndpointConfig();
    if (clearStatus != ERROR_SUCCESS &&
        clearStatus != ERROR_FILE_NOT_FOUND &&
        clearStatus != ERROR_PATH_NOT_FOUND) {
        // Keep listeners alive if the driver may still redirect traffic to them.
        return clearStatus;
    }
    GetTcpBrokerServer().Stop();
    GetUdpBrokerServer().Stop();
    return ERROR_SUCCESS;
}
inline DWORD StopUdpBroker() noexcept {
    // UDP endpoint configuration and redirect filters remain deliberately disabled.
    GetUdpBrokerServer().Stop();
    return ERROR_SUCCESS;
}
inline void PopulateBrokerResponse(FURIOUS_WFP_IPC_RESPONSE* response) noexcept {
    if (response == nullptr) return;
    auto& tcp = GetTcpBrokerServer();
    auto& udp = GetUdpBrokerServer();
    const bool tcpRunning = tcp.IsRunning();
    const bool udpRunning = udp.IsRunning();
    const auto tcpPorts = tcpRunning ? tcp.ListenerPorts() : furious::wfp::broker::TcpBrokerListenerPorts{};
    const auto udpPorts = udpRunning ? udp.ListenerPorts() : furious::wfp::broker::UdpBrokerListenerPorts{};
    response->BrokerProcessId = (tcpRunning || udpRunning) ? GetCurrentProcessId() : 0;
    response->TcpPortV4 = tcpPorts.ipv4;
    response->TcpPortV6 = tcpPorts.ipv6;
    response->UdpPortV4 = udpPorts.ipv4;
    response->UdpPortV6 = udpPorts.ipv6;
}
inline DWORD StartBroker(const void* payload, size_t payloadSize) noexcept {
    if (payload == nullptr || payloadSize != sizeof(FURIOUS_WFP_BROKER_START_REQUEST)) return ERROR_INVALID_DATA;
    FURIOUS_WFP_BROKER_START_REQUEST request = {};
    std::memcpy(&request, payload, sizeof(request));
    if (request.Size != sizeof(request) || request.AbiVersion != FURIOUS_WFP_BROKER_ABI_VERSION || request.Reserved != 0 || request.SocksPort == 0 || (request.Flags & ~FURIOUS_WFP_BROKER_KNOWN_FLAGS) != 0 || request.Flags == 0) return ERROR_INVALID_PARAMETER;
    auto& broker = GetTcpBrokerServer();
    sockaddr_storage address = {};
    int addressLength = 0;
    if (request.SocksAddressFamily == FURIOUS_WFP_BROKER_FAMILY_IPV4) {
        for (size_t i = 4; i < sizeof(request.SocksAddress); ++i) if (request.SocksAddress[i] != 0) return ERROR_INVALID_PARAMETER;
        auto* ipv4 = reinterpret_cast<sockaddr_in*>(&address); ipv4->sin_family = AF_INET; ipv4->sin_port = htons(request.SocksPort);
        std::memcpy(&ipv4->sin_addr, request.SocksAddress, 4); addressLength = sizeof(sockaddr_in);
    } else if (request.SocksAddressFamily == FURIOUS_WFP_BROKER_FAMILY_IPV6) {
        auto* ipv6 = reinterpret_cast<sockaddr_in6*>(&address); ipv6->sin6_family = AF_INET6; ipv6->sin6_port = htons(request.SocksPort);
        std::memcpy(&ipv6->sin6_addr, request.SocksAddress, 16); addressLength = sizeof(sockaddr_in6);
    } else return ERROR_INVALID_PARAMETER;
    if (broker.IsRunning() && !broker.IsConfiguredFor(
            reinterpret_cast<const sockaddr*>(&address), addressLength)) {
        FURIOUS_WFP_DRIVER_STATUS driverStatus = {};
        const DWORD queryStatus = furious::wfp::driver::QueryStatus(&driverStatus);
        if (queryStatus == ERROR_SUCCESS &&
            (driverStatus.Flags & FURIOUS_WFP_DRIVER_FLAG_ENDPOINT_CONFIGURED) != 0) {
            const DWORD clearStatus = furious::wfp::driver::ClearEndpointConfig();
            if (clearStatus != ERROR_SUCCESS) return clearStatus;
        } else if (queryStatus != ERROR_SUCCESS &&
                   queryStatus != ERROR_FILE_NOT_FOUND &&
                   queryStatus != ERROR_PATH_NOT_FOUND) {
            return queryStatus;
        }
        broker.Stop();
    } else if (broker.IsRunning()) {
        return ERROR_SUCCESS;
    }
    const bool listenV4 = (request.Flags & FURIOUS_WFP_BROKER_FLAG_LISTEN_IPV4) != 0;
    const bool listenV6 = (request.Flags & FURIOUS_WFP_BROKER_FLAG_LISTEN_IPV6) != 0;
    return broker.Start(reinterpret_cast<const sockaddr*>(&address), addressLength, listenV4, listenV6) ? ERROR_SUCCESS : ERROR_GEN_FAILURE;
}
inline DWORD StartUdpBroker(const void* payload, size_t payloadSize) noexcept {
    if (payload == nullptr || payloadSize != sizeof(FURIOUS_WFP_BROKER_START_REQUEST))
        return ERROR_INVALID_DATA;
    FURIOUS_WFP_BROKER_START_REQUEST request = {};
    std::memcpy(&request, payload, sizeof(request));
    if (request.Size != sizeof(request) ||
        request.AbiVersion != FURIOUS_WFP_BROKER_ABI_VERSION ||
        request.Reserved != 0 || request.SocksPort == 0 ||
        (request.Flags & ~FURIOUS_WFP_BROKER_KNOWN_FLAGS) != 0 ||
        request.Flags == 0) return ERROR_INVALID_PARAMETER;
    sockaddr_storage address = {};
    int addressLength = 0;
    if (request.SocksAddressFamily == FURIOUS_WFP_BROKER_FAMILY_IPV4) {
        for (size_t i = 4; i < sizeof(request.SocksAddress); ++i)
            if (request.SocksAddress[i] != 0) return ERROR_INVALID_PARAMETER;
        auto* ipv4 = reinterpret_cast<sockaddr_in*>(&address);
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(request.SocksPort);
        std::memcpy(&ipv4->sin_addr, request.SocksAddress, 4);
        addressLength = sizeof(sockaddr_in);
    } else if (request.SocksAddressFamily == FURIOUS_WFP_BROKER_FAMILY_IPV6) {
        auto* ipv6 = reinterpret_cast<sockaddr_in6*>(&address);
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(request.SocksPort);
        std::memcpy(&ipv6->sin6_addr, request.SocksAddress, 16);
        addressLength = sizeof(sockaddr_in6);
    } else return ERROR_INVALID_PARAMETER;
    auto& broker = GetUdpBrokerServer();
    if (broker.IsRunning()) return ERROR_ALREADY_EXISTS;
    const bool listenV4 = (request.Flags & FURIOUS_WFP_BROKER_FLAG_LISTEN_IPV4) != 0;
    const bool listenV6 = (request.Flags & FURIOUS_WFP_BROKER_FLAG_LISTEN_IPV6) != 0;
    return broker.Start(reinterpret_cast<const sockaddr*>(&address), addressLength,
        listenV4, listenV6) ? ERROR_SUCCESS : ERROR_GEN_FAILURE;
}
inline DWORD DispatchCommand(uint32_t command,
                             const void* payload,
                             size_t payloadSize,
                             furious::wfp::Engine* engine = nullptr) noexcept {
    switch (command) {
    case FURIOUS_WFP_IPC_COMMAND_START_BROKER: return StartBroker(payload, payloadSize);
    case FURIOUS_WFP_IPC_COMMAND_STOP_BROKER: return payloadSize == 0 ? StopBroker() : ERROR_INVALID_PARAMETER;
    case FURIOUS_WFP_IPC_COMMAND_START_UDP_BROKER: return StartUdpBroker(payload, payloadSize);
    case FURIOUS_WFP_IPC_COMMAND_STOP_UDP_BROKER: return payloadSize == 0 ? StopUdpBroker() : ERROR_INVALID_PARAMETER;
    case FURIOUS_WFP_IPC_COMMAND_STATUS:
        return payloadSize == 0 ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
    case FURIOUS_WFP_IPC_COMMAND_DRIVER_STATUS: {
        if (payloadSize != 0) {
            return ERROR_INVALID_PARAMETER;
        }
        FURIOUS_WFP_DRIVER_STATUS status = {};
        return furious::wfp::driver::QueryStatus(&status);
    }
    case FURIOUS_WFP_IPC_COMMAND_SET_ENDPOINT_CONFIG: {
        if (payload == nullptr ||
            payloadSize != sizeof(FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG)) {
            return ERROR_INVALID_DATA;
        }
        FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG config = {};
        std::memcpy(&config, payload, sizeof(config));
        // The kernel ABI reserves UDP endpoint fields for forward compatibility,
        // but the service has no UDP relay yet. Reject UDP at the IPC boundary
        // so an accidental caller cannot configure an unusable redirect target.
        if ((config.Flags & FURIOUS_WFP_REDIRECT_FLAG_UDP) != 0 ||
            config.UdpPortV4 != 0 || config.UdpPortV6 != 0) {
            return ERROR_NOT_SUPPORTED;
        }
        return furious::wfp::driver::SetEndpointConfig(config);
    }
    case FURIOUS_WFP_IPC_COMMAND_CLEAR_ENDPOINT_CONFIG:
        if (payloadSize != 0) {
            return ERROR_INVALID_PARAMETER;
        }
        return furious::wfp::driver::ClearEndpointConfig();
    case FURIOUS_WFP_IPC_COMMAND_SET_POLICY:
        if (payload == nullptr || payloadSize == 0) {
            return ERROR_INVALID_DATA;
        }
        return GetPolicyStore().Set(payload, payloadSize, engine);
    case FURIOUS_WFP_IPC_COMMAND_CLEAR_POLICY:
        if (payloadSize != 0) {
            return ERROR_INVALID_PARAMETER;
        }
        return GetPolicyStore().Clear(engine);
    default:
        return ERROR_INVALID_FUNCTION;
    }
}

} // namespace furious::wfp::ipc
