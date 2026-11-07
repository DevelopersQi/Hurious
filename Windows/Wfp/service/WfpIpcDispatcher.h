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
    DWORD Set(const void* data, size_t size, furious::wfp::Engine* engine = nullptr,
              bool includeUdp = false) noexcept {
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
            const DWORD applyStatus = engine->ApplyApplicationPolicy(compiledCandidate, includeUdp);
            if (applyStatus != ERROR_SUCCESS) return applyStatus;
        }
        policy_.swap(candidate);
        compiledPolicy_.swap(compiledCandidate);
        generation_ = header.PolicyGeneration;
        return ERROR_SUCCESS;
    }

    DWORD Reapply(furious::wfp::Engine* engine, bool includeUdp) const noexcept {
        if (engine == nullptr) return ERROR_INVALID_HANDLE;
        std::vector<furious::wfp::policy::CompiledApplicationRule> snapshot;
        const DWORD copyStatus = CopyCompiledSnapshot(snapshot);
        if (copyStatus != ERROR_SUCCESS) return copyStatus;
        return engine->ApplyApplicationPolicy(snapshot, includeUdp);
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
inline std::mutex& EndpointConfigMutex() noexcept {
    static std::mutex mutex;
    return mutex;
}
inline FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG& EndpointConfigSnapshot() noexcept {
    static FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG config = {};
    return config;
}
inline bool& HasEndpointConfigSnapshot() noexcept {
    static bool configured = false;
    return configured;
}
inline bool IsUdpEndpointConfigured() noexcept {
    std::lock_guard<std::mutex> lock(EndpointConfigMutex());
    return HasEndpointConfigSnapshot() &&
        (EndpointConfigSnapshot().Flags & FURIOUS_WFP_REDIRECT_FLAG_UDP) != 0;
}
inline bool UdpBrokerMatchesEndpoint(
    const FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG& config,
    const furious::wfp::broker::UdpBrokerListenerPorts& ports) noexcept {
    const bool v4 = (config.Flags & FURIOUS_WFP_REDIRECT_FLAG_IPV4) != 0;
    const bool v6 = (config.Flags & FURIOUS_WFP_REDIRECT_FLAG_IPV6) != 0;
    const bool udp = (config.Flags & FURIOUS_WFP_REDIRECT_FLAG_UDP) != 0;
    return udp &&
        ((v4 && config.UdpPortV4 != 0 && config.UdpPortV4 == ports.ipv4) ||
         (!v4 && config.UdpPortV4 == 0 && ports.ipv4 == 0)) &&
        ((v6 && config.UdpPortV6 != 0 && config.UdpPortV6 == ports.ipv6) ||
         (!v6 && config.UdpPortV6 == 0 && ports.ipv6 == 0));
}
inline DWORD SetEndpointConfig(
    const FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG& config,
    furious::wfp::Engine* engine) noexcept {
    if (!furious::wfp::redirect::IsValidEndpointConfig(config))
        return ERROR_INVALID_PARAMETER;
    const bool enableUdp = (config.Flags & FURIOUS_WFP_REDIRECT_FLAG_UDP) != 0;
    if (enableUdp) {
        if (engine == nullptr) return ERROR_INVALID_HANDLE;
        auto& broker = GetUdpBrokerServer();
        if (!broker.IsRunning()) return ERROR_SERVICE_NOT_ACTIVE;
        if (!UdpBrokerMatchesEndpoint(config, broker.ListenerPorts()))
            return ERROR_INVALID_PARAMETER;
        bool serviceExcluded = config.ProxyProcessId == GetCurrentProcessId();
        for (FURIOUS_WFP_U32 i = 0; i < config.ExcludedProcessCount; ++i)
            serviceExcluded = serviceExcluded ||
                config.ExcludedProcessIds[i] == GetCurrentProcessId();
        if (!serviceExcluded) return ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(EndpointConfigMutex());
    const bool hadPrevious = HasEndpointConfigSnapshot();
    const auto previous = EndpointConfigSnapshot();
    DWORD status = furious::wfp::driver::SetEndpointConfig(config);
    if (status != ERROR_SUCCESS) return status;
    if (engine != nullptr) {
        status = GetPolicyStore().Reapply(engine, enableUdp);
        if (status != ERROR_SUCCESS) {
            const DWORD rollback = hadPrevious
                ? furious::wfp::driver::SetEndpointConfig(previous)
                : furious::wfp::driver::ClearEndpointConfig();
            return rollback == ERROR_SUCCESS ? status : rollback;
        }
    }
    EndpointConfigSnapshot() = config;
    HasEndpointConfigSnapshot() = true;
    return ERROR_SUCCESS;
}
inline DWORD ClearEndpointConfig(furious::wfp::Engine* engine) noexcept {
    std::lock_guard<std::mutex> lock(EndpointConfigMutex());
    const bool hadPrevious = HasEndpointConfigSnapshot();
    const auto previous = EndpointConfigSnapshot();
    const bool previousUdp = hadPrevious &&
        (previous.Flags & FURIOUS_WFP_REDIRECT_FLAG_UDP) != 0;
    if (engine != nullptr) {
        const DWORD applyStatus = GetPolicyStore().Reapply(engine, false);
        if (applyStatus != ERROR_SUCCESS) return applyStatus;
    }
    const DWORD status = furious::wfp::driver::ClearEndpointConfig();
    if (status != ERROR_SUCCESS) {
        if (engine != nullptr && previousUdp) GetPolicyStore().Reapply(engine, true);
        return status;
    }
    EndpointConfigSnapshot() = FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG{};
    HasEndpointConfigSnapshot() = false;
    return ERROR_SUCCESS;
}
inline DWORD StopBroker(furious::wfp::Engine* engine) noexcept {
    const DWORD clearStatus = ClearEndpointConfig(engine);
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
inline DWORD StopUdpBroker(furious::wfp::Engine* engine) noexcept {
    std::lock_guard<std::mutex> lock(EndpointConfigMutex());
    const bool configured = HasEndpointConfigSnapshot();
    const auto previous = EndpointConfigSnapshot();
    const bool udpEnabled = configured &&
        (previous.Flags & FURIOUS_WFP_REDIRECT_FLAG_UDP) != 0;
    if (udpEnabled) {
        if (engine == nullptr) return ERROR_INVALID_HANDLE;
        DWORD status = GetPolicyStore().Reapply(engine, false);
        if (status != ERROR_SUCCESS) return status;
        auto tcpOnly = previous;
        tcpOnly.Flags &= ~FURIOUS_WFP_REDIRECT_FLAG_UDP;
        tcpOnly.UdpPortV4 = 0;
        tcpOnly.UdpPortV6 = 0;
        const bool tcpEnabled = (tcpOnly.Flags & FURIOUS_WFP_REDIRECT_FLAG_TCP) != 0;
        status = tcpEnabled ? furious::wfp::driver::SetEndpointConfig(tcpOnly)
                            : furious::wfp::driver::ClearEndpointConfig();
        if (status != ERROR_SUCCESS) {
            GetPolicyStore().Reapply(engine, true);
            return status;
        }
        if (tcpEnabled) EndpointConfigSnapshot() = tcpOnly;
        else {
            EndpointConfigSnapshot() = FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG{};
            HasEndpointConfigSnapshot() = false;
        }
    }
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
    case FURIOUS_WFP_IPC_COMMAND_STOP_BROKER: return payloadSize == 0 ? StopBroker(engine) : ERROR_INVALID_PARAMETER;
    case FURIOUS_WFP_IPC_COMMAND_START_UDP_BROKER: return StartUdpBroker(payload, payloadSize);
    case FURIOUS_WFP_IPC_COMMAND_STOP_UDP_BROKER: return payloadSize == 0 ? StopUdpBroker(engine) : ERROR_INVALID_PARAMETER;
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
        return SetEndpointConfig(config, engine);
    }
    case FURIOUS_WFP_IPC_COMMAND_CLEAR_ENDPOINT_CONFIG:
        if (payloadSize != 0) {
            return ERROR_INVALID_PARAMETER;
        }
        return ClearEndpointConfig(engine);
    case FURIOUS_WFP_IPC_COMMAND_SET_POLICY:
        if (payload == nullptr || payloadSize == 0) {
            return ERROR_INVALID_DATA;
        }
        return GetPolicyStore().Set(payload, payloadSize, engine, IsUdpEndpointConfigured());
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
