// MIT License
//
// Copyright (c) 2026 Muhammad Awais Khalid

#pragma once

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_security.h>
extern "C" {
#include <rte_ipsec.h>
}

namespace ipsec_util {

constexpr uint32_t OUTBOUND_SPI = 0x1000;
constexpr uint16_t CRYPTO_QP_ID = 0;
constexpr uint32_t MAX_CRYPTO_SESSIONS = 1;
constexpr uint32_t NUM_CRYPTO_OPS = 4096;
constexpr uint16_t CRYPTO_OP_CACHE = 256;

struct IpsecOutboundContext {
    uint8_t cdev_id {std::numeric_limits<uint8_t>::max()};
    rte_mempool *session_pool {nullptr};
    rte_mempool *crypto_op_pool {nullptr};
    rte_cryptodev_sym_session *sym_session {nullptr};
    rte_ipsec_sa *sa {nullptr};
    rte_ipsec_session ipsec_session {};
};

inline int find_cryptodev()
{
    const uint8_t count = rte_cryptodev_count();
    if (count == 0) {
        std::cerr << "No cryptodev found in the system. " << std::endl;
        return -ENODEV;
    }

    for (uint8_t id = 0; id < count; ++id) {
        rte_cryptodev_info info {};
        rte_cryptodev_info_get(id, &info);
        std::cout << "Cryptodev " << static_cast<unsigned>(id) << ": "
                  << info.driver_name << std::endl;
    }

    return 0;
}

inline int init_cryptodev(IpsecOutboundContext &ctx)
{
    if (find_cryptodev() != 0) {
        return -1;
    }

    ctx.cdev_id = 0;
    const size_t session_size = rte_cryptodev_sym_get_private_session_size(ctx.cdev_id);
    ctx.session_pool = rte_cryptodev_sym_session_pool_create(
        "ipsec_sess_pool", MAX_CRYPTO_SESSIONS, session_size, 0, 0, rte_socket_id());
    if (!ctx.session_pool) {
        std::cerr << "Unable to create cryptodev session pool" << std::endl;
        return -ENOMEM;
    }

    ctx.crypto_op_pool = rte_crypto_op_pool_create(
        "ipsec_crypto_op_pool",
        RTE_CRYPTO_OP_TYPE_SYMMETRIC,
        NUM_CRYPTO_OPS,
        CRYPTO_OP_CACHE,
        sizeof(rte_crypto_sym_xform) * 2,
        rte_socket_id());
    if (!ctx.crypto_op_pool) {
        std::cerr << "Unable to create crypto op pool" << std::endl;
        return -ENOMEM;
    }

    rte_cryptodev_config conf {};
    conf.socket_id = static_cast<int>(rte_socket_id());
    conf.nb_queue_pairs = 1;

    if (rte_cryptodev_configure(ctx.cdev_id, &conf) != 0) {
        std::cerr << "Unable to configure cryptodev " << static_cast<unsigned>(ctx.cdev_id) << std::endl;
        return -1;
    }

    rte_cryptodev_qp_conf qp_conf {};
    qp_conf.nb_descriptors = 2048;
    qp_conf.mp_session = ctx.session_pool;

    if (rte_cryptodev_queue_pair_setup(
            ctx.cdev_id, CRYPTO_QP_ID, &qp_conf, rte_cryptodev_socket_id(ctx.cdev_id)) != 0) {
        std::cerr << "Unable to setup cryptodev queue pair" << std::endl;
        return -1;
    }

    if (rte_cryptodev_start(ctx.cdev_id) != 0) {
        std::cerr << "Unable to start cryptodev" << std::endl;
        return -1;
    }

    return 0;
}

inline int init_outbound_sa(IpsecOutboundContext &ctx)
{
    static rte_crypto_sym_xform cipher_xform {};
    static rte_crypto_sym_xform auth_xform {};

    cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
    cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_NULL;
    cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
    cipher_xform.cipher.key.length = 0;
    cipher_xform.next = &auth_xform;

    auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
    auth_xform.auth.algo = RTE_CRYPTO_AUTH_NULL;
    auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
    auth_xform.auth.digest_length = 0;
    auth_xform.auth.key.length = 0;
    auth_xform.next = nullptr;

    void *session = rte_cryptodev_sym_session_create(
        ctx.cdev_id, &cipher_xform, ctx.session_pool);
    if (!session) {
        std::cerr << "Unable to create cryptodev symmetric session" << std::endl;
        return -ENOMEM;
    }
    ctx.sym_session = static_cast<rte_cryptodev_sym_session *>(session);

    rte_ipsec_sa_prm sa_prm {};
    sa_prm.flags = 0;
    sa_prm.ipsec_xform.spi = OUTBOUND_SPI;
    sa_prm.ipsec_xform.salt = 0;
    sa_prm.ipsec_xform.direction = RTE_SECURITY_IPSEC_SA_DIR_EGRESS;
    sa_prm.ipsec_xform.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP;
    sa_prm.ipsec_xform.mode = RTE_SECURITY_IPSEC_SA_MODE_TRANSPORT;
    sa_prm.ipsec_xform.replay_win_sz = 0;
    sa_prm.trs.proto = IPPROTO_IPIP;
    sa_prm.crypto_xform = &cipher_xform;

    const int sa_size = rte_ipsec_sa_size(&sa_prm);
    if (sa_size <= 0) {
        std::cerr << "Unable to determine IPsec SA size" << std::endl;
        return -EINVAL;
    }

    ctx.sa = static_cast<rte_ipsec_sa *>(rte_zmalloc(
        "ipsec_sa", static_cast<size_t>(sa_size), RTE_CACHE_LINE_SIZE));
    if (!ctx.sa) {
        std::cerr << "Unable to allocate IPsec SA" << std::endl;
        return -ENOMEM;
    }

    if (rte_ipsec_sa_init(ctx.sa, &sa_prm, static_cast<uint32_t>(sa_size)) < 0) {
        std::cerr << "Unable to initialize IPsec SA" << std::endl;
        return -1;
    }

    ctx.ipsec_session.sa = ctx.sa;
    ctx.ipsec_session.type = RTE_SECURITY_ACTION_TYPE_NONE;
    ctx.ipsec_session.crypto.ses = ctx.sym_session;
    ctx.ipsec_session.crypto.dev_id = ctx.cdev_id;

    if (rte_ipsec_session_prepare(&ctx.ipsec_session) != 0) {
        std::cerr << "Unable to prepare IPsec session" << std::endl;
        return -1;
    }

    std::cout << "Outbound ESP transport SA ready. SPI: 0x"
              << std::hex << OUTBOUND_SPI << std::dec
              << " (crypto_null — pipeline demo, not real encryption)" << std::endl;

    return 0;
}

inline void cleanup(IpsecOutboundContext &ctx)
{
    if (ctx.cdev_id != std::numeric_limits<uint8_t>::max()) {
        rte_cryptodev_stop(ctx.cdev_id);
    }

    if (ctx.sym_session && ctx.cdev_id != std::numeric_limits<uint8_t>::max()) {
        rte_cryptodev_sym_session_free(ctx.cdev_id, ctx.sym_session);
        ctx.sym_session = nullptr;
    }

    if (ctx.sa) {
        rte_ipsec_sa_fini(ctx.sa);
        rte_free(ctx.sa);
        ctx.sa = nullptr;
    }

    if (ctx.crypto_op_pool) {
        rte_mempool_free(ctx.crypto_op_pool);
        ctx.crypto_op_pool = nullptr;
    }

    if (ctx.session_pool) {
        rte_mempool_free(ctx.session_pool);
        ctx.session_pool = nullptr;
    }
}

} // namespace ipsec_util
