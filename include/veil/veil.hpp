#pragma once

// 私有项目，保留全部权利。未经许可不得使用、复制、修改或分发。

#include "config.hpp"
#include "detail/common.hpp"
#include "detail/mix.hpp"
#include "detail/observe.hpp"
#include "crypto/sha256.hpp"
#include "crypto/hmac.hpp"
#include "crypto/hkdf.hpp"
#include "crypto/aes.hpp"
#include "crypto/aes_gcm.hpp"
#include "crypto/ed25519.hpp"
#include "platform/syscall.hpp"
#include "platform/peb.hpp"
#include "platform/memory.hpp"
#include "platform/image_file.hpp"
#include "platform/image_map.hpp"
#include "platform/decode.hpp"
#include "platform/remap.hpp"
#include "platform/scan.hpp"
#include "providers/anti_debug.hpp"
#include "providers/code_integrity.hpp"
#include "providers/module_topo.hpp"
#include "providers/cert_pin.hpp"
#include "providers/entropy.hpp"
#include "evidence/layout.hpp"
#include "evidence/binder.hpp"
#include "license/payload.hpp"
#include "license/signed_envelope.hpp"
#include "guard.hpp"

// transport 不在本入口内。它引入 security.h 并要求先定义
// SECURITY_WIN32，会让所有引用者承担该约束。需要 TLS 的调用方
// 单独包含 transport/tls_client.hpp。
