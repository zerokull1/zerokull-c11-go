// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
#ifndef ZK_GPU_RING_H
#define ZK_GPU_RING_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    ZK_ACCEL_CPU_SWAR     = 0,
    ZK_ACCEL_GENERIC_GPU  = 1,
    ZK_ACCEL_DIRECT_RING  = 2
} ZkAccelMode;

typedef struct {
    ZkAccelMode mode;
    uint32_t vendor_id;
    uint32_t ndesc;
    uint32_t cur_put;
    uint32_t ring_mask;
    uint64_t *ring_ptr;
    const volatile uint32_t *get_ptr;
    volatile uint32_t *put_ptr;
    uint64_t desc[64];
    char device_name[128];
} ZkGpuRingCtx;

void zk_gpu_ring_init(ZkGpuRingCtx *ctx);
int  zk_gpu_ring_submit_batch(ZkGpuRingCtx *ctx);
uint32_t zk_swar_batch_entropy_score(const uint8_t *buf, size_t len);

#endif
