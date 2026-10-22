// SPDX-License-Identifier: BSD-3-Clause
#ifndef FP_NODE_MOBILE_H
#define FP_NODE_MOBILE_H
#include <stdint.h>
// Event: 1 = applied routes (return 0 only after OS settings succeed),
// 2 = ready, 3 = engine exit. JSON is borrowed for the duration of the call.
// Never synchronously stop from a callback; stop joins the engine thread.
typedef int32_t (*fp_mobile_event)(uint64_t generation, uint32_t event, const char *json);
char *fp_mobile_keypair(void);
char *fp_mobile_enroll(const char *request);
// fd is borrowed during start; the engine owns its own duplicate.
char *fp_mobile_start(const char *config, int32_t fd, uint64_t generation, fp_mobile_event callback);
char *fp_mobile_stop(uint64_t generation);
void fp_mobile_free(char *value);
#endif
