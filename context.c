#include <assert.h>
#include <stdlib.h>

#include "context.h"

struct context* alloc_context() {
    struct context* ctx = calloc(1, sizeof(struct context));
    assert(ctx);
    ctx->stage = 1;

    return ctx;
}

void free_context(struct context* ctx) { free(ctx); }
