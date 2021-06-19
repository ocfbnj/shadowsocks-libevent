#ifndef CONTEXT_H
#define CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

struct context {
    int stage;
    struct bufferevent* out_bev;
};

struct context* alloc_context();
void free_context(struct context* ctx);

#ifdef __cplusplus
}
#endif

#endif
