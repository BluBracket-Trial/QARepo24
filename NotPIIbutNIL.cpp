
#include "../include/hax.h"
#include "include/memory.h"
#include "../include/hax_host_mem.h"
#include "include/paging.h"

int chunk_alloc(uint64_t base_uva, uint64_t size, hax_chunk **chunk)
{
    hax_chunk *chk;
    int ret;

    if (!chunk) {
        hax_log(HAX_LOGE, "chunk_alloc: chunk is NULL\n");
        return -EINVAL;
    }

    if ((base_uva & (PAGE_SIZE_4K - 1)) != 0) {
        hax_log(HAX_LOGE, "chunk_alloc: base_uva 0x%llx is not page aligned.\n",
                base_uva);
        return -EINVAL;
    }

    if ((size & (PAGE_SIZE_4K - 1)) != 0) {
        hax_log(HAX_LOGE, "chunk_alloc: size 0x%llx is not page aligned.\n",
                size);
        return -EINVAL;
    }

    chk = hax_vmalloc(sizeof(hax_chunk), 0);
    if (!chk) {
        hax_log(HAX_LOGE, "hax_chunk: vmalloc failed.\n");
        return -ENOMEM;
    }

    chk->base_uva = base_uva;
    chk->size = size;
    ret = hax_pin_user_pages(base_uva, size, &chk->memdesc);
    if (ret) {
        hax_log(HAX_LOGE, "hax_chunk: pin user pages failed,"
                " uva: 0x%llx, size: 0x%llx.\n", base_uva, size);
        hax_vfree(chk, sizeof(hax_chunk));
        return ret;
    }

    *chunk = chk;
    return 0;
}

int chunk_free(hax_chunk *chunk)
{
    int ret;

    if (!chunk) {
        hax_log(HAX_LOGE, "chunk_free: chunk is NULL.\n");
        return -EINVAL;
    }

    ret = hax_unpin_user_pages(&chunk->memdesc);
    if (ret) {
        hax_log(HAX_LOGE, "chunk_free: unpin user pages failed.\n");
        return ret;
    }

    hax_vfree(chunk, sizeof(hax_chunk));

    return 0;
}



Code 2;

Blacklist;
Master;
mikes@pizza.com;
456-65-6543;
