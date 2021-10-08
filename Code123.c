
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



Secret Type
	

Description
	

Example(s)

password_assignment
	

Potential password assignment
	

`PaSswOrd` = '13579'

secret_assignment
	

Potential secret assignment
	

`"test_token_123" = "my_secret_token"`

credential_assignment
	

Potential credential assignment
	

`AWS_creDentiAl: 'some-string'

google_api_key
	

Potential Google API key
	

`AIzaSyA-k3UmEeCD6KpySp3cSAlGJwXTNV_oybM`

google_api_key_base64
	

Potential Google API key (base64)
	

`QUl6YVN5QS1rM1VtRWVDRDZLcHlTcDNjU0FsR0p3WFROVl9veWJN`

google_oauth
	

Potential Google OAuth
	

`3572-b3w78sfasfcvs87fasdf6hbvefs21nb3.apps.googleusercontent.com'`

google_oauth_access_token
	

Potential Google OAuth access token
	

`ya29.sd8keCms2swx2sJNW8kWxqzj3`

google_oauth_access_token_base64
	

Potential Google OAuth access token (base64)
	

`eWEyOS5zZDhrZUNtczJzd3gyc0pOVzhrV3hxemoz`

aws_access_key_id
	

Potential AWS access key ID
	

`AKIA2E0A8F3B244C9986`

aws_access_key_id_base64
	

Potential AWS access key ID (base64)

	

`QUtJQTJFMEE4RjNCMjQ0Qzk5ODY non-token`

aws_secret_key
	

Potential AWS Secret key
	

`awS_secret="7CE556A3BC234CC1FF9E8A5C324C0BB70AA21B6D"`

aws_account_id
	

Potential AWS account ID
	

`"aWs_account": "3238-1075-6278"`

aws_mws_key
	

Potential AWS MWS key
	

`amzn.mws.a8fc03d7-7eb3-c92f-b3aa-ae93cbff7acd`

aws_mws_key_base64
	

Potential AWS MWS key (base64)
	

`YW16bi5td3MuYThmYzAzZDctN2ViMy1jOTJmLWIzYWEtYWU5M2NiZmY3YWNk`

github_token
	

Potential GitHub token
	

"`githUb_token`: '9qjxsjq6HWBXKAOP87IJHmhsW8038d73Dm9eDu'"

github_access_token|github_oauth_client_secret
	

Potential GitHub Personal Access Token or OAuth Client Secret
	

`gIthub-access_token = '2b30cc694989f335a4298067c4753a6c09ccfe5e'`

github_token_base64|github_access_token_base64|github_oauth_client_secret_base64
	

Potential GitHub Personal Access Token or OAuth Client Secret (base64)
	

