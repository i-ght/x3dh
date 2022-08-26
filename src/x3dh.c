#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define ARRAY_COUNT(a) (sizeof(a)/sizeof(*a))

enum {OK=0, ERR=-1};
enum {ZERO=0};
enum {MAX_DH_CALCULATIONS=3};

enum SecretOrPublic {SECRET=0, PUBLIC=1};

struct EDKeyPair
{
    uint8_t secret[crypto_sign_SECRETKEYBYTES];
    uint8_t public[crypto_sign_PUBLICKEYBYTES];
};

struct ECKeyPair
{
    uint8_t secret[crypto_scalarmult_SCALARBYTES];
    uint8_t public[crypto_scalarmult_BYTES]; 
};


/* https://gist.github.com/domnikl/af00cc154e3da1c5d965 */
void print_hex(
    const char* desc,
    const void* addr,
    const uint32_t len) 
{
    uint8_t buff[17] = {0};
    uint8_t *pc = (uint8_t*)addr;

    // Output description if given.
    if (desc != NULL)
        printf("%s:\n", desc);
    
    uint32_t i = {0};
    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }

        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf("  %s\n", buff);
}



static int ed_key_pair_generate_of_seed(
    struct EDKeyPair* ed_key_pair,
    const char seed[crypto_sign_SEEDBYTES])
{
    if (OK !=
        crypto_sign_seed_keypair(
            ed_key_pair->public,
            ed_key_pair->secret,
            (const unsigned char*)&seed[0]
        )
    ) {
        return ERR;
    }

    return OK;
}

static int ec_key_pair_generate_of_seed(
    struct ECKeyPair* ec_key_pair,
    const char seed[crypto_box_SEEDBYTES])
{
    if (OK !=
        crypto_box_seed_keypair(
            &ec_key_pair->public[0],
            &ec_key_pair->secret[0],
            (const unsigned char*)&seed[0]
        )
    ) {
        return ERR;
    }

    return OK;
}

static void ec_key_pair_construct(
    struct ECKeyPair* ec_key_pair,
    const uint8_t secret[crypto_scalarmult_SCALARBYTES],
    const uint8_t public[crypto_scalarmult_BYTES])
{
    void* _[] = {
        memmove(
            ec_key_pair->secret,
            secret,
            crypto_scalarmult_SCALARBYTES
        ),
        memmove(
            ec_key_pair->public,
            secret,
            crypto_scalarmult_BYTES
        )
    };
}

static int ec_key_pair_of_ed_key_pair(
    const struct EDKeyPair* ed_key_pair,
    struct ECKeyPair* ec_key_pair)
{
   /* https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519 */

    for (enum SecretOrPublic i = 0; i <= PUBLIC; i++) {
        const int seq[] = {
            crypto_sign_ed25519_sk_to_curve25519(
                &ec_key_pair->secret[0],
                &ed_key_pair->secret[0]
            ),
            crypto_sign_ed25519_pk_to_curve25519(
                &ec_key_pair->public[0],
                &ed_key_pair->public[0]
            ),
        };
        
        for (int j = 0; j < ARRAY_COUNT(seq); j++) {
            if (OK != seq[j]) {
                return ERR;
            }
        }    
    }

    return OK;
}

/*
    DH1 = DH(IKA, SPKB)
    DH2 = DH(EKA, IKB)
    DH3 = DH(EKA, SPKB)
    SK = KDF(DH1 || DH2 || DH3)
*/
static void x3dh_arrange_key_pairs_for_alice(
    const uint8_t ika[crypto_scalarmult_curve25519_BYTES],
    const uint8_t spkb[crypto_scalarmult_curve25519_BYTES],
    const uint8_t eka[crypto_scalarmult_curve25519_BYTES],
    const uint8_t ikb[crypto_scalarmult_curve25519_BYTES],
    uint8_t key_pairs[MAX_DH_CALCULATIONS][2][crypto_scalarmult_curve25519_BYTES])
{
    void* _[] = {
        memmove(
            &key_pairs[0][SECRET][0],
            ika,
            crypto_scalarmult_BYTES        
        ),
        memmove(
            &key_pairs[0][PUBLIC][0],
            spkb,
            crypto_scalarmult_BYTES        
        ),
        memmove(
            &key_pairs[1][SECRET][0],
            eka,
            crypto_scalarmult_BYTES        
        ),
        memmove(
            &key_pairs[1][PUBLIC][0],
            ikb,
            crypto_scalarmult_BYTES        
        ),
        memmove(
            &key_pairs[2][SECRET][0],
            eka,
            crypto_scalarmult_BYTES        
        ),
        memmove(
            &key_pairs[2][PUBLIC][0],
            spkb,
            crypto_scalarmult_BYTES        
        ),  
    };
}


/*
    DH1 = DH(SPKB, IKA)
    DH2 = DH(IKB, EKA)
    DH3 = DH(SPKB, EKA)
    SK = KDF(DH1 || DH2 || DH3)
*/
static void x3dh_arrange_key_pairs_for_bob(
    const uint8_t spkb[crypto_scalarmult_curve25519_BYTES],
    const uint8_t ika[crypto_scalarmult_curve25519_BYTES],
    const uint8_t ikb[crypto_scalarmult_curve25519_BYTES],
    const uint8_t eka[crypto_scalarmult_curve25519_BYTES],
    uint8_t key_pairs[MAX_DH_CALCULATIONS][2][crypto_scalarmult_curve25519_BYTES])
{
    void* _[] = {
        memmove(
            &key_pairs[0][SECRET][0],
            spkb,
            crypto_scalarmult_BYTES        
        ),
        memmove(
            &key_pairs[0][PUBLIC][0],
            ika,
            crypto_scalarmult_BYTES        
        ),
        memmove(
            &key_pairs[1][SECRET][0],
            ikb,
            crypto_scalarmult_BYTES        
        ),
        memmove(
            &key_pairs[1][PUBLIC][0],
            eka,
            crypto_scalarmult_BYTES        
        ),
        memmove(
            &key_pairs[2][SECRET][0],
            spkb,
            crypto_scalarmult_BYTES        
        ),
        memmove(
            &key_pairs[2][PUBLIC][0],
            eka,
            crypto_scalarmult_BYTES        
        ),  
    };
}

static int x3dh(
    const uint8_t key_pairs[MAX_DH_CALCULATIONS][2][crypto_scalarmult_curve25519_BYTES],
    uint8_t shared_secret[crypto_generichash_BYTES])
{
    crypto_generichash_state hash_state = {0};

    const uint8_t* key = NULL;
    const size_t key_len = ZERO;

    if (OK !=
        crypto_generichash_init(
            &hash_state,
            key,
            key_len,
            crypto_generichash_BYTES
        )
    ) {
        return ERR;
    }


    for (int i = 0; i < MAX_DH_CALCULATIONS; i++) {

        const uint8_t* secret = &key_pairs[i][SECRET][0];
        if (NULL == secret) { 
            break;
        }

        const uint8_t* public = &key_pairs[i][PUBLIC][0];

        if (OK !=
            crypto_scalarmult(
                shared_secret,
                secret,
                public
            )
        ) {
            return ERR;
        }

        if (OK !=
            crypto_generichash_update(
                &hash_state,
                shared_secret,
                crypto_generichash_BYTES
            )
        ) {
            return ERR;
        }

        print_hex("secret=", secret, 32);
        print_hex("public=", public, 32);
        print_hex("shared=", shared_secret, crypto_generichash_BYTES);
        printf("====\n");
    }

    if (OK !=
        crypto_generichash_final(
            &hash_state,
            shared_secret,
            crypto_generichash_BYTES
        )
    ) {
        return ERR;
    }

    return OK;
}

static int construct_id_pairs(
    struct EDKeyPair* sign_id,
    struct ECKeyPair* id,
    const char id_seed[crypto_sign_SEEDBYTES])
{
    if (OK != 
        ed_key_pair_generate_of_seed(
            sign_id,
            &id_seed[0]
        )
    ) {
        return ERR;
    }

    if (OK !=
        ec_key_pair_of_ed_key_pair(
            sign_id,
            id
        )
    ) {
        return ERR;
    }

    return OK;
}

static int x3dh_bob_construct(
    struct EDKeyPair* sign_id,
    struct ECKeyPair* id,
    struct ECKeyPair* signed_prekey,
    const char id_seed[crypto_sign_SEEDBYTES],
    const char signed_prekey_seed[crypto_box_SEEDBYTES])
{
    if (OK !=
        construct_id_pairs(
            sign_id,
            id,
            id_seed
        ))
    {
        return ERR;
    }
    
    if (OK !=
        ec_key_pair_generate_of_seed(
            signed_prekey,
            signed_prekey_seed
        )
    ) {
        return ERR;
    }
    
    return OK;
}

static int x3dh_alice_construct(
    struct EDKeyPair* sign_id,
    struct ECKeyPair* id,
    struct ECKeyPair* ephemeral,
    const char id_seed[crypto_sign_SEEDBYTES],
    const char ephemeral_seed[crypto_box_SEEDBYTES])
{
    return
        x3dh_bob_construct(
            sign_id,
            id,
            ephemeral,
            id_seed,
            ephemeral_seed
        );
}

int main(void)
{   
    if (OK != sodium_init()) {
        return EXIT_FAILURE;
    }

    struct ECKeyPair alice_id = {0};
    struct EDKeyPair alice_sign_id = {0};
    struct ECKeyPair alice_ephemeral = {0};
    static const char alice_id_seed[crypto_sign_SEEDBYTES] = "alice";
    static const char alice_ephemeral_seed[crypto_box_SEEDBYTES] = "alice-ephemeral";
    
    if (OK !=
        x3dh_alice_construct(
            &alice_sign_id,
            &alice_id,
            &alice_ephemeral,
            &alice_id_seed[0],
            &alice_ephemeral_seed[0]
        )
    ) {
        return EXIT_FAILURE;
    }

    struct ECKeyPair bob_id = {0};
    struct EDKeyPair bob_sign_id = {0};
    struct ECKeyPair bob_signed_prekey = {0};
    static const char bob_id_seed[crypto_sign_SEEDBYTES] = "bob";
    static const char bob_spk_seed[crypto_box_SEEDBYTES] = "bob-spk";
    
    if (OK !=
        x3dh_bob_construct(
            &bob_sign_id,
            &bob_id,
            &bob_signed_prekey,
            &bob_id_seed[0],
            &bob_spk_seed[0]
        )
    ) {
        return EXIT_FAILURE;
    }


    uint8_t alice_key_pairs[MAX_DH_CALCULATIONS][2][crypto_scalarmult_curve25519_BYTES] = {0};
    uint8_t bob_key_pairs[MAX_DH_CALCULATIONS][2][crypto_scalarmult_curve25519_BYTES] = {0};

    x3dh_arrange_key_pairs_for_alice(
        &alice_id.secret[0],
        &bob_signed_prekey.public[0],
        &alice_ephemeral.secret[0],
        &bob_id.public[0],
        &alice_key_pairs[0]
    );

    x3dh_arrange_key_pairs_for_bob(
        &bob_signed_prekey.secret[0],
        &alice_id.public[0],
        &bob_id.secret[0],
        &alice_ephemeral.public[0],
        bob_key_pairs
    );

    uint8_t shared_secret_0[crypto_generichash_BYTES] = {0};
    uint8_t shared_secret_1[crypto_generichash_BYTES] = {0};

    if (OK !=
        x3dh(
            alice_key_pairs,
            &shared_secret_0[0]
        )
    ) {
        return EXIT_FAILURE;
    }

    if (OK !=
        x3dh(
            bob_key_pairs,
            &shared_secret_1[0]
        )
    ) {
        return EXIT_FAILURE;
    }
    
    print_hex("shared_secret_0=", shared_secret_0, crypto_generichash_BYTES);
    print_hex("shared_secret_1=", shared_secret_1, crypto_generichash_BYTES);
    
    assert(
        0 ==
        memcmp(
            shared_secret_0,
            shared_secret_1,
            crypto_generichash_BYTES
        )
    );

    const int _ = printf("OK\n");

    return EXIT_SUCCESS;
}