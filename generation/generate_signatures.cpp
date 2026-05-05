#include "shrincs.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <stdexcept>

using namespace SHRINCS;

static unsigned char MASTER_SEED[48] = {
    0x4c,0x50,0x41,0x53,0x53,0x5f,0x4c,0x00,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37
};

// Helper to write a hex string to the file
static void fprint_hex(FILE* f, const unsigned char* buf, size_t n) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        fputc(H[buf[i] >> 4],  f);
        fputc(H[buf[i] & 0xf], f);
    }
    fputc('\n', f);
    fputc('\n', f); 
}

int main() {
    printf("Generating deterministic SHRINCS signatures...\n");

    PublicKey pk; 
    SecretKey sk; 
    State st;

    // We use the safe 0xAA payload as discussed
    std::vector<unsigned char> msg(32, 0xAA);

    // ==========================================
    // 1. GENERATE STATELESS SIGNATURE
    // ==========================================
    shrincs_restore(MASTER_SEED, pk, sk, st);
    st.valid = true;

    unsigned char* sig_sl = shrincs_sign_stateless(msg, sk);
    if (!sig_sl) {
        printf("Stateless signature generation failed!\n");
        return 1;
    }

    // UPDATED: Save directly to the generation folder
    FILE* f_sl = fopen("generation/parsed_witness_data.txt", "w");
    fprintf(f_sl, "=== SHRINCS STATELESS PARSED WITNESS DATA ===\n\n");
    fprintf(f_sl, "[MESSAGE]\n"); fprint_hex(f_sl, msg.data(), msg.size());
    fprintf(f_sl, "[PK_SEED]\n"); fprint_hex(f_sl, pk.seed.data(), N);
    fprintf(f_sl, "[PK_ROOT]\n"); fprint_hex(f_sl, pk.root.data(), N);
    fprintf(f_sl, "[FULL_SIGNATURE]\n"); fprint_hex(f_sl, sig_sl, SL_SIZE);

    fprintf(f_sl, "=== PARSED SIGNATURE COMPONENTS ===\n\n");
    uint32_t offset = 0;
    fprintf(f_sl, "[PK_SF]\n"); fprint_hex(f_sl, sig_sl + offset, N); offset += N;
    fprintf(f_sl, "[PORS_R]\n"); fprint_hex(f_sl, sig_sl + offset, R_LEN); offset += R_LEN;
    
    uint32_t pors_sigs_len = (K + M_MAX) * N;
    fprintf(f_sl, "[PORS_SECRETS_AND_AUTH]\n"); fprint_hex(f_sl, sig_sl + offset, pors_sigs_len); offset += pors_sigs_len;

    uint32_t C_BYTES = 4; 
    uint32_t wots_chains_len = L * N; 
    uint32_t xmss_auth_len = H_PRIME * N;

    for (uint32_t layer = 0; layer < D; layer++) {
        fprintf(f_sl, "--- HYPERTREE LAYER %u ---\n\n", layer);
        fprintf(f_sl, "[XMSS_LAYER_%u_R]\n", layer); fprint_hex(f_sl, sig_sl + offset, R_LEN); offset += R_LEN;
        fprintf(f_sl, "[XMSS_LAYER_%u_CTR]\n", layer); fprint_hex(f_sl, sig_sl + offset, C_BYTES); offset += C_BYTES;
        fprintf(f_sl, "[XMSS_LAYER_%u_CHAINS]\n", layer); fprint_hex(f_sl, sig_sl + offset, wots_chains_len); offset += wots_chains_len;
        fprintf(f_sl, "[XMSS_LAYER_%u_AUTH]\n", layer); fprint_hex(f_sl, sig_sl + offset, xmss_auth_len); offset += xmss_auth_len;
    }
    
    fclose(f_sl);
    delete[] sig_sl;

    // ==========================================
    // 2. GENERATE STATEFUL SIGNATURE
    // ==========================================
    shrincs_restore(MASTER_SEED, pk, sk, st);
    st.valid = true;
    st.q = 0;

    unsigned char* sig_sf = shrincs_sign_stateful(msg, sk, st);
    if (!sig_sf) {
        printf("Stateful signature generation failed!\n");
        return 1;
    }

    uint32_t q_raw = st.q;
    if (q_raw > HSF) q_raw -= 1;
    uint32_t auth_path_len = q_raw * N;

    // UPDATED: Save directly to the generation folder
    FILE* f_sf = fopen("generation/parsed_witness_data_stateful.txt", "w");
    fprintf(f_sf, "=== SHRINCS STATEFUL PARSED STATEFUL WITNESS DATA ===\n\n");
    fprintf(f_sf, "[MESSAGE]\n"); fprint_hex(f_sf, msg.data(), msg.size());
    fprintf(f_sf, "[PK_SEED]\n"); fprint_hex(f_sf, pk.seed.data(), N);
    fprintf(f_sf, "[PK_ROOT]\n"); fprint_hex(f_sf, pk.root.data(), N);

    offset = 0;
    fprintf(f_sf, "[PK_SL]\n"); fprint_hex(f_sf, sig_sf + offset, N); offset += N;
    
    fprintf(f_sf, "[UXMSS_R]\n"); fprint_hex(f_sf, sig_sf + offset, R_LEN); offset += R_LEN;
    fprintf(f_sf, "[UXMSS_CTR]\n"); fprint_hex(f_sf, sig_sf + offset, C_BYTES); offset += C_BYTES;
    fprintf(f_sf, "[UXMSS_CHAINS]\n"); fprint_hex(f_sf, sig_sf + offset, wots_chains_len); offset += wots_chains_len;
    
    fprintf(f_sf, "[UXMSS_AUTH]\n"); fprint_hex(f_sf, sig_sf + offset, auth_path_len); offset += auth_path_len;
    fprintf(f_sf, "[UXMSS_Q]\n%u\n\n", q_raw);

    fclose(f_sf);
    delete[] sig_sf;

    printf("Successfully wrote parsed signatures to generation folder!\n");
    return 0;
}