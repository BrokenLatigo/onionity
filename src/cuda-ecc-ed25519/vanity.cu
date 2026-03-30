#include <vector>
#include <random>
#include <chrono>
#include <cmath>

#include <iostream>
#include <ctime>
#include <cstring>
#include <sys/stat.h>

#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>

#include "curand_kernel.h"
#include "ed25519.h"
#include "fixedint.h"
#include "gpu_common.h"
#include "gpu_ctx.h"

#include "keypair.cu"
#include "sc.cu"
#include "fe.cu"
#include "ge.cu"
#include "sha512.cu"
#include "sha3.cuh"
#include "b32enc.cuh"
#include "../config.h"

/* -- Device Globals -------------------------------------------------------- */

struct match_record {
	uint8_t pubkey[32];
	uint8_t secret[64];
	char    onion[57]; // 56 chars + NUL
};

__device__ char dev_prefixes[16][57];         // MAX_PATTERNS x MAX_PREFIX_LEN
__device__ int  dev_num_prefixes;
__device__ int  dev_best_match_len[16];       // MAX_PATTERNS
__device__ char dev_best_match_addr[16][57];  // 56 base32 chars + NUL
__device__ match_record dev_match_queue[16];  // MAX_MATCH_QUEUE
__device__ int  dev_match_write_idx;

/* -- Types ----------------------------------------------------------------- */

typedef struct {
	curandState*    states[8];
	int*            dev_keys_found[8];
	int*            dev_exec_count[8];
	int*            dev_gpu_id[8];
	char            h_prefixes[16][57]; // MAX_PATTERNS x MAX_PREFIX_LEN
	int             num_prefixes;
} vanity_config;

/* -- Prototypes ------------------------------------------------------------ */

void            vanity_setup(vanity_config& cfg);
void            vanity_run(vanity_config& cfg);
void __global__ vanity_init(unsigned long long int* seed, curandState* state);
void __global__ vanity_scan(curandState* state, int* keys_found, int* gpu, int* execution_count);

static void     write_tor_hs_dir(const char* onion_addr, const uint8_t* pubkey, const uint8_t* secret);

/* -- Entry Point ----------------------------------------------------------- */

int main(int argc, char const* argv[]) {
	ed25519_set_verbose(true);

	if (argc < 2) {
		printf("Usage: %s <prefix> [prefix2] [prefix3] ...\n", argv[0]);
		printf("  Prefixes use base32 alphabet: a-z, 2-7, ? = wildcard\n");
		printf("  Example: %s onion test??\n", argv[0]);
		return 1;
	}

	vanity_config cfg;
	memset(&cfg, 0, sizeof(cfg));

	cfg.num_prefixes = 0;
	for (int a = 1; a < argc && cfg.num_prefixes < MAX_PATTERNS; ++a) {
		const char* prefix = argv[a];
		int len = (int)strlen(prefix);
		if (len >= MAX_PREFIX_LEN) {
			printf("ERROR: prefix '%s' too long (max %d chars)\n", prefix, MAX_PREFIX_LEN - 1);
			return 1;
		}
		// Validate characters
		bool valid = true;
		for (int c = 0; c < len; ++c) {
			char ch = prefix[c];
			if (!((ch >= 'a' && ch <= 'z') || (ch >= '2' && ch <= '7') || ch == '?')) {
				printf("ERROR: invalid character '%c' in prefix '%s'\n", ch, prefix);
				printf("  Valid characters: a-z, 2-7, ? (wildcard)\n");
				valid = false;
				break;
			}
		}
		if (!valid) return 1;

		strncpy(cfg.h_prefixes[cfg.num_prefixes], prefix, MAX_PREFIX_LEN - 1);
		cfg.h_prefixes[cfg.num_prefixes][MAX_PREFIX_LEN - 1] = '\0';
		cfg.num_prefixes++;
	}

	printf("Searching for %d prefix(es):\n", cfg.num_prefixes);
	for (int p = 0; p < cfg.num_prefixes; ++p)
		printf("  %d: %s\n", p, cfg.h_prefixes[p]);
	printf("\n");

	vanity_setup(cfg);
	vanity_run(cfg);
}

std::string getTimeStr() {
	std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	std::string s(30, '\0');
	std::strftime(&s[0], s.size(), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
	return s;
}

unsigned long long int makeSeed() {
	unsigned long long int seed = 0;
	char *pseed = (char *)&seed;
	std::random_device rd;
	for (unsigned int b = 0; b < sizeof(seed); b++) {
		auto r = rd();
		char *entropy = (char *)&r;
		pseed[b] = entropy[0];
	}
	return seed;
}

/* -- Write Tor Hidden Service Directory ------------------------------------ */

static void write_tor_hs_dir(const char* onion_addr, const uint8_t* pubkey, const uint8_t* secret) {
	char dirname[128];
	snprintf(dirname, sizeof(dirname), "hs_%s", onion_addr);

	mkdir(dirname, 0700);

	char filepath[256];
	FILE* f;

	// hostname
	snprintf(filepath, sizeof(filepath), "%s/hostname", dirname);
	f = fopen(filepath, "w");
	if (f) {
		fprintf(f, "%s.onion\n", onion_addr);
		fclose(f);
		chmod(filepath, 0600);
	}

	// hs_ed25519_public_key: 32-byte header + 32-byte pubkey
	snprintf(filepath, sizeof(filepath), "%s/hs_ed25519_public_key", dirname);
	f = fopen(filepath, "wb");
	if (f) {
		const char header[] = "== ed25519v1-public: type0 ==";
		fwrite(header, 1, 29, f);
		uint8_t pad[3] = {0, 0, 0};
		fwrite(pad, 1, 3, f);
		fwrite(pubkey, 1, 32, f);
		fclose(f);
		chmod(filepath, 0600);
	}

	// hs_ed25519_secret_key: 32-byte header + 64-byte expanded secret
	snprintf(filepath, sizeof(filepath), "%s/hs_ed25519_secret_key", dirname);
	f = fopen(filepath, "wb");
	if (f) {
		const char header[] = "== ed25519v1-secret: type0 ==";
		fwrite(header, 1, 29, f);
		uint8_t pad[3] = {0, 0, 0};
		fwrite(pad, 1, 3, f);
		fwrite(secret, 1, 64, f);
		fclose(f);
		chmod(filepath, 0600);
	}

	printf("\n  Tor hidden service directory written to: %s/\n", dirname);
}

/* -- Vanity Step Functions ------------------------------------------------- */

void vanity_setup(vanity_config &cfg) {
	printf("GPU: Initializing Memory\n");
	int gpuCount = 0;
	cudaGetDeviceCount(&gpuCount);

	for (int i = 0; i < gpuCount; ++i) {
		cudaSetDevice(i);

		cudaDeviceProp device;
		cudaGetDeviceProperties(&device, i);

		int blockSize       = 0,
		    minGridSize     = 0,
		    maxActiveBlocks = 0;
		cudaOccupancyMaxPotentialBlockSize(&minGridSize, &blockSize, vanity_scan, 0, 0);
		cudaOccupancyMaxActiveBlocksPerMultiprocessor(&maxActiveBlocks, vanity_scan, blockSize, 0);

		printf("GPU: %d (%s <%d, %d, %d>) -- W: %d, P: %d, TPB: %d\n",
			i, device.name,
			blockSize, minGridSize, maxActiveBlocks,
			device.warpSize, device.multiProcessorCount,
			device.maxThreadsPerBlock
		);

		// Increase printf buffer for device-side match output
		cudaDeviceSetLimit(cudaLimitPrintfFifoSize, 32 * 1024 * 1024);

		unsigned long long int rseed = makeSeed();
		printf("  Initializing from entropy: %llu\n", rseed);

		unsigned long long int* dev_rseed;
		cudaMalloc((void**)&dev_rseed, sizeof(unsigned long long int));
		cudaMemcpy(dev_rseed, &rseed, sizeof(unsigned long long int), cudaMemcpyHostToDevice);

		cudaMalloc((void**)&(cfg.states[i]), maxActiveBlocks * blockSize * sizeof(curandState));
		vanity_init<<<maxActiveBlocks, blockSize>>>(dev_rseed, cfg.states[i]);

		// Pre-allocate per-GPU device buffers (fixed: no longer leaks in the loop)
		cudaMalloc((void**)&cfg.dev_keys_found[i], sizeof(int));
		cudaMalloc((void**)&cfg.dev_exec_count[i], sizeof(int));
		cudaMalloc((void**)&cfg.dev_gpu_id[i], sizeof(int));
		cudaMemcpy(cfg.dev_gpu_id[i], &i, sizeof(int), cudaMemcpyHostToDevice);

		cudaFree(dev_rseed);
	}

	// Initialize device globals on ALL GPUs
	for (int i = 0; i < gpuCount; ++i) {
		cudaSetDevice(i);
		// Copy prefixes to device
		cudaMemcpyToSymbol(dev_prefixes, cfg.h_prefixes, sizeof(cfg.h_prefixes));
		cudaMemcpyToSymbol(dev_num_prefixes, &cfg.num_prefixes, sizeof(int));
		// Zero best-match tracking
		int zeros[16] = {0};
		cudaMemcpyToSymbol(dev_best_match_len, zeros, sizeof(zeros));
		char blank[16][57];
		memset(blank, 0, sizeof(blank));
		cudaMemcpyToSymbol(dev_best_match_addr, blank, sizeof(blank));
		int zero = 0;
		cudaMemcpyToSymbol(dev_match_write_idx, &zero, sizeof(int));
	}

	printf("GPU: Initialization Complete\n\n");
}

void vanity_run(vanity_config &cfg) {
	int gpuCount = 0;
	cudaGetDeviceCount(&gpuCount);

	unsigned long long int executions_total = 0;
	int keys_found_total = 0;

	const int num_prefixes = cfg.num_prefixes;

	// Compute expected attempts for ETA/probability per prefix
	int max_prefix_len = 0;
	for (int p = 0; p < num_prefixes; ++p) {
		int len = (int)strlen(cfg.h_prefixes[p]);
		// Count non-wildcard characters for probability
		if (len > max_prefix_len) max_prefix_len = len;
	}

	auto program_start = std::chrono::high_resolution_clock::now();
	int stats_lines = 0; // number of lines in our stats display block

	for (int i = 0; i < MAX_ITERATIONS; ++i) {
		auto iter_start = std::chrono::high_resolution_clock::now();

		unsigned long long int executions_this_iteration = 0;
		int keys_found_this_iteration = 0;

		// Reset per-iteration counters and launch kernels
		for (int g = 0; g < gpuCount; ++g) {
			cudaSetDevice(g);

			int blockSize = 0, minGridSize = 0;
			cudaOccupancyMaxPotentialBlockSize(&minGridSize, &blockSize, vanity_scan, 0, 0);

			cudaMemset(cfg.dev_keys_found[g], 0, sizeof(int));
			cudaMemset(cfg.dev_exec_count[g], 0, sizeof(int));

			vanity_scan<<<minGridSize, blockSize>>>(
				cfg.states[g], cfg.dev_keys_found[g],
				cfg.dev_gpu_id[g], cfg.dev_exec_count[g]
			);
		}

		// Sync all GPUs
		for (int g = 0; g < gpuCount; ++g) {
			cudaSetDevice(g);
			cudaDeviceSynchronize();
		}

		auto iter_end = std::chrono::high_resolution_clock::now();

		// Gather results from all GPUs
		int per_gpu_exec[8] = {0};
		for (int g = 0; g < gpuCount; ++g) {
			cudaSetDevice(g);
			int exec_count = 0, found = 0;
			cudaMemcpy(&found, cfg.dev_keys_found[g], sizeof(int), cudaMemcpyDeviceToHost);
			cudaMemcpy(&exec_count, cfg.dev_exec_count[g], sizeof(int), cudaMemcpyDeviceToHost);
			per_gpu_exec[g] = exec_count;
			keys_found_this_iteration += found;
			executions_this_iteration += (unsigned long long int)exec_count * ATTEMPTS_PER_EXECUTION;
		}
		executions_total += executions_this_iteration;
		keys_found_total += keys_found_this_iteration;

		// Read best-match state from all GPUs and merge (keep best per prefix)
		int h_best_len[16] = {0};
		char h_best_addr[16][57] = {{0}};
		for (int g = 0; g < gpuCount; ++g) {
			cudaSetDevice(g);
			int gpu_best_len[16];
			char gpu_best_addr[16][57];
			cudaMemcpyFromSymbol(gpu_best_len, dev_best_match_len, sizeof(gpu_best_len));
			cudaMemcpyFromSymbol(gpu_best_addr, dev_best_match_addr, sizeof(gpu_best_addr));
			for (int p = 0; p < num_prefixes; ++p) {
				if (gpu_best_len[p] > h_best_len[p]) {
					h_best_len[p] = gpu_best_len[p];
					memcpy(h_best_addr[p], gpu_best_addr[p], 57);
				}
			}
		}

		// Process match queue from all GPUs
		static int last_match_idx[8] = {0};
		for (int g = 0; g < gpuCount; ++g) {
			cudaSetDevice(g);
			int h_match_idx = 0;
			cudaMemcpyFromSymbol(&h_match_idx, dev_match_write_idx, sizeof(int));
			while (last_match_idx[g] < h_match_idx && last_match_idx[g] < MAX_MATCH_QUEUE) {
				match_record rec;
				cudaMemcpyFromSymbol(&rec, dev_match_queue, sizeof(match_record),
					last_match_idx[g] * sizeof(match_record));
				write_tor_hs_dir(rec.onion, rec.pubkey, rec.secret);
				last_match_idx[g]++;
			}
		}

		// Timing
		std::chrono::duration<double> iter_elapsed = iter_end - iter_start;
		std::chrono::duration<double> total_elapsed =
			std::chrono::high_resolution_clock::now() - program_start;

		double iter_rate = executions_this_iteration / iter_elapsed.count();
		double avg_rate = executions_total / total_elapsed.count();

		// Move cursor up to overwrite previous stats block
		if (i > 0 && stats_lines > 0) {
			printf("\033[%dA", stats_lines);
		}

		// Build stats display
		stats_lines = 0;

		// Header
		printf("\033[2K\033[1m");
		printf("========================================");
		printf("========================================\n");
		stats_lines++;

		printf("\033[2K  ONIONITY - Tor v3 Vanity Address Generator\033[0m\n");
		stats_lines++;

		printf("\033[2K\033[1m");
		printf("========================================");
		printf("========================================\n");
		stats_lines++;

		// Hash rate with per-GPU breakdown
		printf("\033[2K  Hash rate:     \033[1;36m%8.2f MH/s\033[0m  (", iter_rate / 1e6);
		for (int g = 0; g < gpuCount; ++g) {
			double gpu_rate = (double)per_gpu_exec[g] * ATTEMPTS_PER_EXECUTION / iter_elapsed.count();
			if (g > 0) printf(" | ");
			printf("GPU %d: %.1fM", g, gpu_rate / 1e6);
		}
		printf(")\n");
		stats_lines++;

		// Total attempts and timing
		printf("\033[2K  Total attempts: %llu\n", executions_total);
		stats_lines++;

		int total_secs = (int)total_elapsed.count();
		printf("\033[2K  Running time:   %02d:%02d:%02d\n",
			total_secs / 3600, (total_secs % 3600) / 60, total_secs % 60);
		stats_lines++;

		printf("\033[2K  Iteration:      %d\n", i + 1);
		stats_lines++;

		printf("\033[2K  Matches found:  \033[1;%dm%d\033[0m\n",
			keys_found_total > 0 ? 32 : 37, keys_found_total);
		stats_lines++;

		// Per-prefix status
		printf("\033[2K\033[1m  %-4s %-20s %-8s %-10s %-6s  %s\033[0m\n",
			"#", "Prefix", "Length", "ETA", "Best", "Best Address");
		stats_lines++;

		for (int p = 0; p < num_prefixes; ++p) {
			int plen = (int)strlen(cfg.h_prefixes[p]);

			// Count effective characters (non-wildcard) for probability
			int effective_chars = 0;
			for (int c = 0; c < plen; ++c) {
				if (cfg.h_prefixes[p][c] != '?') effective_chars++;
			}

			double expected = pow(32.0, effective_chars);
			double prob_found = 1.0 - exp(-(double)executions_total / expected);
			double est_remaining = 0;
			if (avg_rate > 0 && executions_total < expected) {
				est_remaining = (expected - executions_total) / avg_rate;
			}

			// ETA string
			char eta_str[32];
			if (est_remaining <= 0 || executions_total >= (unsigned long long int)expected) {
				snprintf(eta_str, sizeof(eta_str), "overdue");
			} else {
				int rem = (int)est_remaining;
				if (rem > 86400) {
					snprintf(eta_str, sizeof(eta_str), "%dd %02dh", rem / 86400, (rem % 86400) / 3600);
				} else {
					snprintf(eta_str, sizeof(eta_str), "%02d:%02d:%02d",
						rem / 3600, (rem % 3600) / 60, rem % 60);
				}
			}

			// Best match display with color highlighting
			printf("\033[2K  %-4d ", p);

			// Print prefix
			printf("\033[1;33m%-20s\033[0m ", cfg.h_prefixes[p]);
			printf("%-8d ", plen);
			printf("%-10s ", eta_str);

			printf("%d/%-4d ", h_best_len[p], plen);

			if (h_best_len[p] > 0) {
				// Highlight matched portion in green, rest dim
				printf("\033[1;32m");
				for (int c = 0; c < h_best_len[p] && c < 56; ++c)
					printf("%c", h_best_addr[p][c]);
				printf("\033[0;2m");
				for (int c = h_best_len[p]; c < 56 && h_best_addr[p][c]; ++c)
					printf("%c", h_best_addr[p][c]);
				printf("\033[0m");
			} else {
				printf("(searching...)");
			}
			printf("\n");
			stats_lines++;
		}

		// Progress bar (based on longest/hardest prefix)
		{
			int hardest_effective = 0;
			for (int p = 0; p < num_prefixes; ++p) {
				int eff = 0;
				int plen = (int)strlen(cfg.h_prefixes[p]);
				for (int c = 0; c < plen; ++c)
					if (cfg.h_prefixes[p][c] != '?') eff++;
				if (eff > hardest_effective) hardest_effective = eff;
			}
			double expected = pow(32.0, hardest_effective);
			double pct = ((double)executions_total / expected) * 100.0;
			if (pct > 999.9) pct = 999.9;
			double prob = 1.0 - exp(-(double)executions_total / expected);

			int bar_width = 40;
			int filled = (int)(pct / 100.0 * bar_width);
			if (filled > bar_width) filled = bar_width;

			printf("\033[2K  [");
			for (int b = 0; b < bar_width; ++b) {
				if (b < filled) printf("\033[1;32m#\033[0m");
				else printf("\033[2m-\033[0m");
			}
			printf("] %.2f%% (P=%.1f%%)\n", pct, prob * 100.0);
			stats_lines++;
		}

		printf("\033[2K\033[1m");
		printf("========================================");
		printf("========================================\n");
		stats_lines++;

		fflush(stdout);

		if (keys_found_total >= STOP_AFTER_KEYS_FOUND) {
			printf("\nDone! Found %d matching address(es).\n", keys_found_total);
			exit(0);
		}
	}

	printf("\nIterations complete, Done!\n");
}

/* -- CUDA Vanity Functions ------------------------------------------------- */

void __global__ vanity_init(unsigned long long int* rseed, curandState* state) {
	int id = threadIdx.x + (blockIdx.x * blockDim.x);
	curand_init(*rseed + id, id, 0, &state[id]);
}

void __global__ vanity_scan(curandState* state, int* keys_found, int* gpu, int* exec_count) {
	int id = threadIdx.x + (blockIdx.x * blockDim.x);

	atomicAdd(exec_count, 1);

	// Precompute prefix lengths
	int num_patterns = dev_num_prefixes;
	int prefix_letter_counts[16]; // MAX_PATTERNS
	for (int n = 0; n < num_patterns && n < MAX_PATTERNS; ++n) {
		int letter_count = 0;
		for (; dev_prefixes[n][letter_count] != 0; letter_count++);
		prefix_letter_counts[n] = letter_count;
	}

	// Local kernel state
	ge_p3 A;
	curandState localState     = state[id];
	unsigned char seed[32]     = {0};
	unsigned char publick[32]  = {0};
	unsigned char privatek[64] = {0};

	// Generate initial random seed (full byte range 0-255)
	for (int i = 0; i < 32; ++i) {
		seed[i] = (uint8_t)(curand(&localState) & 0xFF);
	}

	// Main scanning loop
	sha512_context md;

	for (int attempts = 0; attempts < ATTEMPTS_PER_EXECUTION; ++attempts) {
		// --- SHA-512 inlined (specialized for 32-byte input) ---
		md.curlen   = 0;
		md.length   = 0;
		md.state[0] = UINT64_C(0x6a09e667f3bcc908);
		md.state[1] = UINT64_C(0xbb67ae8584caa73b);
		md.state[2] = UINT64_C(0x3c6ef372fe94f82b);
		md.state[3] = UINT64_C(0xa54ff53a5f1d36f1);
		md.state[4] = UINT64_C(0x510e527fade682d1);
		md.state[5] = UINT64_C(0x9b05688c2b3e6c1f);
		md.state[6] = UINT64_C(0x1f83d9abfb41bd6b);
		md.state[7] = UINT64_C(0x5be0cd19137e2179);

		const unsigned char *in = seed;
		for (size_t i = 0; i < 32; i++) {
			md.buf[i + md.curlen] = in[i];
		}
		md.curlen += 32;

		md.length += md.curlen * UINT64_C(8);
		md.buf[md.curlen++] = (unsigned char)0x80;
		while (md.curlen < 120) {
			md.buf[md.curlen++] = (unsigned char)0;
		}
		STORE64H(md.length, md.buf+120);

		// Inline sha512_compress
		uint64_t S[8], W[80], t0, t1;
		int ci;

		for (ci = 0; ci < 8; ci++) S[ci] = md.state[ci];
		for (ci = 0; ci < 16; ci++) { LOAD64H(W[ci], md.buf + (8*ci)); }
		for (ci = 16; ci < 80; ci++) {
			W[ci] = Gamma1(W[ci - 2]) + W[ci - 7] + Gamma0(W[ci - 15]) + W[ci - 16];
		}

		#define RND(a,b,c,d,e,f,g,h,i) \
		t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]; \
		t1 = Sigma0(a) + Maj(a, b, c);\
		d += t0; \
		h  = t0 + t1;

		for (ci = 0; ci < 80; ci += 8) {
			RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],ci+0);
			RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],ci+1);
			RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],ci+2);
			RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],ci+3);
			RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],ci+4);
			RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],ci+5);
			RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],ci+6);
			RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],ci+7);
		}

		#undef RND

		for (ci = 0; ci < 8; ci++) md.state[ci] = md.state[ci] + S[ci];
		for (ci = 0; ci < 8; ci++) { STORE64H(md.state[ci], privatek+(8*ci)); }

		// --- Ed25519 clamping ---
		privatek[0]  &= 248;
		privatek[31] &= 63;
		privatek[31] |= 64;

		// --- Ed25519 scalar mult -> public key ---
		ge_scalarmult_base(&A, privatek);
		ge_p3_tobytes(publick, &A);

		// --- Tor v3 onion address: fast prefix filter + SHA3 + base32 ---
		for (int pi = 0; pi < num_patterns; ++pi) {
			int plen = prefix_letter_counts[pi];

			// Phase 1: Fast prefix filter using partial base32 of pubkey only.
			// The first 51 base32 chars come entirely from the 32-byte pubkey
			// (before the 2-byte checksum + 1-byte version appended at the end).
			// So for any prefix <= 51 chars, we can reject without SHA3.
			char partial[52]; // max 51 chars + safety
			base32_enc_partial(partial, publick, 32, plen > 51 ? 51 : plen);

			bool fast_pass = true;
			int fast_match_len = 0;
			for (int j = 0; j < plen && j < 51; ++j) {
				if (dev_prefixes[pi][j] == '?' || dev_prefixes[pi][j] == partial[j]) {
					fast_match_len++;
				} else {
					fast_pass = false;
					break;
				}
			}

			// Update best-match tracking (even on fast-reject, for progress display)
			if (fast_match_len > 0) {
				int old_best = dev_best_match_len[pi];
				if (fast_match_len > old_best) {
					int prev = atomicCAS(&dev_best_match_len[pi], old_best, fast_match_len);
					if (prev == old_best) {
						// Won the CAS — encode 51 chars of the pubkey for display
						char display[52];
						base32_enc_partial(display, publick, 32, 51);
						for (int c = 0; c < 51; ++c)
							dev_best_match_addr[pi][c] = display[c];
						dev_best_match_addr[pi][51] = '\0';
					}
				}
			}

			if (!fast_pass) continue;

			// Phase 2: Compute SHA3-256 checksum (only for candidates that passed fast filter)
			uint8_t keccak_in[48];
			// ".onion checksum" = 15 bytes
			keccak_in[0]  = '.'; keccak_in[1]  = 'o'; keccak_in[2]  = 'n';
			keccak_in[3]  = 'i'; keccak_in[4]  = 'o'; keccak_in[5]  = 'n';
			keccak_in[6]  = ' '; keccak_in[7]  = 'c'; keccak_in[8]  = 'h';
			keccak_in[9]  = 'e'; keccak_in[10] = 'c'; keccak_in[11] = 'k';
			keccak_in[12] = 's'; keccak_in[13] = 'u'; keccak_in[14] = 'm';
			for (int b = 0; b < 32; ++b) keccak_in[15 + b] = publick[b];
			keccak_in[47] = 0x03;

			uint8_t sha3_out[32];
			sha3_256_48(sha3_out, keccak_in);

			// Phase 3: Assemble full 35-byte payload and base32 encode
			uint8_t payload[35];
			for (int b = 0; b < 32; ++b) payload[b] = publick[b];
			payload[32] = sha3_out[0]; // checksum byte 1
			payload[33] = sha3_out[1]; // checksum byte 2
			payload[34] = 0x03;        // version

			char onion[57];
			base32_enc_full(onion, payload);
			onion[56] = '\0';

			// Phase 4: Full prefix verify against complete onion address
			bool full_match = true;
			int full_match_len = 0;
			for (int j = 0; j < plen; ++j) {
				if (dev_prefixes[pi][j] == '?' || dev_prefixes[pi][j] == onion[j]) {
					full_match_len++;
				} else {
					full_match = false;
					break;
				}
			}

			// Update best-match with full address (more accurate than partial)
			if (full_match_len > 0) {
				int old_best = dev_best_match_len[pi];
				if (full_match_len > old_best) {
					int prev = atomicCAS(&dev_best_match_len[pi], old_best, full_match_len);
					if (prev == old_best) {
						for (int c = 0; c < 56; ++c)
							dev_best_match_addr[pi][c] = onion[c];
						dev_best_match_addr[pi][56] = '\0';
					}
				}
			}

			// Phase 5: On full match, output result
			if (full_match) {
				atomicAdd(keys_found, 1);

				// Print human-readable output
				printf("\n*** MATCH FOUND on GPU %d ***\n", *gpu);
				printf("  Onion:   %s.onion\n", onion);
				printf("  Pubkey:  ");
				for (int n = 0; n < 32; ++n) printf("%02x", publick[n]);
				printf("\n");
				printf("  Secret:  ");
				for (int n = 0; n < 64; ++n) printf("%02x", privatek[n]);
				printf("\n");

				// Write to match queue for host-side file output
				int slot = atomicAdd(&dev_match_write_idx, 1);
				if (slot < MAX_MATCH_QUEUE) {
					for (int b = 0; b < 32; ++b)
						dev_match_queue[slot].pubkey[b] = publick[b];
					for (int b = 0; b < 64; ++b)
						dev_match_queue[slot].secret[b] = privatek[b];
					for (int c = 0; c < 56; ++c)
						dev_match_queue[slot].onion[c] = onion[c];
					dev_match_queue[slot].onion[56] = '\0';
				}

				break; // stop checking other prefixes for this key
			}
		}

		// Increment seed
#if SEQUENTIAL_SEED
		for (int si = 0; si < 32; ++si) {
			if (seed[si] == 255) {
				seed[si] = 0;
			} else {
				seed[si] += 1;
				break;
			}
		}
#else
		for (int si = 0; si < 32; ++si) {
			seed[si] = (uint8_t)(curand(&localState) & 0xFF);
		}
#endif
	}

	state[id] = localState;
}
