#ifndef VANITY_CONFIG
#define VANITY_CONFIG

static int const MAX_ITERATIONS = 999999999;
static int const STOP_AFTER_KEYS_FOUND = 1;

// How many times a GPU thread generates a public key in one go.
// Higher = less kernel launch overhead, lower = more responsive stats.
static const int ATTEMPTS_PER_EXECUTION = 100000;

// Seed increment mode:
//   0 = random per attempt (better entropy, slower)
//   1 = sequential increment (fast but insecure)
#define SEQUENTIAL_SEED 0

static const int MAX_PATTERNS = 16;
static const int MAX_PREFIX_LEN = 57; // 56 chars max onion prefix + NUL
static const int MAX_MATCH_QUEUE = 16;

#endif
