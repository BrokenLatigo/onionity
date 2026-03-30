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
#define SEQUENTIAL_SEED 1

static const int MAX_PATTERNS = 16;
static const int MAX_MATCH_QUEUE = 16;

// Prefixes to search for (lowercase base32: a-z, 2-7, ? = wildcard)
__device__ static char const *prefixes[] = {
	"onion",
};

// Host-side mirror of prefixes (cannot read __device__ from host)
static const char *prefixes_host[] = {
	"onion",
};

#endif
