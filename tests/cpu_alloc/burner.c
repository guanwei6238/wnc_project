// burner.c — edge AI stand-in: burns CPU or memory bandwidth on the Pi and reports its own throughput
// Usage: burner <cpu|mem|mlp> <threads> <cpus|any> <duty%> <seconds>
//   cpu: integer and float ops within L1; mem: STREAM triad (three 8 MiB arrays per thread);
//   mlp: float32 MLP 256-1024-1024-256, batch 1, ~6 MiB of weights (all threads share one copy)
//   cpus: comma-separated CPU numbers, threads pinned in order; any = no pinning
//   duty: ms of work per 100 ms (100 = no rest)
//   prints one line per second: t=<sec> ops=<total ops this second>; at the end prints total and per-second mean
//   ops unit: loop iterations (millions) for cpu, MiB moved for mem, inferences for mlp
//   env var BURNER_OPS_FILE: every 200 ms write "cumulative ops and CLOCK_MONOTONIC seconds" to this file, so measurement scripts can read it at any time
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { CPU, MEM, MLP };
static int mode, duty;
static double seconds;
static atomic_long ops;
static atomic_int stop;
static float *W1, *W2, *W3;
#define IN 256
#define H 1024
#define OUT 256
#define NMEM (8 << 20) / sizeof(double)

static double now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec * 1e-9;
}

static void dense(const float *w, const float *x, float *y, int n_in, int n_out) {
  for (int o = 0; o < n_out; o++) {
    const float *row = w + (size_t)o * n_in;
    float s = 0;
    for (int i = 0; i < n_in; i++) s += row[i] * x[i];
    y[o] = s > 0 ? s : 0;
  }
}

static long work_once(void *st) {
  if (mode == CPU) {
    unsigned long *x = st;
    double f = 1.0;
    for (int i = 0; i < 1000000; i++) {
      x[i & 511] = x[(i + 7) & 511] * 6364136223846793005UL + 1442695040888963407UL;
      f = f * 1.0000001 + 0.5;
    }
    if (f == 0) x[0]++;
    return 1;
  }
  if (mode == MEM) {
    double **a = st;
    for (size_t i = 0; i < NMEM; i++) a[0][i] = a[1][i] + 3.0 * a[2][i];
    return 24;
  }
  float *buf = st;
  float *x = buf, *h1 = buf + IN, *h2 = h1 + H, *y = h2 + H;
  x[0] += 1e-3f;
  dense(W1, x, h1, IN, H);
  dense(W2, h1, h2, H, H);
  dense(W3, h2, y, H, OUT);
  if (y[0] < -1) x[1]++;
  return 1;
}

static void *run(void *arg) {
  long cpu = (long)arg;
  if (cpu >= 0) {
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    pthread_setaffinity_np(pthread_self(), sizeof s, &s);
  }
  void *st;
  if (mode == CPU) {
    st = calloc(512, sizeof(unsigned long));
  } else if (mode == MEM) {
    double **a = malloc(3 * sizeof *a);
    for (int k = 0; k < 3; k++) {
      a[k] = malloc(NMEM * sizeof(double));
      for (size_t i = 0; i < NMEM; i++) a[k][i] = i;
    }
    st = a;
  } else {
    st = calloc(IN + 2 * H + OUT, sizeof(float));
  }
  while (!atomic_load(&stop)) {
    double start = now();
    double budget = duty / 1000.0;
    do {
      atomic_fetch_add(&ops, work_once(st));
    } while (duty >= 100 ? !atomic_load(&stop) && now() - start < 0.1 : now() - start < budget);
    if (duty < 100) {
      double rest = 0.1 - (now() - start);
      if (rest > 0) {
        struct timespec t = {0, (long)(rest * 1e9)};
        nanosleep(&t, NULL);
      }
    }
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: burner <cpu|mem|mlp> <threads> <cpus|any> <duty%%> <seconds>\n");
    return 2;
  }
  mode = !strcmp(argv[1], "cpu") ? CPU : !strcmp(argv[1], "mem") ? MEM : !strcmp(argv[1], "mlp") ? MLP : -1;
  int n = atoi(argv[2]);
  duty = atoi(argv[4]);
  seconds = atof(argv[5]);
  if (mode < 0 || n < 1 || duty < 1 || duty > 100) {
    fprintf(stderr, "error: bad arguments\n");
    return 2;
  }
  if (mode == MLP) {
    W1 = malloc(sizeof(float) * IN * H);
    W2 = malloc(sizeof(float) * H * H);
    W3 = malloc(sizeof(float) * H * OUT);
    for (size_t i = 0; i < (size_t)IN * H; i++) W1[i] = ((i * 2654435761u) % 1000) / 1e4f - 0.05f;
    for (size_t i = 0; i < (size_t)H * H; i++) W2[i] = ((i * 2246822519u) % 1000) / 1e4f - 0.05f;
    for (size_t i = 0; i < (size_t)H * OUT; i++) W3[i] = ((i * 3266489917u) % 1000) / 1e4f - 0.05f;
  }
  long cpus[64];
  int nc = 0;
  if (strcmp(argv[3], "any")) {
    char *s = strdup(argv[3]);
    for (char *t = strtok(s, ","); t && nc < 64; t = strtok(NULL, ",")) cpus[nc++] = atol(t);
  }
  pthread_t th[64];
  for (long i = 0; i < n && i < 64; i++) pthread_create(&th[i], NULL, run, (void *)(nc ? cpus[i % nc] : -1L));
  double t0 = now(), last = t0;
  long prev = 0;
  const char *path = getenv("BURNER_OPS_FILE");
  int tick = 0;
  while (now() - t0 < seconds) {
    struct timespec t = {0, 200000000};
    nanosleep(&t, NULL);
    if (path) {
      FILE *f = fopen(path, "w");
      if (f) {
        fprintf(f, "%ld %.6f\n", atomic_load(&ops), now());
        fclose(f);
      }
    }
    if (++tick % 5) continue;
    double t1 = now();
    long cur = atomic_load(&ops);
    printf("t=%.1f ops=%.2f\n", t1 - t0, (cur - prev) / (t1 - last));
    fflush(stdout);
    prev = cur;
    last = t1;
  }
  atomic_store(&stop, 1);
  for (int i = 0; i < n && i < 64; i++) pthread_join(th[i], NULL);
  double el = now() - t0;
  printf("total ops=%ld seconds=%.2f rate=%.2f\n", atomic_load(&ops), el, atomic_load(&ops) / el);
  return 0;
}
