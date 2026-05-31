#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

#define PING_WAIT_SEC 2
#define SPAWN_WAIT_MS 500

// MTU refers to the maximum size of the IP PDU / Ethernet payload.
#define MTU 1500
#define IP_HDR 20
#define ICMP_HDR 8
#define MAX_ICMP_LD (MTU - IP_HDR - ICMP_HDR)

#define UNKNOWN 0
#define SUCCESS 1
#define FAILURE 2
typedef char status_t;

#define check(name, ...) { if (0 != (name) (__VA_ARGS__)) err (EXIT_FAILURE, #name); }

struct pmtud_args {
  const char *addr;
  status_t results[MAX_ICMP_LD + 1];
  int sent_no;
  int rcv_no;
  pthread_mutex_t lock;
};

struct ping_args {
  struct pmtud_args *m_args;
  int size;
  status_t status;
};

struct binsearch_args {
  struct pmtud_args *m_args;
  int start;
  int end;
};

void
pmtud_args_init (struct pmtud_args *m, const char *addr)
{
  pthread_mutex_init (&m->lock, NULL);
  memset (m->results, UNKNOWN, sizeof (m->results));
  m->addr = addr;
  m->rcv_no = 0;
  m->sent_no = 0;
}

void
binsearch_args_init (struct binsearch_args *b, struct pmtud_args *m, int start, int end)
{
  b->m_args = m;
  b->start = start;
  b->end = end;
}

int
calc_mtu (struct pmtud_args *m_args)
{
  pthread_mutex_lock (&m_args->lock);
  int len = sizeof (m_args->results) / sizeof (*m_args->results);
  int mtu = MTU;
  for (int size = 0; size < len; size++) {
    if (m_args->results[size] == FAILURE) {
      mtu = size - 1 + IP_HDR + ICMP_HDR;
      break;
    }
  }
  pthread_mutex_unlock (&m_args->lock);
  return mtu;
}

void *
thread_ping (void *args)
{
  struct ping_args *p_args = args;
  char command[128];
  int status;

  if (p_args == NULL)
    return NULL;

  struct pmtud_args *m_args = p_args->m_args;

  snprintf (command, sizeof command,
    "ping -4 -c 1 -w %d -M do %s -s %d >/dev/null 2>&1",
    PING_WAIT_SEC, m_args->addr, p_args->size);
  status = system (command);

  pthread_mutex_lock (&m_args->lock);
  m_args->sent_no++;
  if (status == 0) {
    m_args->rcv_no++;
    p_args->status = SUCCESS;
    memset (m_args->results, SUCCESS, p_args->size + 1);
  } else {
    p_args->status = FAILURE;
    memset (&m_args->results[p_args->size], FAILURE, MAX_ICMP_LD - p_args->size + 1);
  }
  pthread_mutex_unlock (&m_args->lock);
  pthread_exit (NULL);

  return NULL;
}

/* Returns 0 if this ping size is unknown, 1 if known. */
int
check_status (int size, struct pmtud_args *m_args)
{
  const int len = sizeof (m_args->results) / sizeof (*m_args->results); 

  if (size >= len)
    return 1;

  pthread_mutex_lock (&m_args->lock);
  int status = m_args->results[size]; 
  pthread_mutex_unlock (&m_args->lock);

  return (status == UNKNOWN) ? 0 : 1;
}

void *
thread_binsearch (void *args)
{
  int mid;
  pthread_t tid1, tid2;
  struct binsearch_args *b_args = args;
  struct binsearch_args child_arg;
  struct timespec time_start, time_end;

  // Stop if sentinel is reached
  if (b_args->start > b_args->end)
    return NULL;

  // Get midpoint of the two ping sizes
  mid = (b_args->start + b_args->end) / 2;

  // Only continue if this ping's success is unknown
  if (0 != check_status (mid, b_args->m_args))
    return NULL;

  // Start the ping
  struct ping_args p_args = {
    .size = mid,
    .status = UNKNOWN,
    .m_args = b_args->m_args,
  };
  check (pthread_create, &tid1, NULL, thread_ping, &p_args);

  clock_gettime (CLOCK_MONOTONIC_RAW, &time_start);
  check (pthread_join, tid1, NULL);
  if (b_args->start != b_args->end) {
    // Measure time for ping thread to finish
    clock_gettime (CLOCK_MONOTONIC_RAW, &time_end);

    uint64_t delta_ms = (time_end.tv_sec - time_start.tv_sec) * 1000
      + (time_end.tv_nsec - time_start.tv_nsec) / 1000 / 1000;

    if (p_args.status == SUCCESS && delta_ms < SPAWN_WAIT_MS) {
      uint64_t wait_ms = SPAWN_WAIT_MS - delta_ms;

      struct timespec duration = {
        .tv_nsec = wait_ms % 1000 * 1000 * 1000,
        .tv_sec = wait_ms / 1000,
      };
      check (nanosleep, &duration, NULL);
    }

    // Start a new branched search
    if (p_args.status == FAILURE)
      binsearch_args_init (&child_arg, b_args->m_args, b_args->start, mid - 1);
    else
      binsearch_args_init (&child_arg, b_args->m_args, mid + 1, b_args->end);

    check (pthread_create, &tid2, NULL, thread_binsearch, &child_arg);
    check (pthread_join, tid2, NULL);
  }

  return NULL;
}

/* Pathway MTU discovery thread. Employs strategy to get MTU. */
void *
thread_pmtud (void *args)
{
  struct pmtud_args *m_args = args;
  pthread_t tid1, tid2;
  struct binsearch_args b_args1, b_args2;
  // Two searches are created: one is the unlikely worst-case (where it's not 1500)
  // and the other is the likely best-case (where it's 1500)
  binsearch_args_init (&b_args1, m_args, 0, MAX_ICMP_LD);
  binsearch_args_init (&b_args2, m_args, MAX_ICMP_LD, MAX_ICMP_LD);

  check (pthread_create, &tid1, NULL, thread_binsearch, &b_args1);
  check (pthread_create, &tid2, NULL, thread_binsearch, &b_args2);
  check (pthread_join, tid1, NULL);
  check (pthread_join, tid2, NULL);
  return NULL;
}

int
main (void)
{
  char *addrs[] = {
    "209.51.188.116", // gnu.org
    "172.105.4.254", // kernel.org
    "151.101.194.132", // debian.org
  };

  const int len = sizeof (addrs) / sizeof (*addrs);
  int sent_total, rcv_total;
  pthread_t tids[len];
  struct pmtud_args m_args[len];
  sent_total = 0;
  rcv_total = 0;

  // Start all the MTU searches
  for (int i = 0; i < len; ++i) {
    pmtud_args_init (&m_args[i], addrs[i]);
    check (pthread_create, &tids[i], NULL, thread_pmtud, &m_args[i]);
  }

  // Wait for all the MTU searches to finish and print statistics
  for (int i = 0; i < len; ++i) {
    check (pthread_join, tids[i], NULL);
    struct pmtud_args *a = &m_args[i];
    printf ("%-15s %d bytes (%d sent, %d received)\n", a->addr, calc_mtu (a), a->sent_no, a->rcv_no);
    sent_total += a->sent_no;
    rcv_total += a->rcv_no;
  }
  printf ("total %d sent %d received\n", sent_total, rcv_total);
}
