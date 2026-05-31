#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <linux/time.h>

#define PING_WAIT_SEC 2
#define SPAWN_WAIT_MS 500

#define MTU 1520
#define IP_HDR 20
#define ICMP_HDR 8
#define MAX_PING_PAYLOAD (MTU - IP_HDR - ICMP_HDR)

#define UNKNOWN 0
#define SUCCESS 1
#define FAILURE 2
typedef char status_t;

#define check(name, ...) { if (0 != (name) (__VA_ARGS__)) err (EXIT_FAILURE, #name); }

struct pmtud_args {
  const char *addr;
  status_t results[MAX_PING_PAYLOAD + 1];
  int sent_no;
  int rcv_no;
  pthread_mutex_t lock;
};

struct ping_args {
  struct pmtud_args *m_args;
  int size;
  status_t status;
  pthread_mutex_t status_lock;
};

struct binsearch_args {
  struct pmtud_args *m_args;
  int start;
  int end;
};

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
    memset (&m_args->results[p_args->size], FAILURE, MAX_PING_PAYLOAD - p_args->size + 1);
  }
  pthread_mutex_unlock (&m_args->lock);
  pthread_mutex_unlock (&p_args->status_lock);

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
  status_t status;
  pthread_t tid1, tid2, tid3;
  struct binsearch_args *b_args = args;

  if (b_args->start > b_args->end)
    return NULL;

  mid = (b_args->start + b_args->end) / 2;

  if (0 != check_status (mid, b_args->m_args))
    return NULL;

  struct ping_args p_args = {
    .size = mid,
    .status = UNKNOWN,
    .m_args = b_args->m_args,
    .status_lock = PTHREAD_MUTEX_INITIALIZER,
  };

  struct binsearch_args child1_args = {
    .m_args = b_args->m_args,
    .start = b_args->start,
    .end = mid - 1,
  };

  struct binsearch_args child2_args = {
    .m_args = b_args->m_args,
    .start = mid + 1,
    .end = b_args->end,
  };

  check (pthread_mutex_trylock, &p_args.status_lock);
  check (pthread_create, &tid1, NULL, thread_ping, &p_args);

  struct timespec time_start, time_end;
  clock_gettime(CLOCK_MONOTONIC_RAW, &time_start);

  if (b_args->start != b_args->end) {
    pthread_mutex_lock (&p_args.status_lock);
    clock_gettime(CLOCK_MONOTONIC_RAW, &time_end);

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

    check (pthread_create, &tid2, NULL, thread_binsearch, &child1_args);
    check (pthread_create, &tid3, NULL, thread_binsearch, &child2_args);
    check (pthread_join, tid2, NULL);
    check (pthread_join, tid3, NULL);
  }

  check (pthread_join, tid1, NULL);
  return NULL;
}

int
main (void)
{
  char *addrs[] = {
    "209.51.188.116", // gnu.org
    "1.1.1.1",
  };

  const int len = sizeof (addrs) / sizeof (*addrs);
  pthread_t tids[len];
  struct pmtud_args m_args[len];
  struct binsearch_args b_args[len];

  // Start all the MTU searches
  for (int i = 0; i < len; ++i) {
    pthread_mutex_init (&m_args[i].lock, NULL);
    memset (m_args[i].results, UNKNOWN, sizeof (m_args[i].results));
    m_args[i].addr = addrs[i];
    m_args[i].rcv_no = 0;
    m_args[i].sent_no = 0;
    b_args[i].m_args = &m_args[i];
    b_args[i].start = 0;
    b_args[i].end = MAX_PING_PAYLOAD;
    
    check (pthread_create, &tids[i], NULL, thread_binsearch, &b_args[i]);
  }

  // Wait for all the MTU searches to finish
  int sent_total, rcv_total;
  sent_total = rcv_total = 0;

  for (int i = 0; i < len; ++i) {
    check (pthread_join, tids[i], NULL);
    struct pmtud_args *a = &m_args[i];
    printf ("%-15s: %d bytes (%d sent, %d received)\n", a->addr, calc_mtu (a), a->sent_no, a->rcv_no);
    sent_total += a->sent_no;
    rcv_total += a->rcv_no;
  }
  printf("total %d sent %d received\n", sent_total, rcv_total);
}
