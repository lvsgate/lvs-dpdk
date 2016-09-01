/*
 * Copyright (c) 2016, lvsgate@163.com
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>

#include "ofp.h"

#include "ofp_vs.h"

#define MAX_WORKERS		32

/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	char *conf_file;
} appl_args_t;

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

ofp_init_global_t app_init_params; /**< global OFP init parms */

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))



static void signal_handler(int signal)
{
  const char *signal_name;

  switch (signal) {
    case SIGILL:
        signal_name = "SIGILL";   break;
    case SIGFPE:
        signal_name = "SIGFPE";   break;
    case SIGSEGV:
        signal_name = "SIGSEGV";  break;
    case SIGTERM:
        signal_name = "SIGTERM";  break;
    case SIGINT:
        signal_name = "SIGINT";  break; 
    case SIGBUS:
        signal_name = "SIGBUS";   break;
    default:
        signal_name = "UNKNOWN";  break;
  }
  ofp_stop_processing();
  fprintf(stderr, "Recv signal %u (%s) exiting.\n", signal, signal_name);
}

static void *event_dispatcher(void *arg)
{
	odp_event_t ev;
	odp_packet_t pkt;
	odp_queue_t in_queue;
	odp_event_t events[OFP_EVT_RX_BURST_SIZE];
	int event_idx = 0;
	int event_cnt = 0;
	ofp_pkt_processing_func pkt_func = (ofp_pkt_processing_func)arg;
	odp_bool_t *is_running = NULL;
	int cpuid = odp_cpu_id();
	odp_queue_t time_queue_cpu;

	if (ofp_init_local()) {
		OFP_ERR("ofp_init_local failed");
		return NULL;
	}

	is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("ofp_get_processing_state failed");
		ofp_term_local();
		return NULL;
	}

	/* PER CORE DISPATCHER */
	while (*is_running) {
		event_cnt = odp_schedule_multi(&in_queue, ODP_SCHED_WAIT,
					 events, OFP_EVT_RX_BURST_SIZE);
		for (event_idx = 0; event_idx < event_cnt; event_idx++) {
			ev = events[event_idx];

			if (ev == ODP_EVENT_INVALID)
				continue;

			if (odp_event_type(ev) == ODP_EVENT_TIMEOUT) {
				ofp_timer_handle(ev);
				continue;
			}

			if (odp_event_type(ev) == ODP_EVENT_PACKET) {
				pkt = odp_packet_from_event(ev);
#if 0
				if (odp_unlikely(odp_packet_has_error(pkt))) {
					OFP_DBG("Dropping packet with error");
					odp_packet_free(pkt);
					continue;
				}
#endif
				ofp_packet_input(pkt, in_queue, pkt_func);
				continue;
			}

			OFP_ERR("Unexpected event type: %u", odp_event_type(ev));

			/* Free events by type */
			if (odp_event_type(ev) == ODP_EVENT_BUFFER) {
				odp_buffer_free(odp_buffer_from_event(ev));
				continue;
			}

			if (odp_event_type(ev) == ODP_EVENT_CRYPTO_COMPL) {
				odp_crypto_compl_free(
					odp_crypto_compl_from_event(ev));
				continue;
			}

		}
		ofp_send_pending_pkt();

		/* per cpu ofp timer schedule */
		time_queue_cpu = ofp_timer_queue_cpu(cpuid);
		event_cnt = odp_queue_deq_multi(time_queue_cpu,
					events,
					OFP_EVT_RX_BURST_SIZE);
		for (event_idx = 0; event_idx < event_cnt; event_idx++) {
			ev = events[event_idx];
			if (odp_event_type(ev) == ODP_EVENT_TIMEOUT) {
				ofp_timer_handle(ev);
				continue;
			} else {
				OFP_ERR("Unexpected event type: %u",
					odp_event_type(ev));
			}
		}

		/* dpdk timer schedule */
		rte_timer_manage();
	}

	if (ofp_term_local())
		OFP_ERR("ofp_term_local failed");

	return NULL;
}


/** main() Application entry point
 *
 * @param argc int
 * @param argv[] char*
 * @return int
 *
 */
#include <sys/time.h>
#include <sys/resource.h>

int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	appl_args_t params;
	int core_count, num_workers;
	odp_cpumask_t cpumask;
	char cpumaskstr[64];
	odph_linux_thr_params_t thr_params;
	odp_instance_t instance;
	struct sigaction signal_action;
	struct rlimit rlp;

	memset(&signal_action, 0, sizeof(signal_action));
	signal_action.sa_handler = signal_handler;
	sigfillset(&signal_action.sa_mask);
	//sigaction(SIGILL,  &signal_action, NULL);
	//sigaction(SIGFPE,  &signal_action, NULL);
	//sigaction(SIGSEGV, &signal_action, NULL);
	sigaction(SIGTERM, &signal_action, NULL);
	sigaction(SIGINT, &signal_action, NULL);
	//sigaction(SIGBUS,  &signal_action, NULL);
	signal(SIGPIPE, SIG_IGN);

	getrlimit(RLIMIT_CORE, &rlp);
	printf("RLIMIT_CORE: %ld/%ld\n", rlp.rlim_cur, rlp.rlim_max);
	rlp.rlim_cur = 200000000;
	printf("Setting to max: %d\n", setrlimit(RLIMIT_CORE, &rlp));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &params);

	if (odp_init_global(&instance, NULL, NULL)) {
		OFP_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &params);

	core_count = odp_cpu_count();
	num_workers = core_count;

	if (params.core_count)
		num_workers = params.core_count;
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	/*
	 * By default core #0 runs Linux kernel background tasks.
	 * Start mapping thread from core #1
	 */
	memset(&app_init_params, 0, sizeof(app_init_params));

	app_init_params.linux_core_id = 0;

	if (core_count > 1)
		num_workers--;

	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("odp_cpu_count : %i\n", core_count);
	printf("Num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	app_init_params.if_count = params.if_count;
	app_init_params.if_names = params.if_names;
	app_init_params.pkt_hook[OFP_HOOK_PREROUTING] = ofp_vs_in;
	if (ofp_init_global(instance, &app_init_params)) {
		OFP_ERR("Error: OFP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	memset(thread_tbl, 0, sizeof(thread_tbl));
	/* Start dataplane dispatcher worker threads */

	//thr_params.start = default_event_dispatcher;
	thr_params.start = event_dispatcher;
	thr_params.arg = ofp_eth_vlan_processing;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;
	odph_linux_pthread_create(thread_tbl,
				  &cpumask,
				  &thr_params);

	/* other app code here.*/
	/* Start CLI */
	ofp_start_cli_thread(instance, app_init_params.linux_core_id, params.conf_file);

	rte_timer_subsystem_init();

	if (ofp_vs_init(instance, &app_init_params) < 0) {
		ofp_stop_processing();
		OFP_ERR("ofp_vs_init() failed\n");
	}

	odph_linux_pthread_join(thread_tbl, num_workers);
	printf("End Worker\n");

	ofp_vs_finish();
	printf("End Main()\n");

	return 0;
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *names, *str, *token, *save;
	size_t len;
	int i;
	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{"configuration file", required_argument,
			NULL, 'f'},/* return 'f' */
		{NULL, 0, NULL, 0}
	};

	memset(appl_args, 0, sizeof(*appl_args));

	while (1) {
		opt = getopt_long(argc, argv, "+c:i:hf:",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->core_count = atoi(optarg);
			break;
			/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			names = malloc(len);
			if (names == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
			}
			appl_args->if_count = i;

			if (appl_args->if_count == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
				calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
				appl_args->if_names[i] = token;
			}
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		case 'f':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->conf_file = malloc(len);
			if (appl_args->conf_file == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(appl_args->conf_file, optarg);
			break;

		default:
			break;
		}
	}

	if (appl_args->if_count == 0) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	int i;

	printf("\n"
		   "ODP system info\n"
		   "---------------\n"
		   "ODP API version: %s\n"
		   "CPU model:       %s\n"
		   "CPU freq (hz):   %"PRIu64"\n"
		   "Cache line size: %i\n"
		   "Core count:      %i\n"
		   "\n",
		   odp_version_api_str(), odp_cpu_model_str(),
		   odp_cpu_hz(), odp_sys_cache_line_size(),
		   odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
		   "-----------------\n"
		   "IF-count:        %i\n"
		   "Using IFs:      ",
		   progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
		   "Usage: %s OPTIONS\n"
		   "  E.g. %s -i eth1,eth2,eth3\n"
		   "\n"
		   "ODPFastpath application.\n"
		   "\n"
		   "Mandatory OPTIONS:\n"
		   "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
		   "\n"
		   "Optional OPTIONS\n"
		   "  -c, --count <number> Core count.\n"
		   "  -h, --help           Display help and exit.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname)
		);
}
