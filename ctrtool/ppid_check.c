#include "ctrtool_ppid_check.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
int ctr_scripts_ppid_check_main(int argc, char **argv) {
	ctrtool_clear_saved_argv();
	struct ctrtool_ppid_check_args args = {};
	int opt = 0;
	while ((opt = getopt(argc, argv, "+a:b:D:d:e:i:np:rsu:")) > 0) {
		switch (opt) {
			case 'a':
				args.alarm_time = strtoul(optarg, NULL, 0);
				args.set_alarm = 1;
				break;
			case 'd':
				args.pdeathsig = ctrtool_parse_signal(optarg);
				args.set_pdeathsig = 1;
				break;
			case 'b':
				args.blocked_signals |= 1ULL << (ctrtool_parse_signal(optarg) - 1);
				break;
			case 'D':
				args.default_signals |= 1ULL << (ctrtool_parse_signal(optarg) - 1);
				break;
			case 'u':
				args.unblocked_signals |= 1ULL << (ctrtool_parse_signal(optarg) - 1);
				break;
			case 'i':
				args.ignored_signals |= 1ULL << (ctrtool_parse_signal(optarg) - 1);
				break;
			case 'e':
				args.setenv_prefix = optarg;
				break;
			case 'n':
				args.set_nnp = 1;
				break;
			case 'p':
				args.expected_ppid = strtoul(optarg, NULL, 0);
				args.check_ppid = 1;
				break;
			case 'r':
				args.set_subreaper = 1;
				break;
			case 's':
				args.set_setsid = 1;
				break;
			default:
				/* TODO: help text */
				return 1;
				break;
		}
	}
	if (!argv[optind]) {
		fprintf(stderr, "%s: No program specified\n", argv[0]);
		return 1;
	}
	const char *error_msg = ctrtool_ppid_check_run(&args);
	if (error_msg) {
		perror(error_msg);
		return 2;
	}
	execvp(argv[optind], &argv[optind]);
	perror("execvp");
	return 3;
}
