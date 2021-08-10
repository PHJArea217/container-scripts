#include "ctrtool-common.h"
struct ctrtool_ppid_check_args {
	uint64_t blocked_signals;
	uint64_t unblocked_signals;
	uint64_t ignored_signals;
	uint64_t default_signals;
	unsigned set_alarm:1;
	unsigned set_pdeathsig:1;
	unsigned set_nnp:1;
	unsigned set_setsid:1;
	unsigned set_subreaper:1;
	unsigned check_ppid:1;
	uint16_t pdeathsig;
	unsigned int alarm_time;
	unsigned long expected_ppid;
	const char *setenv_prefix;
};
const char *ctrtool_ppid_check_run(struct ctrtool_ppid_check_args *args);
