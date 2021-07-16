/*
 * TODO dynamic memory allocation for this
 */
#include <stdlib.h>
#include <stdint.h>
#define CTRTOOL_ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
struct ctrtool_opt_element {
	const char *name;
	union {
		void *ptr;
		uint64_t value;
	} value;
};
struct ctrtool_opt_args {
	char *name;
	char *value;
};
struct ctrtool_opt_kv {
	uint64_t key;
	char *value;
};
int ctrtool_options_add_opt(const char *name_value);
void ctrtool_options_sort_opts(void);
void ctrtool_options_clear_opts(void);
char *ctrtool_options_get_arg(const char *name);
uint64_t ctrtool_options_parse_arg_int(const char *arg, const char *error_msg, int *has_error, uint64_t default_value);
struct ctrtool_opt_element *ctrtool_options_parse_arg_enum(const char *arg, struct ctrtool_opt_element *values, size_t nr_values, const char *error_msg, int *has_error, struct ctrtool_opt_element *default_value);
uint64_t ctrtool_options_parse_arg_int_with_preset(const char *arg, struct ctrtool_opt_element *values, size_t nr_values, const char *error_msg, uint64_t default_value);
int ctrtool_options_parse_arg_bool(const char *arg, const char *error_msg, int default_value);
char *ctrtool_options_get_arg_default(char *arg, char *default_value);
struct ctrtool_opt_kv *ctrtool_options_parse_arg_kv(const char *arg, struct ctrtool_opt_element *values, size_t nr_values);
