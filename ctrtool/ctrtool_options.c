#include "ctrtool_options.h"
#include "ctrtool-common.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
static struct ctrtool_opt_element boolean_values[] = {
	{.name = "false", .value = {.value = 0}},
	{.name = "no", .value = {.value = 0}},
	{.name = "off", .value = {.value = 0}},
	{.name = "on", .value = {.value = 1}},
	{.name = "true", .value = {.value = 1}},
	{.name = "yes", .value = {.value = 1}}
};
static struct ctrtool_arraylist my_args_list = {.start = 0, .nr = 0, .max = 0, .elem_size = sizeof(struct ctrtool_opt_args)};
static int compare_args(const void *a, const void *b) {
	return strcasecmp(((struct ctrtool_opt_args *) a)->name, ((struct ctrtool_opt_args *) b)->name);
}
static int compare_opts(const void *a, const void *b) {
	return strcasecmp(((struct ctrtool_opt_element *) a)->name, ((struct ctrtool_opt_element *) b)->name);
}
static char *get_arg(const char *name) {
	struct ctrtool_opt_args req_arg = {(char *) name, 0};
	void *result = bsearch(&req_arg, my_args_list.start, my_args_list.nr, sizeof(struct ctrtool_opt_args), compare_args);
	return result ? ((struct ctrtool_opt_args *) result)->value : NULL;
}
static uint64_t parse_arg_int(const char *arg, const char *error_msg, int *has_error, uint64_t default_value) {
	if (!arg) {
		if (has_error) *has_error = 0;
		return default_value;
	}
	if (isdigit(arg[0])) {
		if (has_error) *has_error = 0;
		int saved_errno = errno;
		errno = 0;
		unsigned long long result = strtoull(arg, NULL, 0);
		if ((errno) || ((sizeof(unsigned long long) > sizeof(uint64_t)) && (result >= (1ULL << (sizeof(uint64_t) * CHAR_BIT))))) {
			fprintf(stderr, "Number invalid or too large: %s\n", arg);
			exit(1);
		}
		errno = saved_errno;
		return result;
	}
	if (has_error) *has_error = 1;
	if (error_msg) {
		fprintf(stderr, "%s: %s\n", error_msg, arg);
		exit(1);
	}
	return -1;
}
static struct ctrtool_opt_element *parse_arg_enum(const char *arg, struct ctrtool_opt_element *values, size_t nr_values, const char *error_msg, int *has_error, struct ctrtool_opt_element *default_value) {
	if (!arg) {
		if (has_error) *has_error = 0;
		return default_value;
	}
	struct ctrtool_opt_element req_arg = {(char *) arg, {0}};
	void *result = bsearch(&req_arg, values, nr_values, sizeof(struct ctrtool_opt_element), compare_opts);
	if (result) {
		if (has_error) *has_error = 0;
		return (struct ctrtool_opt_element *) result;
	}
	if (has_error) *has_error = 1;
	if (error_msg) {
		fprintf(stderr, "%s: %s\n", error_msg, arg);
		exit(1);
	}
	return NULL;
}
static uint64_t parse_arg_int_with_preset(const char *arg, struct ctrtool_opt_element *values, size_t nr_values, const char *error_msg, uint64_t default_value) {
	if (!error_msg) {
		error_msg = "Invalid int/preset option";
	}
	int has_error = 0;
	uint64_t result = parse_arg_int(arg, NULL, &has_error, default_value);
	if (has_error) {
		struct ctrtool_opt_element *result2 = parse_arg_enum(arg, values, nr_values, error_msg, NULL, NULL);
		return result2->value.value;
	}
	return result;
}
static int parse_arg_bool(const char *arg, const char *error_msg, int default_value) {
	if (!error_msg) {
		error_msg = "Invalid boolean";
	}
	if (!arg) {
		return !!default_value;
	}
	int has_error = 0;
	uint64_t result = parse_arg_int(arg, NULL, &has_error, 0);
	if (has_error) {
		struct ctrtool_opt_element *elem = parse_arg_enum(arg, boolean_values, sizeof(boolean_values)/sizeof(boolean_values[0]), error_msg, NULL, NULL);
		return !!elem->value.value;
	}
	return !!result;
}
static char *get_arg_default(char *arg, char *default_value) {
	return arg ? arg : default_value;
}
int ctrtool_options_add_opt(const char *name_value) {
	struct ctrtool_opt_args current = {0};
	current.name = strdup(name_value);
	if (!current.name) {
		errno = ENOMEM;
		return -1;
	}
	char *b = strchr(current.name, '=');
	if (!b) {
		errno = EINVAL;
		return -1;
	}
	*b = 0;
	b++;
	current.value = b;
	if (ctrtool_arraylist_expand(&my_args_list, &current, 10)) {
		free(current.name);
		errno = ENOMEM;
		return -1;
	}
	return 0;
}
void ctrtool_options_sort_opts(void) {
	qsort(my_args_list.start, my_args_list.nr, my_args_list.elem_size, compare_opts);
}
void ctrtool_options_clear_opts(void) {
	struct ctrtool_opt_args *elem = my_args_list.start;
	for (size_t i = 0; i < my_args_list.nr; i++) {
		free(elem[i].name);
	}
	my_args_list.nr = 0;
	my_args_list.max = 0;
	free(my_args_list.start);
	my_args_list.start = NULL;
}
char *ctrtool_options_get_arg(const char *name) {
	return get_arg(name);
}
uint64_t ctrtool_options_parse_arg_int(const char *arg, const char *error_msg, int *has_error, uint64_t default_value) {
	return parse_arg_int(arg, error_msg, has_error, default_value);
}
struct ctrtool_opt_element *ctrtool_options_parse_arg_enum(const char *arg, struct ctrtool_opt_element *values, size_t nr_values, const char *error_msg, int *has_error, struct ctrtool_opt_element *default_value) {
	return parse_arg_enum(arg, values, nr_values, error_msg, has_error, default_value);
}
uint64_t ctrtool_options_parse_arg_int_with_preset(const char *arg, struct ctrtool_opt_element *values, size_t nr_values, const char *error_msg, uint64_t default_value) {
	return parse_arg_int_with_preset(arg, values, nr_values, error_msg, default_value);
}
int ctrtool_options_parse_arg_bool(const char *arg, const char *error_msg, int default_value) {
	return parse_arg_bool(arg, error_msg, default_value);
}
char *ctrtool_options_get_arg_default(char *arg, char *default_value) {
	return get_arg_default(arg, default_value);
}
