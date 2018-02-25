#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <locale.h>
#include <time.h>
#include <errno.h>

#include <seclib.h>

#include "dev_temp.h"


void DevTempTest()
{
	JSON_VALUE *v;
	JSON_OBJECT *o;
	JSON_OBJECT *o2;
	JSON_VALUE *v2;
	char *str;
	
	v = JsonNewObject();

	o = JsonValueGetObject(v);

	JsonDotSetStr(o, "aaa", "123");
	JsonDotSetNumber(o, "bbb", 123456789123456ULL);

	v2 = JsonNewObject();
	o2 = JsonValueGetObject(v2);

	JsonSet(o, "v2", v2);

	JsonSetStr(o2, "Hello", "World");
	JsonSetBool(o2, "Aho", true);

	str = JsonSerializeToStringPretty(v);

	Print("%s\n", str);

	JsonFree(v);

	v = JsonParseStringWithComments(str);
	o = JsonValueGetObject(v);

	Print("value = %s\n", JsonDotGetStr(o, "aaa"));

	JsonFree(v);

	Free(str);
}



/*
Parson ( http://kgabis.github.com/parson/ )
Copyright (c) 2012 - 2017 Krzysztof Gabis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/



/* Apparently sscanf is not implemented in some "standard" libraries, so don't use it, if you
* don't have to. */
#define sscanf THINK_TWICE_ABOUT_USING_SSCANF

#define STARTING_CAPACITY 16
#define MAX_NESTING       2048
#define FLOAT_FORMAT      "%1.17g"

#define SIZEOF_TOKEN(a)       (sizeof(a) - 1)
#define SKIP_CHAR(str)        ((*str)++)
#define SKIP_WHITESPACES(str) while (isspace((unsigned char)(**str))) { SKIP_CHAR(str); }

static JSON_Malloc_Function parson_malloc = Malloc;
static JSON_Free_Function parson_free = Free;

#define IS_CONT(b) (((unsigned char)(b) & 0xC0) == 0x80) /* is utf-8 continuation byte */

/* Various */
static void   remove_comments(char *string, char *start_token, char *end_token);
static char * parson_strndup(char *string, UINT n);
static char * parson_strdup(char *string);
static int    hex_char_to_int(char c);
static int    parse_utf16_hex(char *string, unsigned int *result);
static int    num_bytes_in_utf8_sequence(unsigned char c);
static int    verify_utf8_sequence(unsigned char *string, int *len);
static int    is_valid_utf8(char *string, UINT string_len);
static int    is_decimal(char *string, UINT length);

/* JSON Object */
static JSON_OBJECT * json_object_init(JSON_VALUE *wrapping_value);
static UINT   json_object_add(JSON_OBJECT *object, char *name, JSON_VALUE *value);
static UINT   json_object_resize(JSON_OBJECT *object, UINT new_capacity);
static JSON_VALUE  * json_object_nget_value(JSON_OBJECT *object, char *name, UINT n);
static void          json_object_free(JSON_OBJECT *object);

/* JSON Array */
static JSON_ARRAY * json_array_init(JSON_VALUE *wrapping_value);
static UINT  json_array_add(JSON_ARRAY *array, JSON_VALUE *value);
static UINT  json_array_resize(JSON_ARRAY *array, UINT new_capacity);
static void         json_array_free(JSON_ARRAY *array);

/* JSON Value */
static JSON_VALUE * json_value_init_string_no_copy(char *string);

/* Parser */
static UINT  skip_quotes(char **string);
static int          parse_utf16(char **unprocessed, char **processed);
static char *       process_string(char *input, UINT len);
static char *       get_quoted_string(char **string);
static JSON_VALUE * parse_object_value(char **string, UINT nesting);
static JSON_VALUE * parse_array_value(char **string, UINT nesting);
static JSON_VALUE * parse_string_value(char **string);
static JSON_VALUE * parse_boolean_value(char **string);
static JSON_VALUE * parse_number_value(char **string);
static JSON_VALUE * parse_null_value(char **string);
static JSON_VALUE * parse_value(char **string, UINT nesting);

/* Serialization */
static int    json_serialize_to_buffer_r(JSON_VALUE *value, char *buf, int level, int is_pretty, char *num_buf);
static int    json_serialize_string(char *string, char *buf);
static int    append_indent(char *buf, int level);
static int    append_string(char *buf, char *string);

/* Various */
static char * parson_strndup(char *string, UINT n) {
	char *output_string = (char*)parson_malloc(n + 1);
	if (!output_string) {
		return NULL;
	}
	output_string[n] = '\0';
	strncpy(output_string, string, n);
	return output_string;
}

static char * parson_strdup(char *string) {
	return parson_strndup(string, StrLen(string));
}

static int hex_char_to_int(char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	else if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

static int parse_utf16_hex(char *s, unsigned int *result) {
	int x1, x2, x3, x4;
	if (s[0] == '\0' || s[1] == '\0' || s[2] == '\0' || s[3] == '\0') {
		return 0;
	}
	x1 = hex_char_to_int(s[0]);
	x2 = hex_char_to_int(s[1]);
	x3 = hex_char_to_int(s[2]);
	x4 = hex_char_to_int(s[3]);
	if (x1 == -1 || x2 == -1 || x3 == -1 || x4 == -1) {
		return 0;
	}
	*result = (unsigned int)((x1 << 12) | (x2 << 8) | (x3 << 4) | x4);
	return 1;
}

static int num_bytes_in_utf8_sequence(unsigned char c) {
	if (c == 0xC0 || c == 0xC1 || c > 0xF4 || IS_CONT(c)) {
		return 0;
	}
	else if ((c & 0x80) == 0) {    /* 0xxxxxxx */
		return 1;
	}
	else if ((c & 0xE0) == 0xC0) { /* 110xxxxx */
		return 2;
	}
	else if ((c & 0xF0) == 0xE0) { /* 1110xxxx */
		return 3;
	}
	else if ((c & 0xF8) == 0xF0) { /* 11110xxx */
		return 4;
	}
	return 0; /* won't happen */
}

static int verify_utf8_sequence(unsigned char *string, int *len) {
	unsigned int cp = 0;
	*len = num_bytes_in_utf8_sequence(string[0]);

	if (*len == 1) {
		cp = string[0];
	}
	else if (*len == 2 && IS_CONT(string[1])) {
		cp = string[0] & 0x1F;
		cp = (cp << 6) | (string[1] & 0x3F);
	}
	else if (*len == 3 && IS_CONT(string[1]) && IS_CONT(string[2])) {
		cp = ((unsigned char)string[0]) & 0xF;
		cp = (cp << 6) | (string[1] & 0x3F);
		cp = (cp << 6) | (string[2] & 0x3F);
	}
	else if (*len == 4 && IS_CONT(string[1]) && IS_CONT(string[2]) && IS_CONT(string[3])) {
		cp = string[0] & 0x7;
		cp = (cp << 6) | (string[1] & 0x3F);
		cp = (cp << 6) | (string[2] & 0x3F);
		cp = (cp << 6) | (string[3] & 0x3F);
	}
	else {
		return 0;
	}

	/* overlong encodings */
	if ((cp < 0x80 && *len > 1) ||
		(cp < 0x800 && *len > 2) ||
		(cp < 0x10000 && *len > 3)) {
		return 0;
	}

	/* invalid unicode */
	if (cp > 0x10FFFF) {
		return 0;
	}

	/* surrogate halves */
	if (cp >= 0xD800 && cp <= 0xDFFF) {
		return 0;
	}

	return 1;
}

static int is_valid_utf8(char *string, UINT string_len) {
	int len = 0;
	char *string_end = string + string_len;
	while (string < string_end) {
		if (!verify_utf8_sequence((unsigned char*)string, &len)) {
			return 0;
		}
		string += len;
	}
	return 1;
}

static int is_decimal(char *string, UINT length) {
	if (length > 1 && string[0] == '0' && string[1] != '.') {
		return 0;
	}
	if (length > 2 && !strncmp(string, "-0", 2) && string[2] != '.') {
		return 0;
	}
	while (length--) {
		if (strchr("xX", string[length])) {
			return 0;
		}
	}
	return 1;
}

static void remove_comments(char *string, char *start_token, char *end_token) {
	int in_string = 0, escaped = 0;
	UINT i;
	char *ptr = NULL, current_char;
	UINT start_token_len = StrLen(start_token);
	UINT end_token_len = StrLen(end_token);
	if (start_token_len == 0 || end_token_len == 0) {
		return;
	}
	while ((current_char = *string) != '\0') {
		if (current_char == '\\' && !escaped) {
			escaped = 1;
			string++;
			continue;
		}
		else if (current_char == '\"' && !escaped) {
			in_string = !in_string;
		}
		else if (!in_string && strncmp(string, start_token, start_token_len) == 0) {
			for (i = 0; i < start_token_len; i++) {
				string[i] = ' ';
			}
			string = string + start_token_len;
			ptr = strstr(string, end_token);
			if (!ptr) {
				return;
			}
			for (i = 0; i < (ptr - string) + end_token_len; i++) {
				string[i] = ' ';
			}
			string = ptr + end_token_len - 1;
		}
		escaped = 0;
		string++;
	}
}

/* JSON Object */
static JSON_OBJECT * json_object_init(JSON_VALUE *wrapping_value) {
	JSON_OBJECT *new_obj = (JSON_OBJECT*)parson_malloc(sizeof(JSON_OBJECT));
	if (new_obj == NULL) {
		return NULL;
	}
	new_obj->wrapping_value = wrapping_value;
	new_obj->names = (char**)NULL;
	new_obj->values = (JSON_VALUE**)NULL;
	new_obj->capacity = 0;
	new_obj->count = 0;
	return new_obj;
}

static UINT json_object_add(JSON_OBJECT *object, char *name, JSON_VALUE *value) {
	UINT index = 0;
	if (object == NULL || name == NULL || value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonGet(object, name) != NULL) {
		return JSON_RET_ERROR;
	}
	if (object->count >= object->capacity) {
		UINT new_capacity = MAX(object->capacity * 2, STARTING_CAPACITY);
		if (json_object_resize(object, new_capacity) == JSON_RET_ERROR) {
			return JSON_RET_ERROR;
		}
	}
	index = object->count;
	object->names[index] = parson_strdup(name);
	if (object->names[index] == NULL) {
		return JSON_RET_ERROR;
	}
	value->parent = JsonGetWrappingValue(object);
	object->values[index] = value;
	object->count++;
	return JSON_RET_OK;
}

static UINT json_object_resize(JSON_OBJECT *object, UINT new_capacity) {
	char **temp_names = NULL;
	JSON_VALUE **temp_values = NULL;

	if ((object->names == NULL && object->values != NULL) ||
		(object->names != NULL && object->values == NULL) ||
		new_capacity == 0) {
		return JSON_RET_ERROR; /* Shouldn't happen */
	}
	temp_names = (char**)parson_malloc(new_capacity * sizeof(char*));
	if (temp_names == NULL) {
		return JSON_RET_ERROR;
	}
	temp_values = (JSON_VALUE**)parson_malloc(new_capacity * sizeof(JSON_VALUE*));
	if (temp_values == NULL) {
		parson_free(temp_names);
		return JSON_RET_ERROR;
	}
	if (object->names != NULL && object->values != NULL && object->count > 0) {
		memcpy(temp_names, object->names, object->count * sizeof(char*));
		memcpy(temp_values, object->values, object->count * sizeof(JSON_VALUE*));
	}
	parson_free(object->names);
	parson_free(object->values);
	object->names = temp_names;
	object->values = temp_values;
	object->capacity = new_capacity;
	return JSON_RET_OK;
}

static JSON_VALUE * json_object_nget_value(JSON_OBJECT *object, char *name, UINT n) {
	UINT i, name_length;
	for (i = 0; i < JsonGetCount(object); i++) {
		name_length = StrLen(object->names[i]);
		if (name_length != n) {
			continue;
		}
		if (strncmp(object->names[i], name, n) == 0) {
			return object->values[i];
		}
	}
	return NULL;
}

static void json_object_free(JSON_OBJECT *object) {
	UINT i;
	for (i = 0; i < object->count; i++) {
		parson_free(object->names[i]);
		JsonFree(object->values[i]);
	}
	parson_free(object->names);
	parson_free(object->values);
	parson_free(object);
}

/* JSON Array */
static JSON_ARRAY * json_array_init(JSON_VALUE *wrapping_value) {
	JSON_ARRAY *new_array = (JSON_ARRAY*)parson_malloc(sizeof(JSON_ARRAY));
	if (new_array == NULL) {
		return NULL;
	}
	new_array->wrapping_value = wrapping_value;
	new_array->items = (JSON_VALUE**)NULL;
	new_array->capacity = 0;
	new_array->count = 0;
	return new_array;
}

static UINT json_array_add(JSON_ARRAY *array, JSON_VALUE *value) {
	if (array->count >= array->capacity) {
		UINT new_capacity = MAX(array->capacity * 2, STARTING_CAPACITY);
		if (json_array_resize(array, new_capacity) == JSON_RET_ERROR) {
			return JSON_RET_ERROR;
		}
	}
	value->parent = JsonArrayGetWrappingValue(array);
	array->items[array->count] = value;
	array->count++;
	return JSON_RET_OK;
}

static UINT json_array_resize(JSON_ARRAY *array, UINT new_capacity) {
	JSON_VALUE **new_items = NULL;
	if (new_capacity == 0) {
		return JSON_RET_ERROR;
	}
	new_items = (JSON_VALUE**)parson_malloc(new_capacity * sizeof(JSON_VALUE*));
	if (new_items == NULL) {
		return JSON_RET_ERROR;
	}
	if (array->items != NULL && array->count > 0) {
		memcpy(new_items, array->items, array->count * sizeof(JSON_VALUE*));
	}
	parson_free(array->items);
	array->items = new_items;
	array->capacity = new_capacity;
	return JSON_RET_OK;
}

static void json_array_free(JSON_ARRAY *array) {
	UINT i;
	for (i = 0; i < array->count; i++) {
		JsonFree(array->items[i]);
	}
	parson_free(array->items);
	parson_free(array);
}

/* JSON Value */
static JSON_VALUE * json_value_init_string_no_copy(char *string) {
	JSON_VALUE *new_value = (JSON_VALUE*)parson_malloc(sizeof(JSON_VALUE));
	if (!new_value) {
		return NULL;
	}
	new_value->parent = NULL;
	new_value->type = JSON_TYPE_STRING;
	new_value->value.string = string;
	return new_value;
}

/* Parser */
static UINT skip_quotes(char **string) {
	if (**string != '\"') {
		return JSON_RET_ERROR;
	}
	SKIP_CHAR(string);
	while (**string != '\"') {
		if (**string == '\0') {
			return JSON_RET_ERROR;
		}
		else if (**string == '\\') {
			SKIP_CHAR(string);
			if (**string == '\0') {
				return JSON_RET_ERROR;
			}
		}
		SKIP_CHAR(string);
	}
	SKIP_CHAR(string);
	return JSON_RET_OK;
}

static int parse_utf16(char **unprocessed, char **processed) {
	unsigned int cp, lead, trail;
	int parse_succeeded = 0;
	char *processed_ptr = *processed;
	char *unprocessed_ptr = *unprocessed;
	unprocessed_ptr++; /* skips u */
	parse_succeeded = parse_utf16_hex(unprocessed_ptr, &cp);
	if (!parse_succeeded) {
		return JSON_RET_ERROR;
	}
	if (cp < 0x80) {
		processed_ptr[0] = (char)cp; /* 0xxxxxxx */
	}
	else if (cp < 0x800) {
		processed_ptr[0] = ((cp >> 6) & 0x1F) | 0xC0; /* 110xxxxx */
		processed_ptr[1] = ((cp) & 0x3F) | 0x80; /* 10xxxxxx */
		processed_ptr += 1;
	}
	else if (cp < 0xD800 || cp > 0xDFFF) {
		processed_ptr[0] = ((cp >> 12) & 0x0F) | 0xE0; /* 1110xxxx */
		processed_ptr[1] = ((cp >> 6) & 0x3F) | 0x80; /* 10xxxxxx */
		processed_ptr[2] = ((cp) & 0x3F) | 0x80; /* 10xxxxxx */
		processed_ptr += 2;
	}
	else if (cp >= 0xD800 && cp <= 0xDBFF) { /* lead surrogate (0xD800..0xDBFF) */
		lead = cp;
		unprocessed_ptr += 4; /* should always be within the buffer, otherwise previous sscanf would fail */
		if (*unprocessed_ptr++ != '\\' || *unprocessed_ptr++ != 'u') {
			return JSON_RET_ERROR;
		}
		parse_succeeded = parse_utf16_hex(unprocessed_ptr, &trail);
		if (!parse_succeeded || trail < 0xDC00 || trail > 0xDFFF) { /* valid trail surrogate? (0xDC00..0xDFFF) */
			return JSON_RET_ERROR;
		}
		cp = ((((lead - 0xD800) & 0x3FF) << 10) | ((trail - 0xDC00) & 0x3FF)) + 0x010000;
		processed_ptr[0] = (((cp >> 18) & 0x07) | 0xF0); /* 11110xxx */
		processed_ptr[1] = (((cp >> 12) & 0x3F) | 0x80); /* 10xxxxxx */
		processed_ptr[2] = (((cp >> 6) & 0x3F) | 0x80); /* 10xxxxxx */
		processed_ptr[3] = (((cp) & 0x3F) | 0x80); /* 10xxxxxx */
		processed_ptr += 3;
	}
	else { /* trail surrogate before lead surrogate */
		return JSON_RET_ERROR;
	}
	unprocessed_ptr += 3;
	*processed = processed_ptr;
	*unprocessed = unprocessed_ptr;
	return JSON_RET_OK;
}


/* Copies and processes passed string up to supplied length.
Example: "\u006Corem ipsum" -> lorem ipsum */
static char* process_string(char *input, UINT len) {
	char *input_ptr = input;
	UINT initial_size = (len + 1) * sizeof(char);
	UINT final_size = 0;
	char *output = NULL, *output_ptr = NULL, *resized_output = NULL;
	output = (char*)parson_malloc(initial_size);
	if (output == NULL) {
		goto error;
	}
	output_ptr = output;
	while ((*input_ptr != '\0') && (UINT)(input_ptr - input) < len) {
		if (*input_ptr == '\\') {
			input_ptr++;
			switch (*input_ptr) {
			case '\"': *output_ptr = '\"'; break;
			case '\\': *output_ptr = '\\'; break;
			case '/':  *output_ptr = '/';  break;
			case 'b':  *output_ptr = '\b'; break;
			case 'f':  *output_ptr = '\f'; break;
			case 'n':  *output_ptr = '\n'; break;
			case 'r':  *output_ptr = '\r'; break;
			case 't':  *output_ptr = '\t'; break;
			case 'u':
				if (parse_utf16(&input_ptr, &output_ptr) == JSON_RET_ERROR) {
					goto error;
				}
				break;
			default:
				goto error;
			}
		}
		else if ((unsigned char)*input_ptr < 0x20) {
			goto error; /* 0x00-0x19 are invalid characters for json string (http://www.ietf.org/rfc/rfc4627.txt) */
		}
		else {
			*output_ptr = *input_ptr;
		}
		output_ptr++;
		input_ptr++;
	}
	*output_ptr = '\0';
	/* resize to new length */
	final_size = (UINT)(output_ptr - output) + 1;
	/* todo: don't resize if final_size == initial_size */
	resized_output = (char*)parson_malloc(final_size);
	if (resized_output == NULL) {
		goto error;
	}
	memcpy(resized_output, output, final_size);
	parson_free(output);
	return resized_output;
error:
	parson_free(output);
	return NULL;
}

/* Return processed contents of a string between quotes and
skips passed argument to a matching quote. */
static char * get_quoted_string(char **string) {
	char *string_start = *string;
	UINT string_len = 0;
	UINT status = skip_quotes(string);
	if (status != JSON_RET_OK) {
		return NULL;
	}
	string_len = (UINT)(*string - string_start - 2); /* length without quotes */
	return process_string(string_start + 1, string_len);
}

static JSON_VALUE * parse_value(char **string, UINT nesting) {
	if (nesting > MAX_NESTING) {
		return NULL;
	}
	SKIP_WHITESPACES(string);
	switch (**string) {
	case '{':
		return parse_object_value(string, nesting + 1);
	case '[':
		return parse_array_value(string, nesting + 1);
	case '\"':
		return parse_string_value(string);
	case 'f': case 't':
		return parse_boolean_value(string);
	case '-':
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		return parse_number_value(string);
	case 'n':
		return parse_null_value(string);
	default:
		return NULL;
	}
}

static JSON_VALUE * parse_object_value(char **string, UINT nesting) {
	JSON_VALUE *output_value = JsonNewObject(), *new_value = NULL;
	JSON_OBJECT *output_object = JsonValueGetObject(output_value);
	char *new_key = NULL;
	if (output_value == NULL || **string != '{') {
		return NULL;
	}
	SKIP_CHAR(string);
	SKIP_WHITESPACES(string);
	if (**string == '}') { /* empty object */
		SKIP_CHAR(string);
		return output_value;
	}
	while (**string != '\0') {
		new_key = get_quoted_string(string);
		if (new_key == NULL) {
			JsonFree(output_value);
			return NULL;
		}
		SKIP_WHITESPACES(string);
		if (**string != ':') {
			parson_free(new_key);
			JsonFree(output_value);
			return NULL;
		}
		SKIP_CHAR(string);
		new_value = parse_value(string, nesting);
		if (new_value == NULL) {
			parson_free(new_key);
			JsonFree(output_value);
			return NULL;
		}
		if (json_object_add(output_object, new_key, new_value) == JSON_RET_ERROR) {
			parson_free(new_key);
			JsonFree(new_value);
			JsonFree(output_value);
			return NULL;
		}
		parson_free(new_key);
		SKIP_WHITESPACES(string);
		if (**string != ',') {
			break;
		}
		SKIP_CHAR(string);
		SKIP_WHITESPACES(string);
	}
	SKIP_WHITESPACES(string);
	if (**string != '}' || /* Trim object after parsing is over */
		json_object_resize(output_object, JsonGetCount(output_object)) == JSON_RET_ERROR) {
		JsonFree(output_value);
		return NULL;
	}
	SKIP_CHAR(string);
	return output_value;
}

static JSON_VALUE * parse_array_value(char **string, UINT nesting) {
	JSON_VALUE *output_value = JsonNewArray(), *new_array_value = NULL;
	JSON_ARRAY *output_array = JsonValueGetArray(output_value);
	if (!output_value || **string != '[') {
		return NULL;
	}
	SKIP_CHAR(string);
	SKIP_WHITESPACES(string);
	if (**string == ']') { /* empty array */
		SKIP_CHAR(string);
		return output_value;
	}
	while (**string != '\0') {
		new_array_value = parse_value(string, nesting);
		if (new_array_value == NULL) {
			JsonFree(output_value);
			return NULL;
		}
		if (json_array_add(output_array, new_array_value) == JSON_RET_ERROR) {
			JsonFree(new_array_value);
			JsonFree(output_value);
			return NULL;
		}
		SKIP_WHITESPACES(string);
		if (**string != ',') {
			break;
		}
		SKIP_CHAR(string);
		SKIP_WHITESPACES(string);
	}
	SKIP_WHITESPACES(string);
	if (**string != ']' || /* Trim array after parsing is over */
		json_array_resize(output_array, JsonArrayGetCount(output_array)) == JSON_RET_ERROR) {
		JsonFree(output_value);
		return NULL;
	}
	SKIP_CHAR(string);
	return output_value;
}

static JSON_VALUE * parse_string_value(char **string) {
	JSON_VALUE *value = NULL;
	char *new_string = get_quoted_string(string);
	if (new_string == NULL) {
		return NULL;
	}
	value = json_value_init_string_no_copy(new_string);
	if (value == NULL) {
		parson_free(new_string);
		return NULL;
	}
	return value;
}

static JSON_VALUE * parse_boolean_value(char **string) {
	UINT true_token_size = SIZEOF_TOKEN("true");
	UINT false_token_size = SIZEOF_TOKEN("false");
	if (strncmp("true", *string, true_token_size) == 0) {
		*string += true_token_size;
		return JsonNewBool(1);
	}
	else if (strncmp("false", *string, false_token_size) == 0) {
		*string += false_token_size;
		return JsonNewBool(0);
	}
	return NULL;
}

static JSON_VALUE * parse_number_value(char **string) {
	char *end;
	double number = 0;
	errno = 0;
	number = strtod(*string, &end);
	if (errno || !is_decimal(*string, (UINT)(end - *string))) {
		return NULL;
	}
	*string = end;
	return JsonNewNumber(number);
}

static JSON_VALUE * parse_null_value(char **string) {
	UINT token_size = SIZEOF_TOKEN("null");
	if (strncmp("null", *string, token_size) == 0) {
		*string += token_size;
		return JsonNewNull();
	}
	return NULL;
}

/* Serialization */
#define APPEND_STRING(str) do { written = append_string(buf, (str));\
                                if (written < 0) { return -1; }\
                                if (buf != NULL) { buf += written; }\
                                written_total += written; } while(0)

#define APPEND_INDENT(level) do { written = append_indent(buf, (level));\
                                  if (written < 0) { return -1; }\
                                  if (buf != NULL) { buf += written; }\
                                  written_total += written; } while(0)

static int json_serialize_to_buffer_r(JSON_VALUE *value, char *buf, int level, int is_pretty, char *num_buf)
{
	char *key = NULL, *string = NULL;
	JSON_VALUE *temp_value = NULL;
	JSON_ARRAY *array = NULL;
	JSON_OBJECT *object = NULL;
	UINT i = 0, count = 0;
	double num = 0.0;
	int written = -1, written_total = 0;

	switch (JsonValueGetType(value)) {
	case JSON_TYPE_ARRAY:
		array = JsonValueGetArray(value);
		count = JsonArrayGetCount(array);
		APPEND_STRING("[");
		if (count > 0 && is_pretty) {
			APPEND_STRING("\n");
		}
		for (i = 0; i < count; i++) {
			if (is_pretty) {
				APPEND_INDENT(level + 1);
			}
			temp_value = JsonArrayGet(array, i);
			written = json_serialize_to_buffer_r(temp_value, buf, level + 1, is_pretty, num_buf);
			if (written < 0) {
				return -1;
			}
			if (buf != NULL) {
				buf += written;
			}
			written_total += written;
			if (i < (count - 1)) {
				APPEND_STRING(",");
			}
			if (is_pretty) {
				APPEND_STRING("\n");
			}
		}
		if (count > 0 && is_pretty) {
			APPEND_INDENT(level);
		}
		APPEND_STRING("]");
		return written_total;
	case JSON_TYPE_OBJECT:
		object = JsonValueGetObject(value);
		count = JsonGetCount(object);
		APPEND_STRING("{");
		if (count > 0 && is_pretty) {
			APPEND_STRING("\n");
		}
		for (i = 0; i < count; i++) {
			key = JsonGetName(object, i);
			if (key == NULL) {
				return -1;
			}
			if (is_pretty) {
				APPEND_INDENT(level + 1);
			}
			written = json_serialize_string(key, buf);
			if (written < 0) {
				return -1;
			}
			if (buf != NULL) {
				buf += written;
			}
			written_total += written;
			APPEND_STRING(":");
			if (is_pretty) {
				APPEND_STRING(" ");
			}
			temp_value = JsonGet(object, key);
			written = json_serialize_to_buffer_r(temp_value, buf, level + 1, is_pretty, num_buf);
			if (written < 0) {
				return -1;
			}
			if (buf != NULL) {
				buf += written;
			}
			written_total += written;
			if (i < (count - 1)) {
				APPEND_STRING(",");
			}
			if (is_pretty) {
				APPEND_STRING("\n");
			}
		}
		if (count > 0 && is_pretty) {
			APPEND_INDENT(level);
		}
		APPEND_STRING("}");
		return written_total;
	case JSON_TYPE_STRING:
		string = JsonValueGetStr(value);
		if (string == NULL) {
			return -1;
		}
		written = json_serialize_string(string, buf);
		if (written < 0) {
			return -1;
		}
		if (buf != NULL) {
			buf += written;
		}
		written_total += written;
		return written_total;
	case JSON_TYPE_BOOL:
		if (JsonValueGetBool(value)) {
			APPEND_STRING("true");
		}
		else {
			APPEND_STRING("false");
		}
		return written_total;
	case JSON_TYPE_NUMBER:
		num = JsonValueGetNumber(value);
		if (buf != NULL) {
			num_buf = buf;
		}
		written = sprintf(num_buf, FLOAT_FORMAT, num);
		if (written < 0) {
			return -1;
		}
		if (buf != NULL) {
			buf += written;
		}
		written_total += written;
		return written_total;
	case JSON_TYPE_NULL:
		APPEND_STRING("null");
		return written_total;
	case JSON_TYPE_ERROR:
		return -1;
	default:
		return -1;
	}
}

static int json_serialize_string(char *string, char *buf) {
	UINT i = 0, len = StrLen(string);
	char c = '\0';
	int written = -1, written_total = 0;
	APPEND_STRING("\"");
	for (i = 0; i < len; i++) {
		c = string[i];
		switch (c) {
		case '\"': APPEND_STRING("\\\""); break;
		case '\\': APPEND_STRING("\\\\"); break;
		case '/':  APPEND_STRING("\\/"); break; /* to make json embeddable in xml\/html */
		case '\b': APPEND_STRING("\\b"); break;
		case '\f': APPEND_STRING("\\f"); break;
		case '\n': APPEND_STRING("\\n"); break;
		case '\r': APPEND_STRING("\\r"); break;
		case '\t': APPEND_STRING("\\t"); break;
		case '\x00': APPEND_STRING("\\u0000"); break;
		case '\x01': APPEND_STRING("\\u0001"); break;
		case '\x02': APPEND_STRING("\\u0002"); break;
		case '\x03': APPEND_STRING("\\u0003"); break;
		case '\x04': APPEND_STRING("\\u0004"); break;
		case '\x05': APPEND_STRING("\\u0005"); break;
		case '\x06': APPEND_STRING("\\u0006"); break;
		case '\x07': APPEND_STRING("\\u0007"); break;
			/* '\x08' duplicate: '\b' */
			/* '\x09' duplicate: '\t' */
			/* '\x0a' duplicate: '\n' */
		case '\x0b': APPEND_STRING("\\u000b"); break;
			/* '\x0c' duplicate: '\f' */
			/* '\x0d' duplicate: '\r' */
		case '\x0e': APPEND_STRING("\\u000e"); break;
		case '\x0f': APPEND_STRING("\\u000f"); break;
		case '\x10': APPEND_STRING("\\u0010"); break;
		case '\x11': APPEND_STRING("\\u0011"); break;
		case '\x12': APPEND_STRING("\\u0012"); break;
		case '\x13': APPEND_STRING("\\u0013"); break;
		case '\x14': APPEND_STRING("\\u0014"); break;
		case '\x15': APPEND_STRING("\\u0015"); break;
		case '\x16': APPEND_STRING("\\u0016"); break;
		case '\x17': APPEND_STRING("\\u0017"); break;
		case '\x18': APPEND_STRING("\\u0018"); break;
		case '\x19': APPEND_STRING("\\u0019"); break;
		case '\x1a': APPEND_STRING("\\u001a"); break;
		case '\x1b': APPEND_STRING("\\u001b"); break;
		case '\x1c': APPEND_STRING("\\u001c"); break;
		case '\x1d': APPEND_STRING("\\u001d"); break;
		case '\x1e': APPEND_STRING("\\u001e"); break;
		case '\x1f': APPEND_STRING("\\u001f"); break;
		default:
			if (buf != NULL) {
				buf[0] = c;
				buf += 1;
			}
			written_total += 1;
			break;
		}
	}
	APPEND_STRING("\"");
	return written_total;
}

static int append_indent(char *buf, int level) {
	int i;
	int written = -1, written_total = 0;
	for (i = 0; i < level; i++) {
		APPEND_STRING("    ");
	}
	return written_total;
}

static int append_string(char *buf, char *string) {
	if (buf == NULL) {
		return (int)strlen(string);
	}
	return sprintf(buf, "%s", string);
}

#undef APPEND_STRING
#undef APPEND_INDENT

JSON_VALUE * JsonParseString(char *string) {
	if (string == NULL) {
		return NULL;
	}
	if (string[0] == '\xEF' && string[1] == '\xBB' && string[2] == '\xBF') {
		string = string + 3; /* Support for UTF-8 BOM */
	}
	return parse_value((char**)&string, 0);
}

JSON_VALUE * JsonParseStringWithComments(char *string) {
	JSON_VALUE *result = NULL;
	char *string_mutable_copy = NULL, *string_mutable_copy_ptr = NULL;
	string_mutable_copy = parson_strdup(string);
	if (string_mutable_copy == NULL) {
		return NULL;
	}
	remove_comments(string_mutable_copy, "/*", "*/");
	remove_comments(string_mutable_copy, "//", "\n");
	string_mutable_copy_ptr = string_mutable_copy;
	result = parse_value((char**)&string_mutable_copy_ptr, 0);
	parson_free(string_mutable_copy);
	return result;
}

/* JSON Object API */

JSON_VALUE * JsonGet(JSON_OBJECT *object, char *name) {
	if (object == NULL || name == NULL) {
		return NULL;
	}
	return json_object_nget_value(object, name, StrLen(name));
}

char * JsonGetStr(JSON_OBJECT *object, char *name) {
	return JsonValueGetStr(JsonGet(object, name));
}

double JsonGetNumber(JSON_OBJECT *object, char *name) {
	return JsonValueGetNumber(JsonGet(object, name));
}

JSON_OBJECT * JsonGetObj(JSON_OBJECT *object, char *name) {
	return JsonValueGetObject(JsonGet(object, name));
}

JSON_ARRAY * JsonGetArray(JSON_OBJECT *object, char *name) {
	return JsonValueGetArray(JsonGet(object, name));
}

int JsonGetBool(JSON_OBJECT *object, char *name) {
	return JsonValueGetBool(JsonGet(object, name));
}

JSON_VALUE * JsonDotGet(JSON_OBJECT *object, char *name) {
	char *dot_position = strchr(name, '.');
	if (!dot_position) {
		return JsonGet(object, name);
	}
	object = JsonValueGetObject(json_object_nget_value(object, name, (UINT)(dot_position - name)));
	return JsonDotGet(object, dot_position + 1);
}

char * JsonDotGetStr(JSON_OBJECT *object, char *name) {
	return JsonValueGetStr(JsonDotGet(object, name));
}

double JsonDotGetNumber(JSON_OBJECT *object, char *name) {
	return JsonValueGetNumber(JsonDotGet(object, name));
}

JSON_OBJECT * JsonDotGetObj(JSON_OBJECT *object, char *name) {
	return JsonValueGetObject(JsonDotGet(object, name));
}

JSON_ARRAY * JsonDotGetArray(JSON_OBJECT *object, char *name) {
	return JsonValueGetArray(JsonDotGet(object, name));
}

int JsonDotGetBool(JSON_OBJECT *object, char *name) {
	return JsonValueGetBool(JsonDotGet(object, name));
}

UINT JsonGetCount(JSON_OBJECT *object) {
	return object ? object->count : 0;
}

char * JsonGetName(JSON_OBJECT *object, UINT index) {
	if (object == NULL || index >= JsonGetCount(object)) {
		return NULL;
	}
	return object->names[index];
}

JSON_VALUE * JsonGetValueAt(JSON_OBJECT *object, UINT index) {
	if (object == NULL || index >= JsonGetCount(object)) {
		return NULL;
	}
	return object->values[index];
}

JSON_VALUE *JsonGetWrappingValue(JSON_OBJECT *object) {
	return object->wrapping_value;
}

int JsonIsExists(JSON_OBJECT *object, char *name) {
	return JsonGet(object, name) != NULL;
}

int JsonIsExistsWithValueType(JSON_OBJECT *object, char *name, UINT type) {
	JSON_VALUE *val = JsonGet(object, name);
	return val != NULL && JsonValueGetType(val) == type;
}

int JsonDotIsExists(JSON_OBJECT *object, char *name) {
	return JsonDotGet(object, name) != NULL;
}

int JsonDotIsExistsWithValueType(JSON_OBJECT *object, char *name, UINT type) {
	JSON_VALUE *val = JsonDotGet(object, name);
	return val != NULL && JsonValueGetType(val) == type;
}

/* JSON Array API */
JSON_VALUE * JsonArrayGet(JSON_ARRAY *array, UINT index) {
	if (array == NULL || index >= JsonArrayGetCount(array)) {
		return NULL;
	}
	return array->items[index];
}

char * JsonArrayGetStr(JSON_ARRAY *array, UINT index) {
	return JsonValueGetStr(JsonArrayGet(array, index));
}

double JsonArrayGetNumber(JSON_ARRAY *array, UINT index) {
	return JsonValueGetNumber(JsonArrayGet(array, index));
}

JSON_OBJECT * JsonArrayGetObj(JSON_ARRAY *array, UINT index) {
	return JsonValueGetObject(JsonArrayGet(array, index));
}

JSON_ARRAY * JsonArrayGetArray(JSON_ARRAY *array, UINT index) {
	return JsonValueGetArray(JsonArrayGet(array, index));
}

int JsonArrayGetBool(JSON_ARRAY *array, UINT index) {
	return JsonValueGetBool(JsonArrayGet(array, index));
}

UINT JsonArrayGetCount(JSON_ARRAY *array) {
	return array ? array->count : 0;
}

JSON_VALUE * JsonArrayGetWrappingValue(JSON_ARRAY *array) {
	return array->wrapping_value;
}

/* JSON Value API */
UINT JsonValueGetType(JSON_VALUE *value) {
	return value ? value->type : JSON_TYPE_ERROR;
}

JSON_OBJECT * JsonValueGetObject(JSON_VALUE *value) {
	return JsonValueGetType(value) == JSON_TYPE_OBJECT ? value->value.object : NULL;
}

JSON_ARRAY * JsonValueGetArray(JSON_VALUE *value) {
	return JsonValueGetType(value) == JSON_TYPE_ARRAY ? value->value.array : NULL;
}

char * JsonValueGetStr(JSON_VALUE *value) {
	return JsonValueGetType(value) == JSON_TYPE_STRING ? value->value.string : NULL;
}

double JsonValueGetNumber(JSON_VALUE *value) {
	return JsonValueGetType(value) == JSON_TYPE_NUMBER ? value->value.number : 0;
}

int JsonValueGetBool(JSON_VALUE *value) {
	return JsonValueGetType(value) == JSON_TYPE_BOOL ? value->value.boolean : 0;
}

JSON_VALUE * JsonValueGetParent(JSON_VALUE *value) {
	return value ? value->parent : NULL;
}

void JsonFree(JSON_VALUE *value) {
	switch (JsonValueGetType(value)) {
	case JSON_TYPE_OBJECT:
		json_object_free(value->value.object);
		break;
	case JSON_TYPE_STRING:
		parson_free(value->value.string);
		break;
	case JSON_TYPE_ARRAY:
		json_array_free(value->value.array);
		break;
	default:
		break;
	}
	parson_free(value);
}

JSON_VALUE * JsonNewObject(void) {
	JSON_VALUE *new_value = (JSON_VALUE*)parson_malloc(sizeof(JSON_VALUE));
	if (!new_value) {
		return NULL;
	}
	new_value->parent = NULL;
	new_value->type = JSON_TYPE_OBJECT;
	new_value->value.object = json_object_init(new_value);
	if (!new_value->value.object) {
		parson_free(new_value);
		return NULL;
	}
	return new_value;
}

JSON_VALUE * JsonNewArray(void) {
	JSON_VALUE *new_value = (JSON_VALUE*)parson_malloc(sizeof(JSON_VALUE));
	if (!new_value) {
		return NULL;
	}
	new_value->parent = NULL;
	new_value->type = JSON_TYPE_ARRAY;
	new_value->value.array = json_array_init(new_value);
	if (!new_value->value.array) {
		parson_free(new_value);
		return NULL;
	}
	return new_value;
}

JSON_VALUE * JsonNewStr(char *string) {
	char *copy = NULL;
	JSON_VALUE *value;
	UINT string_len = 0;
	if (string == NULL) {
		return NULL;
	}
	string_len = StrLen(string);
	if (!is_valid_utf8(string, string_len)) {
		return NULL;
	}
	copy = parson_strndup(string, string_len);
	if (copy == NULL) {
		return NULL;
	}
	value = json_value_init_string_no_copy(copy);
	if (value == NULL) {
		parson_free(copy);
	}
	return value;
}

JSON_VALUE * JsonNewNumber(double number) {
	JSON_VALUE *new_value = NULL;
	if ((number * 0.0) != 0.0) { /* nan and inf test */
		return NULL;
	}
	new_value = (JSON_VALUE*)parson_malloc(sizeof(JSON_VALUE));
	if (new_value == NULL) {
		return NULL;
	}
	new_value->parent = NULL;
	new_value->type = JSON_TYPE_NUMBER;
	new_value->value.number = number;
	return new_value;
}

JSON_VALUE * JsonNewBool(int boolean) {
	JSON_VALUE *new_value = (JSON_VALUE*)parson_malloc(sizeof(JSON_VALUE));
	if (!new_value) {
		return NULL;
	}
	new_value->parent = NULL;
	new_value->type = JSON_TYPE_BOOL;
	new_value->value.boolean = boolean ? 1 : 0;
	return new_value;
}

JSON_VALUE * JsonNewNull(void) {
	JSON_VALUE *new_value = (JSON_VALUE*)parson_malloc(sizeof(JSON_VALUE));
	if (!new_value) {
		return NULL;
	}
	new_value->parent = NULL;
	new_value->type = JSON_TYPE_NULL;
	return new_value;
}

JSON_VALUE * JsonDeepCopy(JSON_VALUE *value) {
	UINT i = 0;
	JSON_VALUE *return_value = NULL, *temp_value_copy = NULL, *temp_value = NULL;
	char *temp_string = NULL, *temp_key = NULL;
	char *temp_string_copy = NULL;
	JSON_ARRAY *temp_array = NULL, *temp_array_copy = NULL;
	JSON_OBJECT *temp_object = NULL, *temp_object_copy = NULL;

	switch (JsonValueGetType(value)) {
	case JSON_TYPE_ARRAY:
		temp_array = JsonValueGetArray(value);
		return_value = JsonNewArray();
		if (return_value == NULL) {
			return NULL;
		}
		temp_array_copy = JsonValueGetArray(return_value);
		for (i = 0; i < JsonArrayGetCount(temp_array); i++) {
			temp_value = JsonArrayGet(temp_array, i);
			temp_value_copy = JsonDeepCopy(temp_value);
			if (temp_value_copy == NULL) {
				JsonFree(return_value);
				return NULL;
			}
			if (json_array_add(temp_array_copy, temp_value_copy) == JSON_RET_ERROR) {
				JsonFree(return_value);
				JsonFree(temp_value_copy);
				return NULL;
			}
		}
		return return_value;
	case JSON_TYPE_OBJECT:
		temp_object = JsonValueGetObject(value);
		return_value = JsonNewObject();
		if (return_value == NULL) {
			return NULL;
		}
		temp_object_copy = JsonValueGetObject(return_value);
		for (i = 0; i < JsonGetCount(temp_object); i++) {
			temp_key = JsonGetName(temp_object, i);
			temp_value = JsonGet(temp_object, temp_key);
			temp_value_copy = JsonDeepCopy(temp_value);
			if (temp_value_copy == NULL) {
				JsonFree(return_value);
				return NULL;
			}
			if (json_object_add(temp_object_copy, temp_key, temp_value_copy) == JSON_RET_ERROR) {
				JsonFree(return_value);
				JsonFree(temp_value_copy);
				return NULL;
			}
		}
		return return_value;
	case JSON_TYPE_BOOL:
		return JsonNewBool(JsonValueGetBool(value));
	case JSON_TYPE_NUMBER:
		return JsonNewNumber(JsonValueGetNumber(value));
	case JSON_TYPE_STRING:
		temp_string = JsonValueGetStr(value);
		if (temp_string == NULL) {
			return NULL;
		}
		temp_string_copy = parson_strdup(temp_string);
		if (temp_string_copy == NULL) {
			return NULL;
		}
		return_value = json_value_init_string_no_copy(temp_string_copy);
		if (return_value == NULL) {
			parson_free(temp_string_copy);
		}
		return return_value;
	case JSON_TYPE_NULL:
		return JsonNewNull();
	case JSON_TYPE_ERROR:
		return NULL;
	default:
		return NULL;
	}
}

UINT JsonGetSerializationSize(JSON_VALUE *value) {
	char num_buf[1100]; /* recursively allocating buffer on stack is a bad idea, so let's do it only once */
	int res = json_serialize_to_buffer_r(value, NULL, 0, 0, num_buf);
	return res < 0 ? 0 : (UINT)(res + 1);
}

UINT JsonSerializeToBuffer(JSON_VALUE *value, char *buf, UINT buf_size_in_bytes) {
	int written = -1;
	UINT needed_size_in_bytes = JsonGetSerializationSize(value);
	if (needed_size_in_bytes == 0 || buf_size_in_bytes < needed_size_in_bytes) {
		return JSON_RET_ERROR;
	}
	written = json_serialize_to_buffer_r(value, buf, 0, 0, NULL);
	if (written < 0) {
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

char * JsonSerializeToString(JSON_VALUE *value) {
	UINT serialization_result = JSON_RET_ERROR;
	UINT buf_size_bytes = JsonGetSerializationSize(value);
	char *buf = NULL;
	if (buf_size_bytes == 0) {
		return NULL;
	}
	buf = (char*)parson_malloc(buf_size_bytes);
	if (buf == NULL) {
		return NULL;
	}
	serialization_result = JsonSerializeToBuffer(value, buf, buf_size_bytes);
	if (serialization_result == JSON_RET_ERROR) {
		JsonFreeString(buf);
		return NULL;
	}
	return buf;
}

UINT JsonGetSerializationSizePretty(JSON_VALUE *value) {
	char num_buf[1100]; /* recursively allocating buffer on stack is a bad idea, so let's do it only once */
	int res = json_serialize_to_buffer_r(value, NULL, 0, 1, num_buf);
	return res < 0 ? 0 : (UINT)(res + 1);
}

UINT JsonSerializeToBufferPretty(JSON_VALUE *value, char *buf, UINT buf_size_in_bytes) {
	int written = -1;
	UINT needed_size_in_bytes = JsonGetSerializationSizePretty(value);
	if (needed_size_in_bytes == 0 || buf_size_in_bytes < needed_size_in_bytes) {
		return JSON_RET_ERROR;
	}
	written = json_serialize_to_buffer_r(value, buf, 0, 1, NULL);
	if (written < 0) {
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

char * JsonSerializeToStringPretty(JSON_VALUE *value) {
	UINT serialization_result = JSON_RET_ERROR;
	UINT buf_size_bytes = JsonGetSerializationSizePretty(value);
	char *buf = NULL;
	if (buf_size_bytes == 0) {
		return NULL;
	}
	buf = (char*)parson_malloc(buf_size_bytes);
	if (buf == NULL) {
		return NULL;
	}
	serialization_result = JsonSerializeToBufferPretty(value, buf, buf_size_bytes);
	if (serialization_result == JSON_RET_ERROR) {
		JsonFreeString(buf);
		return NULL;
	}
	return buf;
}

void JsonFreeString(char *string) {
	parson_free(string);
}

UINT JsonArrayDelete(JSON_ARRAY *array, UINT ix) {
	UINT to_move_bytes = 0;
	if (array == NULL || ix >= JsonArrayGetCount(array)) {
		return JSON_RET_ERROR;
	}
	JsonFree(JsonArrayGet(array, ix));
	to_move_bytes = (JsonArrayGetCount(array) - 1 - ix) * sizeof(JSON_VALUE*);
	memmove(array->items + ix, array->items + ix + 1, to_move_bytes);
	array->count -= 1;
	return JSON_RET_OK;
}

UINT JsonArrayReplace(JSON_ARRAY *array, UINT ix, JSON_VALUE *value) {
	if (array == NULL || value == NULL || value->parent != NULL || ix >= JsonArrayGetCount(array)) {
		return JSON_RET_ERROR;
	}
	JsonFree(JsonArrayGet(array, ix));
	value->parent = JsonArrayGetWrappingValue(array);
	array->items[ix] = value;
	return JSON_RET_OK;
}

UINT JsonArrayReplaceStr(JSON_ARRAY *array, UINT i, char* string) {
	JSON_VALUE *value = JsonNewStr(string);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayReplace(array, i, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayReplaceNumber(JSON_ARRAY *array, UINT i, double number) {
	JSON_VALUE *value = JsonNewNumber(number);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayReplace(array, i, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayReplaceBool(JSON_ARRAY *array, UINT i, int boolean) {
	JSON_VALUE *value = JsonNewBool(boolean);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayReplace(array, i, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayReplaceNull(JSON_ARRAY *array, UINT i) {
	JSON_VALUE *value = JsonNewNull();
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayReplace(array, i, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayDeleteAll(JSON_ARRAY *array) {
	UINT i = 0;
	if (array == NULL) {
		return JSON_RET_ERROR;
	}
	for (i = 0; i < JsonArrayGetCount(array); i++) {
		JsonFree(JsonArrayGet(array, i));
	}
	array->count = 0;
	return JSON_RET_OK;
}

UINT JsonArrayAdd(JSON_ARRAY *array, JSON_VALUE *value) {
	if (array == NULL || value == NULL || value->parent != NULL) {
		return JSON_RET_ERROR;
	}
	return json_array_add(array, value);
}

UINT JsonArrayAddStr(JSON_ARRAY *array, char *string) {
	JSON_VALUE *value = JsonNewStr(string);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayAdd(array, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayAddNumber(JSON_ARRAY *array, double number) {
	JSON_VALUE *value = JsonNewNumber(number);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayAdd(array, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayAddBool(JSON_ARRAY *array, int boolean) {
	JSON_VALUE *value = JsonNewBool(boolean);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayAdd(array, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayAddNull(JSON_ARRAY *array) {
	JSON_VALUE *value = JsonNewNull();
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayAdd(array, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonSet(JSON_OBJECT *object, char *name, JSON_VALUE *value) {
	UINT i = 0;
	JSON_VALUE *old_value;
	if (object == NULL || name == NULL || value == NULL || value->parent != NULL) {
		return JSON_RET_ERROR;
	}
	old_value = JsonGet(object, name);
	if (old_value != NULL) { /* free and overwrite old value */
		JsonFree(old_value);
		for (i = 0; i < JsonGetCount(object); i++) {
			if (strcmp(object->names[i], name) == 0) {
				value->parent = JsonGetWrappingValue(object);
				object->values[i] = value;
				return JSON_RET_OK;
			}
		}
	}
	/* add new key value pair */
	return json_object_add(object, name, value);
}

UINT JsonSetStr(JSON_OBJECT *object, char *name, char *string) {
	return JsonSet(object, name, JsonNewStr(string));
}

UINT JsonSetNumber(JSON_OBJECT *object, char *name, double number) {
	return JsonSet(object, name, JsonNewNumber(number));
}

UINT JsonSetBool(JSON_OBJECT *object, char *name, int boolean) {
	return JsonSet(object, name, JsonNewBool(boolean));
}

UINT JsonSetNull(JSON_OBJECT *object, char *name) {
	return JsonSet(object, name, JsonNewNull());
}

UINT JsonDotSet(JSON_OBJECT *object, char *name, JSON_VALUE *value) {
	char *dot_pos = NULL;
	char *current_name = NULL;
	JSON_OBJECT *temp_obj = NULL;
	JSON_VALUE *new_value = NULL;
	if (object == NULL || name == NULL || value == NULL) {
		return JSON_RET_ERROR;
	}
	dot_pos = strchr(name, '.');
	if (dot_pos == NULL) {
		return JsonSet(object, name, value);
	}
	else {
		current_name = parson_strndup(name, (UINT)(dot_pos - name));
		temp_obj = JsonGetObj(object, current_name);
		if (temp_obj == NULL) {
			new_value = JsonNewObject();
			if (new_value == NULL) {
				parson_free(current_name);
				return JSON_RET_ERROR;
			}
			if (json_object_add(object, current_name, new_value) == JSON_RET_ERROR) {
				JsonFree(new_value);
				parson_free(current_name);
				return JSON_RET_ERROR;
			}
			temp_obj = JsonGetObj(object, current_name);
		}
		parson_free(current_name);
		return JsonDotSet(temp_obj, dot_pos + 1, value);
	}
}

UINT JsonDotSetStr(JSON_OBJECT *object, char *name, char *string) {
	JSON_VALUE *value = JsonNewStr(string);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonDotSet(object, name, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonDotSetNumber(JSON_OBJECT *object, char *name, double number) {
	JSON_VALUE *value = JsonNewNumber(number);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonDotSet(object, name, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonDotSetBool(JSON_OBJECT *object, char *name, int boolean) {
	JSON_VALUE *value = JsonNewBool(boolean);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonDotSet(object, name, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonDotSetNull(JSON_OBJECT *object, char *name) {
	JSON_VALUE *value = JsonNewNull();
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonDotSet(object, name, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonDelete(JSON_OBJECT *object, char *name) {
	UINT i = 0, last_item_index = 0;
	if (object == NULL || JsonGet(object, name) == NULL) {
		return JSON_RET_ERROR;
	}
	last_item_index = JsonGetCount(object) - 1;
	for (i = 0; i < JsonGetCount(object); i++) {
		if (strcmp(object->names[i], name) == 0) {
			parson_free(object->names[i]);
			JsonFree(object->values[i]);
			if (i != last_item_index) { /* Replace key value pair with one from the end */
				object->names[i] = object->names[last_item_index];
				object->values[i] = object->values[last_item_index];
			}
			object->count -= 1;
			return JSON_RET_OK;
		}
	}
	return JSON_RET_ERROR; /* No execution path should end here */
}

UINT JsonDotDelete(JSON_OBJECT *object, char *name) {
	char *dot_pos = strchr(name, '.');
	char *current_name = NULL;
	JSON_OBJECT *temp_obj = NULL;
	if (dot_pos == NULL) {
		return JsonDelete(object, name);
	}
	else {
		current_name = parson_strndup(name, (UINT)(dot_pos - name));
		temp_obj = JsonGetObj(object, current_name);
		parson_free(current_name);
		if (temp_obj == NULL) {
			return JSON_RET_ERROR;
		}
		return JsonDotDelete(temp_obj, dot_pos + 1);
	}
}

UINT JsonDeleteAll(JSON_OBJECT *object) {
	UINT i = 0;
	if (object == NULL) {
		return JSON_RET_ERROR;
	}
	for (i = 0; i < JsonGetCount(object); i++) {
		parson_free(object->names[i]);
		JsonFree(object->values[i]);
	}
	object->count = 0;
	return JSON_RET_OK;
}

UINT JsonValidate(JSON_VALUE *schema, JSON_VALUE *value) {
	JSON_VALUE *temp_schema_value = NULL, *temp_value = NULL;
	JSON_ARRAY *schema_array = NULL, *value_array = NULL;
	JSON_OBJECT *schema_object = NULL, *value_object = NULL;
	UINT schema_type = JSON_TYPE_ERROR, value_type = JSON_TYPE_ERROR;
	char *key = NULL;
	UINT i = 0, count = 0;
	if (schema == NULL || value == NULL) {
		return JSON_RET_ERROR;
	}
	schema_type = JsonValueGetType(schema);
	value_type = JsonValueGetType(value);
	if (schema_type != value_type && schema_type != JSON_TYPE_NULL) { /* null represents all values */
		return JSON_RET_ERROR;
	}
	switch (schema_type) {
	case JSON_TYPE_ARRAY:
		schema_array = JsonValueGetArray(schema);
		value_array = JsonValueGetArray(value);
		count = JsonArrayGetCount(schema_array);
		if (count == 0) {
			return JSON_RET_OK; /* Empty array allows all types */
		}
		/* Get first value from array, rest is ignored */
		temp_schema_value = JsonArrayGet(schema_array, 0);
		for (i = 0; i < JsonArrayGetCount(value_array); i++) {
			temp_value = JsonArrayGet(value_array, i);
			if (JsonValidate(temp_schema_value, temp_value) == JSON_RET_ERROR) {
				return JSON_RET_ERROR;
			}
		}
		return JSON_RET_OK;
	case JSON_TYPE_OBJECT:
		schema_object = JsonValueGetObject(schema);
		value_object = JsonValueGetObject(value);
		count = JsonGetCount(schema_object);
		if (count == 0) {
			return JSON_RET_OK; /* Empty object allows all objects */
		}
		else if (JsonGetCount(value_object) < count) {
			return JSON_RET_ERROR; /* Tested object mustn't have less name-value pairs than schema */
		}
		for (i = 0; i < count; i++) {
			key = JsonGetName(schema_object, i);
			temp_schema_value = JsonGet(schema_object, key);
			temp_value = JsonGet(value_object, key);
			if (temp_value == NULL) {
				return JSON_RET_ERROR;
			}
			if (JsonValidate(temp_schema_value, temp_value) == JSON_RET_ERROR) {
				return JSON_RET_ERROR;
			}
		}
		return JSON_RET_OK;
	case JSON_TYPE_STRING: case JSON_TYPE_NUMBER: case JSON_TYPE_BOOL: case JSON_TYPE_NULL:
		return JSON_RET_OK; /* equality already tested before switch */
	case JSON_TYPE_ERROR: default:
		return JSON_RET_ERROR;
	}
}

int JsonCmp(JSON_VALUE *a, JSON_VALUE *b) {
	JSON_OBJECT *a_object = NULL, *b_object = NULL;
	JSON_ARRAY *a_array = NULL, *b_array = NULL;
	char *a_string = NULL, *b_string = NULL;
	char *key = NULL;
	UINT a_count = 0, b_count = 0, i = 0;
	UINT a_type, b_type;
	a_type = JsonValueGetType(a);
	b_type = JsonValueGetType(b);
	if (a_type != b_type) {
		return 0;
	}
	switch (a_type) {
	case JSON_TYPE_ARRAY:
		a_array = JsonValueGetArray(a);
		b_array = JsonValueGetArray(b);
		a_count = JsonArrayGetCount(a_array);
		b_count = JsonArrayGetCount(b_array);
		if (a_count != b_count) {
			return 0;
		}
		for (i = 0; i < a_count; i++) {
			if (!JsonCmp(JsonArrayGet(a_array, i),
				JsonArrayGet(b_array, i))) {
				return 0;
			}
		}
		return 1;
	case JSON_TYPE_OBJECT:
		a_object = JsonValueGetObject(a);
		b_object = JsonValueGetObject(b);
		a_count = JsonGetCount(a_object);
		b_count = JsonGetCount(b_object);
		if (a_count != b_count) {
			return 0;
		}
		for (i = 0; i < a_count; i++) {
			key = JsonGetName(a_object, i);
			if (!JsonCmp(JsonGet(a_object, key),
				JsonGet(b_object, key))) {
				return 0;
			}
		}
		return 1;
	case JSON_TYPE_STRING:
		a_string = JsonValueGetStr(a);
		b_string = JsonValueGetStr(b);
		if (a_string == NULL || b_string == NULL) {
			return 0; /* shouldn't happen */
		}
		return strcmp(a_string, b_string) == 0;
	case JSON_TYPE_BOOL:
		return JsonValueGetBool(a) == JsonValueGetBool(b);
	case JSON_TYPE_NUMBER:
		return fabs(JsonValueGetNumber(a) - JsonValueGetNumber(b)) < 0.000001; /* EPSILON */
	case JSON_TYPE_ERROR:
		return 1;
	case JSON_TYPE_NULL:
		return 1;
	default:
		return 1;
	}
}

UINT JsonType(JSON_VALUE *value) {
	return JsonValueGetType(value);
}

JSON_OBJECT * JsonObject(JSON_VALUE *value) {
	return JsonValueGetObject(value);
}

JSON_ARRAY * JsonArray(JSON_VALUE *value) {
	return JsonValueGetArray(value);
}

char * JsonString(JSON_VALUE *value) {
	return JsonValueGetStr(value);
}

double JsonNumber(JSON_VALUE *value) {
	return JsonValueGetNumber(value);
}

int JsonBool(JSON_VALUE *value) {
	return JsonValueGetBool(value);
}

void JsonSetAllocationFunctions(JSON_Malloc_Function malloc_fun, JSON_Free_Function free_fun) {
	parson_malloc = malloc_fun;
	parson_free = free_fun;
}
