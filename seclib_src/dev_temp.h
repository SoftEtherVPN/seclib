void DevTempTest();



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

/* Types and enums */
typedef struct JSON_OBJECT JSON_OBJECT;
typedef struct JSON_ARRAY  JSON_ARRAY;
typedef struct JSON_VALUE  JSON_VALUE;


/* Type definitions */
typedef union JSON_VALUE_UNION {
	char        *string;
	double       number;
	JSON_OBJECT *object;
	JSON_ARRAY  *array;
	int          boolean;
	int          null;
} JSON_VALUE_UNION;

struct JSON_VALUE {
	JSON_VALUE      *parent;
	UINT  type;
	JSON_VALUE_UNION value;
};

struct JSON_OBJECT {
	JSON_VALUE  *wrapping_value;
	char       **names;
	JSON_VALUE **values;
	UINT       count;
	UINT       capacity;
};

struct JSON_ARRAY {
	JSON_VALUE  *wrapping_value;
	JSON_VALUE **items;
	UINT       count;
	UINT       capacity;
};


enum JSON_TYPES {
	JSON_TYPE_ERROR = -1,
	JSON_TYPE_NULL = 1,
	JSON_TYPE_STRING = 2,
	JSON_TYPE_NUMBER = 3,
	JSON_TYPE_OBJECT = 4,
	JSON_TYPE_ARRAY = 5,
	JSON_TYPE_BOOL = 6
};
typedef unsigned int UINT;

enum JSON_RETS {
	JSON_RET_OK = 0,
	JSON_RET_ERROR = -1
};

typedef void * (*JSON_Malloc_Function)(UINT);
typedef void(*JSON_Free_Function)(void *);

/* Call only once, before calling any other function from parson API. If not called, malloc and free
from stdlib will be used for all allocations */
void JsonSetAllocationFunctions(JSON_Malloc_Function malloc_fun, JSON_Free_Function free_fun);

/*  Parses first JSON value in a string, returns NULL in case of error */
JSON_VALUE * JsonParseString(char *string);

/*  Parses first JSON value in a string and ignores comments (/ * * / and //),
returns NULL in case of error */
JSON_VALUE * JsonParseStringWithComments(char *string);

/* Serialization */
UINT      JsonGetSerializationSize(JSON_VALUE *value); /* returns 0 on fail */
UINT JsonSerializeToBuffer(JSON_VALUE *value, char *buf, UINT buf_size_in_bytes);
char *      JsonSerializeToString(JSON_VALUE *value);

/* Pretty serialization */
UINT      JsonGetSerializationSizePretty(JSON_VALUE *value); /* returns 0 on fail */
UINT JsonSerializeToBufferPretty(JSON_VALUE *value, char *buf, UINT buf_size_in_bytes);
char *      JsonSerializeToStringPretty(JSON_VALUE *value);

void        JsonFreeString(char *string); /* frees string from json_serialize_to_string and json_serialize_to_string_pretty */

										  /* Comparing */
int  JsonCmp(JSON_VALUE *a, JSON_VALUE *b);

/* Validation
This is *NOT* JSON Schema. It validates json by checking if object have identically
named fields with matching types.
For example schema {"name":"", "age":0} will validate
{"name":"Joe", "age":25} and {"name":"Joe", "age":25, "gender":"m"},
but not {"name":"Joe"} or {"name":"Joe", "age":"Cucumber"}.
In case of arrays, only first value in schema is checked against all values in tested array.
Empty objects ({}) validate all objects, empty arrays ([]) validate all arrays,
null validates values of every type.
*/
UINT JsonValidate(JSON_VALUE *schema, JSON_VALUE *value);

/*
* JSON Object
*/
JSON_VALUE  * JsonGet(JSON_OBJECT *object, char *name);
char  * JsonGetStr(JSON_OBJECT *object, char *name);
JSON_OBJECT * JsonGetObj(JSON_OBJECT *object, char *name);
JSON_ARRAY  * JsonGetArray(JSON_OBJECT *object, char *name);
double        JsonGetNumber(JSON_OBJECT *object, char *name); /* returns 0 on fail */
int           JsonGetBool(JSON_OBJECT *object, char *name); /* returns -1 on fail */

															/* dotget functions enable addressing values with dot notation in nested objects,
															just like in structs or c++/java/c# objects (e.g. objectA.objectB.value).
															Because valid names in JSON can contain dots, some values may be inaccessible
															this way. */
JSON_VALUE  * JsonDotGet(JSON_OBJECT *object, char *name);
char  * JsonDotGetStr(JSON_OBJECT *object, char *name);
JSON_OBJECT * JsonDotGetObj(JSON_OBJECT *object, char *name);
JSON_ARRAY  * JsonDotGetArray(JSON_OBJECT *object, char *name);
double        JsonDotGetNumber(JSON_OBJECT *object, char *name); /* returns 0 on fail */
int           JsonDotGetBool(JSON_OBJECT *object, char *name); /* returns -1 on fail */

															   /* Functions to get available names */
UINT        JsonGetCount(JSON_OBJECT *object);
char  * JsonGetName(JSON_OBJECT *object, UINT index);
JSON_VALUE  * JsonGetValueAt(JSON_OBJECT *object, UINT index);
JSON_VALUE  * JsonGetWrappingValue(JSON_OBJECT *object);

/* Functions to check if object has a value with a specific name. Returned value is 1 if object has
* a value and 0 if it doesn't. dothas functions behave exactly like dotget functions. */
int JsonIsExists(JSON_OBJECT *object, char *name);
int JsonIsExistsWithValueType(JSON_OBJECT *object, char *name, UINT type);

int JsonDotIsExists(JSON_OBJECT *object, char *name);
int JsonDotIsExistsWithValueType(JSON_OBJECT *object, char *name, UINT type);

/* Creates new name-value pair or frees and replaces old value with a new one.
* json_object_set_value does not copy passed value so it shouldn't be freed afterwards. */
UINT JsonSet(JSON_OBJECT *object, char *name, JSON_VALUE *value);
UINT JsonSetStr(JSON_OBJECT *object, char *name, char *string);
UINT JsonSetNumber(JSON_OBJECT *object, char *name, double number);
UINT JsonSetBool(JSON_OBJECT *object, char *name, int boolean);
UINT JsonSetNull(JSON_OBJECT *object, char *name);

/* Works like dotget functions, but creates whole hierarchy if necessary.
* json_object_dotset_value does not copy passed value so it shouldn't be freed afterwards. */
UINT JsonDotSet(JSON_OBJECT *object, char *name, JSON_VALUE *value);
UINT JsonDotSetStr(JSON_OBJECT *object, char *name, char *string);
UINT JsonDotSetNumber(JSON_OBJECT *object, char *name, double number);
UINT JsonDotSetBool(JSON_OBJECT *object, char *name, int boolean);
UINT JsonDotSetNull(JSON_OBJECT *object, char *name);

/* Frees and removes name-value pair */
UINT JsonDelete(JSON_OBJECT *object, char *name);

/* Works like dotget function, but removes name-value pair only on exact match. */
UINT JsonDotDelete(JSON_OBJECT *object, char *key);

/* Removes all name-value pairs in object */
UINT JsonDeleteAll(JSON_OBJECT *object);

/*
*JSON Array
*/
JSON_VALUE  * JsonArrayGet(JSON_ARRAY *array, UINT index);
char  * JsonArrayGetStr(JSON_ARRAY *array, UINT index);
JSON_OBJECT * JsonArrayGetObj(JSON_ARRAY *array, UINT index);
JSON_ARRAY  * JsonArrayGetArray(JSON_ARRAY *array, UINT index);
double        JsonArrayGetNumber(JSON_ARRAY *array, UINT index); /* returns 0 on fail */
int           JsonArrayGetBool(JSON_ARRAY *array, UINT index); /* returns -1 on fail */
UINT        JsonArrayGetCount(JSON_ARRAY *array);
JSON_VALUE  * JsonArrayGetWrappingValue(JSON_ARRAY *array);

/* Frees and removes value at given index, does nothing and returns JSONFailure if index doesn't exist.
* Order of values in array may change during execution.  */
UINT JsonArrayDelete(JSON_ARRAY *array, UINT i);

/* Frees and removes from array value at given index and replaces it with given one.
* Does nothing and returns JSONFailure if index doesn't exist.
* json_array_replace_value does not copy passed value so it shouldn't be freed afterwards. */
UINT JsonArrayReplace(JSON_ARRAY *array, UINT i, JSON_VALUE *value);
UINT JsonArrayReplaceStr(JSON_ARRAY *array, UINT i, char* string);
UINT JsonArrayReplaceNumber(JSON_ARRAY *array, UINT i, double number);
UINT JsonArrayReplaceBool(JSON_ARRAY *array, UINT i, int boolean);
UINT JsonArrayReplaceNull(JSON_ARRAY *array, UINT i);

/* Frees and removes all values from array */
UINT JsonArrayDeleteAll(JSON_ARRAY *array);

/* Appends new value at the end of array.
* json_array_append_value does not copy passed value so it shouldn't be freed afterwards. */
UINT JsonArrayAdd(JSON_ARRAY *array, JSON_VALUE *value);
UINT JsonArrayAddStr(JSON_ARRAY *array, char *string);
UINT JsonArrayAddNumber(JSON_ARRAY *array, double number);
UINT JsonArrayAddBool(JSON_ARRAY *array, int boolean);
UINT JsonArrayAddNull(JSON_ARRAY *array);


/*
*JSON Value
*/
JSON_VALUE * JsonNewObject(void);
JSON_VALUE * JsonNewArray(void);
JSON_VALUE * JsonNewStr(char *string); /* copies passed string */
JSON_VALUE * JsonNewNumber(double number);
JSON_VALUE * JsonNewBool(int boolean);
JSON_VALUE * JsonNewNull(void);
JSON_VALUE * JsonDeepCopy(JSON_VALUE *value);
void         JsonFree(JSON_VALUE *value);

UINT JsonValueGetType(JSON_VALUE *value);
JSON_OBJECT *   JsonValueGetObject(JSON_VALUE *value);
JSON_ARRAY  *   JsonValueGetArray(JSON_VALUE *value);
char  *   JsonValueGetStr(JSON_VALUE *value);
double          JsonValueGetNumber(JSON_VALUE *value);
int             JsonValueGetBool(JSON_VALUE *value);
JSON_VALUE  *   JsonValueGetParent(JSON_VALUE *value);

/* Same as above, but shorter */
UINT JsonType(JSON_VALUE *value);
JSON_OBJECT *   JsonObject(JSON_VALUE *value);
JSON_ARRAY  *   JsonArray(JSON_VALUE *value);
char  *   JsonString(JSON_VALUE *value);
double          JsonNumber(JSON_VALUE *value);
int             JsonBool(JSON_VALUE *value);

