/* fakeglib.c - A shim for applications that require GLib
 * without the whole kit and kaboodle.
 *
 * Copyright (C) 2020 Evan Miller
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#define _GNU_SOURCE
#include "mdbfakeglib.h"

#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_ICONV
#include <iconv.h>
#endif

/* Linked from libmdb */
const char *mdb_iconv_name_from_code_page(int code_page);

/* string functions */

void *g_memdup(const void *src, size_t len) {
    void *dst = malloc(len);
    memcpy(dst, src, len);
    return dst;
}

int g_str_equal(const void *str1, const void *str2) {
    return strcmp(str1, str2) == 0;
}

// max_tokens not yet implemented
char **g_strsplit(const char *haystack, const char *needle, int max_tokens) {
    char **ret = NULL;
    char *found = NULL;
    size_t components = 2; // last component + terminating NULL
    
    while ((found = strstr(haystack, needle))) {
        components++;
        haystack = found + strlen(needle);
    }

    ret = calloc(components, sizeof(char *));

    int i = 0;
    while ((found = strstr(haystack, needle))) {
        ret[i++] = g_strndup(haystack, found - haystack);
        haystack = found + strlen(needle);
    }
    ret[i] = strdup(haystack);

    return ret;
}

void g_strfreev(char **dir) {
    int i=0;
    while (dir[i]) {
        free(dir[i]);
        i++;
    }
    free(dir);
}

char *g_strconcat(const char *first, ...) {
    char *ret = NULL;
    size_t len = strlen(first);
    char *arg = NULL;
    va_list argp;

    va_start(argp, first);
    while ((arg = va_arg(argp, char *))) {
        len += strlen(arg);
    }
    va_end(argp);

    ret = malloc(len+1);

    char *pos = strcpy(ret, first) + strlen(first);

    va_start(argp, first);
    while ((arg = va_arg(argp, char *))) {
        pos = strcpy(pos, arg) + strlen(arg);
    }
    va_end(argp);

    ret[len] = '\0';

    return ret;
}

#if defined _WIN32 && !defined(HAVE_VASPRINTF) && !defined(HAVE_VASNPRINTF)
int vasprintf(char **ret, const char *format, va_list ap) {
    int len;
    int retval;
    char *result;
    if ((len = _vscprintf(format, ap)) < 0)
        return -1;
    if ((result = malloc(len+1)) == NULL)
        return -1;
    if ((retval = vsprintf_s(result, len+1, format, ap)) == -1) {
        free(result);
        return -1;
    }
    *ret = result;
    return retval;
}
#endif

char *g_strdup(const char *input) {
    size_t len = strlen(input);
    return g_memdup(input, len+1);
}

char *g_strndup(const char *src, size_t len) {
    if (!src)
        return NULL;
    char *result = malloc(len+1);
    size_t i=0;
    while (*src && i<len) {
        result[i++] = *src++;
    }
    result[i] = '\0';
    return result;
}

char *g_strdup_printf(const char *format, ...) {
    char *ret = NULL;
    va_list argp;

    va_start(argp, format);
#ifdef HAVE_VASNPRINTF
    size_t len = 0;
    ret = vasnprintf(ret, &len, format, argp);
#else
    int gcc_is_dumb = vasprintf(&ret, format, argp);
    (void)gcc_is_dumb;
#endif
    va_end(argp);

    return ret;
}

gchar *g_strdelimit(gchar *string, const gchar *delimiters, gchar new_delimiter) {
    char *orig = string;
    if (delimiters == NULL)
        delimiters = G_STR_DELIMITERS;
    size_t n = strlen(delimiters);
    while (*string) {
        size_t i;
        for (i=0; i<n; i++) {
            if (*string == delimiters[i]) {
                *string = new_delimiter;
                break;
            }
        }
        string++;
    }

    return orig;
}

void g_printerr(const gchar *format, ...) {
    va_list argp;
    va_start(argp, format);
    vfprintf(stderr, format, argp);
    va_end(argp);
}

/* GString */

GString *g_string_new (const gchar *init) {
    GString *str = calloc(1, sizeof(GString));
    str->str = strdup(init ? init : "");
    str->len = strlen(str->str);
    str->allocated_len = str->len+1;
    return str;
}

GString *g_string_assign(GString *string, const gchar *rval) {
    size_t len = strlen(rval);
    string->str = realloc(string->str, len+1);
    strncpy(string->str, rval, len+1);
    string->len = len;
    string->allocated_len = len+1;
    return string;
}

GString * g_string_append (GString *string, const gchar *val) {
    size_t len = strlen(val);
    string->str = realloc(string->str, string->len + len + 1);
    strncpy(&string->str[string->len], val, len+1);
    string->len += len;
    string->allocated_len = string->len + len + 1;
    return string;
}

gchar *g_string_free (GString *string, gboolean free_segment) {
    char *data = string->str;
    free(string);
    if (free_segment) {
        free(data);
        return NULL;
    }
    return data;
}

/* conversion */
gint g_unichar_to_utf8(gunichar u, gchar *dst) {
    if (u >= 0x0800) {
        *dst++ = 0xE0 | ((u & 0xF000) >> 12);
        *dst++ = 0x80 | ((u & 0x0FC0) >> 6);
        *dst++ = 0x80 | ((u & 0x003F) >> 0);
        return 3;
    }
    if (u >= 0x0080) {
        *dst++ = 0xC0 | ((u & 0x07C0) >> 6);
        *dst++ = 0x80 | ((u & 0x003F) >> 0);
        return 2;
    }
    *dst++ = (u & 0x7F);
    return 1;
}

gchar *g_locale_to_utf8(const gchar *opsysstring, size_t len,
        size_t *bytes_read, size_t *bytes_written, GError **error) {
    if (len == (size_t)-1)
        len = strlen(opsysstring);
    wchar_t *utf16 = malloc(sizeof(wchar_t)*(len+1));
    if (mbstowcs(utf16, opsysstring, len+1) == (size_t)-1) {
        free(utf16);
        return g_strndup(opsysstring, len);
    }
    gchar *utf8 = malloc(3*len+1);
    gchar *dst = utf8;
    for (size_t i=0; i<len; i++) {
        // u >= 0x10000 requires surrogate pairs, ignore
        dst += g_unichar_to_utf8(utf16[i], dst);
    }
    *dst++ = '\0';
    free(utf16);
    return utf8;
}

/* GHashTable */

typedef struct MyNode {
    char *key;
    void *value;
} MyNode;

void *g_hash_table_lookup(GHashTable *table, const void *key) {
    guint i;
    for (i=0; i<table->array->len; i++) {
        MyNode *node = g_ptr_array_index(table->array, i);
        if (table->compare(key, node->key))
            return node->value;
    }
    return NULL;
}

gboolean g_hash_table_lookup_extended (GHashTable *table, const void *lookup_key,
        void **orig_key, void **value) {
    guint i;
    for (i=0; i<table->array->len; i++) {
        MyNode *node = g_ptr_array_index(table->array, i);
        if (table->compare(lookup_key, node->key)) {
            *orig_key = node->key;
            *value = node->value;
            return TRUE;
        }
    }
    return FALSE;
}

void g_hash_table_insert(GHashTable *table, void *key, void *value) {
    MyNode *node = calloc(1, sizeof(MyNode));
    node->value = value;
    node->key = key;
    g_ptr_array_add(table->array, node);
}

gboolean g_hash_table_remove(GHashTable *table, gconstpointer key) {
    int found = 0;
    for (guint i=0; i<table->array->len; i++) {
        MyNode *node = g_ptr_array_index(table->array, i);
        if (found) {
            table->array->pdata[i-1] = table->array->pdata[i];
        } else if (!found && table->compare(key, node->key)) {
            found = 1;
        }
    }
    if (found) {
        table->array->len--;
    }
    return found;
}

GHashTable *g_hash_table_new(GHashFunc hashes, GEqualFunc equals) {
    GHashTable *table = calloc(1, sizeof(GHashTable));
    table->array = g_ptr_array_new();
    table->compare = equals;
    return table;
}

void g_hash_table_foreach(GHashTable *table, GHFunc function, void *data) {
    guint i;
    for (i=0; i<table->array->len; i++) {
        MyNode *node = g_ptr_array_index(table->array, i);
        function(node->key, node->value, data);
    }
}

void g_hash_table_destroy(GHashTable *table) {
    guint i;
    for (i=0; i<table->array->len; i++) {
        MyNode *node = g_ptr_array_index(table->array, i);
        free(node);
    }
    g_ptr_array_free(table->array, TRUE);
    free(table);
}

/* GPtrArray */

void g_ptr_array_sort(GPtrArray *array, GCompareFunc func) {
    qsort(array->pdata, array->len, sizeof(void *), func);
}

void g_ptr_array_foreach(GPtrArray *array, GFunc function, gpointer user_data) {
    guint i;
    for (i=0; i<array->len; i++) {
        function(g_ptr_array_index(array, i), user_data);
    }
}

GPtrArray *g_ptr_array_new() {
    GPtrArray *array = malloc(sizeof(GPtrArray));
    array->len = 0;
    array->pdata = NULL;
    return array;
}

void g_ptr_array_add(GPtrArray *array, void *entry) {
    array->pdata = realloc(array->pdata, (array->len+1) * sizeof(void *));
    array->pdata[array->len++] = entry;
}

gboolean g_ptr_array_remove(GPtrArray *array, gpointer data) {
    int found = 0;
    for (guint i=0; i<array->len; i++) {
        if (found) {
            array->pdata[i-1] = array->pdata[i];
        } else if (!found && array->pdata[i] == data) {
            found = 1;
        }
    }
    if (found) {
        array->len--;
    }
    return found;
}

void g_ptr_array_free(GPtrArray *array, gboolean something) {
    free(array->pdata);
    free(array);
}

/* GList */

GList *g_list_append(GList *list, void *data) {
    GList *new_list = calloc(1, sizeof(GList));
    new_list->data = data;
    new_list->next = list;
    if (list)
        list->prev = new_list;
    return new_list;
}

GList *g_list_last(GList *list) {
    while (list && list->next) {
        list = list->next;
    }
    return list;
}

GList *g_list_remove(GList *list, void *data) {
    GList *link = list;
    while (link) {
        if (link->data == data) {
            GList *return_list = list;
            if (link->prev)
                link->prev->next = link->next;
            if (link->next)
                link->next->prev = link->prev;
            if (link == list)
                return_list = link->next;
            free(link);
            return return_list;
        }
        link = link->next;
    }
    return list;
}

void g_list_free(GList *list) {
    GList *next = NULL;
    while (list) {
        next = list->next;
        free(list);
        list = next;
    }
}
