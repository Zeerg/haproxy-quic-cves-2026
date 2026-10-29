typedef unsigned long uint64_t;

int advance_cursor(uint64_t *value, const unsigned char **cursor,
                   const unsigned char *end)
{
    if (*cursor >= end)
        return 0;
    *value = *(*cursor)++;
    return 1;
}

int cannot_fail(uint64_t *value, const unsigned char **cursor)
{
    *value = *(*cursor)++;
    return 1;
}

int bad(const unsigned char **cursor, const unsigned char *end)
{
    uint64_t value;

    advance_cursor(&value, cursor, end); // BAD: failure leaves cursor unchanged
    return (int)value;
}

int good(const unsigned char **cursor, const unsigned char *end)
{
    uint64_t value;

    if (!advance_cursor(&value, cursor, end))
        return 0;
    return (int)value;
}

int ignored_infallible(const unsigned char **cursor)
{
    uint64_t value;

    cannot_fail(&value, cursor);
    return (int)value;
}
