typedef unsigned long size_t;

void consume(const unsigned char *data, size_t length);

void bad(const unsigned char *token, size_t token_length)
{
    const unsigned char *random = token + token_length - 32; // BAD
    size_t payload_length = token_length - 33; // BAD

    consume(token + 1, payload_length);
    consume(random, 32);
}

void good(const unsigned char *token, size_t token_length)
{
    const unsigned char *random;

    if (token_length < 33)
        return;

    random = token + token_length - 32;
    consume(token + 1, token_length - 33);
    consume(random, 32);
}
