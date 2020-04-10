// evasi0n6

struct sysent
{
    uint16_t sy_narg;
    uint8_t sy_resv;
    uint8_t sy_flags;
    uint32_t sy_call;
    uint32_t sy_arg_munge32;
    uint32_t sy_arg_munge64;
    uint32_t sy_return_type;
    uint32_t sy_arg_bytes;
};

