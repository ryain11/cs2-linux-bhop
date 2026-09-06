#pragma once

#define FIFO_PATH "/tmp/bhop_pipe.fifo"

struct Flags {
    bool uninject = false;
    bool bhopEnabled = true;
};

typedef struct Flags Flags;