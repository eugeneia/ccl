#define r_rip arg0
#define r_fn uregs[R_R13]
#define word unsigned long

#defmacro PHASE(p) (this->phase == (p))

#define START 0
#define LOOP 1
#define END 2
#define DONE 100

#define TRA_TAGMASK 7
#define TRA_TAG 4
/* [From ../x86-constants64.h]
 * To determine the function associated with a tagged return
 * address, we attempt to recognize an the instruction
 * (lea (@ disp (% rip)) (% fn)) at the tra.
 */
#define RECOVER_FN_FROM_RIP_LENGTH 7 /* the instruction is 7 bytes long */
#define RECOVER_FN_FROM_RIP_DISP_OFFSET 3 /* displacement word is 3 bytes in */
#define RECOVER_FN_FROM_RIP_WORD0 0x8d4c /* 0x4c 0x8d, little-endian */
#define RECOVER_FN_FROM_RIP_BYTE2 0x2d  /* third byte of opcode */

#define TRA_P(r) (r & TRA_TAGMASK == TRA_TAG && \
                  *(short *)r == RECOVER_FN_FROM_RIP_WORD0 && \
                  *(char *)(r+2) == RECOVER_FN_FROM_RIP_BYTE2)

#define TRA_FNOFFSET(r) (*(int *)(r+RECOVER_FN_FROM_RIP_DISP_OFFSET) + \
                         RECOVER_FN_FROM_RIP_LENGTH)

#define TAGMASK ((word)0xF)

#define PTRMASK (!TAGMASK)

#define TAG(o) ((o) & TAGMASK)

#define UVREF(u,i) (*(word *)((u)+(i)*sizeof(word)))

#define UVSIZE(u) (UVREF(u, 0) >> 8)

#define LFBITS(fn) UVREF(fn, UVSIZE(fn))

#define LFSYMP(fn) ((LFBITS(fn) & 0x20000000) == 0)

#define LFSYM(fn) (UVREF(fn, UVSIZE(fn)-1) & PTRMASK)

#define SYMNAME(s) (UVREF(s, 1) & PTRMASK)

dtrace:helper:ustack:
{
        this->phase = START;
        this->hint = TRA_P(r_rip) ? *(word *)(rip+TRA_FNOFFSET(r_rip)) : r_fn;
        this->fn = TAG(this->hint) == 0xF ? this->hint & PTRMASK : 0;
        this->name = this->fn && LFSYMP(this->fn) ? SYMNAME(LFSYM(this->fn)) : 0;
}

#define APPEND_CHR(c) (this->buf[this->off++] = (c))

dtrace:helper:ustack:
/PHASE(START) && this->name > 0/
{
        this->len = UVSIZE(this->name);
        this->buf = (char *)alloca(len+1);
        this->off = 0;
        this->phase = LOOP;
}

dtrace:helper:ustack:
/PHASE(START) && this->name == 0/
{
        this->phase = DONE;
        "@ccl/unknown";
}

dtrace:helper:ustack:
/PHASE(LOOP)/
{
        APPEND_CHR((char)(UVREF(this->name, this->off+1) & 0x7F);
        this->phase = this->off < this->len ? LOOP : END;
}

dtrace:helper:ustack:
/PHASE(END)/
{
        this->phase = DONE;
        APPEND_CHR('\0');
        stringof(this->buf);
}
