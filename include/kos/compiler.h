#ifndef KOS_COMPILER_H
#define KOS_COMPILER_H

#define KOS_ALIGNED(bytes) __attribute__((aligned(bytes)))
#define KOS_NOINLINE __attribute__((noinline))
#define KOS_NORETURN __attribute__((noreturn))
#define KOS_OPTNONE __attribute__((optnone))
#define KOS_SECTION(name) __attribute__((section(name)))
#define KOS_USED __attribute__((used))
#define KOS_PACKED __attribute__((packed))

#endif
