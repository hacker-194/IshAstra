{{/*
Expand the name of the chart.
*/}}
{{- define "strix.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "strix.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "strix.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "strix.appSecretName" -}}
{{- if .Values.api.envFromSecrets }}
{{- index (index .Values.api.envFromSecrets 0) "name" }}
{{- else }}
{{- printf "%s-secrets" (include "strix.fullname" .) }}
{{- end }}
{{- end }}

{{- define "strix.redisSecretName" -}}
{{- default (printf "%s-redis-secret" (include "strix.fullname" .)) .Values.redis.auth.existingSecret }}
{{- end }}

{{- define "strix.postgresqlSecretName" -}}
{{- default (printf "%s-postgresql-secret" (include "strix.fullname" .)) .Values.postgresql.auth.existingSecret }}
{{- end }}

{{- define "strix.grafanaSecretName" -}}
{{- default (printf "%s-grafana-secret" (include "strix.fullname" .)) .Values.monitoring.grafana.grafana.admin.existingSecret }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "strix.labels" -}}
helm.sh/chart: {{ include "strix.chart" . }}
{{ include "strix.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "strix.selectorLabels" -}}
app.kubernetes.io/name: {{ include "strix.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Common annotations
*/}}
{{- define "strix.annotations" -}}
{{- if .Values.additionalAnnotations }}
{{- toYaml .Values.additionalAnnotations | nindent 4 }}
{{- end }}
{{- end }}

{{/*
Security context for containers - generates restricted pod security standard
*/}}
{{- define "strix.containerSecurityContext" -}}
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
Security context for pods - generates restricted pod security standard
*/}}
{{- define "strix.podSecurityContext" -}}
fsGroup: 10001
fsGroupChangePolicy: OnRootMismatch
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "strix.imagePullSecrets" -}}
{{- $pullSecrets := .Values.global.image.pullSecrets | default .Values.imagePullSecrets -}}
{{- if $pullSecrets }}
imagePullSecrets:
{{- toYaml $pullSecrets | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Priority class name
*/}}
{{- define "strix.priorityClassName" -}}
{{- if .Values.priorityClassName }}
{{ .Values.priorityClassName }}
{{- end }}
{{- end }}

{{/*
Topology spread constraints
*/}}
{{- define "strix.topologySpreadConstraints" -}}
{{- if .Values.topologySpreadConstraints }}
topologySpreadConstraints:
{{- toYaml .Values.topologySpreadConstraints | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Affinity
*/}}
{{- define "strix.affinity" -}}
{{- if .Values.api.affinity }}
affinity:
{{- toYaml .Values.api.affinity | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Scheduler affinity
*/}}
{{- define "strix.scheduler.affinity" -}}
{{- if .Values.scheduler.affinity }}
affinity:
{{- toYaml .Values.scheduler.affinity | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Worker affinity
*/}}
{{- define "strix.worker.affinity" -}}
{{- if .Values.worker.affinity }}
affinity:
{{- toYaml .Values.worker.affinity | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Tolerations
*/}}
{{- define "strix.tolerations" -}}
{{- if .Values.api.tolerations }}
tolerations:
{{- toYaml .Values.api.tolerations | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Scheduler tolerations
*/}}
{{- define "strix.scheduler.tolerations" -}}
{{- if .Values.scheduler.tolerations }}
tolerations:
{{- toYaml .Values.scheduler.tolerations | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Worker tolerations
*/}}
{{- define "strix.worker.tolerations" -}}
{{- if .Values.worker.tolerations }}
tolerations:
{{- toYaml .Values.worker.tolerations | nindent 2 }}
{{- end }}
{{- end }}

{{/*
K8s Jobs affinity
*/}}
{{- define "strix.k8sJobs.affinity" -}}
{{- if .Values.k8sJobs.affinity }}
affinity:
{{- toYaml .Values.k8sJobs.affinity | nindent 2 }}
{{- end }}
{{- end }}

{{/*
K8s Jobs tolerations
*/}}
{{- define "strix.k8sJobs.tolerations" -}}
{{- if .Values.k8sJobs.tolerations }}
tolerations:
{{- toYaml .Values.k8sJobs.tolerations | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Resource requirements
*/}}
{{- define "strix.resources" -}}
{{- if .Values.api.resources }}
resources:
{{- toYaml .Values.api.resources | nindent 12 }}
{{- end }}
{{- end }}

{{/*
Scheduler resource requirements
*/}}
{{- define "strix.scheduler.resources" -}}
{{- if .Values.scheduler.resources }}
resources:
{{- toYaml .Values.scheduler.resources | nindent 12 }}
{{- end }}
{{- end }}

{{/*
Worker resource requirements
*/}}
{{- define "strix.worker.resources" -}}
{{- if .Values.worker.resources }}
resources:
{{- toYaml .Values.worker.resources | nindent 12 }}
{{- end }}
{{- end }}

{{/*
Environment variables from config
*/}}
{{- define "strix.env" -}}
{{- range $key, $value := .Values.api.env }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- if .Values.redis.enabled }}
- name: STRIX_REDIS_REQUIRED
  value: "1"
{{- end }}
{{- end }}

{{/*
Scheduler environment variables
*/}}
{{- define "strix.scheduler.env" -}}
{{- range $key, $value := .Values.scheduler.env }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}

{{/*
Worker environment variables
*/}}
{{- define "strix.worker.env" -}}
{{- range $key, $value := .Values.worker.env }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}

{{/*
Environment from secrets
*/}}
{{- define "strix.envFromSecrets" -}}
{{- range .Values.api.envFromSecrets }}
- secretRef:
    name: {{ .name }}
  prefix: {{ .prefix | default "" }}
{{- end }}
{{- end }}

{{/*
Scheduler environment from secrets
*/}}
{{- define "strix.scheduler.envFromSecrets" -}}
{{- range .Values.scheduler.envFromSecrets }}
- secretRef:
    name: {{ .name }}
  prefix: {{ .prefix | default "" }}
{{- end }}
{{- end }}

{{/*
Worker environment from secrets
*/}}
{{- define "strix.worker.envFromSecrets" -}}
{{- range .Values.worker.envFromSecrets }}
- secretRef:
    name: {{ .name }}
  prefix: {{ .prefix | default "" }}
{{- end }}
{{- end }}

{{/*
Volumes
*/}}
{{- define "strix.volumes" -}}
{{- if .Values.api.volumes }}
volumes:
{{- range .Values.api.volumes }}
  - name: {{ .name }}
    {{- if .persistentVolumeClaim }}
    persistentVolumeClaim:
      claimName: {{ .persistentVolumeClaim.claimName }}
    {{- end }}
    {{- if .configMap }}
    configMap:
      name: {{ .configMap.name }}
      items:
      {{- range .configMap.items }}
      - key: {{ .key }}
        path: {{ .path }}
      {{- end }}
    {{- end }}
    {{- if hasKey . "emptyDir" }}
    {{- if or .emptyDir.medium .emptyDir.sizeLimit }}
    emptyDir:
      {{- if .emptyDir.medium }}
      medium: {{ .emptyDir.medium }}
      {{- end }}
      {{- if .emptyDir.sizeLimit }}
      sizeLimit: {{ .emptyDir.sizeLimit }}
      {{- end }}
    {{- else }}
    emptyDir: {}
    {{- end }}
    {{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Scheduler volumes
*/}}
{{- define "strix.scheduler.volumes" -}}
{{- if .Values.scheduler.volumes }}
volumes:
{{- range .Values.scheduler.volumes }}
  - name: {{ .name }}
    {{- if .persistentVolumeClaim }}
    persistentVolumeClaim:
      claimName: {{ .persistentVolumeClaim.claimName }}
    {{- end }}
    {{- if .configMap }}
    configMap:
      name: {{ .configMap.name }}
      items:
      {{- range .configMap.items }}
      - key: {{ .key }}
        path: {{ .path }}
      {{- end }}
    {{- end }}
    {{- if hasKey . "emptyDir" }}
    {{- if or .emptyDir.medium .emptyDir.sizeLimit }}
    emptyDir:
      {{- if .emptyDir.medium }}
      medium: {{ .emptyDir.medium }}
      {{- end }}
      {{- if .emptyDir.sizeLimit }}
      sizeLimit: {{ .emptyDir.sizeLimit }}
      {{- end }}
    {{- else }}
    emptyDir: {}
    {{- end }}
    {{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Worker volumes
*/}}
{{- define "strix.worker.volumes" -}}
{{- if .Values.worker.volumes }}
volumes:
{{- range .Values.worker.volumes }}
  - name: {{ .name }}
    {{- if .persistentVolumeClaim }}
    persistentVolumeClaim:
      claimName: {{ .persistentVolumeClaim.claimName }}
    {{- end }}
    {{- if .configMap }}
    configMap:
      name: {{ .configMap.name }}
      items:
      {{- range .configMap.items }}
      - key: {{ .key }}
        path: {{ .path }}
      {{- end }}
    {{- end }}
    {{- if hasKey . "emptyDir" }}
    {{- if or .emptyDir.medium .emptyDir.sizeLimit }}
    emptyDir:
      {{- if .emptyDir.medium }}
      medium: {{ .emptyDir.medium }}
      {{- end }}
      {{- if .emptyDir.sizeLimit }}
      sizeLimit: {{ .emptyDir.sizeLimit }}
      {{- end }}
    {{- else }}
    emptyDir: {}
    {{- end }}
    {{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Volume mounts
*/}}
{{- define "strix.volumeMounts" -}}
{{- if or .Values.api.volumeMounts .Values.scopeSigning.enabled }}
volumeMounts:
{{- range .Values.api.volumeMounts }}
  - name: {{ .name }}
    mountPath: {{ .mountPath }}
    {{- if .subPath }}
    subPath: {{ .subPath }}
    {{- end }}
    {{- if .readOnly }}
    readOnly: {{ .readOnly }}
    {{- end }}
{{- end }}
{{- if .Values.scopeSigning.enabled }}
  - name: scope-signing-jwks
    mountPath: /etc/strix/scope-signing
    subPath: {{ .Values.scopeSigning.publicDirectory | quote }}
    readOnly: true
{{- end }}
{{- end }}
{{- end }}

{{/*
Scheduler volume mounts
*/}}
{{- define "strix.scheduler.volumeMounts" -}}
{{- if .Values.scheduler.volumeMounts }}
volumeMounts:
{{- range .Values.scheduler.volumeMounts }}
  - name: {{ .name }}
    mountPath: {{ .mountPath }}
    {{- if .subPath }}
    subPath: {{ .subPath }}
    {{- end }}
    {{- if .readOnly }}
    readOnly: {{ .readOnly }}
    {{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Worker volume mounts
*/}}
{{- define "strix.worker.volumeMounts" -}}
{{- if .Values.worker.volumeMounts }}
volumeMounts:
{{- range .Values.worker.volumeMounts }}
  - name: {{ .name }}
    mountPath: {{ .mountPath }}
    {{- if .subPath }}
    subPath: {{ .subPath }}
    {{- end }}
    {{- if .readOnly }}
    readOnly: {{ .readOnly }}
    {{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Liveness probe
*/}}
{{- define "strix.livenessProbe" -}}
{{- toYaml .Values.api.livenessProbe }}
{{- end }}

{{/*
Scheduler liveness probe
*/}}
{{- define "strix.scheduler.livenessProbe" -}}
{{- toYaml .Values.scheduler.livenessProbe }}
{{- end }}

{{/*
Worker liveness probe
*/}}
{{- define "strix.worker.livenessProbe" -}}
{{- toYaml .Values.worker.livenessProbe }}
{{- end }}

{{/*
Readiness probe
*/}}
{{- define "strix.readinessProbe" -}}
{{- toYaml .Values.api.readinessProbe }}
{{- end }}

{{/*
Scheduler readiness probe
*/}}
{{- define "strix.scheduler.readinessProbe" -}}
{{- toYaml .Values.scheduler.readinessProbe }}
{{- end }}

{{/*
Worker readiness probe
*/}}
{{- define "strix.worker.readinessProbe" -}}
{{- toYaml .Values.worker.readinessProbe }}
{{- end }}

{{/*
Startup probe
*/}}
{{- define "strix.startupProbe" -}}
{{- toYaml .Values.api.startupProbe }}
{{- end }}

{{/*
Update strategy
*/}}
{{- define "strix.updateStrategy" -}}
{{- toYaml .Values.api.updateStrategy | nindent 8 }}
{{- end }}

{{/*
Scheduler update strategy
*/}}
{{- define "strix.scheduler.updateStrategy" -}}
{{- toYaml .Values.scheduler.updateStrategy | nindent 8 }}
{{- end }}

{{/*
Worker update strategy
*/}}
{{- define "strix.worker.updateStrategy" -}}
{{- toYaml .Values.worker.updateStrategy | nindent 8 }}
{{- end }}

{{/*
Service configuration
*/}}
{{- define "strix.service" -}}
{{- if .Values.api.service }}
{{- toYaml .Values.api.service | nindent 8 }}
{{- end }}
{{- end }}

{{/*
Scheduler service
*/}}
{{- define "strix.scheduler.service" -}}
{{- if .Values.scheduler.service }}
{{- toYaml .Values.scheduler.service | nindent 8 }}
{{- end }}
{{- end }}

{{/*
ServiceAccount name
*/}}
{{- define "strix.serviceAccountName" -}}
{{- if .Values.serviceAccount.enabled }}
{{- $name := .Values.serviceAccount.name | default (include "strix.fullname" .) -}}
{{- $name | quote -}}
{{- else }}
"default"
{{- end }}
{{- end }}

{{/*
Seccomp profile for nmap
*/}}
{{- define "strix.seccomp.nmap" -}}
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "close", "fstat", "lstat", "poll", "mmap", "munmap",
        "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64",
        "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield",
        "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl",
        "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer",
        "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom",
        "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername",
        "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "exit",
        "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget",
        "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync",
        "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename",
        "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod",
        "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit",
        "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid",
        "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
        "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid",
        "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid",
        "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
        "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality",
        "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority",
        "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler",
        "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval",
        "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt",
        "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit",
        "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon",
        "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm",
        "create_module", "init_module", "delete_module", "get_kernel_syms",
        "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall",
        "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr",
        "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr",
        "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time",
        "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area",
        "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel",
        "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old",
        "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address",
        "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime",
        "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime",
        "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait",
        "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy",
        "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
        "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key",
        "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch",
        "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat",
        "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat",
        "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
        "unshare", "set_robust_list", "get_robust_list", "splice", "tee",
        "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait",
        "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime",
        "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1",
        "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo",
        "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64",
        "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs",
        "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev",
        "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2",
        "seccomp", "getrandom", "memfd_create", "kexec_file_load", "bpf", "execveat",
        "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2",
        "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx",
        "io_pgetevents", "rseq", "pidfd_send_signal", "io_uring_setup",
        "io_uring_enter", "io_uring_register", "openat2", "pidfd_getfd",
        "faccessat2", "process_madvise", "epoll_pwait2", "mount_setattr",
        "quotactl_fd", "landlock_create_ruleset", "landlock_add_rule",
        "landlock_restrict_self", "memfd_secret", "process_mrelease",
        "futex_waitv", "set_mempolicy_home_node", "cachestat", "fchmodat2",
        "map_shadow_stack", "futex_wake", "futex_wait", "futex_requeue"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
{{- end }}

{{/*
Seccomp profile for nuclei
*/}}
{{- define "strix.seccomp.nuclei" -}}
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "close", "fstat", "lstat", "poll", "mmap", "munmap",
        "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64",
        "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield",
        "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl",
        "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer",
        "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom",
        "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername",
        "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "exit",
        "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget",
        "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync",
        "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename",
        "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod",
        "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit",
        "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid",
        "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
        "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid",
        "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid",
        "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
        "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality",
        "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority",
        "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler",
        "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval",
        "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt",
        "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit",
        "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon",
        "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm",
        "create_module", "init_module", "delete_module", "get_kernel_syms",
        "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall",
        "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr",
        "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr",
        "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time",
        "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area",
        "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel",
        "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old",
        "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address",
        "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime",
        "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime",
        "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait",
        "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy",
        "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
        "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key",
        "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch",
        "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat",
        "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat",
        "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
        "unshare", "set_robust_list", "get_robust_list", "splice", "tee",
        "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait",
        "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime",
        "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1",
        "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo",
        "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64",
        "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs",
        "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev",
        "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2",
        "seccomp", "getrandom", "memfd_create", "kexec_file_load", "bpf", "execveat",
        "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2",
        "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx",
        "io_pgetevents", "rseq", "pidfd_send_signal", "io_uring_setup",
        "io_uring_enter", "io_uring_register", "openat2", "pidfd_getfd",
        "faccessat2", "process_madvise", "epoll_pwait2", "mount_setattr",
        "quotactl_fd", "landlock_create_ruleset", "landlock_add_rule",
        "landlock_restrict_self", "memfd_secret", "process_mrelease",
        "futex_waitv", "set_mempolicy_home_node", "cachestat", "fchmodat2",
        "map_shadow_stack", "futex_wake", "futex_wait", "futex_requeue"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
{{- end }}

{{/*
Seccomp profile for nikto
*/}}
{{- define "strix.seccomp.nikto" -}}
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "close", "fstat", "lstat", "poll", "mmap", "munmap",
        "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64",
        "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield",
        "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl",
        "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer",
        "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom",
        "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername",
        "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "exit",
        "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget",
        "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync",
        "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename",
        "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod",
        "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit",
        "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid",
        "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
        "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid",
        "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid",
        "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
        "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality",
        "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority",
        "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler",
        "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval",
        "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt",
        "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit",
        "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon",
        "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm",
        "create_module", "init_module", "delete_module", "get_kernel_syms",
        "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall",
        "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr",
        "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr",
        "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time",
        "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area",
        "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel",
        "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old",
        "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address",
        "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime",
        "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime",
        "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait",
        "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy",
        "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
        "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key",
        "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch",
        "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat",
        "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat",
        "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
        "unshare", "set_robust_list", "get_robust_list", "splice", "tee",
        "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait",
        "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime",
        "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1",
        "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo",
        "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64",
        "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs",
        "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev",
        "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2",
        "seccomp", "getrandom", "memfd_create", "kexec_file_load", "bpf", "execveat",
        "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2",
        "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx",
        "io_pgetevents", "rseq", "pidfd_send_signal", "io_uring_setup",
        "io_uring_enter", "io_uring_register", "openat2", "pidfd_getfd",
        "faccessat2", "process_madvise", "epoll_pwait2", "mount_setattr",
        "quotactl_fd", "landlock_create_ruleset", "landlock_add_rule",
        "landlock_restrict_self", "memfd_secret", "process_mrelease",
        "futex_waitv", "set_mempolicy_home_node", "cachestat", "fchmodat2",
        "map_shadow_stack", "futex_wake", "futex_wait", "futex_requeue"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
{{- end }}

{{/*
Seccomp profile for sqlmap
*/}}
{{- define "strix.seccomp.sqlmap" -}}
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "close", "fstat", "lstat", "poll", "mmap", "munmap",
        "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64",
        "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield",
        "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl",
        "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer",
        "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom",
        "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername",
        "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "exit",
        "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget",
        "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync",
        "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename",
        "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod",
        "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit",
        "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid",
        "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
        "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid",
        "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid",
        "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
        "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality",
        "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority",
        "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler",
        "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval",
        "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt",
        "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit",
        "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon",
        "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm",
        "create_module", "init_module", "delete_module", "get_kernel_syms",
        "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall",
        "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr",
        "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr",
        "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time",
        "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area",
        "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel",
        "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old",
        "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address",
        "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime",
        "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime",
        "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait",
        "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy",
        "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
        "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key",
        "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch",
        "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat",
        "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat",
        "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
        "unshare", "set_robust_list", "get_robust_list", "splice", "tee",
        "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait",
        "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime",
        "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1",
        "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo",
        "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64",
        "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs",
        "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev",
        "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2",
        "seccomp", "getrandom", "memfd_create", "kexec_file_load", "bpf", "execveat",
        "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2",
        "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx",
        "io_pgetevents", "rseq", "pidfd_send_signal", "io_uring_setup",
        "io_uring_enter", "io_uring_register", "openat2", "pidfd_getfd",
        "faccessat2", "process_madvise", "epoll_pwait2", "mount_setattr",
        "quotactl_fd", "landlock_create_ruleset", "landlock_add_rule",
        "landlock_restrict_self", "memfd_secret", "process_mrelease",
        "futex_waitv", "set_mempolicy_home_node", "cachestat", "fchmodat2",
        "map_shadow_stack", "futex_wake", "futex_wait", "futex_requeue"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
{{- end }}

{{/*
Default seccomp profile (baseline for all scanners)
*/}}
{{- define "strix.seccomp.default" -}}
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "close", "fstat", "lstat", "poll", "mmap", "munmap",
        "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64",
        "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield",
        "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl",
        "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer",
        "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom",
        "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername",
        "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "exit",
        "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget",
        "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync",
        "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename",
        "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod",
        "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit",
        "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid",
        "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
        "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid",
        "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid",
        "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
        "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality",
        "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority",
        "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler",
        "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval",
        "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt",
        "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit",
        "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon",
        "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm",
        "create_module", "init_module", "delete_module", "get_kernel_syms",
        "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall",
        "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr",
        "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr",
        "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time",
        "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area",
        "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel",
        "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old",
        "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address",
        "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime",
        "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime",
        "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait",
        "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy",
        "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
        "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key",
        "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch",
        "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat",
        "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat",
        "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
        "unshare", "set_robust_list", "get_robust_list", "splice", "tee",
        "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait",
        "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime",
        "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1",
        "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo",
        "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64",
        "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs",
        "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev",
        "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2",
        "seccomp", "getrandom", "memfd_create", "kexec_file_load", "bpf", "execveat",
        "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2",
        "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx",
        "io_pgetevents", "rseq", "pidfd_send_signal", "io_uring_setup",
        "io_uring_enter", "io_uring_register", "openat2", "pidfd_getfd",
        "faccessat2", "process_madvise", "epoll_pwait2", "mount_setattr",
        "quotactl_fd", "landlock_create_ruleset", "landlock_add_rule",
        "landlock_restrict_self", "memfd_secret", "process_mrelease",
        "futex_waitv", "set_mempolicy_home_node", "cachestat", "fchmodat2",
        "map_shadow_stack", "futex_wake", "futex_wait", "futex_requeue"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
{{- end }}
{{/*
SQLite is single-writer. Refuse to render more than one API pod on it: that is
how two pods end up with two different databases and half the state disappears.
*/}}
{{- define "strix.validateDatabase" -}}
{{- $env := .Values.api.env | default dict -}}
{{- $url := toString (index $env "STRIX_DATABASE_URL" | default "") -}}
{{- $postgres := or .Values.postgresql.enabled (hasPrefix "postgres" $url) -}}
{{- $replicas := int (.Values.api.replicaCount | default 1) -}}
{{- if .Values.api.hpa.enabled -}}
{{- $replicas = max $replicas (int (.Values.api.hpa.minReplicas | default 1)) -}}
{{- end -}}
{{- $allow := get (default dict .Values.database) "allowSqliteMultiReplica" | default false -}}
{{- if and (not $postgres) (not $allow) (gt $replicas 1) -}}
{{- fail (printf "SQLite backs one API pod, but this render asks for %d. Enable postgresql.enabled (or set api.env.STRIX_DATABASE_URL to a postgres:// URL), or pin api.replicaCount: 1 and api.hpa.enabled: false." $replicas) -}}
{{- end -}}
{{- end -}}

{{/*
Assessment Jobs run in their own pods and cannot read the API's SQLite file.
*/}}
{{- define "strix.validateK8sJobs" -}}
{{- if and .Values.k8sJobs.enabled (not .Values.postgresql.enabled) -}}
{{- fail "k8sJobs requires PostgreSQL: Job pods cannot share the API's SQLite file. Set postgresql.enabled=true (or run STRIX_QUEUE_MODE=inprocess)." -}}
{{- end -}}
{{- end -}}

{{/*
Scope-key rotation needs durable, shared storage for the signer and verifier.
*/}}
{{- define "strix.validateScopeSigning" -}}
{{- if and .Values.scopeSigning.enabled (not .Values.scopeSigning.existingClaim) -}}
{{- fail "scopeSigning.enabled requires scopeSigning.existingClaim: provision a ReadWriteMany PVC and seed its public/scope-jwks.json with strix scope-keygen." -}}
{{- end -}}
{{- if and .Values.scopeSigning.rotation.enabled (not .Values.scopeSigning.enabled) -}}
{{- fail "scopeSigning.rotation.enabled requires scopeSigning.enabled=true." -}}
{{- end -}}
{{- end -}}
