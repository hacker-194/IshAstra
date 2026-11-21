{{/*
Expand the name of the chart.
*/}}
{{- define "ishastra.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ishastra.fullname" -}}
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
{{- define "ishastra.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ishastra.appSecretName" -}}
{{- if .Values.api.envFromSecrets }}
{{- index (index .Values.api.envFromSecrets 0) "name" }}
{{- else }}
{{- printf "%s-secrets" (include "ishastra.fullname" .) }}
{{- end }}
{{- end }}

{{- define "ishastra.redisSecretName" -}}
{{- default (printf "%s-redis-secret" (include "ishastra.fullname" .)) .Values.redis.auth.existingSecret }}
{{- end }}

{{- define "ishastra.postgresqlSecretName" -}}
{{- default (printf "%s-postgresql-secret" (include "ishastra.fullname" .)) .Values.postgresql.auth.existingSecret }}
{{- end }}

{{- define "ishastra.grafanaSecretName" -}}
{{- default (printf "%s-grafana-secret" (include "ishastra.fullname" .)) .Values.monitoring.grafana.grafana.admin.existingSecret }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ishastra.labels" -}}
helm.sh/chart: {{ include "ishastra.chart" . }}
{{ include "ishastra.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ishastra.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ishastra.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Common annotations
*/}}
{{- define "ishastra.annotations" -}}
{{- if .Values.additionalAnnotations }}
{{- toYaml .Values.additionalAnnotations | nindent 4 }}
{{- end }}
{{- end }}

{{/*
Security context for containers - generates restricted pod security standard
*/}}
{{- define "ishastra.containerSecurityContext" -}}
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
{{- define "ishastra.podSecurityContext" -}}
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
{{- define "ishastra.imagePullSecrets" -}}
{{- $pullSecrets := .Values.global.image.pullSecrets | default .Values.imagePullSecrets -}}
{{- if $pullSecrets }}
imagePullSecrets:
{{- toYaml $pullSecrets | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Priority class name
*/}}
{{- define "ishastra.priorityClassName" -}}
{{- if .Values.priorityClassName }}
{{ .Values.priorityClassName }}
{{- end }}
{{- end }}

{{/*
Topology spread constraints
*/}}
{{- define "ishastra.topologySpreadConstraints" -}}
{{- if .Values.topologySpreadConstraints }}
topologySpreadConstraints:
{{- toYaml .Values.topologySpreadConstraints | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Affinity
*/}}
{{- define "ishastra.affinity" -}}
{{- if .Values.api.affinity }}
affinity:
{{- toYaml .Values.api.affinity | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Scheduler affinity
*/}}
{{- define "ishastra.scheduler.affinity" -}}
{{- if .Values.scheduler.affinity }}
affinity:
{{- toYaml .Values.scheduler.affinity | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Worker affinity
*/}}
{{- define "ishastra.worker.affinity" -}}
{{- if .Values.worker.affinity }}
affinity:
{{- toYaml .Values.worker.affinity | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Tolerations
*/}}
{{- define "ishastra.tolerations" -}}
{{- if .Values.api.tolerations }}
tolerations:
{{- toYaml .Values.api.tolerations | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Scheduler tolerations
*/}}
{{- define "ishastra.scheduler.tolerations" -}}
{{- if .Values.scheduler.tolerations }}
tolerations:
{{- toYaml .Values.scheduler.tolerations | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Worker tolerations
*/}}
{{- define "ishastra.worker.tolerations" -}}
{{- if .Values.worker.tolerations }}
tolerations:
{{- toYaml .Values.worker.tolerations | nindent 2 }}
{{- end }}
{{- end }}

{{/*
K8s Jobs affinity
*/}}
{{- define "ishastra.k8sJobs.affinity" -}}
{{- if .Values.k8sJobs.affinity }}
affinity:
{{- toYaml .Values.k8sJobs.affinity | nindent 2 }}
{{- end }}
{{- end }}

{{/*
K8s Jobs tolerations
*/}}
{{- define "ishastra.k8sJobs.tolerations" -}}
{{- if .Values.k8sJobs.tolerations }}
tolerations:
{{- toYaml .Values.k8sJobs.tolerations | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Operator affinity
*/}}
{{- define "ishastra.operator.affinity" -}}
{{- if .Values.operator.affinity }}
affinity:
{{- toYaml .Values.operator.affinity | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Operator tolerations
*/}}
{{- define "ishastra.operator.tolerations" -}}
{{- if .Values.operator.tolerations }}
tolerations:
{{- toYaml .Values.operator.tolerations | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Resource requirements
*/}}
{{- define "ishastra.resources" -}}
{{- if .Values.api.resources }}
resources:
{{- toYaml .Values.api.resources | nindent 12 }}
{{- end }}
{{- end }}

{{/*
Scheduler resource requirements
*/}}
{{- define "ishastra.scheduler.resources" -}}
{{- if .Values.scheduler.resources }}
resources:
{{- toYaml .Values.scheduler.resources | nindent 12 }}
{{- end }}
{{- end }}

{{/*
Worker resource requirements
*/}}
{{- define "ishastra.worker.resources" -}}
{{- if .Values.worker.resources }}
resources:
{{- toYaml .Values.worker.resources | nindent 12 }}
{{- end }}
{{- end }}

{{/*
Environment variables from config
*/}}
{{- define "ishastra.env" -}}
{{- range $key, $value := .Values.api.env }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- if .Values.redis.enabled }}
- name: ISHASTRA_REDIS_REQUIRED
  value: "1"
{{- end }}
{{ include "ishastra.queue.env" . }}
{{- end }}

{{/*
Scheduler environment variables
*/}}
{{- define "ishastra.scheduler.env" -}}
{{- range $key, $value := .Values.scheduler.env }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}

{{/*
Worker environment variables
*/}}
{{- define "ishastra.worker.env" -}}
{{- range $key, $value := .Values.worker.env }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{ include "ishastra.queue.env" . }}
{{- end }}

{{/*
Assessment queue environment: the mode has one source of truth here instead
of being repeated (and drifting) in every service's env map.
*/}}
{{- define "ishastra.queue.env" -}}
- name: ISHASTRA_QUEUE_MODE
  value: {{ .Values.queue.mode | quote }}
{{- if eq .Values.queue.mode "redis-streams" }}
- name: ISHASTRA_REDIS_QUEUE_STREAM
  value: {{ .Values.queue.stream | quote }}
- name: ISHASTRA_REDIS_QUEUE_GROUP
  value: {{ .Values.queue.group | quote }}
- name: ISHASTRA_REDIS_QUEUE_VISIBILITY_SECONDS
  value: {{ .Values.queue.visibilitySeconds | quote }}
{{- end }}
{{- end }}

{{/*
Refuse a configuration the code cannot honour. The in-process queue holds an
exclusive per-database worker lease, so a second pod exits with
WorkerLeaseError instead of helping.
*/}}
{{- define "ishastra.queue.validate" -}}
{{- $mode := .Values.queue.mode -}}
{{- if not (has $mode (list "inprocess" "redis-streams" "k8s-jobs")) -}}
{{- fail (printf "queue.mode must be inprocess, redis-streams or k8s-jobs (got %q)" $mode) -}}
{{- end -}}
{{- if and (gt (int .Values.api.replicaCount) 1) (or (ne $mode "redis-streams") (not .Values.redis.enabled)) -}}
{{- fail "api.replicaCount > 1 requires queue.mode=redis-streams and redis.enabled: login flow state, rate limits and the API key registry are shared through Redis. Key revocation reaches every replica within 5 seconds." -}}
{{- end -}}
{{- if eq $mode "inprocess" -}}
{{- if and .Values.worker.enabled (gt (int .Values.worker.replicaCount) 1) -}}
{{- fail "worker.replicaCount > 1 requires queue.mode=redis-streams: the in-process queue takes an exclusive per-database worker lease" -}}
{{- end -}}
{{- if and .Values.worker.enabled .Values.worker.hpa .Values.worker.hpa.enabled -}}
{{- fail "worker.hpa requires queue.mode=redis-streams: scaling the in-process queue starts a second writer" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
Environment from secrets
*/}}
{{- define "ishastra.envFromSecrets" -}}
{{- range .Values.api.envFromSecrets }}
- secretRef:
    name: {{ .name }}
  prefix: {{ .prefix | default "" }}
{{- end }}
{{- end }}

{{/*
Scheduler environment from secrets
*/}}
{{- define "ishastra.scheduler.envFromSecrets" -}}
{{- range .Values.scheduler.envFromSecrets }}
- secretRef:
    name: {{ .name }}
  prefix: {{ .prefix | default "" }}
{{- end }}
{{- end }}

{{/*
Worker environment from secrets
*/}}
{{- define "ishastra.worker.envFromSecrets" -}}
{{- range .Values.worker.envFromSecrets }}
- secretRef:
    name: {{ .name }}
  prefix: {{ .prefix | default "" }}
{{- end }}
{{- end }}

{{/*
Operator environment from secrets
*/}}
{{- define "ishastra.operator.envFromSecrets" -}}
{{- range .Values.operator.envFromSecrets }}
- secretRef:
    name: {{ .name }}
  prefix: {{ .prefix | default "" }}
{{- end }}
{{- end }}

{{/*
Volumes
*/}}
{{- define "ishastra.volumes" -}}
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
{{- define "ishastra.scheduler.volumes" -}}
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
{{- define "ishastra.worker.volumes" -}}
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
Operator volumes
*/}}
{{- define "ishastra.operator.volumes" -}}
{{- if .Values.operator.volumes }}
volumes:
{{- range .Values.operator.volumes }}
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
Operator volume mounts
*/}}
{{- define "ishastra.operator.volumeMounts" -}}
{{- if .Values.operator.volumeMounts }}
volumeMounts:
{{- range .Values.operator.volumeMounts }}
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
Volume mounts
*/}}
{{- define "ishastra.volumeMounts" -}}
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
{{- define "ishastra.scheduler.volumeMounts" -}}
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
{{- define "ishastra.worker.volumeMounts" -}}
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
{{- define "ishastra.livenessProbe" -}}
{{- toYaml .Values.api.livenessProbe }}
{{- end }}

{{/*
Scheduler liveness probe
*/}}
{{- define "ishastra.scheduler.livenessProbe" -}}
{{- toYaml .Values.scheduler.livenessProbe }}
{{- end }}

{{/*
Worker liveness probe
*/}}
{{- define "ishastra.worker.livenessProbe" -}}
{{- toYaml .Values.worker.livenessProbe }}
{{- end }}

{{/*
Readiness probe
*/}}
{{- define "ishastra.readinessProbe" -}}
{{- toYaml .Values.api.readinessProbe }}
{{- end }}

{{/*
Scheduler readiness probe
*/}}
{{- define "ishastra.scheduler.readinessProbe" -}}
{{- toYaml .Values.scheduler.readinessProbe }}
{{- end }}

{{/*
Worker readiness probe
*/}}
{{- define "ishastra.worker.readinessProbe" -}}
{{- toYaml .Values.worker.readinessProbe }}
{{- end }}

{{/*
Startup probe
*/}}
{{- define "ishastra.startupProbe" -}}
{{- toYaml .Values.api.startupProbe }}
{{- end }}

{{/*
Update strategy
*/}}
{{- define "ishastra.updateStrategy" -}}
{{- toYaml .Values.api.updateStrategy | nindent 8 }}
{{- end }}

{{/*
Scheduler update strategy
*/}}
{{- define "ishastra.scheduler.updateStrategy" -}}
{{- toYaml .Values.scheduler.updateStrategy | nindent 8 }}
{{- end }}

{{/*
Worker update strategy
*/}}
{{- define "ishastra.worker.updateStrategy" -}}
{{- toYaml .Values.worker.updateStrategy | nindent 8 }}
{{- end }}

{{/*
Service configuration
*/}}
{{- define "ishastra.service" -}}
{{- if .Values.api.service }}
{{- toYaml .Values.api.service | nindent 8 }}
{{- end }}
{{- end }}

{{/*
Scheduler service
*/}}
{{- define "ishastra.scheduler.service" -}}
{{- if .Values.scheduler.service }}
{{- toYaml .Values.scheduler.service | nindent 8 }}
{{- end }}
{{- end }}

{{/*
ServiceAccount name
*/}}
{{- define "ishastra.serviceAccountName" -}}
{{- if .Values.serviceAccount.enabled }}
{{- $name := .Values.serviceAccount.name | default (include "ishastra.fullname" .) -}}
{{- $name | quote -}}
{{- else }}
"default"
{{- end }}
{{- end }}

{{/*
Seccomp profile for nmap
*/}}
{{- define "ishastra.seccomp.nmap" -}}
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
{{- define "ishastra.seccomp.nuclei" -}}
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
{{- define "ishastra.seccomp.nikto" -}}
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
{{- define "ishastra.seccomp.sqlmap" -}}
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
{{- define "ishastra.seccomp.default" -}}
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
{{- define "ishastra.validateDatabase" -}}
{{- $env := .Values.api.env | default dict -}}
{{- $url := toString (index $env "ISHASTRA_DATABASE_URL" | default "") -}}
{{- $postgres := or .Values.postgresql.enabled (hasPrefix "postgres" $url) -}}
{{- $replicas := int (.Values.api.replicaCount | default 1) -}}
{{- if .Values.api.hpa.enabled -}}
{{- $replicas = max $replicas (int (.Values.api.hpa.minReplicas | default 1)) -}}
{{- end -}}
{{- $allow := get (default dict .Values.database) "allowSqliteMultiReplica" | default false -}}
{{- if and (not $postgres) (not $allow) (gt $replicas 1) -}}
{{- fail (printf "SQLite backs one API pod, but this render asks for %d. Enable postgresql.enabled (or set api.env.ISHASTRA_DATABASE_URL to a postgres:// URL), or pin api.replicaCount: 1 and api.hpa.enabled: false." $replicas) -}}
{{- end -}}
{{- end -}}

{{/*
Assessment Jobs run in their own pods and cannot read the API's SQLite file.
*/}}
{{- define "ishastra.validateK8sJobs" -}}
{{- if and .Values.k8sJobs.enabled (not .Values.postgresql.enabled) -}}
{{- fail "k8sJobs requires PostgreSQL: Job pods cannot share the API's SQLite file. Set postgresql.enabled=true (or run ISHASTRA_QUEUE_MODE=inprocess)." -}}
{{- end -}}
{{- end -}}

{{/*
Scope-key rotation needs durable, shared storage for the signer and verifier.
*/}}
{{- define "ishastra.validateScopeSigning" -}}
{{- if and .Values.scopeSigning.enabled (not .Values.scopeSigning.existingClaim) -}}
{{- fail "scopeSigning.enabled requires scopeSigning.existingClaim: provision a ReadWriteMany PVC and seed its public/scope-jwks.json with strix scope-keygen." -}}
{{- end -}}
{{- if and .Values.scopeSigning.rotation.enabled (not .Values.scopeSigning.enabled) -}}
{{- fail "scopeSigning.rotation.enabled requires scopeSigning.enabled=true." -}}
{{- end -}}
{{- end -}}

{{/*
Worker command for Redis Streams mode
*/}}
{{- define "ishastra.worker.command" -}}
{{- if eq .Values.queue.mode "redis-streams" }}
command:
  - python
  - -m
  - ishastra
  - worker
  {{- if .Values.worker.concurrency }}
  - --concurrency
  - "{{ .Values.worker.concurrency }}"
  {{- end }}
  {{- if .Values.worker.queueMax }}
  - --queue-max
  - "{{ .Values.worker.queueMax }}"
  {{- end }}
  {{- if .Values.worker.redisStreams.extraArgs }}
  {{- range .Values.worker.redisStreams.extraArgs }}
  - {{ . }}
  {{- end }}
  {{- end }}
{{- else }}
command:
  - python
  - -m
  - ishastra
  - serve
  - --host
  - 0.0.0.0
  - --port
  - "{{ .Values.worker.service.port | default 8000 }}"
{{- end }}
{{- end }}

{{/*
Operator command and args
*/}}
{{- define "ishastra.operator.command" -}}
command:
  - /manager
args:
  - --leader-elect
  - --metrics-bind-address=:{{ .Values.operator.metrics.port }}
  - --health-probe-bind-address=:{{ .Values.operator.health.port }}
  {{- if .Values.operator.webhook.enabled }}
  - --webhook-port={{ .Values.operator.webhook.port }}
  - --webhook-cert-dir={{ .Values.operator.webhook.certDir }}
  {{- end }}
  {{- if .Values.operator.enableK8sJobsMode }}
  - --enable-k8s-jobs-mode
  {{- end }}
  {{- if .Values.operator.enableRedisStreamsMode }}
  - --enable-redis-streams-mode
  {{- end }}
  {{- if .Values.operator.redis.address }}
  - --redis-address={{ .Values.operator.redis.address }}
  {{- end }}
  {{- if .Values.operator.logLevel }}
  - --log-level={{ .Values.operator.logLevel }}
  {{- end }}
  {{- if .Values.operator.logFormat }}
  - --log-format={{ .Values.operator.logFormat }}
  {{- end }}
{{- end }}

{{/*
Operator validation
*/}}
{{- define "ishastra.operator.validate" -}}
{{- if .Values.operator.enabled }}
{{- if and .Values.operator.webhook.enabled (not .Values.operator.webhook.caBundle) }}
{{- fail "operator.webhook.enabled requires operator.webhook.caBundle: provide a CA bundle for the webhook server" -}}
{{- end }}
{{- if and .Values.operator.enableRedisStreamsMode (not .Values.redis.enabled) }}
{{- fail "operator.enableRedisStreamsMode requires redis.enabled=true" -}}
{{- end }}
{{- if and .Values.operator.enableK8sJobsMode (not .Values.postgresql.enabled) }}
{{- fail "operator.enableK8sJobsMode requires postgresql.enabled=true (or external database via ISHASTRA_DATABASE_URL)" -}}
{{- end }}
{{- end }}
{{- end }}
