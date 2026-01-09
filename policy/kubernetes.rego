package kubernetes

#
# Enforced rules:
# 1) No :latest tag (or no tag)
# 2) CPU + Memory limits required
# 3) No privileged containers
#

deny[msg] {
  is_workload(input)
  containers := all_containers(input)
  some i
  c := containers[i]

  uses_latest(c.image)

  msg := sprintf("%s/%s: container '%s' uses a ':latest' (or untagged) image (%s)", [
    input.kind, obj_name(input), container_name(c), c.image
  ])
}

deny[msg] {
  is_workload(input)
  containers := all_containers(input)
  some i
  c := containers[i]

  missing_limits(c)

  msg := sprintf("%s/%s: container '%s' is missing resources.limits.cpu and/or resources.limits.memory", [
    input.kind, obj_name(input), container_name(c)
  ])
}

deny[msg] {
  is_workload(input)
  containers := all_containers(input)
  some i
  c := containers[i]

  is_privileged(c)

  msg := sprintf("%s/%s: container '%s' is privileged (securityContext.privileged=true)", [
    input.kind, obj_name(input), container_name(c)
  ])
}

##########
# Helpers
##########

# Workloads with Pod specs (including CronJob)
is_workload(obj) {
  obj.kind == "Deployment"
} or {
  obj.kind == "StatefulSet"
} or {
  obj.kind == "DaemonSet"
} or {
  obj.kind == "Job"
} or {
  obj.kind == "ReplicaSet"
} or {
  obj.kind == "ReplicationController"
} or {
  obj.kind == "CronJob"
}

# Return the pod spec for supported workload types
podspec(obj) = ps {
  obj.kind == "CronJob"
  ps := obj.spec.jobTemplate.spec.template.spec
} else = ps {
  obj.kind != "CronJob"
  ps := obj.spec.template.spec
}

# containers + initContainers (if present)
all_containers(obj) = out {
  ps := podspec(obj)
  cs := object.get(ps, "containers", [])
  ics := object.get(ps, "initContainers", [])
  out := array.concat(cs, ics)
}

obj_name(obj) = n {
  n := object.get(obj.metadata, "name", "unknown")
}

container_name(c) = n {
  n := object.get(c, "name", "unnamed")
}

# latest detection:
# - ends with :latest
# - OR has no tag (and no digest)
uses_latest(image) {
  endswith(image, ":latest")
} or {
  not contains(image, ":")
  not contains(image, "@sha256:")
}

missing_limits(c) {
  not c.resources
} or {
  not c.resources.limits
} or {
  not c.resources.limits.cpu
} or {
  not c.resources.limits.memory
}

is_privileged(c) {
  c.securityContext.privileged == true
}
