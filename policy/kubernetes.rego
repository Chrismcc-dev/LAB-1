package kubernetes

#
# Enforced rules:
# 1) No :latest tag (or untagged images)
# 2) CPU + Memory limits required
# 3) No privileged containers
#

deny[msg] {
  is_workload(input)
  container(c)
  uses_latest(c.image)
  msg = sprintf("%s/%s: container '%s' uses ':latest' (or untagged) image (%s)", [
    input.kind, obj_name(input), container_name(c), c.image
  ])
}

deny[msg] {
  is_workload(input)
  container(c)
  missing_limits(c)
  msg = sprintf("%s/%s: container '%s' missing resources.limits.cpu and/or resources.limits.memory", [
    input.kind, obj_name(input), container_name(c)
  ])
}

deny[msg] {
  is_workload(input)
  container(c)
  is_privileged(c)
  msg = sprintf("%s/%s: container '%s' is privileged (securityContext.privileged=true)", [
    input.kind, obj_name(input), container_name(c)
  ])
}

################
# Workload kinds
################

is_workload(obj) { obj.kind == "Deployment" }
is_workload(obj) { obj.kind == "StatefulSet" }
is_workload(obj) { obj.kind == "DaemonSet" }
is_workload(obj) { obj.kind == "Job" }
is_workload(obj) { obj.kind == "ReplicaSet" }
is_workload(obj) { obj.kind == "ReplicationController" }
is_workload(obj) { obj.kind == "CronJob" }

#########################
# Pod spec + containers
#########################

podspec(ps) {
  input.kind != "CronJob"
  ps = input.spec.template.spec
}

podspec(ps) {
  input.kind == "CronJob"
  ps = input.spec.jobTemplate.spec.template.spec
}

# Regular containers (explicit index, no _)
container(c) {
  podspec(ps)
  some i
  c = ps.containers[i]
}

# Init containers (explicit index, no _)
container(c) {
  podspec(ps)
  ps.initContainers
  some j
  c = ps.initContainers[j]
}

################
# Field helpers
################

obj_name(obj) = n {
  obj.metadata.name == n
}

obj_name(obj) = "unknown" {
  not obj.metadata.name
}

container_name(c) = n {
  c.name == n
}

container_name(c) = "unnamed" {
  not c.name
}

################
# Rule helpers
################

uses_latest(image) {
  endswith(image, ":latest")
}

uses_latest(image) {
  not contains(image, ":")
  not contains(image, "@sha256:")
}

missing_limits(c) { not c.resources }
missing_limits(c) { not c.resources.limits }
missing_limits(c) { not c.resources.limits.cpu }
missing_limits(c) { not c.resources.limits.memory }

is_privileged(c) {
  c.securityContext.privileged == true
}
