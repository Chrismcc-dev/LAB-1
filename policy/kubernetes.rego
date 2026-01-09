package kubernetes

# Conftest will feed each YAML document as `input`.

deny[msg] {
  is_workload_with_pod_spec(input)
  c := all_containers(input)[_]
  image_uses_latest(c.image)
  msg := sprintf("%s/%s: container '%s' uses a ':latest' image tag (%s)", [input.kind, object_name(input), container_name(c), c.image])
}

deny[msg] {
  is_workload_with_pod_spec(input)
  c := all_containers(input)[_]
  missing_limits(c)
  msg := sprintf("%s/%s: container '%s' is missing resources.limits.cpu and/or resources.limits.memory", [input.kind, object_name(input), container_name(c)])
}

deny[msg] {
  is_workload_with_pod_spec(input)
  c := all_containers(input)[_]
  is_privileged(c)
  msg := sprintf("%s/%s: container '%s' is privileged (securityContext.privileged=true)", [input.kind, object_name(input), container_name(c)])
}

###
# Helpers
###

# Workloads that contain a pod template spec:
# Deployment, StatefulSet, DaemonSet, Job, ReplicaSet, ReplicationController, CronJob
is_workload_with_pod_spec(obj) {
  obj.kind == "Deployment"
  obj.spec.template.spec
}
is_workload_with_pod_spec(obj) {
  obj.kind == "StatefulSet"
  obj.spec.template.spec
}
is_workload_with_pod_spec(obj) {
  obj.kind == "DaemonSet"
  obj.spec.template.spec
}
is_workload_with_pod_spec(obj) {
  obj.kind == "Job"
  obj.spec.template.spec
}
is_workload_with_pod_spec(obj) {
  obj.kind == "ReplicaSet"
  obj.spec.template.spec
}
is_workload_with_pod_spec(obj) {
  obj.kind == "ReplicationController"
  obj.spec.template.spec
}
is_workload_with_pod_spec(obj) {
  obj.kind == "CronJob"
  obj.spec.jobTemplate.spec.template.spec
}

# Grab all containers (+ initContainers if present)
all_containers(obj) = containers {
  obj.kind == "CronJob"
  podspec := obj.spec.jobTemplate.spec.template.spec
  containers := concat_arrays([
    get_array(podspec, ["containers"]),
    get_array(podspec, ["initContainers"])
  ])
}

all_containers(obj) = containers {
  obj.kind != "CronJob"
  podspec := obj.spec.template.spec
  containers := concat_arrays([
    get_array(podspec, ["containers"]),
    get_array(podspec, ["initContainers"])
  ])
}

get_array(obj, path) = arr {
  arr := object.get(obj, path[0], [])
}

concat_arrays(arrs) = out {
  out := [x | arr := arrs[_]; x := arr[_]]
}

object_name(obj) = name {
  name := obj.metadata.name
} else = "unknown" {
  true
}

container_name(c) = n {
  n := c.name
} else = "unnamed" {
  true
}

# latest detection:
# - image ends with :latest
# - or has no tag (defaults to latest in many runtimes)
image_uses_latest(image) {
  endswith(image, ":latest")
}

image_uses_latest(image) {
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
