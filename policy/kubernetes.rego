package kubernetes

#
# DENY if a container uses :latest or no tag
#

deny[msg] {
  input.kind != "CronJob"
  some i
  c := input.spec.template.spec.containers[i]
  endswith(c.image, ":latest")

  msg = sprintf("%s/%s: container '%s' uses :latest image (%s)", [
    input.kind,
    input.metadata.name,
    c.name,
    c.image
  ])
}

deny[msg] {
  input.kind != "CronJob"
  some i
  c := input.spec.template.spec.containers[i]
  not contains(c.image, ":")
  not contains(c.image, "@sha256:")

  msg = sprintf("%s/%s: container '%s' uses untagged image (%s)", [
    input.kind,
    input.metadata.name,
    c.name,
    c.image
  ])
}

#
# DENY if CPU or memory limits are missing
#

deny[msg] {
  input.kind != "CronJob"
  some i
  c := input.spec.template.spec.containers[i]
  not c.resources.limits.cpu

  msg = sprintf("%s/%s: container '%s' missing CPU limit", [
    input.kind,
    input.metadata.name,
    c.name
  ])
}

deny[msg] {
  input.kind != "CronJob"
  some i
  c := input.spec.template.spec.containers[i]
  not c.resources.limits.memory

  msg = sprintf("%s/%s: container '%s' missing memory limit", [
    input.kind,
    input.metadata.name,
    c.name
  ])
}

#
# DENY if container is privileged
#

deny[msg] {
  input.kind != "CronJob"
  some i
  c := input.spec.template.spec.containers[i]
  c.securityContext.privileged == true

  msg = sprintf("%s/%s: container '%s' is privileged", [
    input.kind,
    input.metadata.name,
    c.name
  ])
}

#
# CronJob variants
#

deny[msg] {
  input.kind == "CronJob"
  some i
  c := input.spec.jobTemplate.spec.template.spec.containers[i]
  endswith(c.image, ":latest")

  msg = sprintf("CronJob/%s: container '%s' uses :latest image (%s)", [
    input.metadata.name,
    c.name,
    c.image
  ])
}

deny[msg] {
  input.kind == "CronJob"
  some i
  c := input.spec.jobTemplate.spec.template.spec.containers[i]
  not c.resources.limits.cpu

  msg = sprintf("CronJob/%s: container '%s' missing CPU limit", [
    input.metadata.name,
    c.name
  ])
}

deny[msg] {
  input.kind == "CronJob"
  some i
  c := input.spec.jobTemplate.spec.template.spec.containers[i]
  c.securityContext.privileged == true

  msg = sprintf("CronJob/%s: container '%s' is privileged", [
    input.metadata.name,
    c.name
  ])
}
