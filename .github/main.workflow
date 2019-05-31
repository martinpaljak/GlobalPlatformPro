workflow "New workflow" {
  on = "check_run"
  resolves = ["docker"]
}

action "docker" {
  uses = "docker"
  runs = "ubuntu:18.04"
  args = "uptime"
}
