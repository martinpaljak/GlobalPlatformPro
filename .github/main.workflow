workflow "New workflow" {
  on = "check_run"
  resolves = ["docker"]
}

action "docker" {
  uses = "docker://ubuntu:18.04"
  runs = "uptime"
}
