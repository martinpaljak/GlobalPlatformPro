workflow "Default workflow for pushes" {
  on = "push"
  resolves = "release"
}

action "mvn" {
  uses = "docker://maven:3.6.1-jdk-8"
  # uses = "docker://martinpaljak/gppro-build"
  runs = "mvn"
  args = "-U -B verify"
}


action "on-tag" {
  # Filter for tag
  needs = "mvn"
  uses = "actions/bin/filter@master"
  args = "tag"
}


action "release" {
  needs = "on-tag"
  uses = "martinpaljak/actions/deploy-release@master"
  args = "tool/target/gp.jar tool/target/gp.exe"
  secrets = ["GITHUB_TOKEN"]
}
