data_dir = "/tmp/nomad-execute"
bind_addr = "0.0.0.0"
datacenter = "dc1"
server {
  enabled = true
  bootstrap_expect = 1
}
client {
  enabled = true
  cpu_total_compute = 1000
  memory_total_mb = 256
  options = {
    "driver.allowlist" = "raw_exec"
  }
}
plugin "raw_exec" {
  config {
    enabled = true
  }
}
