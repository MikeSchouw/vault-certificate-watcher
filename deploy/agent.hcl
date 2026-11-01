pid_file = "/tmp/agent.pid"
disable_mlock = true
vault {
  address = "https://vault:8200"
  ca_cert = "/ca/root-ca.pem"
  tls_server_name = "vault.home"
}
auto_auth {
  method "token_file" {
    config = {
      token_file_path = "/seed/token"
    }
  }
  sink "file" {
    config = {
      path = "/sink/token"
      mode = 0600
    }
  }
}
