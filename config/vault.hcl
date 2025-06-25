storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1  # Change to "0" and set certs for production security
}

disable_mlock = true
disable_sealwrap = true

ui = true
