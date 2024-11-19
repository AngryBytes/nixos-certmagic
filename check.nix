{ config, lib, ... }:
let

  pkgs = config.node.pkgs;

  commonConfig = "${pkgs.path}/nixos/tests/common/acme/client";

  dnsServerIP = nodes: nodes.dnsserver.networking.primaryIPAddress;

in
{
  name = "acme";
  meta = {
    # Hard timeout in seconds. Average run time is about 30 seconds.
    timeout = 300;
  };

  nodes = {
    # The fake ACME server which will respond to client requests
    acme = { nodes, ... }: {
      imports = [ "${pkgs.path}/nixos/tests/common/acme/server" ];
      networking.nameservers = lib.mkForce [ (dnsServerIP nodes) ];
    };

    # A fake DNS server which can be configured with records as desired
    # Used to test DNS-01 challenge
    dnsserver = { nodes, ... }: {
      networking.firewall.allowedTCPPorts = [ 8055 53 ];
      networking.firewall.allowedUDPPorts = [ 53 ];
      systemd.services.pebble-challtestsrv = {
        enable = true;
        description = "Pebble ACME challenge test server";
        wantedBy = [ "network.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.pebble}/bin/pebble-challtestsrv -dns01 ':53' -defaultIPv6 '' -defaultIPv4 '${nodes.webserver.networking.primaryIPAddress}'";
          # Required to bind on privileged ports.
          AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        };
      };
    };

    # A web server which will be the node requesting certs
    webserver = { nodes, config, ... }: {
      imports = [ ./module/withoutOverlay.nix commonConfig ];
      networking.nameservers = lib.mkForce [ (dnsServerIP nodes) ];
      networking.firewall.allowedTCPPorts = [ 80 443 ];

      # OpenSSL will be used for more thorough certificate validation
      environment.systemPackages = [ pkgs.openssl ];

      services.nginx = {
        enable = true;
        # Set log level to info so that we can see when the service is reloaded
        logError = "stderr info";
        virtualHosts."a.example.test" = {
          enableACME = true;
          forceSSL = true;
          locations."/".root = pkgs.runCommand "docroot" { } ''
            mkdir -p "$out"
            echo hello world > "$out/index.html"
          '';
        };
      };
      # Manually start nginx and acme-manager.
      systemd.services.nginx.wantedBy = lib.mkForce [ ];

      # Test MySQL storage.
      security.acme.defaults.credentialFiles = {
        CERTMAGIC_MYSQL_DSN_FILE = pkgs.writeText "certmagic-mysql-dsn" "acme@unix(/run/mysqld/mysqld.sock)/acme";
      };
      services.mysql = {
        enable = true;
        package = pkgs.mariadb;
        ensureDatabases = [ "acme" ];
        ensureUsers = [
          {
            name = "acme";
            ensurePermissions."acme.*" = "ALL PRIVILEGES";
          }
        ];
      };
    };

    # The client will be used to curl the webserver to validate configuration
    client = { nodes, ... }: {
      imports = [ commonConfig ];
      networking.nameservers = lib.mkForce [ (dnsServerIP nodes) ];

      # OpenSSL will be used for more thorough certificate validation
      environment.systemPackages = [ pkgs.openssl ];
    };
  };

  testScript = { nodes, ... }:
    let
      caDomain = nodes.acme.test-support.acme.caDomain;
    in
    ''
      import time


      TOTAL_RETRIES = 20


      class BackoffTracker(object):
          delay = 1
          increment = 1

          def handle_fail(self, retries, message) -> int:
              assert retries < TOTAL_RETRIES, message

              print(f"Retrying in {self.delay}s, {retries + 1}/{TOTAL_RETRIES}")
              time.sleep(self.delay)

              # Only increment after the first try
              if retries == 0:
                  self.delay += self.increment
                  self.increment *= 2

              return retries + 1


      backoff = BackoffTracker()


      # Ensures the issuer of our cert matches the chain
      # and matches the issuer we expect it to be.
      # It's a good validation to ensure the cert.pem and fullchain.pem
      # are not still selfsigned after verification
      def check_issuer(node, cert_name, issuer):
          for fname in ("cert.pem", "fullchain.pem"):
              actual_issuer = node.succeed(
                  f"openssl x509 -noout -issuer -in /var/lib/acme/{cert_name}/{fname}"
              ).partition("=")[2]
              print(f"{fname} issuer: {actual_issuer}")
              assert issuer.lower() in actual_issuer.lower()


      # Ensure cert comes before chain in fullchain.pem
      def check_fullchain(node, cert_name):
          subject_data = node.succeed(
              f"openssl crl2pkcs7 -nocrl -certfile /var/lib/acme/{cert_name}/fullchain.pem"
              " | openssl pkcs7 -print_certs -noout"
          )
          for line in subject_data.lower().split("\n"):
              if "subject" in line:
                  print(f"First subject in fullchain.pem: {line}")
                  assert cert_name.lower() in line
                  return

          assert False


      def check_connection(node, domain, retries=0):
          result = node.succeed(
              "openssl s_client -brief -verify 2 -CAfile /tmp/ca.crt"
              f" -servername {domain} -connect {domain}:443 < /dev/null 2>&1"
          )

          for line in result.lower().split("\n"):
              if "verification" in line and "error" in line:
                  retries = backoff.handle_fail(retries, f"Failed to connect to https://{domain}")
                  return check_connection(node, domain, retries)


      def download_ca_certs(node, retries=0):
          exit_code, _ = node.execute("curl https://${caDomain}:15000/roots/0 > /tmp/ca.crt")
          exit_code_2, _ = node.execute(
              "curl https://${caDomain}:15000/intermediate-keys/0 >> /tmp/ca.crt"
          )

          if exit_code + exit_code_2 > 0:
              retries = backoff.handle_fail(retries, "Failed to connect to pebble to download root CA certs")
              return download_ca_certs(node, retries)


      start_all()

      dnsserver.wait_for_unit("pebble-challtestsrv.service")
      client.wait_for_unit("default.target")

      client.succeed(
          'curl --data \'{"host": "${caDomain}", "addresses": ["${nodes.acme.networking.primaryIPAddress}"]}\' http://${dnsServerIP nodes}:8055/add-a'
      )

      acme.systemctl("start network-online.target")
      acme.wait_for_unit("network-online.target")
      acme.wait_for_unit("pebble.service")

      download_ca_certs(client)

      # NOTE: Simple service dependency may race here. Wait for the actual socket.
      webserver.wait_for_file("/run/mysqld/mysqld.sock")

      with subtest("Can generate valid selfsigned certs"):
          # Without nginx, challenges fail, so we only have selfsigned certs
          webserver.systemctl("start acme-manager.service")
          webserver.wait_for_unit("acme-manager.service")
          check_fullchain(webserver, "a.example.test")
          check_issuer(webserver, "a.example.test", "a.example.test")
          # Stopping acme here means it restarts with nginx,
          # allowing us to time the next attempt
          webserver.systemctl("stop acme-manager.service")

      with subtest("Certificates and accounts have safe + valid permissions"):
          # Nginx will set the group appropriately when enableACME is used
          webserver.succeed(
              "test $(stat -L -c '%a %U %G' /var/lib/acme/a.example.test/*.pem | tee /dev/stderr | grep '640 acme nginx' | wc -l) -eq 4"
          )
          webserver.succeed(
              "test $(stat -L -c '%a %U %G' /var/lib/acme/a.example.test | tee /dev/stderr | grep '750 acme nginx' | wc -l) -eq 1"
          )

      with subtest("Can request certificate with HTTP-01 challenge"):
          # Remove the selfsigned cert and wait for real ones to appear.
          # (This specific file is unused by nginx, so it can still start.)
          webserver.succeed("rm /var/lib/acme/a.example.test/cert.pem")
          webserver.systemctl("start nginx.service")
          webserver.wait_for_file("/var/lib/acme/a.example.test/cert.pem")
          check_fullchain(webserver, "a.example.test")
          check_issuer(webserver, "a.example.test", "pebble")
          check_connection(client, "a.example.test")

      with subtest("Correctly reloads certificates from MySQL"):
          webserver.systemctl("stop nginx.service acme-manager.service")
          webserver.succeed("rm /var/lib/acme/a.example.test/*.pem")
          webserver.systemctl("start acme-manager.service")
          webserver.succeed("rm /var/lib/acme/a.example.test/cert.pem")
          webserver.systemctl("start nginx.service")
          webserver.wait_for_file("/var/lib/acme/a.example.test/cert.pem")
          check_fullchain(webserver, "a.example.test")
    '';
}
