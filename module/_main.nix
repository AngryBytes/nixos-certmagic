{ config, lib, pkgs, modulesPath, ... }:
let

  cfg = config.security.acme;
  configJson = (pkgs.formats.json { }).generate "nixos-certmagic.json" cfg;

  # These options can be specified within
  # security.acme.defaults or security.acme.certs.<name>
  inheritableModule = isDefaults: { config, ... }:
    let
      defaultAndText = name: default: {
        # When ! isDefaults then this is the option declaration for the
        # security.acme.certs.<name> path, which has the extra inheritDefaults
        # option, which if disabled means that we can't inherit it
        default = if isDefaults || !config.inheritDefaults then default else cfg.defaults.${name};
        # The docs however don't need to depend on inheritDefaults, they should
        # stay constant. Though notably it wouldn't matter much, because to get
        # the option information, a submodule with name `<name>` is evaluated
        # without any definitions.
        defaultText = if isDefaults then default else lib.literalExpression "config.security.acme.defaults.${name}";
      };
    in
    {
      options = {
        group = lib.mkOption {
          type = lib.types.str;
          inherit (defaultAndText "group" "acme") default defaultText;
          description = "Group with read access to the certificate files.";
        };

        # Not supported. Present for compat with webserver modules.
        webroot = lib.mkOption {
          type = lib.types.enum [ "/var/empty" ];
          default = "/var/empty";
          internal = true;
        };

        # TODO: Not yet supported.
        dnsProvider = lib.mkOption {
          type = lib.types.enum [ null ];
          default = null;
          internal = true;
        };
      };
    };

  # TODO: We currently only support these options in `defaults`, not per cert.
  defaultsOpts.options = {
    server = lib.mkOption {
      type = lib.types.str;
      default = "https://acme-v02.api.letsencrypt.org/directory";
      description = ''
        ACME Directory Resource URI.
        Defaults to Let's Encrypt's production endpoint.
        For testing Let's Encrypt's [staging endpoint](https://letsencrypt.org/docs/staging-environment/)
        should be used to avoid the rather tight rate limit on the production endpoint.
      '';
    };

    email = lib.mkOption {
      type = with lib.types; nullOr str;
      description = ''
        Email address for account creation and correspondence from the CA.
        It is recommended to use the same email for all certs to avoid account
        creation limits.
      '';
    };

    credentialFiles = lib.mkOption {
      type = with lib.types; attrsOf path;
      default = { };
      description = ''
        Environment variables suffixed by "_FILE" to set for the service.
      '';
      example = lib.literalExpression ''
        {
          CERTMAGIC_MYSQL_DSN_FILE = "/run/secrets/certmagic-mysql-dsn";
        }
      '';
    };
  };

  certOpts = { name, ... }: {
    options = {
      directory = lib.mkOption {
        type = lib.types.str;
        readOnly = true;
        default = "/var/lib/acme/${name}";
        description = "Directory where certificate and other state is stored.";
      };

      domain = lib.mkOption {
        type = lib.types.str;
        default = name;
        description = "Domain to fetch certificate for (defaults to the entry name).";
      };

      inheritDefaults = lib.mkOption {
        default = true;
        example = true;
        description = "Whether to inherit values set in `security.acme.defaults` or not.";
        type = lib.types.bool;
      };

      # Not supported. Present for compat with webserver modules.
      extraDomainNames = lib.mkOption {
        type = lib.types.enum [ [ ] ];
        default = [ ];
        internal = true;
      };
    };
  };

in
{

  # Disable default ACME module.
  disabledModules = [ "${modulesPath}/security/acme" ];

  options = {
    security.acme = {
      package = lib.mkPackageOption pkgs "nixos-certmagic" { };

      preliminarySelfsigned = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Whether a preliminary self-signed certificate should be generated before
          doing ACME requests. This can be useful when certificates are required in
          a webserver, but ACME needs the webserver to make its requests.

          With preliminary self-signed certificate the webserver can be started and
          can later reload the correct ACME certificates.
        '';
      };

      acceptTerms = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Accept the CA's terms of service. The default provider is Let's Encrypt,
          you can find their ToS at <https://letsencrypt.org/repository/>.
        '';
      };

      defaults = lib.mkOption {
        type = lib.types.submodule [ (inheritableModule true) defaultsOpts ];
        description = ''
          Default values inheritable by all configured certs. You can
          use this to define options shared by all your certs. These defaults
          can also be ignored on a per-cert basis using the
          {option}`security.acme.certs.''${cert}.inheritDefaults` option.
        '';
      };

      certs = lib.mkOption {
        default = { };
        type = with lib.types; attrsOf (submodule [ (inheritableModule false) certOpts ]);
        description = ''
          Attribute set of certificates to get signed and renewed. Creates
          `acme-''${cert}.{service,timer}` systemd units for
          each certificate defined here. Other services can add dependencies
          to those units if they rely on the certificates being present,
          or trigger restarts of the service if certificates get renewed.
        '';
        example = lib.literalExpression ''
          {
            "example.com" = { };
            "bar.example.com" = { };
          }
        '';
      };
    };

    # Force nginx to use proxying for ACME challenge requests.
    services.nginx.virtualHosts = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        config = {
          # TODO: Upstream inherits root if we set this to `null`, which is
          # probably dangerous, because `try_files` remains.
          acmeRoot = "/var/empty";
          acmeFallbackHost = "unix:/run/acme-manager.socket";
        };
      });
    };
  };

  config = lib.mkMerge [
    (lib.mkIf (cfg.certs != { }) {
      assertions = [
        {
          assertion = cfg.acceptTerms;
          message = ''
            You must accept the CA's terms of service before using
            the ACME module by setting `security.acme.acceptTerms`
            to `true`. For Let's Encrypt's ToS see https://letsencrypt.org/repository/
          '';
        }
        {
          assertion = lib.all
            (lib.hasSuffix "_FILE")
            (lib.attrNames cfg.defaults.credentialFiles);
          message = ''
            Option `security.acme.defaults.credentialFiles` can only be
            used for variables suffixed by "_FILE".
          '';
        }
      ];

      users.users.acme = {
        home = "/var/lib/acme";
        group = "acme";
        isSystemUser = true;
        # Add groups other than 'acme' to extraGroups, so it can chown.
        extraGroups = lib.filter (group: group != "acme")
          (lib.unique (map (cert: cert.group) (lib.attrValues cfg.certs)));
      };

      users.groups.acme = { };

      systemd.sockets.acme-manager = {
        socketConfig = {
          ListenStream = "/run/acme-manager.socket";
          SocketUser = "acme";
          SocketMode = "0666";
        };
      };
      systemd.services.acme-manager = {
        description = "ACME certificate manager";
        requires = [ "acme-manager.socket" ];
        wants = [ "network-online.target" ];
        after = [ "network-online.target" "acme-manager.socket" ];
        serviceConfig = {
          Type = "notify";
          ExecStart = "${lib.getBin cfg.package}/bin/nixos-certmagic ${configJson}";
          User = "acme";
          Group = "acme";
          UMask = "0022";
          StateDirectory = "acme";
          ReadWritePaths = [ "/var/lib/acme" ];
          WorkingDirectory = "/var/lib/acme";

          Environment = lib.mapAttrsToList
            (k: v: ''"${k}=%d/${k}"'')
            cfg.defaults.credentialFiles;
          LoadCredential = lib.mapAttrsToList
            (k: v: "${k}:${v}")
            cfg.defaults.credentialFiles;

          CapabilityBoundingSet = [ "" ];
          DevicePolicy = "closed";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateTmp = true;
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectControlGroups = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          ProcSubset = "pid";
          RemoveIPC = true;
          RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [
            # 1. allow a reasonable set of syscalls
            "@system-service @resources"
            # 2. and deny unreasonable ones
            "~@privileged"
            # 3. then allow the required subset within denied groups
            "@chown"
          ];
        };
      };
    })

    (
      let
        nginxCfg = config.services.nginx;
        acmeVhosts = lib.filterAttrs
          (name: value: value.enableACME)
          nginxCfg.virtualHosts;
      in
      lib.mkIf (nginxCfg.enable && acmeVhosts != { }) {
        # Delay nginx until selfsigned certificates are available.
        systemd.services.nginx = {
          requires = [ "acme-manager.service" ];
          after = [ "acme-manager.service" ];
        };
        # Reload nginx if any of its certificates changes.
        systemd.paths.nginx-config-reload = {
          wantedBy = [ "paths.target" ];
          pathConfig.PathModified = map
            (name: cfg.certs.${name}.directory)
            (lib.attrNames acmeVhosts);
        };
        # We specifically require `proxy_set_header Host $host` for `acmeFallbackHost`,
        # because certmagic matches challenges based on hostname.
        # TODO: Maybe upstream this nginx setting for the challenge location only.
        services.nginx.recommendedProxySettings = true;
      }
    )
  ];

  meta = {
    doc = ./default.md;
  };
}
