# nixos-certmagic

**Status: EXPERIMENTAL**

A NixOS module that replaces ACME certificate management with an implementation
based on [certmagic].

[certmagic]: https://github.com/caddyserver/certmagic

Pros:

- Faster NixOS activation when dealing with lots of certificates.
- Webserver clustering support, by using custom storage.

Cons:

- Doesn't support all NixOS `security.acme` options. (Some simply TODO.)
- Maintained out-of-tree.
- Currently supports only Nginx. (TODO: Apache HTTPd, maybe even Caddy.)
- No individual systemd units to create dependencies on.

## Usage

NOTE: Certmagic cannot migrate the state directory of the standard NixOS
module. Swapping this in on an existing server will create a new Let's Encrypt
account and request new certificates. It is, however, safe to switch back and
forth between implementations.

Import `<nixos-certmagic/module>` into your NixOS configuration. Our
preference is to use Nix flakes, which looks like this:

```nix
{
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
        nixos-certmagic = {
            url = "github:AngryBytes/nixos-certmagic";
            inputs.nixpkgs.follows = "nixpkgs";
        };
    };
    outputs = { self, nixpkgs, nixos-certmagic }: {
        # Example configuration for a host.
        nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
            system = "x86_64-linux";
            modules = [
                # Import the nixos-certmagic module.
                nixos-certmagic.nixosModules.default
                # This is your own configuration.
                ./configuration.nix
            ];
        };
    };
}
```

## Custom storage

When using custom storage, multiple hosts can coordinate certificate requests
using a simple locking mechanism, and share the resulting keys and
certificates. This allows you to create a simple cluster of webservers with
DNS round-robin, for example.

Currently, there is only one custom storage option: MySQL

```nix
{
    # For the format of the Data Source Name (DSN), see:
    # https://github.com/go-sql-driver/mysql?tab=readme-ov-file#dsn-data-source-name
    # The DSN is treated like a secret, because it often contains a password.
    # The file can simple be owned by `root` with `0600` permissions.
    #
    # Tables are automatically created. Just make sure the database and user exist.
    security.acme.defaults.credentialFiles = {
        CERTMAGIC_MYSQL_DSN_FILE = "/run/secrets/certmagic-mysql-dsn";
    };
}
```
