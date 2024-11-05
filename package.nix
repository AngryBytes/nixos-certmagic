{ buildGoModule }:

buildGoModule {
  name = "nixos-certmagic";
  src = ./src;
  vendorHash = "sha256-XcsGj3NazC3iykjvOBYmwRAJDOWLeJKZkNT/yKfgcbI=";
}
