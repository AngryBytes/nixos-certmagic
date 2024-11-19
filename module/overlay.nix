# This is a separate module so that we can disable it for tests.
{
  nixpkgs.overlays = [
    (import ../overlay.nix)
  ];
}
