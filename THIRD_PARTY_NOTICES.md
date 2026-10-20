# Third-party routing components

The optional selected-service AWG router runs sing-box v1.14.3 built from the
pinned upstream commit 7054cac5124465ffdb145870d7c01885566711b1. The version suffix
`-awg-domain1` identifies our small FakeIP durability modification. The complete
modification is reproducibly applied by scripts/patch_sing_box_fakeip.py; build
commands and Go version are in Dockerfile. It keeps metadata on reads and saves
allocator progress before returning a new mapping, so an immediate process crash
does not lose or reuse client-visible FakeIP addresses. No routing protocol code
is changed.

sing-box runs as a separate process and is licensed under GNU GPL version 3 or
later. Its license is included in web-ui/data/sing-box-LICENSE and in the image
under /app/web-ui/data/. The corresponding source consists of the pinned upstream
source below together with the patch script and Dockerfile in this repository.

Corresponding upstream source and build definitions:
https://github.com/SagerNet/sing-box/tree/v1.14.3
Release and source archives:
https://github.com/SagerNet/sing-box/releases/tag/v1.14.3
Official image:
https://github.com/SagerNet/sing-box/pkgs/container/sing-box

The bundled service-domain lists are from v2fly/domain-list-community under
MIT. See web-ui/data/service_domains/LICENSE and SOURCES.md for the exact
revision, source URLs, official service-specific supplements and update policy.

Karing's published routing and DNS documentation informed the design. No
Karing application source code is incorporated.
