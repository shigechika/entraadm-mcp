# Changelog

## [1.8.1](https://github.com/shigechika/entraadm-mcp/compare/v1.8.0...v1.8.1) (2026-10-26)


### Bug Fixes

* **deps:** bump certifi and opentelemetry-api (security) ([#33](https://github.com/shigechika/entraadm-mcp/issues/33)) ([07f8176](https://github.com/shigechika/entraadm-mcp/commit/07f8176841ba68f4b8ad8d5c99d568c1b960491f))

## [1.8.0](https://github.com/shigechika/entraadm-mcp/compare/v1.7.0...v1.8.0) (2026-10-24)


### Features

* report Identity Protection licensing and use Microsoft risky users when licensed ([#31](https://github.com/shigechika/entraadm-mcp/issues/31)) ([6965cf1](https://github.com/shigechika/entraadm-mcp/commit/6965cf109bd18205c9c334b2e9860bb95ebd4181))

## [1.7.0](https://github.com/shigechika/entraadm-mcp/compare/v1.6.0...v1.7.0) (2026-10-24)


### Features

* add compromise_suspects, accounts that were probably taken over ([#27](https://github.com/shigechika/entraadm-mcp/issues/27)) ([273f30f](https://github.com/shigechika/entraadm-mcp/commit/273f30f902d4209121fae6b783730d2bc6294370))

## [1.6.0](https://github.com/shigechika/entraadm-mcp/compare/v1.5.0...v1.6.0) (2026-10-24)


### Features

* serve several Entra tenants from one process ([#25](https://github.com/shigechika/entraadm-mcp/issues/25)) ([5bcd8ba](https://github.com/shigechika/entraadm-mcp/commit/5bcd8baf7ac838d2382504015b21f20196a74ab8))

## [1.5.0](https://github.com/shigechika/entraadm-mcp/compare/v1.4.0...v1.5.0) (2026-10-24)


### Features

* add opt-in revoke_sign_in_sessions tool ([#23](https://github.com/shigechika/entraadm-mcp/issues/23)) ([7deb029](https://github.com/shigechika/entraadm-mcp/commit/7deb0298535de883dc3d4c7d7297c5b3ab396683))

## [1.4.0](https://github.com/shigechika/entraadm-mcp/compare/v1.3.0...v1.4.0) (2026-10-22)


### Features

* vm_activity — who or what restarted an Azure VM ([#21](https://github.com/shigechika/entraadm-mcp/issues/21)) ([2356a64](https://github.com/shigechika/entraadm-mcp/commit/2356a64a800874305575d4dea70b6e79e54e6c60))

## [1.3.0](https://github.com/shigechika/entraadm-mcp/compare/v1.2.0...v1.3.0) (2026-10-15)


### Features

* Azure VM backup posture and Microsoft 365 service health tools ([#18](https://github.com/shigechika/entraadm-mcp/issues/18)) ([3f0c122](https://github.com/shigechika/entraadm-mcp/commit/3f0c1227965187043646fc2b2fddbe96cc77fb68))

## [1.2.0](https://github.com/shigechika/entraadm-mcp/compare/v1.1.0...v1.2.0) (2026-10-14)


### Features

* separate the tenant's own address ranges from spray suspects (ENTRAADM_SITES_INI) ([#15](https://github.com/shigechika/entraadm-mcp/issues/15)) ([600973e](https://github.com/shigechika/entraadm-mcp/commit/600973e02df95b98dbd1ce56bfbba546ed11c77d))

## [1.1.0](https://github.com/shigechika/entraadm-mcp/compare/v1.0.1...v1.1.0) (2026-10-02)


### Features

* add signin_success_stats and signin_by_ip (successes by source IP, one IP's history) ([#10](https://github.com/shigechika/entraadm-mcp/issues/10)) ([ea7a1f2](https://github.com/shigechika/entraadm-mcp/commit/ea7a1f2e04ebb022565e66b21daa02d91b57d7a8))

## [1.0.1](https://github.com/shigechika/entraadm-mcp/compare/v1.0.0...v1.0.1) (2026-09-29)


### Bug Fixes

* report a tool exception message to the model on mcp 2.x ([#8](https://github.com/shigechika/entraadm-mcp/issues/8)) ([9eeeedd](https://github.com/shigechika/entraadm-mcp/commit/9eeeedd4554370226290ce07c03e03c9a316d198))

## [1.0.0](https://github.com/shigechika/entraadm-mcp/compare/v0.2.0...v1.0.0) (2026-09-29)


### ⚠ BREAKING CHANGES

* require mcp 2.x (MCPServer) and drop 1.x support ([#6](https://github.com/shigechika/entraadm-mcp/issues/6))

### Features

* require mcp 2.x (MCPServer) and drop 1.x support ([#6](https://github.com/shigechika/entraadm-mcp/issues/6)) ([b8bf5a9](https://github.com/shigechika/entraadm-mcp/commit/b8bf5a9d3a29635670e4ea302dbe9c63668db4dd))

## [0.2.0](https://github.com/shigechika/entraadm-mcp/compare/v0.1.0...v0.2.0) (2026-09-29)


### Features

* bound tool calls with a wall-clock deadline and add a category filter ([#4](https://github.com/shigechika/entraadm-mcp/issues/4)) ([b8c8b40](https://github.com/shigechika/entraadm-mcp/commit/b8c8b40f03d7aade7af443d08c16db0c84100363))

## 0.1.0 (2026-08-24)


### Features

* initial entraadm-mcp scaffold ([#1](https://github.com/shigechika/entraadm-mcp/issues/1)) ([a7cc26a](https://github.com/shigechika/entraadm-mcp/commit/a7cc26a98e4bec515fa02b4931f464e7c0aa767f))
