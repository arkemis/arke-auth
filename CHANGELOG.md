# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.4] - 2026-04-14

### Added
- Add git cliff by @ilyichv

### Changed
- Update elixir version by @ilyichv
- Update arke to v0.6.0 by @ilyichv

## [0.4.3] - 2025-08-04

### Changed
- Otp expiration in config by @ErikFerrari in [#27](https://github.com/arkemis/arke-auth/pull/27)

## [0.4.2] - 2025-07-01

### Added
- Add configurable ttl for reset password token by @vittorio-reinaudo in [#25](https://github.com/arkemis/arke-auth/pull/25)

### Changed
- Align mix.exs by @vittorio-reinaudo

## [0.4.0] - 2025-06-03

### Changed
- Min arke version by @ErikFerrari

### Fixed
- Gh action by @ErikFerrari in [#24](https://github.com/arkemis/arke-auth/pull/24)

## [0.3.5] - 2025-02-14

### Added
- Added get_member function and permission check for impersonate by @Robbi-aka-Rob in [#22](https://github.com/arkemis/arke-auth/pull/22)
- Add microsoft_oauth to registry by @ilyichv in [#21](https://github.com/arkemis/arke-auth/pull/21)

### Fixed
- Guardian import by @ErikFerrari
- Arke min deps by @ErikFerrari

### New Contributors
* @Robbi-aka-Rob made their first contribution in [#22](https://github.com/arkemis/arke-auth/pull/22)

## [0.3.4] - 2024-09-17

### Fixed
- Manage member and member_id by @vittorio-reinaudo in [#20](https://github.com/arkemis/arke-auth/pull/20)

## [0.3.2] - 2024-06-26

### Changed
- Align dev by @ErikFerrari in [#18](https://github.com/arkemis/arke-auth/pull/18)

## [0.3.1] - 2024-06-21

### Changed
- Lowercase parameter in registry by @ErikFerrari in [#17](https://github.com/arkemis/arke-auth/pull/17)

### Fixed
- Enable_sso group in registry by @ErikFerrari
- Member_pulic in arke_auth_member_group by @ErikFerrari

## [0.3.0] - 2024-04-23

### Changed
- Set version to v0.3.0 by @ErikFerrari
- Registry file by @ErikFerrari in [#12](https://github.com/arkemis/arke-auth/pull/12)

### New Contributors
* @manolo-battista made their first contribution

## [0.1.16] - 2024-03-06

### Changed
- Set mix_version by @ErikFerrari
- Inactive user ignored by @ErikFerrari in [#14](https://github.com/arkemis/arke-auth/pull/14)
- Handled child_only_permission by @dorianmercatante in [#13](https://github.com/arkemis/arke-auth/pull/13)

## [0.1.14] - 2023-12-22

### Changed
- Improved opt management by @dorianmercatante

## [0.1.12] - 2023-12-14

### Changed
- Return all member detail on signin by @dorianmercatante

## [0.1.11] - 2023-12-14

### Changed
- Limited information data in access token by @dorianmercatante

## [0.1.10] - 2023-11-15

### Changed
- Handled otp auth method by @dorianmercatante

## [0.1.9] - 2023-10-26

### Fixed
- User arke now use before_struct_encode function by @dorianmercatante

## [0.1.8] - 2023-10-05

### Changed
- Updated library version by @dorianmercatante

## [0.1.7] - 2023-09-26

### Changed
- Handled permission for system arke by @dorianmercatante

## [0.1.6] - 2023-08-30

### Changed
- Permission handler by @dorianmercatante

### New Contributors
* @dorianmercatante made their first contribution

## [0.1.5] - 2023-08-30

### Changed
- Set version to v0.1.5 by @ErikFerrari

### Fixed
- User arke now has email by @ErikFerrari in [#8](https://github.com/arkemis/arke-auth/pull/8)

## [0.1.4] - 2023-05-31

### Changed
- Set version to 0.1.4 by @ilyichv

### Removed
- Remove configuration in favor of metadata by @ilyichv in [#3](https://github.com/arkemis/arke-auth/pull/3)
- Remove password_hash during enconding by @ilyichv in [#5](https://github.com/arkemis/arke-auth/pull/5)

## [0.1.3] - 2023-05-19

### Changed
- Set version to 0.1.3 by @ilyichv

## [0.1.2] - 2023-05-19

### Changed
- Set version to 0.1.2 by @ilyichv
- Run release only on version tag by @ErikFerrari

### Fixed
- Github link by @ErikFerrari

### New Contributors
* @ilyichv made their first contribution
* @ErikFerrari made their first contribution in [#2](https://github.com/arkemis/arke-auth/pull/2)

[0.4.4]: https://github.com/arkemis/arke-auth/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/arkemis/arke-auth/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/arkemis/arke-auth/compare/v0.4.0...v0.4.2
[0.4.0]: https://github.com/arkemis/arke-auth/compare/v0.3.5...v0.4.0
[0.3.5]: https://github.com/arkemis/arke-auth/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/arkemis/arke-auth/compare/v0.3.3...v0.3.4
[0.3.2]: https://github.com/arkemis/arke-auth/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/arkemis/arke-auth/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/arkemis/arke-auth/compare/v0.1.16...v0.3.0
[0.1.16]: https://github.com/arkemis/arke-auth/compare/v0.1.14...v0.1.16
[0.1.14]: https://github.com/arkemis/arke-auth/compare/v0.1.13...v0.1.14
[0.1.12]: https://github.com/arkemis/arke-auth/compare/v0.1.11...v0.1.12
[0.1.11]: https://github.com/arkemis/arke-auth/compare/v0.1.10...v0.1.11
[0.1.10]: https://github.com/arkemis/arke-auth/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/arkemis/arke-auth/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/arkemis/arke-auth/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/arkemis/arke-auth/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/arkemis/arke-auth/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/arkemis/arke-auth/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/arkemis/arke-auth/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/arkemis/arke-auth/compare/v0.1.2...v0.1.3

<!-- generated by git-cliff -->
