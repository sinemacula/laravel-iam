# Changelog

## 1.0.0 (2026-11-14)


### Features

* act as a caller across the suite in one call, and write the guides ([#18](https://github.com/sinemacula/laravel-iam/issues/18)) ([4cd8b01](https://github.com/sinemacula/laravel-iam/commit/4cd8b01a5530b7d8a0d0ea1f676096f428c10a1f))
* add the foundation: binding rule, storage connection, retries and worker reset ([#5](https://github.com/sinemacula/laravel-iam/issues/5)) ([03eb15f](https://github.com/sinemacula/laravel-iam/commit/03eb15f483924207f2f76af75f5b63b3be43db9f))
* answer the tenant authentication policy and SSO's evidence, freshness and link judgements ([#14](https://github.com/sinemacula/laravel-iam/issues/14)) ([dca83d1](https://github.com/sinemacula/laravel-iam/commit/dca83d16cf69255e81d96d7b2779dc534a3ce0da))
* audit laravel-authorization's role exclusion changes ([#69](https://github.com/sinemacula/laravel-iam/issues/69)) ([20eff91](https://github.com/sinemacula/laravel-iam/commit/20eff91143834d4e1f6f0d252f8822a389571c0f))
* **audit:** record allowed checks of sensitive actions ([#79](https://github.com/sinemacula/laravel-iam/issues/79)) ([b651bc4](https://github.com/sinemacula/laravel-iam/commit/b651bc4cdd1224f02ce3fc86708a3ba34d1d0748))
* bind laravel-mfa's session seams to laravel-authentication ([#7](https://github.com/sinemacula/laravel-iam/issues/7)) ([6634957](https://github.com/sinemacula/laravel-iam/commit/6634957c6b6b7c806833237aede4b6bdddedc489))
* close the member gaps laravel-mfa and laravel-authentication answered ([#12](https://github.com/sinemacula/laravel-iam/issues/12)) ([4f2928b](https://github.com/sinemacula/laravel-iam/commit/4f2928b0f7fd126f24f78c32370a18137770ee14))
* contribute the mfa context, confirm SSO links from proofs, and share proof translation ([#19](https://github.com/sinemacula/laravel-iam/issues/19)) ([18ef216](https://github.com/sinemacula/laravel-iam/commit/18ef216c460770d016e62b4ba19ab4eda382dd43))
* decide authorization for the suite's caller, its proofs and its scopes ([#20](https://github.com/sinemacula/laravel-iam/issues/20)) ([616e01e](https://github.com/sinemacula/laravel-iam/commit/616e01eb2f1530c8e69cd887d4fa39ba20890f16))
* declare iam:check to laravel-authorization as composing its check ([#39](https://github.com/sinemacula/laravel-iam/issues/39)) ([4513d8c](https://github.com/sinemacula/laravel-iam/commit/4513d8c9672197ef5e2029c92f5358d6c7e8e6fa))
* declare the adapters bound over laravel-authorization's contracts to authorization:check ([#38](https://github.com/sinemacula/laravel-iam/issues/38)) ([7161714](https://github.com/sinemacula/laravel-iam/commit/716171444cacc11dfe38019e0f80adba7d41ca8c))
* declare the suite's assurance keys to authorization and drop the binding workarounds ([#22](https://github.com/sinemacula/laravel-iam/issues/22)) ([c2f0d54](https://github.com/sinemacula/laravel-iam/commit/c2f0d547c988354cdee19d7638f7c5f348a1d842))
* deliver codes through shared gateways and bind MFA's challenges, passkeys and resolvers ([#10](https://github.com/sinemacula/laravel-iam/issues/10)) ([04a3751](https://github.com/sinemacula/laravel-iam/commit/04a3751e2f6b2a883f4f21dcdea45a423f321a72))
* grant, scope, tree, group mapping, catalogue, audit access and invalidation for authorization ([#29](https://github.com/sinemacula/laravel-iam/issues/29)) ([f42cefb](https://github.com/sinemacula/laravel-iam/commit/f42cefb98b57ca26ec4b8c614e8f59f67883db07))
* hand SSO the caller and drop the caller scope ([#23](https://github.com/sinemacula/laravel-iam/issues/23)) ([6f85c7d](https://github.com/sinemacula/laravel-iam/commit/6f85c7dbeee99bc3548d78a2b72dc775d12a5cef))
* hand the proof store the identity and the sign-in it reads ([#21](https://github.com/sinemacula/laravel-iam/issues/21)) ([cf566c2](https://github.com/sinemacula/laravel-iam/commit/cf566c2cabbe874ed22413e9c3598857dcf39b19))
* install the suite, check it across members, and schedule its work ([#17](https://github.com/sinemacula/laravel-iam/issues/17)) ([77a086f](https://github.com/sinemacula/laravel-iam/commit/77a086ff5bc088213d86a21d76a897f03fe29f7f))
* provision people from SSO, and answer memberships, principal scope and the tenant tree ([#15](https://github.com/sinemacula/laravel-iam/issues/15)) ([5f888e9](https://github.com/sinemacula/laravel-iam/commit/5f888e939cfa41ff321c8770376cd707713de5e1))
* recognise authorization's defaults through isPackageDefault and leave configured classes to it ([#28](https://github.com/sinemacula/laravel-iam/issues/28)) ([e4fd1d4](https://github.com/sinemacula/laravel-iam/commit/e4fd1d49dd7260ed4fc78066c247ca85a55db247))
* record the audit trail of laravel-authentication, laravel-mfa and laravel-sso ([#16](https://github.com/sinemacula/laravel-iam/issues/16)) ([b597d0a](https://github.com/sinemacula/laravel-iam/commit/b597d0a77fd4854c64206e55feac0f23e95a5a59))
* redeem SSO's handoffs through laravel-authentication, and bind its links and session revocation ([#13](https://github.com/sinemacula/laravel-iam/issues/13)) ([103c021](https://github.com/sinemacula/laravel-iam/commit/103c021154f8a30ee08e084dc35543825d5a541f))
* report the suite's authentication findings in authentication:check ([#33](https://github.com/sinemacula/laravel-iam/issues/33)) ([b547a4c](https://github.com/sinemacula/laravel-iam/commit/b547a4c3e3bc76966e4e9c06b4b07566469db551))
* start sessions with a first factor and confirm links from recovery sessions ([#24](https://github.com/sinemacula/laravel-iam/issues/24)) ([12bc666](https://github.com/sinemacula/laravel-iam/commit/12bc666f356ea2174772762bf214ceb104c14329))
* **testing:** record actingAsVerified() sign-ins through laravel-authentication ([#34](https://github.com/sinemacula/laravel-iam/issues/34)) ([b4818b7](https://github.com/sinemacula/laravel-iam/commit/b4818b70a7ff64bdb463e726a76c075503d32a90))


### Bug Fixes

* adopt what audit-log, authorization and authentication have merged and drop the stop-gaps ([#36](https://github.com/sinemacula/laravel-iam/issues/36)) ([bc2a69b](https://github.com/sinemacula/laravel-iam/commit/bc2a69bf8606e207ab327a8800e4ae026a379fc2))
* clear the qlty findings and drop configuration the shared source provides ([#32](https://github.com/sinemacula/laravel-iam/issues/32)) ([999d543](https://github.com/sinemacula/laravel-iam/commit/999d543d1e9f7b0b3c377a794df97a851df0d709))
* forget every decision the request remembers through laravel-authorization when its proofs change ([#41](https://github.com/sinemacula/laravel-iam/issues/41)) ([e74bff8](https://github.com/sinemacula/laravel-iam/commit/e74bff8b7713b07a5dc6dd4945c7ed71744d616b))
* **install:** prefix authorization's tables by the names it ships ([#31](https://github.com/sinemacula/laravel-iam/issues/31)) ([f2e4599](https://github.com/sinemacula/laravel-iam/commit/f2e4599268e12378c4cb76d648b78dfd586d85f6))
* read freshness current and record MFA's own multifactor evidence ([#8](https://github.com/sinemacula/laravel-iam/issues/8)) ([f8df382](https://github.com/sinemacula/laravel-iam/commit/f8df382f526ace9eb3de5a6f053d1eb9aefb16fb))
