# Changelog

## [0.1.8](https://github.com/c0dewhacker/dlpduck/compare/v0.1.7...v0.1.8) (2026-09-12)


### Features

* **chart:** support more than one replica ([e3b6154](https://github.com/c0dewhacker/dlpduck/commit/e3b6154a5bb56ba0085b00d04929c899d14c07e2))
* HA leader election, parallel extraction, and drop SQLite ([24d1a2b](https://github.com/c0dewhacker/dlpduck/commit/24d1a2b9de3422aed9ac528e2375e681d2f85782))
* HA leader election, parallel extraction, and drop SQLite ([5d1a038](https://github.com/c0dewhacker/dlpduck/commit/5d1a0383d133b087af99d34ebe6f8e462161ff48))
* Kubernetes Lease-based leader election for the watch loop ([06ceb48](https://github.com/c0dewhacker/dlpduck/commit/06ceb48bc85892bd068f47b417b9200b4486507a))
* send the full job outcome to syslog and webhook ([f48d8ea](https://github.com/c0dewhacker/dlpduck/commit/f48d8ea6d5017316e8e6a29f19c905612872dfd0))
* send the full job outcome to syslog and webhook, not a subset ([8f813b7](https://github.com/c0dewhacker/dlpduck/commit/8f813b73387269bb82de8404fa43fa21704fb105))
* split claim from extraction so it can be spread across replicas ([15d534d](https://github.com/c0dewhacker/dlpduck/commit/15d534de27dea650f00dfd8fc4577c022092fc1f))


### Bug Fixes

* bound the syslog payload so it can't exceed a UDP datagram ([f9389fd](https://github.com/c0dewhacker/dlpduck/commit/f9389fdb23c5e2497b75d81b0c24a4c34294f612))
* claim() can clobber a job another actor is actively processing ([da29c9c](https://github.com/c0dewhacker/dlpduck/commit/da29c9c8a72daddc818fe452c38d867e9b7f0df7))
* stop staged-job recovery from blocking console readiness ([50a3820](https://github.com/c0dewhacker/dlpduck/commit/50a3820f61dbd2a6a4e42e93ba03de3795866f85))
* stop staged-job recovery from blocking console readiness ([9ee9d16](https://github.com/c0dewhacker/dlpduck/commit/9ee9d160f8c5c6f0a2950e9c70589dab7349a2d7))
* three more bugs found in review ([245a4ad](https://github.com/c0dewhacker/dlpduck/commit/245a4adaee52523cc91abe7a28a60bac4ac0afbb))

## [0.1.7](https://github.com/c0dewhacker/dlpduck/compare/v0.1.6...v0.1.7) (2026-09-11)


### Features

* **chart:** first-class logging.level / logging.traceContentOutput values ([72dfaec](https://github.com/c0dewhacker/dlpduck/commit/72dfaec548deb93c59266de9dd93d801c910c0d9))
* configurable log level, and a double-gated switch for content tracing ([cfd5df5](https://github.com/c0dewhacker/dlpduck/commit/cfd5df57c4149f42d4211a78edad0e9cf1a7e5b8))
* configurable log level, and a double-gated switch for content tracing ([ba4ed70](https://github.com/c0dewhacker/dlpduck/commit/ba4ed7049a82118a2b355fc9e259590ecaa661c2))

## [0.1.6](https://github.com/c0dewhacker/dlpduck/compare/v0.1.5...v0.1.6) (2026-09-10)


### Features

* dot-path field extraction for nested companion metadata ([9e18ec7](https://github.com/c0dewhacker/dlpduck/commit/9e18ec7b9b6de77be1f0204543f9743b9c729dcd))
* dot-path field extraction for nested companion metadata ([c8c5631](https://github.com/c0dewhacker/dlpduck/commit/c8c5631bebbc4bcd5ca5ce1b535c0fe1f4279fee))

## [0.1.5](https://github.com/c0dewhacker/dlpduck/compare/v0.1.4...v0.1.5) (2026-09-10)


### Features

* allow environment config overrides ([ca8bf3b](https://github.com/c0dewhacker/dlpduck/commit/ca8bf3bbecdd02103d933da78f120ee484b62064))
* allow environment config overrides ([687ea67](https://github.com/c0dewhacker/dlpduck/commit/687ea67b1dcee3919d764d12eaeca0d617009292))

## [0.1.4](https://github.com/c0dewhacker/dlpduck/compare/v0.1.3...v0.1.4) (2026-09-10)


### Features

* add Helm deployment and managed version reporting ([3ba858d](https://github.com/c0dewhacker/dlpduck/commit/3ba858d9975dea8856dc564ed75dd713972bc9be))
* add Kubernetes Helm chart ([7a3f884](https://github.com/c0dewhacker/dlpduck/commit/7a3f884ab83b4856e439a970cca2d6ccac539d72))
* display managed application version ([203d3ac](https://github.com/c0dewhacker/dlpduck/commit/203d3ac9e38d3f22a54b0f4f635052dcb99e0cb1))

## [0.1.3](https://github.com/c0dewhacker/dlpduck/compare/v0.1.2...v0.1.3) (2026-09-09)


### Features

* support combined Docker deployment ([85218fc](https://github.com/c0dewhacker/dlpduck/commit/85218fc98a2574c8ed15d91bc29db4f6a1f8cffa))


### Performance Improvements

* reduce Docker image size ([0509af4](https://github.com/c0dewhacker/dlpduck/commit/0509af482432c21e8345e3fc1b654e990f4d506e))
* reduce Docker image size by 30% ([982b24f](https://github.com/c0dewhacker/dlpduck/commit/982b24f27ba3d30b89de43edb78d5f269e82931c))

## [0.1.2](https://github.com/c0dewhacker/dlpduck/compare/v0.1.1...v0.1.2) (2026-09-09)


### Bug Fixes

* secrets context is not valid in a job-level if condition ([b1ff627](https://github.com/c0dewhacker/dlpduck/commit/b1ff6270067bff756191c7139602785418af424d))

## [0.1.1](https://github.com/c0dewhacker/dlpduck/compare/v0.1.0...v0.1.1) (2026-09-09)


### Bug Fixes

* replace PyMuPDF with permissive PDFium binding ([3b66aba](https://github.com/c0dewhacker/dlpduck/commit/3b66aba0aafb22a5d4b3a50927d7a5b7621f0686))
* replace PyMuPDF with pypdfium2 ([a76061d](https://github.com/c0dewhacker/dlpduck/commit/a76061d134623f083bc08e310dd62b035e50d2d5))
