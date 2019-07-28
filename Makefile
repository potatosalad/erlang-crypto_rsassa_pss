PROJECT = crypto_rsassa_pss
PROJECT_DESCRIPTION = RSASSA-PSS Public Key Cryptographic Signature Algorithm for Erlang and Elixir.
PROJECT_VERSION = 2.0.0

TEST_DEPS = proper

dep_proper = git git://github.com/proper-testing/proper.git v1.3

include erlang.mk

.PHONY: docker-build docker-load docker-setup docker-save docker-shell docker-test

DOCKER_OTP_VERSION ?= 22.0

docker-build::
	$(gen_verbose) docker build \
		-t docker-otp-${DOCKER_OTP_VERSION} \
		-f test/Dockerfile \
		--build-arg OTP_VERSION=${DOCKER_OTP_VERSION} \
		test

docker-load::
	$(gen_verbose) docker load \
		-i "docker-otp-${DOCKER_OTP_VERSION}/image.tar"

docker-save::
	$(verbose) mkdir -p "docker-otp-${DOCKER_OTP_VERSION}"
	$(gen_verbose) docker save \
		-o "docker-otp-${DOCKER_OTP_VERSION}/image.tar" \
		docker-otp-${DOCKER_OTP_VERSION}

docker-setup::
	$(verbose) if [ -f "docker-otp-${DOCKER_OTP_VERSION}/image.tar" ]; then \
		$(MAKE) docker-load; \
	else \
		$(MAKE) docker-build; \
		$(MAKE) docker-save; \
	fi

docker-shell::
	$(verbose) docker run \
		-v "$(shell pwd)":"/build/crypto_rsassa_pss" --rm -it "docker-otp-${DOCKER_OTP_VERSION}" \
		/bin/bash -l

docker-test::
	$(gen_verbose) docker run \
		-v "$(shell pwd)":"/build/crypto_rsassa_pss" "docker-otp-${DOCKER_OTP_VERSION}" \
		sh -c 'cd crypto_rsassa_pss && make tests'

